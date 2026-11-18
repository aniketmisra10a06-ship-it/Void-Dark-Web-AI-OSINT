"""Run Tor as a child process of Void, so no Tor Browser or system daemon is needed.

With ``TOR_PROXY=auto`` (the default) Void starts its own client-only Tor on a free loopback
port, with its own data directory, and reports bootstrap progress to the UI. Setting ``TOR_PROXY``
to an explicit ``socks5h://host:port`` skips this and uses that proxy instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import shutil
import socket
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_BOOTSTRAP = re.compile(r"Bootstrapped (\d{1,3})%")
MAX_RESTARTS = 3
INSTALL_HINT = (
    "Tor is not installed. Install it with `sudo apt install tor` "
    "(the Docker image already includes it)."
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def write_torrc(path: Path, data_dir: Path, port: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "ClientOnly 1",
                f"DataDirectory {data_dir}",
                f"SocksPort 127.0.0.1:{port}",
                "SafeSocks 1",  # refuse requests that would leak DNS lookups
                "AvoidDiskWrites 1",
                "Log notice stdout",
                "",
            ]
        ),
        encoding="utf-8",
    )


class TorManager:
    """Owns the Tor child process (or points at an external proxy) and tracks its state."""

    def __init__(self, proxy: str, binary: str, data_dir: Path) -> None:
        self.embedded = proxy.strip().lower() == "auto"
        self._binary = binary
        self._dir = data_dir / "tor"
        self._port = free_port() if self.embedded else 0
        self.proxy_url = f"socks5h://127.0.0.1:{self._port}" if self.embedded else proxy
        self.progress = 0
        self.error = ""
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopping = False

    # ---- state
    @property
    def ready(self) -> bool:
        return self.progress >= 100 and not self.error

    def snapshot(self) -> dict[str, object]:
        if not self.embedded:
            return {"mode": "external", "progress": None, "error": ""}
        return {"mode": "embedded", "progress": self.progress, "error": self.error}

    # ---- lifecycle
    async def start(self) -> None:
        if not self.embedded:
            return
        exe = shutil.which(self._binary)
        if not exe:
            self.error = INSTALL_HINT
            log.error(self.error)
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            self._dir.chmod(0o700)  # Tor refuses a group/world-accessible DataDirectory
        torrc = self._dir / "torrc"
        write_torrc(torrc, self._dir / "data", self._port)
        (self._dir / "data").mkdir(exist_ok=True, mode=0o700)
        self._task = asyncio.create_task(self._supervise(exe, torrc))

    async def _supervise(self, exe: str, torrc: Path) -> None:
        restarts = 0
        while not self._stopping:
            self.progress, self.error = 0, ""
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    exe,
                    "-f",
                    str(torrc),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except OSError as exc:
                self.error = f"Could not start Tor: {exc.strerror or exc}"
                log.error(self.error)
                return
            log.info("Started Tor (pid %s) on 127.0.0.1:%s", self._proc.pid, self._port)
            assert self._proc.stdout is not None
            async for raw in self._proc.stdout:
                line = raw.decode("utf-8", "replace").rstrip()
                m = _BOOTSTRAP.search(line)
                if m:
                    self.progress = min(100, int(m.group(1)))
                elif "[err]" in line or "[warn]" in line:
                    log.warning("tor: %s", line[-200:])
            code = await self._proc.wait()
            if self._stopping:
                return
            restarts += 1
            self.progress = 0
            self.error = f"Tor stopped unexpectedly (exit code {code})."
            log.error(self.error)
            if restarts > MAX_RESTARTS:
                return
            await asyncio.sleep(min(30, 2**restarts))

    async def stop(self) -> None:
        self._stopping = True
        proc = self._proc
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 10)
            except TimeoutError:
                proc.kill()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task

    async def external_reachable(self) -> bool:
        """For an external proxy: is something listening on its host and port?"""
        parsed = urlparse(self.proxy_url)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(parsed.hostname, parsed.port or 9050), 3
            )
        except (OSError, TimeoutError):
            return False
        writer.close()
        return True
