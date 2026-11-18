import asyncio
import stat

from app.tor import INSTALL_HINT, TorManager, write_torrc


def _fake_tor(path, lines):
    body = "\n".join(f'echo "{ln}"' for ln in lines)
    path.write_text(f"#!/bin/sh\n{body}\nsleep 30\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


async def _wait(cond, timeout=5.0):
    end = asyncio.get_running_loop().time() + timeout
    while not cond():
        if asyncio.get_running_loop().time() > end:
            raise AssertionError("timed out")
        await asyncio.sleep(0.05)


async def test_embedded_tor_tracks_bootstrap_progress(tmp_path):
    exe = _fake_tor(
        tmp_path / "faketor",
        ["Nov 18 [notice] Bootstrapped 5% (conn): x", "[notice] Bootstrapped 100% (done): Done"],
    )
    tor = TorManager("auto", exe, tmp_path)
    assert tor.embedded and tor.proxy_url.startswith("socks5h://127.0.0.1:")
    await tor.start()
    try:
        await _wait(lambda: tor.ready)
        assert tor.snapshot() == {"mode": "embedded", "progress": 100, "error": ""}
        torrc = (tmp_path / "tor" / "torrc").read_text()
        assert "ClientOnly 1" in torrc and "SafeSocks 1" in torrc
        assert f"SocksPort 127.0.0.1:{tor.proxy_url.rsplit(':', 1)[1]}" in torrc
    finally:
        await tor.stop()


async def test_missing_tor_binary_reports_install_hint(tmp_path):
    tor = TorManager("auto", "definitely-not-a-real-tor-binary", tmp_path)
    await tor.start()
    assert tor.error == INSTALL_HINT and not tor.ready
    await tor.stop()


async def test_external_proxy_is_not_started(tmp_path):
    tor = TorManager("socks5h://127.0.0.1:9", "tor", tmp_path)
    assert not tor.embedded and tor.proxy_url == "socks5h://127.0.0.1:9"
    await tor.start()
    assert tor.snapshot()["mode"] == "external"
    assert await tor.external_reachable() is False


def test_torrc_is_client_only_and_loopback(tmp_path):
    write_torrc(tmp_path / "torrc", tmp_path / "d", 19050)
    text = (tmp_path / "torrc").read_text()
    assert "SocksPort 127.0.0.1:19050" in text and "ClientOnly 1" in text
    assert "ExitRelay" not in text and "ORPort" not in text
