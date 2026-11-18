"""Persist the chosen AI provider (including the API key) in the data volume.

The key is stored server-side with owner-only permissions and is never sent back to the browser.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .config import Settings
from .providers import LLMConfig, build_config, config_from_settings

log = logging.getLogger(__name__)


class LLMStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> dict[str, str] | None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("Ignoring unreadable %s: %s", self._path.name, type(exc).__name__)
            return None
        if not isinstance(data, dict):
            return None
        return {k: str(data.get(k, "")) for k in ("provider", "model", "base_url", "api_key")}

    def save(self, cfg: LLMConfig) -> None:
        """Atomically write the config with 0600 permissions (raises OSError on failure)."""
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self._path.with_name(self._path.name + ".tmp")
        payload = json.dumps(
            {
                "provider": cfg.provider,
                "model": cfg.model,
                "base_url": cfg.base_url,
                "api_key": cfg.api_key,
            }
        )
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            tmp.unlink(missing_ok=True)


def initial_llm_config(settings: Settings, store: LLMStore) -> tuple[LLMConfig, str]:
    """Saved UI settings win over environment variables. Returns (config, 'saved' | 'env')."""
    saved = store.load()
    if saved:
        try:
            return build_config(**saved, ollama_host=settings.ollama_host), "saved"
        except (TypeError, ValueError) as exc:
            log.warning("Saved AI settings are invalid and were ignored: %s", exc)
    try:
        return config_from_settings(settings), "env"
    except ValueError as exc:
        log.warning("AI settings from the environment are invalid: %s", exc)
        return LLMConfig(), "env"
