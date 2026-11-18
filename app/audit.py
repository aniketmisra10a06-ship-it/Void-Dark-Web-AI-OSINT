"""Append-only JSONL audit log: who searched what, and which URLs were read.

Page *content* is never written here, only queries, URLs and counts.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()

    def record(self, event: dict[str, Any]) -> None:
        if self._path is None:
            return
        entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), **event}
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:  # never let logging break a request
            log.warning("Could not write audit log: %s", exc)
