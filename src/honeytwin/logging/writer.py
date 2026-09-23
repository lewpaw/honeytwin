"""Appends structured connection events to a twin's local JSON Lines log.

Failure tolerance (per the `logging` capability spec's "logging failures
do not affect the listener" requirement) is the *caller's* responsibility
- write_event raises on failure rather than swallowing it, so the caller
(runtime/listener.py) can catch and degrade gracefully without this
module silently hiding a real problem from anyone who does want to know.
"""

from __future__ import annotations

import re
from pathlib import Path

from honeytwin.logging.schema import ConnectionEvent

EVENTS_FILENAME = "events.jsonl"
LOGS_SUBDIR = "logs"


def twin_log_dir(twin_name: str, data_dir: Path) -> Path:
    """The host directory holding a twin's event log and attacker records."""
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", twin_name)
    return data_dir / LOGS_SUBDIR / safe_name


def write_event(event: ConnectionEvent, log_dir: Path) -> Path:
    """Append one JSON Line for `event` to `<log_dir>/events.jsonl`."""
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / EVENTS_FILENAME
    with path.open("a", encoding="utf-8") as f:
        f.write(event.model_dump_json())
        f.write("\n")
    return path
