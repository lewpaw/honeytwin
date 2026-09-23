"""Correlates connection events by source IP into a per-attacker record.

Scoped to one twin's own process (see design.md's non-goals — cross-twin/
cross-process correlation is Epic 4 territory). The caller (the
listener's connection handler) already serializes calls into this module
with its own `asyncio.Lock`, so the read-modify-write here doesn't need
its own locking for the single-twin-process case this epic covers.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

ATTACKERS_SUBDIR = "attackers"


def _sanitize_ip(source_ip: str) -> str:
    return re.sub(r"[^A-Za-z0-9.:_-]", "_", source_ip)


def update_attacker_record(source_ip: str, twin_name: str, log_dir: Path) -> Path:
    """Read-modify-write the per-attacker record for `source_ip`."""
    attackers_dir = log_dir / ATTACKERS_SUBDIR
    attackers_dir.mkdir(parents=True, exist_ok=True)
    path = attackers_dir / f"{_sanitize_ip(source_ip)}.json"

    now = datetime.now(tz=UTC).isoformat()

    if path.exists():
        record = json.loads(path.read_text(encoding="utf-8"))
        record["last_seen"] = now
        record["session_count"] = record.get("session_count", 0) + 1
        twins_targeted = set(record.get("twins_targeted", []))
        twins_targeted.add(twin_name)
        record["twins_targeted"] = sorted(twins_targeted)
    else:
        record = {
            "source_ip": source_ip,
            "first_seen": now,
            "last_seen": now,
            "session_count": 1,
            "twins_targeted": [twin_name],
        }

    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path
