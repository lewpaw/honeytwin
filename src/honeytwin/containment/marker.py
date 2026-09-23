"""The record of whether the host egress restriction is in effect.

`honeytwin run` deliberately does not run as root, so it cannot read the
firewall tables to check for itself. It reads this marker instead, which
`containment-setup` writes.

A marker saying "setup was run" would survive a reboot that flushed the
rules — exactly the containment claim that quietly stops holding. So the
marker also records the host's boot id, which is world-readable and
changes on every boot: if it no longer matches, the marker is stale and
the restriction is treated as absent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

MARKER_FILENAME = "containment.json"
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


class ContainmentState(StrEnum):
    """Whether the egress restriction can be relied on right now."""

    ACTIVE = "active"
    STALE = "stale"
    SUBNET_MISMATCH = "subnet-mismatch"
    MISSING = "missing"


@dataclass(frozen=True)
class ContainmentMarker:
    """What `containment-setup` recorded when it installed the rules."""

    subnet: str
    boot_id: str
    installed_at: str


def marker_path(data_dir: Path) -> Path:
    """Where the containment marker lives for a given data directory."""
    return data_dir / MARKER_FILENAME


def read_boot_id() -> str | None:
    """The host's current boot id, or None where there isn't one (Windows).

    Absence is not an error here: it means this host has no boot id to
    compare against, which `evaluate` treats as "cannot confirm".
    """
    try:
        return BOOT_ID_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def write_marker(data_dir: Path, *, subnet: str) -> ContainmentMarker:
    """Record that the egress restriction was installed for `subnet`."""
    marker = ContainmentMarker(
        subnet=subnet,
        boot_id=read_boot_id() or "",
        installed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    marker_path(data_dir).write_text(json.dumps(marker.__dict__, indent=2) + "\n", encoding="utf-8")
    return marker


def read_marker(data_dir: Path) -> ContainmentMarker | None:
    """The recorded marker, or None if there isn't a readable, valid one.

    A corrupt or truncated marker is treated as no marker at all — the
    safe reading, since the consequence is refusing to start a twin
    rather than starting an uncontained one.
    """
    try:
        data = json.loads(marker_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return ContainmentMarker(
            subnet=data["subnet"],
            boot_id=data["boot_id"],
            installed_at=data["installed_at"],
        )
    except (KeyError, TypeError):
        return None


def remove_marker(data_dir: Path) -> None:
    """Delete the marker, if there is one."""
    marker_path(data_dir).unlink(missing_ok=True)


def evaluate(data_dir: Path, *, subnet: str) -> tuple[ContainmentState, ContainmentMarker | None]:
    """Whether the egress restriction can be relied on for `subnet`.

    Checked in the order that gives the most useful message: no marker at
    all, then a marker for a different subnet, then one invalidated by a
    reboot.
    """
    marker = read_marker(data_dir)
    if marker is None:
        return ContainmentState.MISSING, None
    if marker.subnet != subnet:
        return ContainmentState.SUBNET_MISMATCH, marker

    current_boot_id = read_boot_id()
    if current_boot_id is not None and marker.boot_id != current_boot_id:
        return ContainmentState.STALE, marker

    return ContainmentState.ACTIVE, marker
