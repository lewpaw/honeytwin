"""Small builders shared by CLI tests."""

from __future__ import annotations

from datetime import UTC, datetime

from honeytwin.profile.schema import PortInfo, ScanProfileName, TwinProfile


def make_profile(target: str = "192.0.2.10") -> TwinProfile:
    """A minimal stored profile with one open, bannered port."""
    return TwinProfile(
        target=target,
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[PortInfo(protocol="tcp", port=22, state="open", banner="SSH-2.0-OpenSSH_8.9p1")],
    )
