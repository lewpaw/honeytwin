from datetime import UTC, datetime

from honeytwin.profile.schema import (
    CURRENT_SCHEMA_VERSION,
    OSMatch,
    PortInfo,
    ScanProfileName,
    ScriptResult,
    TwinProfile,
)


def test_twin_profile_from_fixture_like_data():
    """Constructs a profile with the same shape as tests/fixtures/nmap_scan.xml."""
    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.DEEP,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[
            PortInfo(
                protocol="tcp",
                port=22,
                state="open",
                service="ssh",
                product="OpenSSH",
                version="8.9p1",
                banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            ),
            PortInfo(
                protocol="tcp",
                port=80,
                state="open",
                service="http",
                product="nginx",
                version="1.18.0",
                banner="nginx/1.18.0 (Ubuntu)",
            ),
            PortInfo(protocol="tcp", port=443, state="closed", service="https"),
        ],
        os_match=OSMatch(name="Linux 5.4 - 5.15", accuracy=95),
        scripts=[
            ScriptResult(script_id="banner", output="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
            ScriptResult(script_id="http-server-header", output="nginx/1.18.0 (Ubuntu)"),
        ],
    )

    assert profile.schema_version == CURRENT_SCHEMA_VERSION
    assert profile.target == "192.0.2.10"
    assert len(profile.ports) == 3
    assert profile.ports[0].port == 22
    assert profile.os_match.name == "Linux 5.4 - 5.15"
    assert len(profile.scripts) == 2


def test_twin_profile_defaults():
    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.LIGHT,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert profile.ports == []
    assert profile.os_match is None
    assert profile.scripts == []
