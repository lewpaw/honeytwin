import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from honeytwin.config.schema import GlobalConfig
from honeytwin.generate.generator import generate_twin_config
from honeytwin.profile.schema import PortInfo, ScanProfileName, TwinProfile
from honeytwin.profile.store import load_profile, save_profile


def test_generation_from_stored_profile_touches_neither_subprocess_nor_sockets(
    tmp_path: Path, monkeypatch
):
    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[PortInfo(protocol="tcp", port=22, state="open", banner="SSH-2.0-OpenSSH_8.9p1")],
    )
    profile_path = save_profile(profile, tmp_path)

    def _forbidden(*args, **kwargs):
        raise AssertionError("generation must not invoke subprocess or open sockets")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)

    loaded_profile = load_profile(profile_path)
    config = generate_twin_config(loaded_profile, "web-01", GlobalConfig())

    assert config.ports[0].port == 22
    assert config.ports[0].banner == "SSH-2.0-OpenSSH_8.9p1"
