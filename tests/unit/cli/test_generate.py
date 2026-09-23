from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import GlobalConfig
from honeytwin.profile.schema import PortInfo, ScanProfileName, TwinProfile
from honeytwin.profile.store import save_profile

runner = CliRunner()


def test_generate_creates_twin_config_from_stored_profile(tmp_path: Path):
    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[
            PortInfo(protocol="tcp", port=22, state="open", banner="SSH-2.0-OpenSSH_8.9p1"),
            PortInfo(protocol="tcp", port=443, state="closed"),
        ],
    )
    profile_path = save_profile(profile, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)

    with patch("honeytwin.cli.commands.generate.load_global_config", return_value=settings):
        result = runner.invoke(
            app, ["generate", "--name", "web-01", "--profile", str(profile_path)]
        )

    assert result.exit_code == 0, result.output
    assert "Generated twin 'web-01'" in result.output

    config_file = tmp_path / "twins" / "web-01" / "config.json"
    assert config_file.exists()


def test_generate_reports_missing_profile_file(tmp_path: Path):
    settings = GlobalConfig(data_dir=tmp_path)
    missing = tmp_path / "does-not-exist.json"

    with patch("honeytwin.cli.commands.generate.load_global_config", return_value=settings):
        result = runner.invoke(app, ["generate", "--name", "web-01", "--profile", str(missing)])

    assert result.exit_code != 0
