import os
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import GlobalConfig
from honeytwin.containment.firewall import FirewallError
from honeytwin.containment.marker import read_marker, write_marker

runner = CliRunner()
SUBNET = "172.31.240.0/24"


def _settings(tmp_path: Path) -> GlobalConfig:
    return GlobalConfig(data_dir=tmp_path, bridge_subnet=SUBNET)


def test_setup_installs_rules_and_records_the_marker(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)

    with (
        patch(
            "honeytwin.cli.commands.containment.load_settings",
            return_value=_settings(tmp_path),
        ),
        patch(
            "honeytwin.cli.commands.containment.install_rules",
            return_value=[f"DOCKER-USER -s {SUBNET} -j DROP"],
        ) as mock_install,
        patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"),
    ):
        result = runner.invoke(app, ["containment-setup"])

    assert result.exit_code == 0, result.output
    mock_install.assert_called_once_with(SUBNET)
    assert "installed" in result.output
    assert "do not survive a reboot" in result.output

    marker = read_marker(tmp_path)
    assert marker.subnet == SUBNET
    assert marker.boot_id == "boot-aaa"


def test_setup_reports_when_rules_were_already_in_place(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)

    with (
        patch(
            "honeytwin.cli.commands.containment.load_settings",
            return_value=_settings(tmp_path),
        ),
        patch("honeytwin.cli.commands.containment.install_rules", return_value=[]),
        patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"),
    ):
        result = runner.invoke(app, ["containment-setup"])

    assert result.exit_code == 0, result.output
    assert "already in place" in result.output


def test_setup_refuses_without_root(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1001, raising=False)

    with patch("honeytwin.cli.commands.containment.install_rules") as mock_install:
        result = runner.invoke(app, ["containment-setup"])

    assert result.exit_code != 0
    assert "requires root" in result.output
    mock_install.assert_not_called()
    assert read_marker(tmp_path) is None


def test_setup_reports_a_firewall_failure_without_writing_a_marker(tmp_path: Path, monkeypatch):
    """A marker written after a failed install would claim containment that
    was never applied."""
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)

    with (
        patch(
            "honeytwin.cli.commands.containment.load_settings",
            return_value=_settings(tmp_path),
        ),
        patch(
            "honeytwin.cli.commands.containment.install_rules",
            side_effect=FirewallError("iptables was not found on this host"),
        ),
    ):
        result = runner.invoke(app, ["containment-setup"])

    assert result.exit_code != 0
    assert "iptables was not found" in result.output
    assert read_marker(tmp_path) is None


def test_status_reports_active(tmp_path: Path):
    with patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)

        with (
            patch(
                "honeytwin.cli.commands.containment.load_settings",
                return_value=_settings(tmp_path),
            ),
            patch("honeytwin.cli.commands.containment.rules_installed", return_value=True),
        ):
            result = runner.invoke(app, ["containment-status"])

    assert result.exit_code == 0, result.output
    assert "active" in result.output
    assert "present" in result.output


def test_status_reports_stale_after_a_reboot(tmp_path: Path):
    with patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)

    with (
        patch("honeytwin.containment.marker.read_boot_id", return_value="boot-bbb"),
        patch(
            "honeytwin.cli.commands.containment.load_settings",
            return_value=_settings(tmp_path),
        ),
        patch("honeytwin.cli.commands.containment.rules_installed", return_value=False),
    ):
        result = runner.invoke(app, ["containment-status"])

    assert result.exit_code != 0
    assert "STALE" in result.output
    assert "containment-setup" in result.output


def test_status_reports_missing(tmp_path: Path):
    with (
        patch(
            "honeytwin.cli.commands.containment.load_settings",
            return_value=_settings(tmp_path),
        ),
        patch("honeytwin.cli.commands.containment.rules_installed", return_value=False),
    ):
        result = runner.invoke(app, ["containment-status"])

    assert result.exit_code != 0
    assert "not installed" in result.output


def test_status_says_so_when_it_cannot_read_the_live_rules(tmp_path: Path):
    with patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)

        with (
            patch(
                "honeytwin.cli.commands.containment.load_settings",
                return_value=_settings(tmp_path),
            ),
            patch(
                "honeytwin.cli.commands.containment.rules_installed",
                side_effect=FirewallError("Could not inspect DOCKER-USER"),
            ),
        ):
            result = runner.invoke(app, ["containment-status"])

    assert result.exit_code == 0, result.output
    assert "not readable without root" in result.output


def test_both_commands_appear_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "containment-setup" in result.output
    assert "containment-status" in result.output
