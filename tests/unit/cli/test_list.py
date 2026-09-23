from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig
from honeytwin.docker.client import DockerUnavailableError
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.generate.store import save_twin_config

runner = CliRunner()


def _make_twin(tmp_path: Path, name: str, port: int = 22) -> None:
    save_twin_config(
        TwinConfigFile(
            name=name,
            target="192.0.2.10",
            ports=[TwinPortConfig(port=port, protocol="tcp", banner="SSH-2.0-test")],
            docker_network_mode=DockerNetworkMode.BRIDGE,
            exposure_scope=ExposureScope.LOCAL,
        ),
        tmp_path,
    )


def test_list_shows_generated_twins_with_status(tmp_path: Path):
    _make_twin(tmp_path, "web-01", port=80)
    _make_twin(tmp_path, "ssh-02", port=22)
    settings = GlobalConfig(data_dir=tmp_path)

    with (
        patch("honeytwin.cli.commands.list.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.list.get_client", return_value=MagicMock()),
        patch(
            "honeytwin.cli.commands.list.get_twin_container_status",
            side_effect=lambda client, *, name: "running" if name == "web-01" else None,
        ),
    ):
        result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, result.output
    assert "web-01" in result.output
    assert "ssh-02" in result.output
    assert "running" in result.output
    assert "not running" in result.output
    assert "80" in result.output
    assert "bridge" in result.output
    assert "local" in result.output


def test_list_honors_name_filter(tmp_path: Path):
    _make_twin(tmp_path, "web-01")
    _make_twin(tmp_path, "ssh-02")
    settings = GlobalConfig(data_dir=tmp_path)

    with (
        patch("honeytwin.cli.commands.list.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.list.get_client", return_value=MagicMock()),
        patch("honeytwin.cli.commands.list.get_twin_container_status", return_value=None),
    ):
        result = runner.invoke(app, ["list", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert "web-01" in result.output
    assert "ssh-02" not in result.output


def test_list_filter_for_unknown_name_reports_clearly(tmp_path: Path):
    _make_twin(tmp_path, "web-01")
    settings = GlobalConfig(data_dir=tmp_path)

    with patch("honeytwin.cli.commands.list.load_settings", return_value=settings):
        result = runner.invoke(app, ["list", "--name", "nope"])

    assert result.exit_code == 0, result.output
    assert "No twin named 'nope'" in result.output


def test_list_with_no_twins_is_not_an_error(tmp_path: Path):
    settings = GlobalConfig(data_dir=tmp_path)

    with patch("honeytwin.cli.commands.list.load_settings", return_value=settings):
        result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, result.output
    assert "No twins have been generated" in result.output


def test_list_still_lists_twins_when_docker_unavailable(tmp_path: Path):
    _make_twin(tmp_path, "web-01", port=443)
    settings = GlobalConfig(data_dir=tmp_path)

    with (
        patch("honeytwin.cli.commands.list.load_settings", return_value=settings),
        patch(
            "honeytwin.cli.commands.list.get_client",
            side_effect=DockerUnavailableError("daemon not reachable"),
        ),
    ):
        result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, result.output
    assert "web-01" in result.output
    assert "443" in result.output
    assert "unknown" in result.output
