from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig
from honeytwin.docker.client import DockerUnavailableError
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.generate.store import save_twin_config
from honeytwin.logging.writer import twin_log_dir

runner = CliRunner()


def test_stop_running_twin_stops_and_removes_container():
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.stop.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.stop.get_twin_container_status", return_value="running"),
        patch("honeytwin.cli.commands.stop.stop_twin_container") as mock_stop,
        patch("honeytwin.cli.commands.stop.remove_twin_container") as mock_remove,
    ):
        result = runner.invoke(app, ["stop", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert "stopped" in result.output
    mock_stop.assert_called_once_with(mock_client, name="web-01")
    mock_remove.assert_called_once_with(mock_client, name="web-01")


def test_stop_twin_that_is_not_running_exits_nonzero():
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.stop.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.stop.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.stop.stop_twin_container") as mock_stop,
        patch("honeytwin.cli.commands.stop.remove_twin_container") as mock_remove,
    ):
        result = runner.invoke(app, ["stop", "--name", "web-01"])

    assert result.exit_code != 0
    assert "not running" in result.output
    mock_stop.assert_not_called()
    mock_remove.assert_not_called()


def test_stop_reports_docker_unavailable():
    with patch(
        "honeytwin.cli.commands.stop.get_client",
        side_effect=DockerUnavailableError("daemon not reachable"),
    ):
        result = runner.invoke(app, ["stop", "--name", "web-01"])

    assert result.exit_code != 0
    assert "not reachable" in result.output


def test_stop_leaves_generated_config_and_logs_on_disk(tmp_path: Path):
    """The twin-runtime capability requires stopping to preserve a twin's
    config and logs - exercised here for the first time."""
    settings = GlobalConfig(data_dir=tmp_path)
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner="SSH-2.0-test")],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
    )
    config_path = save_twin_config(config, settings.data_dir)

    log_dir = twin_log_dir("web-01", settings.data_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    events = log_dir / "events.jsonl"
    events.write_text('{"twin_name":"web-01"}\n', encoding="utf-8")

    mock_client = MagicMock()
    with (
        patch("honeytwin.cli.commands.stop.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.stop.get_twin_container_status", return_value="running"),
        patch("honeytwin.cli.commands.stop.stop_twin_container"),
        patch("honeytwin.cli.commands.stop.remove_twin_container"),
    ):
        result = runner.invoke(app, ["stop", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert config_path.exists()
    assert events.exists()
    assert events.read_text(encoding="utf-8") == '{"twin_name":"web-01"}\n'
