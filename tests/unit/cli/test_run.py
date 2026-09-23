from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.generate.store import save_twin_config

runner = CliRunner()


def _local_config(tmp_path: Path, name: str = "web-01") -> TwinConfigFile:
    config = TwinConfigFile(
        name=name,
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner="SSH-2.0-OpenSSH_8.9p1")],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
    )
    save_twin_config(config, tmp_path)
    return config


def _internet_config(tmp_path: Path, name: str = "web-01") -> TwinConfigFile:
    config = TwinConfigFile(
        name=name,
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner="SSH-2.0-OpenSSH_8.9p1")],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.INTERNET,
    )
    save_twin_config(config, tmp_path)
    return config


def test_run_local_twin_no_warning_and_starts_container(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_global_config", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container") as mock_start,
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert "reachable from any network" not in result.output
    mock_create_container.assert_called_once()
    mock_start.assert_called_once_with(mock_client, name="web-01")


def test_run_internet_twin_prints_warning_before_start(tmp_path: Path):
    _internet_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_global_config", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container"),
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert "reachable from any network" in result.output
    assert result.output.index("reachable from any network") < result.output.index("started")


def test_run_creates_log_dir_and_passes_it_to_container(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_global_config", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output

    expected_log_dir = tmp_path / "logs" / "web-01"
    assert expected_log_dir.exists()
    assert mock_create_container.call_args.kwargs["log_dir"] == expected_log_dir


def test_run_missing_twin_config_exits_nonzero_with_clear_error(tmp_path: Path):
    settings = GlobalConfig(data_dir=tmp_path)

    with patch("honeytwin.cli.commands.run.load_global_config", return_value=settings):
        result = runner.invoke(app, ["run", "--name", "does-not-exist"])

    assert result.exit_code != 0
    assert "No generated config found" in result.output


def test_run_macvlan_without_required_settings_exits_nonzero(tmp_path: Path):
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)  # no macvlan_parent_interface/subnet set
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_global_config", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "macvlan mode requires" in result.output


def test_run_refuses_when_twin_already_running(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_global_config", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value="running"),
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container") as mock_start,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "already running" in result.output
    mock_create_container.assert_not_called()
    mock_start.assert_not_called()
