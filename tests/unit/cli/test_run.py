import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig
from honeytwin.containment.marker import write_marker
from honeytwin.docker.client import NetworkSubnetMismatchError
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
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
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
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
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
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
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

    with patch("honeytwin.cli.commands.run.load_settings", return_value=settings):
        result = runner.invoke(app, ["run", "--name", "does-not-exist"])

    assert result.exit_code != 0
    assert "No generated config found" in result.output


def test_run_macvlan_without_required_settings_exits_nonzero(tmp_path: Path):
    # allow_outbound is required for macvlan at all now - host rules cannot
    # restrict it - so this exercises the settings check beyond that refusal.
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
        allow_outbound=True,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)  # no macvlan_parent_interface/subnet set
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "macvlan mode requires" in result.output


def test_run_attaches_default_twin_to_the_contained_subnet_without_warning(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container"),
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert mock_create_bridge.call_args.kwargs["subnet"] == settings.bridge_subnet
    assert mock_create_bridge.call_args.kwargs["name"] == "honeytwin-bridge"
    assert "allow_outbound" not in result.output


def test_run_with_outbound_allowed_uses_the_uncovered_subnet_and_warns(tmp_path: Path):
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
        allow_outbound=True,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container"),
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge-egress"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert mock_create_bridge.call_args.kwargs["subnet"] == settings.bridge_egress_subnet
    assert mock_create_bridge.call_args.kwargs["name"] == "honeytwin-bridge-egress"
    assert "allow_outbound" in result.output
    assert "weakens containment" in result.output


def test_run_passes_resource_limits_from_twin_config(tmp_path: Path):
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
        mem_limit="128m",
        pids_limit=48,
        cpu_quota=30000,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    kwargs = mock_create_container.call_args.kwargs
    assert kwargs["mem_limit"] == "128m"
    assert kwargs["pids_limit"] == 48
    assert kwargs["cpu_quota"] == 30000


def test_run_reports_a_network_left_over_with_the_wrong_egress_setting(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch(
            "honeytwin.cli.commands.run.create_bridge_network",
            side_effect=NetworkSubnetMismatchError("already exists with internal=False"),
        ),
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "already exists with internal=False" in result.output
    mock_create_container.assert_not_called()


def test_run_refuses_to_start_a_twin_as_root(tmp_path: Path, monkeypatch):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "getgid", lambda: 0, raising=False)

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client") as mock_get_client,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container") as mock_start,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "refusing to start a twin as root" in result.output
    mock_get_client.assert_not_called()
    mock_create_container.assert_not_called()
    mock_start.assert_not_called()


def test_run_as_non_root_user_passes_that_uid_gid_and_starts(tmp_path: Path, monkeypatch):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    monkeypatch.setattr(os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(os, "getgid", lambda: 1002, raising=False)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container") as mock_start,
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert mock_create_container.call_args.kwargs["run_as_user"] == "1001:1002"
    mock_start.assert_called_once()


def test_run_without_posix_uids_passes_no_user_override(tmp_path: Path, monkeypatch):
    """The Windows path: no os.getuid at all, so neither the root refusal nor
    the uid override applies and the run proceeds unchanged."""
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    monkeypatch.delattr(os, "getuid", raising=False)
    monkeypatch.delattr(os, "getgid", raising=False)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert mock_create_container.call_args.kwargs["run_as_user"] is None


def test_run_refuses_when_twin_already_running(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
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


def test_run_refuses_when_containment_was_never_installed(tmp_path: Path):
    """An egress-denied twin depends on a host firewall rule; starting without
    it would report containment that isn't there."""
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container") as mock_start,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "egress restriction is not installed" in result.output
    assert "containment-setup" in result.output
    mock_create_container.assert_not_called()
    mock_start.assert_not_called()


def test_run_refuses_when_containment_is_stale_after_a_reboot(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"):
        write_marker(tmp_path, subnet=settings.bridge_subnet)

    with (
        patch("honeytwin.containment.marker.read_boot_id", return_value="boot-bbb"),
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "rebooted" in result.output
    mock_create_container.assert_not_called()


def test_run_refuses_when_containment_was_installed_for_another_subnet(tmp_path: Path):
    _local_config(tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    write_marker(tmp_path, subnet="172.20.0.0/16")
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "172.20.0.0/16" in result.output
    mock_create_container.assert_not_called()


def test_run_refuses_a_macvlan_twin_that_denies_outbound(tmp_path: Path):
    """Verified on real Linux: macvlan traffic never reaches the host firewall,
    so the restriction cannot apply to it (design.md)."""
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(
        data_dir=tmp_path, macvlan_parent_interface="eth0", macvlan_subnet="192.168.1.0/24"
    )
    write_marker(tmp_path, subnet=settings.bridge_subnet)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_macvlan_network") as mock_macvlan,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
    ):
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code != 0
    assert "macvlan twin cannot be denied outbound access" in result.output
    assert "allow_outbound: true" in result.output
    mock_macvlan.assert_not_called()
    mock_create_container.assert_not_called()


def test_run_allows_a_macvlan_twin_that_opts_into_outbound(tmp_path: Path):
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
        allow_outbound=True,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(
        data_dir=tmp_path, macvlan_parent_interface="eth0", macvlan_subnet="192.168.1.0/24"
    )
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_macvlan_network") as mock_macvlan,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_macvlan.return_value.name = "honeytwin-macvlan"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert "weakens containment" in result.output
    mock_create_container.assert_called_once()


def test_run_with_outbound_allowed_does_not_require_containment(tmp_path: Path):
    """The restriction only covers the denied-egress subnet, so a twin that
    opted out has nothing to wait for."""
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner=None)],
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
        allow_outbound=True,
    )
    save_twin_config(config, tmp_path)
    settings = GlobalConfig(data_dir=tmp_path)
    mock_client = MagicMock()

    with (
        patch("honeytwin.cli.commands.run.load_settings", return_value=settings),
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_create_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create_container,
        patch("honeytwin.cli.commands.run.start_twin_container"),
    ):
        mock_create_bridge.return_value.name = "honeytwin-bridge-egress"
        result = runner.invoke(app, ["run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    mock_create_container.assert_called_once()
