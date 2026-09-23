from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException, NotFound

from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.docker.client import (
    TWIN_CONFIG_MOUNT_PATH,
    TWIN_LOG_MOUNT_PATH,
    DockerUnavailableError,
    NetworkSubnetMismatchError,
    create_bridge_network,
    create_macvlan_network,
    create_twin_container,
    get_client,
    get_twin_container_status,
    remove_twin_container,
    start_twin_container,
    stop_twin_container,
)


def test_get_client_returns_client_and_pings(monkeypatch):
    mock_client = MagicMock()
    monkeypatch.setattr("docker.from_env", lambda: mock_client)
    client = get_client()
    mock_client.ping.assert_called_once()
    assert client is mock_client


def test_get_client_raises_when_daemon_unreachable(monkeypatch):
    monkeypatch.setattr("docker.from_env", MagicMock(side_effect=DockerException("no daemon")))
    with pytest.raises(DockerUnavailableError):
        get_client()


def test_get_client_raises_when_ping_fails(monkeypatch):
    mock_client = MagicMock()
    mock_client.ping.side_effect = DockerException("connection refused")
    monkeypatch.setattr("docker.from_env", lambda: mock_client)
    with pytest.raises(DockerUnavailableError):
        get_client()


def test_create_bridge_network_pins_the_requested_subnet():
    mock_client = MagicMock()
    mock_client.networks.get.side_effect = NotFound("no such network")
    created_network = MagicMock()
    mock_client.networks.create.return_value = created_network

    result = create_bridge_network(mock_client, name="honeytwin-bridge", subnet="172.31.240.0/24")

    call = mock_client.networks.create.call_args
    assert call.args[0] == "honeytwin-bridge"
    assert call.kwargs["driver"] == "bridge"
    pool = call.kwargs["ipam"]["Config"][0]
    assert pool["Subnet"] == "172.31.240.0/24"
    assert result is created_network


def test_create_bridge_network_reuses_existing_with_matching_subnet():
    mock_client = MagicMock()
    existing_network = MagicMock()
    existing_network.attrs = {"IPAM": {"Config": [{"Subnet": "172.31.240.0/24"}]}}
    mock_client.networks.get.return_value = existing_network

    result = create_bridge_network(mock_client, name="honeytwin-bridge", subnet="172.31.240.0/24")

    mock_client.networks.create.assert_not_called()
    assert result is existing_network


def test_create_bridge_network_refuses_existing_network_on_a_different_subnet():
    """The egress restriction is a firewall rule naming one subnet, so a twin
    on any other subnet would sit outside it."""
    mock_client = MagicMock()
    existing_network = MagicMock()
    existing_network.attrs = {"IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]}}
    mock_client.networks.get.return_value = existing_network

    with pytest.raises(NetworkSubnetMismatchError):
        create_bridge_network(mock_client, name="honeytwin-bridge", subnet="172.31.240.0/24")


def test_create_macvlan_network_creates_when_missing():
    mock_client = MagicMock()
    mock_client.networks.get.side_effect = NotFound("no such network")
    created_network = MagicMock()
    mock_client.networks.create.return_value = created_network

    result = create_macvlan_network(
        mock_client,
        name="honeytwin-macvlan",
        parent_interface="eth0",
        subnet="192.168.1.0/24",
        gateway="192.168.1.1",
    )

    assert mock_client.networks.create.call_count == 1
    call = mock_client.networks.create.call_args
    assert call.args[0] == "honeytwin-macvlan"
    assert call.kwargs["driver"] == "macvlan"
    assert call.kwargs["options"] == {"parent": "eth0"}
    assert result is created_network


def test_create_macvlan_network_reuses_existing():
    mock_client = MagicMock()
    existing_network = MagicMock()
    mock_client.networks.get.return_value = existing_network

    result = create_macvlan_network(
        mock_client, name="honeytwin-macvlan", parent_interface="eth0", subnet="192.168.1.0/24"
    )

    mock_client.networks.create.assert_not_called()
    assert result is existing_network


def test_create_twin_container_bridge_mode_internet_binds_all_interfaces():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22, 80],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.INTERNET,
    )

    call = mock_client.containers.create.call_args
    assert call.args[0] == "honeytwin-twin:local"
    assert call.kwargs["name"] == "web-01"
    assert call.kwargs["network"] == "honeytwin-bridge"
    assert call.kwargs["ports"] == {
        "22/tcp": ("0.0.0.0", 22),
        "80/tcp": ("0.0.0.0", 80),
    }
    assert call.kwargs["cap_add"] == ["NET_BIND_SERVICE"]
    assert call.kwargs["volumes"] == {
        str(Path("/data/twins/web-01/config.json")): {
            "bind": TWIN_CONFIG_MOUNT_PATH,
            "mode": "ro",
        },
        str(Path("/data/logs/web-01")): {
            "bind": TWIN_LOG_MOUNT_PATH,
            "mode": "rw",
        },
    }


def test_create_twin_container_bridge_mode_local_binds_discovered_address(monkeypatch):
    mock_client = MagicMock()
    monkeypatch.setattr("honeytwin.docker.client._discover_lan_bind_address", lambda: "10.0.0.5")

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["ports"] == {"22/tcp": ("10.0.0.5", 22)}


def test_create_twin_container_macvlan_mode_publishes_no_ports():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22, 80],
        network_mode=DockerNetworkMode.MACVLAN,
        network_name="honeytwin-macvlan",
        exposure_scope=ExposureScope.LOCAL,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["ports"] is None
    assert call.kwargs["network"] == "honeytwin-macvlan"


def test_create_twin_container_passes_run_as_user_when_given():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
        run_as_user="1001:1001",
    )

    assert mock_client.containers.create.call_args.kwargs["user"] == "1001:1001"


def test_create_twin_container_omits_user_when_not_given():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
    )

    assert "user" not in mock_client.containers.create.call_args.kwargs


def test_create_twin_container_includes_log_mount():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.MACVLAN,
        network_name="honeytwin-macvlan",
        exposure_scope=ExposureScope.LOCAL,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["volumes"][str(Path("/data/logs/web-01"))] == {
        "bind": TWIN_LOG_MOUNT_PATH,
        "mode": "rw",
    }


def test_create_twin_container_drops_all_capabilities_and_adds_back_net_bind_service():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["cap_drop"] == ["ALL"]
    assert call.kwargs["cap_add"] == ["NET_BIND_SERVICE"]


def test_create_twin_container_applies_resource_limits_and_read_only_rootfs():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
        mem_limit="64m",
        pids_limit=32,
        cpu_quota=25000,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["read_only"] is True
    assert call.kwargs["mem_limit"] == "64m"
    assert call.kwargs["pids_limit"] == 32
    assert call.kwargs["cpu_quota"] == 25000


def test_create_twin_container_applies_conservative_limit_defaults():
    mock_client = MagicMock()

    create_twin_container(
        mock_client,
        name="web-01",
        image="honeytwin-twin:local",
        config_path=Path("/data/twins/web-01/config.json"),
        log_dir=Path("/data/logs/web-01"),
        ports=[22],
        network_mode=DockerNetworkMode.BRIDGE,
        network_name="honeytwin-bridge",
        exposure_scope=ExposureScope.LOCAL,
    )

    call = mock_client.containers.create.call_args
    assert call.kwargs["mem_limit"] == "256m"
    assert call.kwargs["pids_limit"] == 128
    assert call.kwargs["cpu_quota"] == 50000


def test_get_twin_container_status_returns_status_when_container_exists():
    mock_client = MagicMock()
    mock_client.containers.get.return_value.status = "running"

    assert get_twin_container_status(mock_client, name="web-01") == "running"
    mock_client.containers.get.assert_called_once_with("web-01")


def test_get_twin_container_status_returns_none_when_not_found():
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = NotFound("no such container")

    assert get_twin_container_status(mock_client, name="web-01") is None


def test_start_twin_container_calls_start():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    start_twin_container(mock_client, name="web-01")

    mock_client.containers.get.assert_called_once_with("web-01")
    mock_container.start.assert_called_once()


def test_stop_twin_container_calls_stop():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    stop_twin_container(mock_client, name="web-01")

    mock_container.stop.assert_called_once()


def test_remove_twin_container_calls_remove_force():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    remove_twin_container(mock_client, name="web-01")

    mock_container.remove.assert_called_once_with(force=True)
