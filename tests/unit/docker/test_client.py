from unittest.mock import MagicMock, patch

import pytest
from docker.errors import DockerException

from honeytwin.docker.client import (
    DockerUnavailableError,
    create_bridge_network,
    create_macvlan_network,
    create_twin_container,
    get_client,
    remove_twin_container,
    start_twin_container,
    stop_twin_container,
)


def test_get_client_returns_client_and_pings():
    mock_client = MagicMock()
    with patch("docker.from_env", return_value=mock_client) as mock_from_env:
        client = get_client()
    mock_from_env.assert_called_once()
    mock_client.ping.assert_called_once()
    assert client is mock_client


def test_get_client_raises_when_daemon_unreachable():
    with patch("docker.from_env", side_effect=DockerException("no daemon")):
        with pytest.raises(DockerUnavailableError):
            get_client()


def test_get_client_raises_when_ping_fails():
    mock_client = MagicMock()
    mock_client.ping.side_effect = DockerException("connection refused")
    with patch("docker.from_env", return_value=mock_client):
        with pytest.raises(DockerUnavailableError):
            get_client()


@pytest.mark.parametrize(
    "func,kwargs",
    [
        (
            create_twin_container,
            {"name": "web-01", "image": "honeytwin/twin", "network_mode": "macvlan"},
        ),
        (start_twin_container, {"name": "web-01"}),
        (stop_twin_container, {"name": "web-01"}),
        (remove_twin_container, {"name": "web-01"}),
    ],
)
def test_container_lifecycle_functions_are_stubs(func, kwargs):
    with pytest.raises(NotImplementedError):
        func(MagicMock(), **kwargs)


def test_create_macvlan_network_is_stub():
    with pytest.raises(NotImplementedError):
        create_macvlan_network(MagicMock(), parent_interface="eth0", subnet="192.0.2.0/24")


def test_create_bridge_network_is_stub():
    with pytest.raises(NotImplementedError):
        create_bridge_network(MagicMock(), name="honeytwin-bridge")
