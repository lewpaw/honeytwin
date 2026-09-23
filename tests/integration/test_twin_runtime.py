"""Integration tests that build the real honeytwin-twin image (must be
built beforehand: `docker build -t honeytwin-twin:local -f Dockerfile .`),
generate a real twin config, run it as a real container via the actual
Docker lifecycle functions, and verify a real client connecting to it.
"""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig
from honeytwin.docker.client import (
    _discover_lan_bind_address,
    create_bridge_network,
    create_twin_container,
    get_client,
    remove_twin_container,
    start_twin_container,
    stop_twin_container,
)
from honeytwin.generate.generator import generate_twin_config
from honeytwin.generate.store import load_twin_config, save_twin_config
from honeytwin.profile.schema import PortInfo, ScanProfileName, TwinProfile
from honeytwin.profile.store import save_profile

TWIN_IMAGE = "honeytwin-twin:local"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.integration
def test_generated_twin_replays_banner_and_holds_no_banner_port_open(tmp_path: Path):
    banner_port = _free_port()
    quiet_port = _free_port()

    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[
            PortInfo(
                protocol="tcp",
                port=banner_port,
                state="open",
                banner="SSH-2.0-OpenSSH_8.9p1 real-twin\r\n",
            ),
            PortInfo(protocol="tcp", port=quiet_port, state="open", banner=None),
        ],
    )
    profile_path = save_profile(profile, tmp_path)

    settings = GlobalConfig(
        data_dir=tmp_path,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.INTERNET,  # binds 0.0.0.0, reachable via 127.0.0.1
    )
    twin_config = generate_twin_config(profile, "integration-twin", settings)
    config_path = save_twin_config(twin_config, tmp_path)

    client = get_client()
    network = create_bridge_network(client, name="honeytwin-test-bridge")

    container_name = "honeytwin-test-integration-twin"
    try:
        create_twin_container(
            client,
            name=container_name,
            image=TWIN_IMAGE,
            config_path=config_path,
            ports=[p.port for p in twin_config.ports],
            network_mode=DockerNetworkMode.BRIDGE,
            network_name=network.name,
            exposure_scope=ExposureScope.INTERNET,
        )
        start_twin_container(client, name=container_name)
        time.sleep(1.5)  # let the listener bind inside the container

        with socket.create_connection(("127.0.0.1", banner_port), timeout=5) as sock:
            received = sock.recv(1024)
        assert received == b"SSH-2.0-OpenSSH_8.9p1 real-twin\r\n"

        with socket.create_connection(("127.0.0.1", quiet_port), timeout=5) as sock:
            sock.settimeout(0.5)
            with pytest.raises(TimeoutError):
                sock.recv(1024)
    finally:
        stop_twin_container(client, name=container_name)
        remove_twin_container(client, name=container_name)

    # Stopping/removing the container must not touch the source profile or
    # generated twin config on disk.
    assert profile_path.exists()
    assert config_path.exists()
    reloaded = load_twin_config("integration-twin", tmp_path)
    assert reloaded == twin_config


@pytest.mark.integration
def test_local_scope_bridge_binds_to_discovered_lan_address(tmp_path: Path):
    port = _free_port()

    profile = TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[PortInfo(protocol="tcp", port=port, state="open", banner="local-scope-banner")],
    )

    settings = GlobalConfig(
        data_dir=tmp_path,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
    )
    twin_config = generate_twin_config(profile, "local-scope-twin", settings)
    config_path = save_twin_config(twin_config, tmp_path)

    client = get_client()
    network = create_bridge_network(client, name="honeytwin-test-bridge")

    container_name = "honeytwin-test-local-scope-twin"
    try:
        create_twin_container(
            client,
            name=container_name,
            image=TWIN_IMAGE,
            config_path=config_path,
            ports=[port],
            network_mode=DockerNetworkMode.BRIDGE,
            network_name=network.name,
            exposure_scope=ExposureScope.LOCAL,
        )
        start_twin_container(client, name=container_name)
        time.sleep(1.5)

        bind_address = _discover_lan_bind_address()
        with socket.create_connection((bind_address, port), timeout=5) as sock:
            received = sock.recv(1024)
        assert received == b"local-scope-banner"
    finally:
        stop_twin_container(client, name=container_name)
        remove_twin_container(client, name=container_name)
