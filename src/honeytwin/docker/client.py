"""Thin wrapper around the docker-py SDK for twin container lifecycle and
networking.
"""

from __future__ import annotations

import socket
from pathlib import Path

import docker
from docker.errors import DockerException, NotFound
from docker.models.containers import Container
from docker.models.networks import Network

from honeytwin.config.schema import DockerNetworkMode, ExposureScope

TWIN_CONFIG_MOUNT_PATH = "/etc/honeytwin/twin.json"
TWIN_LOG_MOUNT_PATH = "/var/log/honeytwin"


class DockerUnavailableError(Exception):
    """Raised when the Docker daemon cannot be reached."""


def get_client() -> docker.DockerClient:
    """Construct a docker-py client and verify the daemon responds to ping."""
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        raise DockerUnavailableError(f"Docker daemon is not reachable: {exc}") from exc
    return client


def _discover_lan_bind_address() -> str:
    """Best-effort discovery of a non-loopback host IP for local-scope binding.

    Not a hard security boundary — see design.md's exposure-scope decision:
    true "LAN but not internet" isolation ultimately depends on the host's
    network topology/firewalling, which HoneyTwin doesn't control. This is
    a best-effort default, falling back to 127.0.0.1 (host-only) if
    discovery fails.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class NetworkSubnetMismatchError(Exception):
    """Raised when an existing network's subnet is not the one asked for."""


def _network_subnets(network: Network) -> list[str]:
    """The subnets configured on a network, as CIDR strings."""
    ipam = network.attrs.get("IPAM") or {}
    return [c["Subnet"] for c in (ipam.get("Config") or []) if c.get("Subnet")]


def create_bridge_network(client: docker.DockerClient, *, name: str, subnet: str) -> Network:
    """Create a bridge network on a fixed subnet, or return the existing one.

    The subnet is pinned rather than left to Docker's IPAM because the
    host egress restriction is a firewall rule that has to name it (see
    design.md). Egress is therefore a property of which network a twin
    attaches to: the denied-egress subnet is covered by the rules, the
    allowed-egress one deliberately is not, so twins with different
    egress settings cannot share a network.

    Reusing a network whose subnet differs from the one asked for would
    put the twin outside the rules that were installed for it, so that
    case raises rather than proceeding.
    """
    try:
        network = client.networks.get(name)
    except NotFound:
        ipam_pool = docker.types.IPAMPool(subnet=subnet)
        ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
        return client.networks.create(name, driver="bridge", ipam=ipam_config)

    existing = _network_subnets(network)
    if subnet not in existing:
        raise NetworkSubnetMismatchError(
            f"Docker network {name!r} already exists on {existing or 'an unknown subnet'}, "
            f"but {subnet} was required — the host egress restriction is installed for "
            f"{subnet}, so a twin on any other subnet would not be covered by it. "
            f"Remove it (docker network rm {name}) and retry."
        )
    return network


def create_macvlan_network(
    client: docker.DockerClient,
    *,
    name: str,
    parent_interface: str,
    subnet: str,
    gateway: str | None = None,
) -> Network:
    """Create a macvlan network so a twin gets its own LAN-visible IP/MAC.

    Real-world reachability needs verification on a native Linux host —
    cloud VM virtual networking (and Docker Desktop's WSL2 backend) may
    block macvlan's new-MAC-address traffic even where this call succeeds
    (see design.md's acknowledged gap).
    """
    try:
        return client.networks.get(name)
    except NotFound:
        ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
        ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
        return client.networks.create(
            name,
            driver="macvlan",
            options={"parent": parent_interface},
            ipam=ipam_config,
        )


def create_twin_container(
    client: docker.DockerClient,
    *,
    name: str,
    image: str,
    config_path: Path,
    log_dir: Path,
    ports: list[int],
    network_mode: DockerNetworkMode,
    network_name: str,
    exposure_scope: ExposureScope,
    run_as_user: str | None = None,
    mem_limit: str = "256m",
    pids_limit: int = 128,
    cpu_quota: int = 50000,
) -> Container:
    """Create (but do not start) a twin's container.

    Bridge mode publishes the twin's ports on the host (bound per
    `exposure_scope`); macvlan mode needs no port publishing since the
    container has its own directly-reachable LAN IP. Either way, the
    twin's generated config is bind-mounted read-only, `log_dir` is
    bind-mounted read-write for the listener's local event log and
    attacker records, and the container is granted `NET_BIND_SERVICE` so
    its non-root user can still bind privileged ports.

    Containment (Epic 5): every other Linux capability is dropped — a
    banner-replay listener has no use for `NET_RAW` and the rest of
    Docker's default set; the root filesystem is read-only apart from
    the mounted log directory; and memory, PID, and CPU limits bound
    what a twin under abuse can take from the host. Egress denial is a
    property of the network the twin attaches to, handled by the caller
    via `create_bridge_network(internal=...)`.

    `run_as_user` ("uid:gid") overrides the image's built-in non-root
    user. On Linux this must be set to the host user owning `log_dir`,
    or the container can't write its logs there — the image's own uid
    won't match the host's. It stays non-root either way: `run` refuses
    to start when the operator is root.
    """
    volumes = {
        str(config_path): {"bind": TWIN_CONFIG_MOUNT_PATH, "mode": "ro"},
        str(log_dir): {"bind": TWIN_LOG_MOUNT_PATH, "mode": "rw"},
    }

    port_bindings = None
    if network_mode is DockerNetworkMode.BRIDGE:
        bind_host = (
            "0.0.0.0" if exposure_scope is ExposureScope.INTERNET else _discover_lan_bind_address()
        )
        port_bindings = {f"{p}/tcp": (bind_host, p) for p in ports}

    create_kwargs = {}
    if run_as_user is not None:
        create_kwargs["user"] = run_as_user

    return client.containers.create(
        image,
        name=name,
        network=network_name,
        ports=port_bindings,
        volumes=volumes,
        cap_drop=["ALL"],
        cap_add=["NET_BIND_SERVICE"],
        read_only=True,
        mem_limit=mem_limit,
        pids_limit=pids_limit,
        cpu_quota=cpu_quota,
        **create_kwargs,
    )


def get_twin_container_status(client: docker.DockerClient, *, name: str) -> str | None:
    """The twin container's status (e.g. "running", "exited"), or None if
    no container exists for that twin.

    Absence is an ordinary answer to "is this twin running?", not an
    error, so `NotFound` is handled here rather than pushed onto callers.
    """
    try:
        return client.containers.get(name).status
    except NotFound:
        return None


def start_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Start a twin's already-created container."""
    container = client.containers.get(name)
    container.start()


def stop_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Stop a twin's running container."""
    container = client.containers.get(name)
    container.stop()


def remove_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Remove a twin's container."""
    container = client.containers.get(name)
    container.remove(force=True)
