"""Thin wrapper around the docker-py SDK for twin container lifecycle and
networking.

Only client construction and daemon-reachability checking are implemented
in this change. Container lifecycle and macvlan/bridge network creation
are Epic 2's responsibility (docs/ROADMAP.md); the signatures below exist
so that code can be written against them now.
"""

from __future__ import annotations

import docker
from docker.errors import DockerException


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


def create_twin_container(
    client: docker.DockerClient, *, name: str, image: str, network_mode: str
) -> None:
    """Create a twin's container. Full implementation is Epic 2's job."""
    raise NotImplementedError("twin container creation is implemented in Epic 2 (docs/ROADMAP.md)")


def start_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Start a twin's container. Full implementation is Epic 2's job."""
    raise NotImplementedError("twin container start is implemented in Epic 2 (docs/ROADMAP.md)")


def stop_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Stop a twin's container. Full implementation is Epic 4's job."""
    raise NotImplementedError("twin container stop is implemented in Epic 4 (docs/ROADMAP.md)")


def remove_twin_container(client: docker.DockerClient, *, name: str) -> None:
    """Remove a twin's container. Full implementation is Epic 4's job."""
    raise NotImplementedError("twin container removal is implemented in Epic 4 (docs/ROADMAP.md)")


def create_macvlan_network(
    client: docker.DockerClient, *, parent_interface: str, subnet: str
) -> None:
    """Create a macvlan network so a twin gets its own LAN-visible IP/MAC.

    Full implementation is Epic 2's job (docs/PRD.md section 9: macvlan is
    the default Docker network mode for LAN-facing twins).
    """
    raise NotImplementedError("macvlan network setup is implemented in Epic 2 (docs/ROADMAP.md)")


def create_bridge_network(client: docker.DockerClient, *, name: str) -> None:
    """Create a standard bridge network (the opt-out from macvlan).

    Full implementation is Epic 2's job.
    """
    raise NotImplementedError("bridge network setup is implemented in Epic 2 (docs/ROADMAP.md)")
