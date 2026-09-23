"""Shared fixtures for integration tests that need a real service to scan.

Per the scan-and-profile design decision, Epic 1's integration tests scan
a disposable Docker container rather than localhost or an external host,
so the scan target is always something we spun up and fully control.
"""

from __future__ import annotations

import socket
import time
import uuid
from collections.abc import Iterator

import pytest

from honeytwin.docker.client import DockerUnavailableError, get_client


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def disposable_nginx_container() -> Iterator[tuple[str, int]]:
    """Start a disposable nginx container bound to a random localhost port.

    Yields (host, port). Tears the container down afterward regardless of
    test outcome.
    """
    try:
        client = get_client()
    except DockerUnavailableError as exc:
        pytest.skip(f"Docker daemon not reachable: {exc}")

    host = "127.0.0.1"
    port = _free_port()
    name = f"honeytwin-test-{uuid.uuid4().hex[:8]}"

    container = client.containers.run(
        "nginx:alpine",
        detach=True,
        ports={"80/tcp": (host, port)},
        name=name,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                break
            time.sleep(0.5)
        yield host, port
    finally:
        container.remove(force=True)
