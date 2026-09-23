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
        # Docker reporting "running" only means the container started, not
        # that nginx is accepting connections yet - poll the port itself,
        # otherwise tests race the service's startup under load.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            pytest.fail(f"nginx container {name} never became reachable on {host}:{port}")
        yield host, port
    finally:
        container.remove(force=True)
