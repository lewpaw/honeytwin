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
        # Readiness has to be proven by a real response, not a successful
        # connect: Docker's host-side port proxy accepts connections before
        # nginx inside the container is listening, so a connect-only probe
        # passes while requests still come back empty.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1) as probe:
                    probe.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    if probe.recv(64):
                        break
            except OSError:
                pass
            time.sleep(0.25)
        else:
            pytest.fail(f"nginx container {name} never served a response on {host}:{port}")
        yield host, port
    finally:
        container.remove(force=True)
