import socket

import pytest

from honeytwin.docker.client import get_client


@pytest.mark.integration
def test_disposable_nginx_container_starts_and_is_reachable(disposable_nginx_container):
    host, port = disposable_nginx_container

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024)
    assert b"HTTP" in response


@pytest.mark.integration
def test_no_leftover_honeytwin_test_containers():
    """Runs after the fixture-using test above; confirms it was cleaned up."""
    client = get_client()
    leftover = [
        c.name for c in client.containers.list(all=True) if c.name.startswith("honeytwin-test-")
    ]
    assert leftover == [], f"leftover test containers not cleaned up: {leftover}"
