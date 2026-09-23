import socket
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from honeytwin.logging.schema import ConnectionEvent
from honeytwin.logging.syslog_forwarder import format_rfc5424, send_syslog


def _make_event() -> ConnectionEvent:
    return ConnectionEvent(
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        twin_name="web-01",
        source_ip="203.0.113.5",
        source_port=54321,
        destination_port=22,
        protocol="tcp",
        duration_seconds=1.5,
        payload_base64="dGVzdA==",
        truncated=False,
    )


def test_format_rfc5424_structure():
    event = _make_event()
    message = format_rfc5424(event, hostname="honeytwin-twin")

    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    assert message.startswith("<134>1 ")
    assert "honeytwin-twin" in message
    assert "honeytwin" in message
    assert '"twin_name":"web-01"' in message
    assert '"source_ip":"203.0.113.5"' in message


def test_send_syslog_udp_uses_sendto():
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("socket.socket", return_value=mock_sock) as mock_socket_ctor:
        send_syslog("<134>1 test message", host="syslog.example.com", port=514, protocol="udp")

    mock_socket_ctor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_sock.sendto.assert_called_once_with(b"<134>1 test message", ("syslog.example.com", 514))


def test_send_syslog_tcp_uses_sendall():
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("socket.create_connection", return_value=mock_sock) as mock_create_conn:
        send_syslog("<134>1 test message", host="syslog.example.com", port=6514, protocol="tcp")

    mock_create_conn.assert_called_once_with(("syslog.example.com", 6514), timeout=5)
    mock_sock.sendall.assert_called_once_with(b"<134>1 test message\n")
