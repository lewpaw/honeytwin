"""RFC 5424 syslog forwarding for connection events.

Hand-rolled framing rather than stdlib `logging.handlers.SysLogHandler`,
which defaults to legacy RFC 3164 framing — see design.md's "Syslog"
decision.
"""

from __future__ import annotations

import socket

from honeytwin.logging.schema import ConnectionEvent

_FACILITY_LOCAL0 = 16
_SEVERITY_INFORMATIONAL = 6
_PRI = _FACILITY_LOCAL0 * 8 + _SEVERITY_INFORMATIONAL


def format_rfc5424(event: ConnectionEvent, *, hostname: str) -> str:
    """Build an RFC 5424 syslog message for a connection event."""
    timestamp = event.timestamp.isoformat()
    msg = event.model_dump_json()
    return f"<{_PRI}>1 {timestamp} {hostname} honeytwin - - - {msg}"


def send_syslog(message: str, *, host: str, port: int, protocol: str) -> None:
    """Send a pre-formatted RFC 5424 message over UDP (default) or TCP."""
    data = message.encode("utf-8")
    if protocol == "tcp":
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(data + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))
