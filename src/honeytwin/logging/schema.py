"""The structured connection event record: one per connection a twin's
listener accepts, per the `logging` capability spec.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ConnectionEvent(BaseModel):
    """A single connection event to a twin's listener."""

    timestamp: datetime
    twin_name: str
    source_ip: str
    source_port: int
    destination_port: int
    protocol: str
    duration_seconds: float
    payload_base64: str = ""
    truncated: bool = False
