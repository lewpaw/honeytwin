from datetime import UTC, datetime

from honeytwin.logging.schema import ConnectionEvent


def test_connection_event_construction():
    event = ConnectionEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        twin_name="web-01",
        source_ip="203.0.113.5",
        source_port=54321,
        destination_port=22,
        protocol="tcp",
        duration_seconds=1.25,
        payload_base64="dGVzdA==",
        truncated=False,
    )
    assert event.twin_name == "web-01"
    assert event.source_ip == "203.0.113.5"
    assert event.payload_base64 == "dGVzdA=="
    assert event.truncated is False


def test_connection_event_defaults():
    event = ConnectionEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        twin_name="web-01",
        source_ip="203.0.113.5",
        source_port=54321,
        destination_port=22,
        protocol="tcp",
        duration_seconds=0.1,
    )
    assert event.payload_base64 == ""
    assert event.truncated is False
