import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeytwin.logging.schema import ConnectionEvent
from honeytwin.logging.writer import write_event


def _make_event(**overrides) -> ConnectionEvent:
    defaults = dict(
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
    defaults.update(overrides)
    return ConnectionEvent(**defaults)


def test_write_event_appends_jsonl_line(tmp_path: Path):
    event = _make_event()
    path = write_event(event, tmp_path)

    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    round_tripped = ConnectionEvent.model_validate_json(lines[0])
    assert round_tripped == event


def test_write_event_appends_multiple_events(tmp_path: Path):
    write_event(_make_event(source_port=1), tmp_path)
    write_event(_make_event(source_port=2), tmp_path)

    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["source_port"] == 1
    assert json.loads(lines[1])["source_port"] == 2


def test_write_event_raises_when_log_dir_path_is_unusable(tmp_path: Path):
    # Create a *file* where the log directory should be, so mkdir() fails.
    blocked_path = tmp_path / "not-a-directory"
    blocked_path.write_text("blocking file", encoding="utf-8")

    with pytest.raises(OSError):
        write_event(_make_event(), blocked_path)
