import json
from pathlib import Path

from honeytwin.logging.fingerprint import update_attacker_record


def test_first_contact_creates_new_record(tmp_path: Path):
    path = update_attacker_record("203.0.113.5", "web-01", tmp_path)

    assert path.exists()
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["source_ip"] == "203.0.113.5"
    assert record["session_count"] == 1
    assert record["twins_targeted"] == ["web-01"]
    assert record["first_seen"] == record["last_seen"]


def test_repeat_contact_updates_existing_record(tmp_path: Path):
    first_path = update_attacker_record("203.0.113.5", "web-01", tmp_path)
    first_record = json.loads(first_path.read_text(encoding="utf-8"))

    second_path = update_attacker_record("203.0.113.5", "web-01", tmp_path)
    second_record = json.loads(second_path.read_text(encoding="utf-8"))

    assert second_path == first_path
    assert second_record["session_count"] == 2
    assert second_record["first_seen"] == first_record["first_seen"]


def test_repeat_contact_against_different_twin_adds_to_twins_targeted(tmp_path: Path):
    update_attacker_record("203.0.113.5", "web-01", tmp_path)
    path = update_attacker_record("203.0.113.5", "ssh-02", tmp_path)

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["session_count"] == 2
    assert set(record["twins_targeted"]) == {"web-01", "ssh-02"}


def test_different_source_ips_get_separate_records(tmp_path: Path):
    path_a = update_attacker_record("203.0.113.5", "web-01", tmp_path)
    path_b = update_attacker_record("198.51.100.9", "web-01", tmp_path)

    assert path_a != path_b
    assert json.loads(path_a.read_text(encoding="utf-8"))["session_count"] == 1
    assert json.loads(path_b.read_text(encoding="utf-8"))["session_count"] == 1
