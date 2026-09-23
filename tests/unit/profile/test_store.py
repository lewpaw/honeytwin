import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeytwin.profile.schema import CURRENT_SCHEMA_VERSION, ScanProfileName, TwinProfile
from honeytwin.profile.store import (
    ProfileSchemaVersionError,
    RawXmlLoadError,
    load_profile,
    load_raw_xml,
    save_profile,
    save_raw_xml,
)


def _make_profile() -> TwinProfile:
    return TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_save_then_load_round_trip(tmp_path: Path):
    profile = _make_profile()
    path = save_profile(profile, tmp_path)
    assert path.exists()

    loaded = load_profile(path)
    assert loaded == profile


def test_load_rejects_schema_version_mismatch(tmp_path: Path):
    profile = _make_profile()
    path = save_profile(profile, tmp_path)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = CURRENT_SCHEMA_VERSION + 1
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ProfileSchemaVersionError):
        load_profile(path)

    # the file itself must not be altered/migrated by the failed load attempt
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == CURRENT_SCHEMA_VERSION + 1


def test_save_raw_xml_writes_under_raw_xml_dir_with_matching_basename(tmp_path: Path):
    profile = _make_profile()
    profile_path = save_profile(profile, tmp_path)

    xml_path = save_raw_xml("<nmaprun></nmaprun>", profile.target, profile.scanned_at, tmp_path)

    assert xml_path.exists()
    assert xml_path.parent.name == "raw-xml"
    assert xml_path.stem == profile_path.stem


def test_save_then_load_raw_xml_round_trip(tmp_path: Path):
    xml_path = save_raw_xml(
        "<nmaprun>content</nmaprun>", "192.0.2.10", datetime(2026, 1, 1, tzinfo=UTC), tmp_path
    )
    assert load_raw_xml(xml_path) == "<nmaprun>content</nmaprun>"


def test_load_raw_xml_missing_file_raises(tmp_path: Path):
    with pytest.raises(RawXmlLoadError):
        load_raw_xml(tmp_path / "does-not-exist.xml")
