from pathlib import Path

import pytest

from honeytwin.profile.schema import ScanProfileName
from honeytwin.scan.import_ import import_xml_file
from honeytwin.scan.xml_parser import NmapXmlParseError

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "fixtures" / "nmap_scan.xml"


def test_import_xml_file_writes_profile_and_raw_xml(tmp_path: Path):
    profile = import_xml_file(FIXTURE_PATH, tmp_path)

    assert profile.scan_profile is ScanProfileName.IMPORTED
    assert profile.target == "192.0.2.10"

    profiles_dir = tmp_path / "profiles"
    raw_xml_dir = tmp_path / "raw-xml"
    assert list(profiles_dir.glob("*.json"))
    assert list(raw_xml_dir.glob("*.xml"))

    profile_file = next(profiles_dir.glob("*.json"))
    xml_file = next(raw_xml_dir.glob("*.xml"))
    assert profile_file.stem == xml_file.stem
    assert xml_file.read_text(encoding="utf-8") == FIXTURE_PATH.read_text(encoding="utf-8")


def test_import_malformed_xml_writes_nothing(tmp_path: Path):
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("not xml at all <<<", encoding="utf-8")

    with pytest.raises(NmapXmlParseError):
        import_xml_file(bad_xml, tmp_path)

    assert not (tmp_path / "profiles").exists()
    assert not (tmp_path / "raw-xml").exists()
