from pathlib import Path

import pytest

from honeytwin.profile.schema import ScanProfileName
from honeytwin.profile.store import load_profile, save_profile
from honeytwin.scan.xml_parser import parse

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_scan.xml"


@pytest.mark.integration
def test_profile_regenerated_from_retained_raw_xml(tmp_path: Path):
    """A twin profile can be re-derived from retained raw nmap XML without
    contacting the original target again (docs/PRD.md FR2 / FR7).
    """
    raw_xml = FIXTURE_PATH.read_text(encoding="utf-8")

    original = parse(raw_xml, scan_profile=ScanProfileName.DEEP)
    saved_path = save_profile(original, tmp_path)
    loaded = load_profile(saved_path)
    assert loaded == original

    # Regenerate straight from the retained raw XML, as if the schema had
    # changed and the stored profile needed to be rebuilt (no re-scan).
    regenerated = parse(raw_xml, scan_profile=ScanProfileName.DEEP)
    assert regenerated == original
