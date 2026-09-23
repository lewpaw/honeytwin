"""Imports an existing nmap XML file as a twin profile, skipping live
scan execution entirely (PRD FR3 / the scan capability's import
requirement).
"""

from __future__ import annotations

from pathlib import Path

from honeytwin.profile.schema import ScanProfileName, TwinProfile
from honeytwin.profile.store import save_profile, save_raw_xml
from honeytwin.scan.xml_parser import parse


def import_xml_file(path: Path, data_dir: Path) -> TwinProfile:
    """Parse an existing nmap XML file into a twin profile and persist both.

    Reuses the same profile/raw-XML persistence path a live scan uses
    (design.md: "one persistence path to test and reason about"), so a
    parse failure raises before anything is written to disk.
    """
    xml = path.read_text(encoding="utf-8")
    profile = parse(xml, scan_profile=ScanProfileName.IMPORTED)

    save_profile(profile, data_dir)
    save_raw_xml(xml, profile.target, profile.scanned_at, data_dir)

    return profile
