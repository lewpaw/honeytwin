from pathlib import Path

import pytest

from honeytwin.profile.schema import ScanProfileName
from honeytwin.scan.xml_parser import NmapXmlParseError, parse

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "nmap_scan.xml"
NO_OS_MATCH_FIXTURE = FIXTURES_DIR / "nmap_scan_no_os_match.xml"
NO_OPEN_PORTS_FIXTURE = FIXTURES_DIR / "nmap_scan_no_open_ports.xml"
MULTI_SCRIPT_FIXTURE = FIXTURES_DIR / "nmap_scan_multi_script.xml"


def test_parse_fixture_produces_valid_profile():
    xml = FIXTURE_PATH.read_text(encoding="utf-8")
    profile = parse(xml, scan_profile=ScanProfileName.DEEP)

    assert profile.target == "192.0.2.10"
    assert profile.scan_profile is ScanProfileName.DEEP
    assert len(profile.ports) == 3

    ssh = next(p for p in profile.ports if p.port == 22)
    assert ssh.state == "open"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9p1"
    assert ssh.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    https = next(p for p in profile.ports if p.port == 443)
    assert https.state == "closed"

    assert profile.os_match is not None
    assert profile.os_match.name == "Linux 5.4 - 5.15"
    assert profile.os_match.accuracy == 95

    assert len(profile.scripts) == 2


def test_parse_defaults_scan_profile_to_imported():
    xml = FIXTURE_PATH.read_text(encoding="utf-8")
    profile = parse(xml)
    assert profile.scan_profile is ScanProfileName.IMPORTED


def test_parse_rejects_invalid_xml():
    with pytest.raises(NmapXmlParseError):
        parse("not xml at all <<<")


def test_parse_rejects_missing_host():
    with pytest.raises(NmapXmlParseError):
        parse("<nmaprun></nmaprun>")


def test_parse_host_with_no_os_element_leaves_os_match_none():
    xml = NO_OS_MATCH_FIXTURE.read_text(encoding="utf-8")
    profile = parse(xml)
    assert profile.os_match is None
    assert len(profile.ports) == 1


def test_parse_host_with_no_open_ports_does_not_error():
    xml = NO_OPEN_PORTS_FIXTURE.read_text(encoding="utf-8")
    profile = parse(xml)
    assert len(profile.ports) == 2
    assert all(p.state != "open" for p in profile.ports)


def test_parse_host_with_missing_ports_element_does_not_error():
    xml = "<nmaprun><host><address addr='192.0.2.99' addrtype='ipv4'/></host></nmaprun>"
    profile = parse(xml)
    assert profile.ports == []


def test_parse_collects_all_scripts_for_a_port():
    xml = MULTI_SCRIPT_FIXTURE.read_text(encoding="utf-8")
    profile = parse(xml)
    script_ids = {s.script_id for s in profile.scripts}
    assert script_ids == {"banner", "ftp-anon", "ftp-syst"}
    assert len(profile.scripts) == 3


def test_parse_tolerates_service_missing_product_and_version():
    xml = FIXTURE_PATH.read_text(encoding="utf-8")
    profile = parse(xml)
    https = next(p for p in profile.ports if p.port == 443)
    assert https.product is None
    assert https.version is None
