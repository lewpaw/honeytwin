"""Integration tests that run real nmap scans against a disposable
container, per the scan-and-profile design decision (not localhost, not an
external host).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeytwin.profile.schema import ScanProfileName
from honeytwin.profile.store import save_raw_xml
from honeytwin.scan.import_ import import_xml_file
from honeytwin.scan.nmap_runner import NmapScanError, run_nmap
from honeytwin.scan.xml_parser import parse


def _scan_container_port(host: str, port: int) -> str:
    """Connect-scan (unprivileged) the container's mapped port, skipping the
    test rather than failing it if nmap still reports a privilege error."""
    try:
        return run_nmap(host, ["-sT", "-p", str(port)], timeout_seconds=60)
    except NmapScanError as exc:
        if "elevated privileges" in str(exc):
            pytest.skip(f"nmap requires elevated privileges in this environment: {exc}")
        raise


@pytest.mark.integration
def test_live_scan_reports_container_port_open(disposable_nginx_container):
    host, port = disposable_nginx_container
    xml = _scan_container_port(host, port)

    profile = parse(xml, scan_profile=ScanProfileName.LIGHT)

    matching = [p for p in profile.ports if p.port == port]
    assert matching, f"port {port} not found in scan results: {profile.ports}"
    assert matching[0].state == "open"


@pytest.mark.integration
def test_regenerating_from_retained_xml_matches_live_scan(
    disposable_nginx_container, tmp_path: Path
):
    host, port = disposable_nginx_container
    xml = _scan_container_port(host, port)

    original = parse(xml, scan_profile=ScanProfileName.LIGHT)
    raw_xml_path = save_raw_xml(xml, original.target, original.scanned_at, tmp_path)

    regenerated = import_xml_file(raw_xml_path, tmp_path)

    assert regenerated.target == original.target
    assert regenerated.ports == original.ports
