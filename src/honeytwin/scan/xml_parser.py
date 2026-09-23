"""Parses nmap XML output (`-oX`) into a TwinProfile.

Covers the fields exercised by tests/fixtures/nmap_scan.xml: target
address, per-port service/banner detail, OS match, and NSE script output.
Broader coverage of nmap's XML dialect (multiple hosts, hostscripts,
tracing, etc.) is Epic 1's responsibility.
"""

from __future__ import annotations

from datetime import UTC, datetime
from xml.etree import ElementTree

from honeytwin.profile.schema import OSMatch, PortInfo, ScanProfileName, ScriptResult, TwinProfile


class NmapXmlParseError(Exception):
    """Raised when nmap XML cannot be parsed into a TwinProfile."""


def parse(xml: str, scan_profile: ScanProfileName = ScanProfileName.IMPORTED) -> TwinProfile:
    """Parse raw nmap XML into a TwinProfile for its (first) host."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise NmapXmlParseError(f"Could not parse nmap XML: {exc}") from exc

    host = root.find("host")
    if host is None:
        raise NmapXmlParseError("nmap XML has no <host> element")

    address_el = host.find("address")
    if address_el is None or "addr" not in address_el.attrib:
        raise NmapXmlParseError("nmap XML host has no <address addr=...>")
    target = address_el.attrib["addr"]

    starttime = host.attrib.get("starttime")
    scanned_at = (
        datetime.fromtimestamp(int(starttime), tz=UTC) if starttime else datetime.now(tz=UTC)
    )

    ports: list[PortInfo] = []
    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            banner = None
            for script_el in port_el.findall("script"):
                if script_el.attrib.get("id") in ("banner", "http-server-header"):
                    banner = script_el.attrib.get("output")
                    break
            ports.append(
                PortInfo(
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    port=int(port_el.attrib["portid"]),
                    state=state_el.attrib.get("state", "unknown")
                    if state_el is not None
                    else "unknown",
                    service=service_el.attrib.get("name") if service_el is not None else None,
                    product=service_el.attrib.get("product") if service_el is not None else None,
                    version=service_el.attrib.get("version") if service_el is not None else None,
                    banner=banner,
                )
            )

    os_match = None
    os_el = host.find("os")
    if os_el is not None:
        osmatch_el = os_el.find("osmatch")
        if osmatch_el is not None:
            accuracy = osmatch_el.attrib.get("accuracy")
            os_match = OSMatch(
                name=osmatch_el.attrib.get("name", "unknown"),
                accuracy=int(accuracy) if accuracy is not None else None,
            )

    scripts = [
        ScriptResult(
            script_id=script_el.attrib.get("id", ""), output=script_el.attrib.get("output", "")
        )
        for port_el in (ports_el.findall("port") if ports_el is not None else [])
        for script_el in port_el.findall("script")
    ]

    return TwinProfile(
        target=target,
        scan_profile=scan_profile,
        scanned_at=scanned_at,
        ports=ports,
        os_match=os_match,
        scripts=scripts,
    )
