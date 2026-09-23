"""Load/save twin profiles and their raw nmap XML to disk.

Loading enforces the versioning contract from the twin-profile-schema
capability spec: a profile whose schema_version does not match the
version this build implements is refused, not migrated. The operator is
told to regenerate the profile from its retained raw nmap XML instead.

Raw XML is saved under a sibling directory using the same
`<safe_target>-<timestamp>` filename base as its profile, correlating the
two by naming convention rather than a schema field (see the scan
capability's design.md for the rationale).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from honeytwin.profile.schema import CURRENT_SCHEMA_VERSION, TwinProfile

PROFILES_SUBDIR = "profiles"
RAW_XML_SUBDIR = "raw-xml"


class ProfileSchemaVersionError(Exception):
    """Raised when a stored profile's schema_version doesn't match this build."""


class ProfileLoadError(Exception):
    """Raised when a stored profile is missing, unreadable, or fails validation."""


def _filename_base(target: str, scanned_at: datetime) -> str:
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    timestamp = scanned_at.strftime("%Y%m%dT%H%M%SZ")
    return f"{safe_target}-{timestamp}"


def _profile_filename(profile: TwinProfile) -> str:
    return f"{_filename_base(profile.target, profile.scanned_at)}.json"


def _unique_path(path: Path) -> Path:
    """Return `path`, or a `-1`, `-2`, ... variant if it already exists.

    Two scans can complete within the same second-resolution timestamp, and
    the scan capability's spec requires a re-scan to never alter or delete
    a prior profile — so an existing file at the timestamp-derived path is
    never overwritten.
    """
    if not path.exists():
        return path
    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}-{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def save_profile(profile: TwinProfile, data_dir: Path) -> Path:
    """Write a twin profile as JSON under <data_dir>/profiles/ and return its path."""
    profiles_dir = data_dir / PROFILES_SUBDIR
    profiles_dir.mkdir(parents=True, exist_ok=True)
    path = _unique_path(profiles_dir / _profile_filename(profile))
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_profile(path: Path) -> TwinProfile:
    """Load a twin profile from disk, refusing on a schema_version mismatch."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileLoadError(f"Could not read twin profile {path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProfileLoadError(f"Twin profile {path} is not valid JSON: {exc}") from exc

    stored_version = data.get("schema_version")
    if stored_version != CURRENT_SCHEMA_VERSION:
        raise ProfileSchemaVersionError(
            f"Twin profile {path} has schema_version={stored_version!r}, "
            f"but this build implements schema_version={CURRENT_SCHEMA_VERSION}. "
            "Regenerate the profile from its retained raw nmap XML rather than "
            "attempting to load it directly."
        )

    try:
        return TwinProfile.model_validate(data)
    except ValidationError as exc:
        raise ProfileLoadError(f"Twin profile {path} failed validation: {exc}") from exc


class RawXmlLoadError(Exception):
    """Raised when a retained raw XML file is missing or unreadable."""


def save_raw_xml(xml: str, target: str, scanned_at: datetime, data_dir: Path) -> Path:
    """Write raw nmap XML under <data_dir>/raw-xml/, matching a profile's filename base."""
    raw_xml_dir = data_dir / RAW_XML_SUBDIR
    raw_xml_dir.mkdir(parents=True, exist_ok=True)
    path = _unique_path(raw_xml_dir / f"{_filename_base(target, scanned_at)}.xml")
    path.write_text(xml, encoding="utf-8")
    return path


def load_raw_xml(path: Path) -> str:
    """Load retained raw nmap XML from disk."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RawXmlLoadError(f"Could not read raw XML {path}: {exc}") from exc
