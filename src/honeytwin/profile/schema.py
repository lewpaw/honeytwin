"""The twin profile: a versioned document describing a scanned target's
observable fingerprint. Produced by the scan stage, consumed by generation
and drift detection. See docs/PRD.md section 9 and the twin-profile-schema
capability spec for the versioning contract.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

CURRENT_SCHEMA_VERSION = 1


class ScanProfileName(StrEnum):
    """Which nmap profile (or import path) produced this twin profile."""

    LIGHT = "light"
    STANDARD = "standard"
    DEEP = "deep"
    IMPORTED = "imported"


class PortInfo(BaseModel):
    """One port's observable fingerprint as reported by nmap."""

    protocol: str
    port: int
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = Field(
        default=None,
        description="Raw banner/handshake bytes captured during the scan, if any.",
    )


class OSMatch(BaseModel):
    """nmap's OS fingerprint guess, when OS detection was enabled."""

    name: str
    accuracy: int | None = None


class ScriptResult(BaseModel):
    """Raw output of one NSE script, when scripts were run."""

    script_id: str
    output: str


class TwinProfile(BaseModel):
    """A versioned, structured twin profile."""

    schema_version: int = CURRENT_SCHEMA_VERSION
    target: str
    scan_profile: ScanProfileName
    scanned_at: datetime
    ports: list[PortInfo] = Field(default_factory=list)
    os_match: OSMatch | None = None
    scripts: list[ScriptResult] = Field(default_factory=list)
