"""Loads the light/standard/deep nmap flag presets from config/nmap_profiles.yaml.

Operators can override the shipped file or point at their own via the
`path` argument to `load_nmap_profiles`, per docs/PRD.md section 9.
"""

from __future__ import annotations

from pathlib import Path

import yaml

SHIPPED_PROFILES_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "config" / "nmap_profiles.yaml"
)


class NmapProfilesError(Exception):
    """Raised when the nmap profiles file is missing or malformed."""


def load_nmap_profiles(path: Path | None = None) -> dict[str, list[str]]:
    """Load nmap profile name -> flag list mapping from YAML."""
    source = path if path is not None else SHIPPED_PROFILES_PATH

    try:
        raw = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise NmapProfilesError(f"Could not read nmap profiles file {source}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise NmapProfilesError(f"Invalid YAML in {source}: {exc}") from exc

    if not isinstance(data, dict):
        raise NmapProfilesError(f"{source} must contain a mapping of profile name to flag list")

    profiles: dict[str, list[str]] = {}
    for name, flags in data.items():
        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
            raise NmapProfilesError(f"Profile {name!r} in {source} must be a list of string flags")
        profiles[name] = flags

    return profiles


def get_profile_flags(name: str, path: Path | None = None) -> list[str]:
    """Get the flag list for a single named profile."""
    profiles = load_nmap_profiles(path)
    try:
        return profiles[name]
    except KeyError:
        raise NmapProfilesError(
            f"Unknown nmap profile {name!r}; available: {sorted(profiles)}"
        ) from None
