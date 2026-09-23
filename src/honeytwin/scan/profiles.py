"""Loads the light/standard/deep nmap flag presets from the shipped
nmap_profiles.yaml.

Operators can point at their own file via the `path` argument to
`load_nmap_profiles`, per docs/PRD.md section 9. The shipped copy is read
through `importlib.resources` rather than by locating it relative to this
file, so it is found whether HoneyTwin runs from a source checkout or an
installed package.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

PROFILES_RESOURCE = "nmap_profiles.yaml"


class NmapProfilesError(Exception):
    """Raised when the nmap profiles file is missing or malformed."""


def _read_shipped_profiles() -> str:
    """Read the nmap profiles file that ships inside the package."""
    try:
        return files("honeytwin.data").joinpath(PROFILES_RESOURCE).read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError) as exc:
        raise NmapProfilesError(
            f"Could not read the packaged nmap profiles ({PROFILES_RESOURCE}): {exc}. "
            f"This usually means the HoneyTwin install is incomplete."
        ) from exc


def load_nmap_profiles(path: Path | None = None) -> dict[str, list[str]]:
    """Load nmap profile name -> flag list mapping from YAML."""
    source = path if path is not None else PROFILES_RESOURCE

    if path is None:
        raw = _read_shipped_profiles()
    else:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise NmapProfilesError(f"Could not read nmap profiles file {path}: {exc}") from exc

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
