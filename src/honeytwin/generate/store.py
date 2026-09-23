"""Save/load a generated twin configuration to/from disk.

Stored under <data_dir>/twins/<twin-name>/config.json, distinct from the
twin profile it was derived from (design.md's "separate generated
artifact" decision) so a twin can be regenerated or reloaded without
touching its source profile.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import ValidationError

from honeytwin.generate.schema import TwinConfigFile

TWINS_SUBDIR = "twins"
CONFIG_FILENAME = "config.json"


class TwinConfigLoadError(Exception):
    """Raised when a stored twin config is missing, unreadable, or invalid."""


def _safe_twin_dirname(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def twin_dir(name: str, data_dir: Path) -> Path:
    """The directory a twin's generated config (and related files) live under."""
    return data_dir / TWINS_SUBDIR / _safe_twin_dirname(name)


def save_twin_config(config: TwinConfigFile, data_dir: Path) -> Path:
    """Write a twin config as JSON under <data_dir>/twins/<name>/config.json."""
    directory = twin_dir(config.name, data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / CONFIG_FILENAME
    path.write_text(config.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_twin_config(name: str, data_dir: Path) -> TwinConfigFile:
    """Load a twin's generated config from <data_dir>/twins/<name>/config.json."""
    path = twin_dir(name, data_dir) / CONFIG_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TwinConfigLoadError(f"No generated config found for twin {name!r} ({path})") from exc

    try:
        return TwinConfigFile.model_validate_json(raw)
    except ValidationError as exc:
        raise TwinConfigLoadError(f"Twin config {path} failed validation: {exc}") from exc
