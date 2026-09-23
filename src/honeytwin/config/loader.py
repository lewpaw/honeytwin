"""Loads and resolves HoneyTwin YAML configuration.

Precedence, highest first: per-twin config > global defaults file (falling
back to the package-shipped defaults.yaml) > GlobalConfig's built-in field
defaults. Invalid config (malformed YAML or a schema-invalid value) is
rejected before use, per the `config` capability spec.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from honeytwin.config.schema import GlobalConfig, TwinConfig

SHIPPED_DEFAULTS_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "config" / "defaults.yaml"
)


class ConfigError(Exception):
    """Raised when a config file is malformed or fails schema validation."""


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a YAML mapping at the top level")
    return data


def load_global_config(path: Path | None = None) -> GlobalConfig:
    """Load global config, layering an optional override file over shipped defaults."""
    data: dict[str, Any] = {}

    if SHIPPED_DEFAULTS_PATH.exists():
        data.update(_load_yaml_mapping(SHIPPED_DEFAULTS_PATH))

    if path is not None:
        if not path.exists():
            raise ConfigError(f"Global config file not found: {path}")
        data.update(_load_yaml_mapping(path))

    try:
        return GlobalConfig(**data)
    except ValidationError as exc:
        source = path if path is not None else SHIPPED_DEFAULTS_PATH
        raise ConfigError(f"Invalid global config ({source}): {exc}") from exc


def load_twin_config(path: Path) -> TwinConfig:
    """Load a per-twin config override file."""
    data = _load_yaml_mapping(path)
    try:
        return TwinConfig(**data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid twin config ({path}): {exc}") from exc


def resolve_twin_config(twin: TwinConfig, global_config: GlobalConfig) -> GlobalConfig:
    """Merge a twin's overrides onto the global config to get its effective settings."""
    merged = global_config.model_dump()
    merged.update(twin.model_dump(exclude_none=True))
    return GlobalConfig(**merged)
