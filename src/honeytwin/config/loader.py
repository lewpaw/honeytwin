"""Loads and resolves HoneyTwin YAML configuration.

Resolution order, lowest to highest:

1. `GlobalConfig`'s built-in field defaults
2. the packaged `defaults.yaml`
3. the operator's own config file - discovered at
   `$XDG_CONFIG_HOME/honeytwin/config.yaml` (falling back to
   `~/.config/honeytwin/config.yaml`), or given explicitly
4. per-twin settings

Layers 1 and 2 are both "built-in" in the sense the `config` capability
means: neither is operator-owned. Layer 3 is the capability's global
defaults file. Layer 4 is currently reached only through a twin's
generated configuration, written when the twin is generated - per-twin
config files are not implemented yet.

The packaged defaults are read through `importlib.resources` so they are
found from a source checkout and an installed wheel alike. Invalid config
(malformed YAML or a schema-invalid value) is rejected before use, per the
`config` capability spec.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from honeytwin.config.schema import GlobalConfig, TwinConfig

DEFAULTS_RESOURCE = "defaults.yaml"
USER_CONFIG_FILENAME = "config.yaml"
USER_CONFIG_DIRNAME = "honeytwin"


class ConfigError(Exception):
    """Raised when a config file is malformed or fails schema validation."""


def user_config_path() -> Path:
    """Where an operator's own config file is looked for.

    `$XDG_CONFIG_HOME/honeytwin/config.yaml` when that variable is set to
    an absolute path, else `~/.config/honeytwin/config.yaml`.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".config"
    return base / USER_CONFIG_DIRNAME / USER_CONFIG_FILENAME


def _parse_yaml_mapping(raw: str, source: str | Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {source}: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {source} must contain a YAML mapping at the top level")
    return data


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc
    return _parse_yaml_mapping(raw, path)


def _load_shipped_defaults() -> dict[str, Any]:
    """Read the defaults that ship inside the package.

    Unreadable packaged defaults are an error, not something to fall back
    from: the built-in field defaults happen to match the shipped file
    today, so silently skipping it would let an operator edit a config
    that is never read and see neither effect nor warning.
    """
    try:
        raw = files("honeytwin.data").joinpath(DEFAULTS_RESOURCE).read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError) as exc:
        raise ConfigError(
            f"Could not read the packaged defaults ({DEFAULTS_RESOURCE}): {exc}. "
            f"This usually means the HoneyTwin install is incomplete."
        ) from exc
    return _parse_yaml_mapping(raw, DEFAULTS_RESOURCE)


def load_global_config(path: Path | None = None) -> GlobalConfig:
    """Load global config: packaged defaults with the operator's file over them.

    `path` names an operator config file explicitly. A path that does not
    exist is an error - someone who typed a path meant that path, and
    quietly using different settings could start a twin under a
    configuration they did not intend. An absent *discovered* file is
    ordinary and silent.
    """
    data: dict[str, Any] = _load_shipped_defaults()

    if path is not None:
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        data.update(_load_yaml_mapping(path))
    else:
        discovered = user_config_path()
        if discovered.exists():
            data.update(_load_yaml_mapping(discovered))

    try:
        return GlobalConfig(**data)
    except ValidationError as exc:
        source = path if path is not None else user_config_path()
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
