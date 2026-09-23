"""Shared CLI option definitions and config loading.

A single `typer.Option` instance is reused across every subcommand that
selects a twin by name, so `--name`/`-n` has identical flag name and value
format everywhere it appears, per the `cli` capability spec.

`--config` is a global option rather than a per-subcommand one, for the
same reason: one definition that cannot drift between commands. The
callback records it here and every command reads it through
`load_settings`.
"""

from __future__ import annotations

from pathlib import Path

import typer

from honeytwin.config.loader import ConfigError, load_global_config
from honeytwin.config.schema import GlobalConfig

TWIN_NAME_OPTION = typer.Option("--name", "-n", help="Name of the twin to select.")

_config_path: Path | None = None


def set_config_path(path: Path | None) -> None:
    """Record the `--config` path for this invocation.

    Set on every invocation, including to `None`, so one run never
    inherits the previous one's path.
    """
    global _config_path
    _config_path = path


def config_path() -> Path | None:
    """The `--config` path for this invocation, or None to auto-discover."""
    return _config_path


def load_settings(command: str) -> GlobalConfig:
    """Load global config, reporting a bad one as a clean CLI error.

    The `config` capability requires invalid configuration to be reported
    and refused rather than guessed at, so a `ConfigError` becomes a
    message and a non-zero exit instead of a traceback.
    """
    try:
        return load_global_config(config_path())
    except ConfigError as exc:
        typer.echo(f"honeytwin {command}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
