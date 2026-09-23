"""`honeytwin generate` — derives a runnable twin configuration from a
stored twin profile (Epic 2, docs/ROADMAP.md)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION
from honeytwin.config.loader import load_global_config
from honeytwin.generate.generator import generate_twin_config
from honeytwin.generate.store import save_twin_config
from honeytwin.profile.store import ProfileLoadError, ProfileSchemaVersionError, load_profile


def generate(
    name: Annotated[str, TWIN_NAME_OPTION],
    profile_path: Annotated[
        Path, typer.Option("--profile", help="Path to a stored twin profile JSON file.")
    ],
) -> None:
    """Generate a twin configuration from a stored twin profile."""
    settings = load_global_config()

    try:
        profile = load_profile(profile_path)
    except (ProfileLoadError, ProfileSchemaVersionError) as exc:
        typer.echo(f"honeytwin generate: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    twin_config = generate_twin_config(profile, name, settings)
    saved_path = save_twin_config(twin_config, settings.data_dir)

    typer.echo(
        f"Generated twin {name!r} ({len(twin_config.ports)} port(s)); config saved to {saved_path}"
    )
