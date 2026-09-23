"""`honeytwin list` — not yet implemented (Epic 4, docs/ROADMAP.md)."""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION


def list_twins(name: Annotated[str | None, TWIN_NAME_OPTION] = None) -> None:
    """List running twins, optionally filtered by name."""
    typer.echo("honeytwin list: not yet implemented (see docs/ROADMAP.md Epic 4)", err=True)
    raise typer.Exit(code=1)
