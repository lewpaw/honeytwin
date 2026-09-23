"""`honeytwin run` — not yet implemented (Epic 2/4, docs/ROADMAP.md)."""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION


def run(name: Annotated[str, TWIN_NAME_OPTION]) -> None:
    """Run a generated twin."""
    typer.echo(
        f"honeytwin run --name {name}: not yet implemented (see docs/ROADMAP.md Epic 2/4)",
        err=True,
    )
    raise typer.Exit(code=1)
