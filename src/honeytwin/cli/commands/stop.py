"""`honeytwin stop` — not yet implemented (Epic 4, docs/ROADMAP.md)."""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION


def stop(name: Annotated[str, TWIN_NAME_OPTION]) -> None:
    """Stop a running twin."""
    typer.echo(
        f"honeytwin stop --name {name}: not yet implemented (see docs/ROADMAP.md Epic 4)",
        err=True,
    )
    raise typer.Exit(code=1)
