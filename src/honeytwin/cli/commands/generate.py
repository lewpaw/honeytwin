"""`honeytwin generate` — not yet implemented (Epic 2, docs/ROADMAP.md)."""

from __future__ import annotations

import typer


def generate() -> None:
    """Generate a honeypot twin configuration from a stored twin profile."""
    typer.echo("honeytwin generate: not yet implemented (see docs/ROADMAP.md Epic 2)", err=True)
    raise typer.Exit(code=1)
