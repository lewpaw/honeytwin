"""Shared, non-blocking operator warnings (PRD FR5: no hard authorization
gate, just a printed reminder before scanning or exposing a twin)."""

from __future__ import annotations

import typer

AUTHORIZATION_WARNING = (
    "WARNING: scanning and impersonating a target requires authorization "
    "from the target's owner. Proceeding is the operator's responsibility."
)


def print_authorization_warning() -> None:
    """Print the non-blocking authorization reminder before a scan proceeds."""
    typer.echo(AUTHORIZATION_WARNING, err=True)
