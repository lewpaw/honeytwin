"""Shared, non-blocking operator warnings (PRD FR5: no hard authorization
gate, just a printed reminder before scanning or exposing a twin)."""

from __future__ import annotations

import typer

AUTHORIZATION_WARNING = (
    "WARNING: scanning and impersonating a target requires authorization "
    "from the target's owner. Proceeding is the operator's responsibility."
)

INTERNET_EXPOSURE_WARNING = (
    "WARNING: this twin's exposure_scope is 'internet' — its listeners will "
    "be reachable from any network. Ensure this is intentional and "
    "authorized before it starts."
)


def print_authorization_warning() -> None:
    """Print the non-blocking authorization reminder before a scan proceeds."""
    typer.echo(AUTHORIZATION_WARNING, err=True)


def print_internet_exposure_warning() -> None:
    """Print the non-blocking reminder before an internet-facing twin starts."""
    typer.echo(INTERNET_EXPOSURE_WARNING, err=True)
