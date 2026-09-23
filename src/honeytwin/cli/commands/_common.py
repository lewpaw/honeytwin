"""Shared CLI option definitions.

A single `typer.Option` instance is reused across every subcommand that
selects a twin by name, so `--name`/`-n` has identical flag name and value
format everywhere it appears, per the `cli` capability spec.
"""

from __future__ import annotations

import typer

TWIN_NAME_OPTION = typer.Option("--name", "-n", help="Name of the twin to select.")
