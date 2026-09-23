"""`honeytwin list` — shows the twins on this host and their status.

Generated configs on disk are the source of truth for *what twins
exist*; the container runtime only answers *is it running right now*.
So Docker is optional enrichment: if it's unreachable, twins are still
listed with an unknown status rather than the command failing
(design.md).
"""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION, load_settings
from honeytwin.docker.client import (
    DockerUnavailableError,
    get_client,
    get_twin_container_status,
)
from honeytwin.generate.store import TwinConfigLoadError, list_twin_names, load_twin_config

UNKNOWN_STATUS = "unknown"
NOT_RUNNING_STATUS = "not running"


def list_twins(name: Annotated[str | None, TWIN_NAME_OPTION] = None) -> None:
    """List twins on this host, optionally filtered by name."""
    settings = load_settings("list")

    names = list_twin_names(settings.data_dir)
    if name is not None:
        names = [n for n in names if n == name]
        if not names:
            typer.echo(f"No twin named {name!r} has been generated.")
            raise typer.Exit(code=0)

    if not names:
        typer.echo("No twins have been generated yet. Create one with: honeytwin generate")
        raise typer.Exit(code=0)

    client = None
    try:
        client = get_client()
    except DockerUnavailableError as exc:
        typer.echo(f"(container runtime unavailable, status unknown: {exc})", err=True)

    rows = []
    for twin_name in names:
        try:
            config = load_twin_config(twin_name, settings.data_dir)
        except TwinConfigLoadError as exc:
            typer.echo(f"(skipping {twin_name!r}: {exc})", err=True)
            continue

        if client is None:
            status = UNKNOWN_STATUS
        else:
            status = get_twin_container_status(client, name=twin_name) or NOT_RUNNING_STATUS

        rows.append(
            (
                twin_name,
                status,
                ",".join(str(p.port) for p in config.ports) or "-",
                config.docker_network_mode.value,
                config.exposure_scope.value,
            )
        )

    headers = ("NAME", "STATUS", "PORTS", "NETWORK", "EXPOSURE")
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    typer.echo("  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)))
    for row in rows:
        typer.echo("  ".join(value.ljust(w) for value, w in zip(row, widths, strict=True)))
