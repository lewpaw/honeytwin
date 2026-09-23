"""`honeytwin stop` — stops and removes a running twin's container.

Removing rather than merely stopping keeps the twin's name free for the
next `run` (design.md). Nothing the operator cares about is lost: the
twin's config, profile, and logs live on host bind mounts, not inside
the container.
"""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION
from honeytwin.docker.client import (
    DockerUnavailableError,
    get_client,
    get_twin_container_status,
    remove_twin_container,
    stop_twin_container,
)


def stop(name: Annotated[str, TWIN_NAME_OPTION]) -> None:
    """Stop a running twin."""
    try:
        client = get_client()
    except DockerUnavailableError as exc:
        typer.echo(f"honeytwin stop: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if get_twin_container_status(client, name=name) is None:
        typer.echo(f"honeytwin stop: twin {name!r} is not running", err=True)
        raise typer.Exit(code=1)

    stop_twin_container(client, name=name)
    remove_twin_container(client, name=name)

    typer.echo(f"Twin {name!r} stopped")
