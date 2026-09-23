"""`honeytwin run` — runs a generated twin as an isolated Docker container
(Epic 2/4, docs/ROADMAP.md)."""

from __future__ import annotations

from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION
from honeytwin.cli.commands._warnings import print_internet_exposure_warning
from honeytwin.config.loader import load_global_config
from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.docker.client import (
    DockerUnavailableError,
    create_bridge_network,
    create_macvlan_network,
    create_twin_container,
    get_client,
    start_twin_container,
)
from honeytwin.generate.store import (
    CONFIG_FILENAME,
    TwinConfigLoadError,
    load_twin_config,
    twin_dir,
)

TWIN_IMAGE = "honeytwin-twin:local"
BRIDGE_NETWORK_NAME = "honeytwin-bridge"
MACVLAN_NETWORK_NAME = "honeytwin-macvlan"


def run(name: Annotated[str, TWIN_NAME_OPTION]) -> None:
    """Run a generated twin as a Docker container."""
    settings = load_global_config()

    try:
        twin_config = load_twin_config(name, settings.data_dir)
    except TwinConfigLoadError as exc:
        typer.echo(f"honeytwin run: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if twin_config.exposure_scope is ExposureScope.INTERNET:
        print_internet_exposure_warning()

    try:
        client = get_client()
    except DockerUnavailableError as exc:
        typer.echo(f"honeytwin run: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if twin_config.docker_network_mode is DockerNetworkMode.MACVLAN:
        if not settings.macvlan_parent_interface or not settings.macvlan_subnet:
            typer.echo(
                "honeytwin run: macvlan mode requires macvlan_parent_interface and "
                "macvlan_subnet to be configured",
                err=True,
            )
            raise typer.Exit(code=1)
        network = create_macvlan_network(
            client,
            name=MACVLAN_NETWORK_NAME,
            parent_interface=settings.macvlan_parent_interface,
            subnet=settings.macvlan_subnet,
            gateway=settings.macvlan_gateway,
        )
    else:
        network = create_bridge_network(client, name=BRIDGE_NETWORK_NAME)

    config_path = twin_dir(name, settings.data_dir) / CONFIG_FILENAME
    create_twin_container(
        client,
        name=twin_config.name,
        image=TWIN_IMAGE,
        config_path=config_path,
        ports=[p.port for p in twin_config.ports],
        network_mode=twin_config.docker_network_mode,
        network_name=network.name,
        exposure_scope=twin_config.exposure_scope,
    )
    start_twin_container(client, name=twin_config.name)

    typer.echo(
        f"Twin {name!r} started ({len(twin_config.ports)} port(s), "
        f"{twin_config.docker_network_mode.value} mode)"
    )
