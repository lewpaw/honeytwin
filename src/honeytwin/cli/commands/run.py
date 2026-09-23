"""`honeytwin run` — runs a generated twin as an isolated Docker container
(Epic 2/4, docs/ROADMAP.md)."""

from __future__ import annotations

import os
from typing import Annotated

import typer

from honeytwin.cli.commands._common import TWIN_NAME_OPTION
from honeytwin.cli.commands._warnings import (
    print_internet_exposure_warning,
    print_outbound_access_warning,
)
from honeytwin.config.loader import load_global_config
from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.containment.marker import ContainmentState, evaluate
from honeytwin.docker.client import (
    DockerUnavailableError,
    NetworkSubnetMismatchError,
    create_bridge_network,
    create_macvlan_network,
    create_twin_container,
    get_client,
    get_twin_container_status,
    start_twin_container,
)
from honeytwin.generate.store import (
    CONFIG_FILENAME,
    TwinConfigLoadError,
    load_twin_config,
    twin_dir,
)
from honeytwin.logging.writer import twin_log_dir

TWIN_IMAGE = "honeytwin-twin:local"
# The host egress restriction is a firewall rule naming one subnet, so
# twins that deny outbound and twins that allow it get separate networks
# on separate subnets (design.md).
BRIDGE_NETWORK_NAME_CONTAINED = "honeytwin-bridge"
BRIDGE_NETWORK_NAME_EGRESS = "honeytwin-bridge-egress"
MACVLAN_NETWORK_NAME = "honeytwin-macvlan"

MACVLAN_UNCONTAINABLE_MESSAGE = (
    "honeytwin run: a macvlan twin cannot be denied outbound access. Its "
    "traffic leaves on the physical segment and never reaches the host's "
    "firewall, so the restriction has no effect on it (verified — see "
    "design.md). Either switch this twin to bridge mode, or set "
    "allow_outbound: true to consciously accept an uncontained twin."
)


ROOT_REFUSAL_MESSAGE = (
    "honeytwin run: refusing to start a twin as root. The container would "
    "inherit uid 0 and run privileged, which defeats containment. Run "
    "'honeytwin run' as an ordinary user (scanning may need sudo; running "
    "a twin must not)."
)


def _host_user_spec() -> str | None:
    """The "uid:gid" the twin container should run as, so it can write to
    the host-owned log directory. `None` on platforms without POSIX uids
    (Windows), where bind mounts don't enforce ownership anyway."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return None
    return f"{getuid()}:{getgid()}"


def _refuse_if_root() -> None:
    """Refuse to start a twin when the operator is root.

    `_host_user_spec()` exists so the container can write its host-owned
    log directory, but under `sudo` it yields "0:0" — silently overriding
    the image's non-root user. Substituting the image's uid instead would
    re-break log writes (the directory would be root-owned), so the
    refusal is deliberate: both guarantees stay intact and the fix is in
    the operator's hands (see design.md).
    """
    getuid = getattr(os, "getuid", None)
    if getuid is not None and getuid() == 0:
        typer.echo(ROOT_REFUSAL_MESSAGE, err=True)
        raise typer.Exit(code=1)


def _require_containment(settings, twin_config) -> None:
    """Refuse to start a twin whose containment would not actually hold.

    A twin that denies outbound access depends on a host firewall rule
    someone has to have installed. Starting one without it would report
    containment that isn't there, which is the failure mode this whole
    epic exists to remove — so it refuses instead.
    """
    if twin_config.allow_outbound:
        return

    if twin_config.docker_network_mode is DockerNetworkMode.MACVLAN:
        typer.echo(MACVLAN_UNCONTAINABLE_MESSAGE, err=True)
        raise typer.Exit(code=1)

    state, marker = evaluate(settings.data_dir, subnet=settings.bridge_subnet)
    if state is ContainmentState.ACTIVE:
        return

    reasons = {
        ContainmentState.MISSING: (
            f"the host egress restriction is not installed for {settings.bridge_subnet}"
        ),
        ContainmentState.STALE: (
            "the host has rebooted since the egress restriction was installed, "
            "so its rules are gone"
        ),
        ContainmentState.SUBNET_MISMATCH: (
            f"the egress restriction was installed for "
            f"{marker.subnet if marker else 'another subnet'}, but twins now use "
            f"{settings.bridge_subnet}"
        ),
    }
    typer.echo(
        f"honeytwin run: refusing to start twin {twin_config.name!r} — "
        f"{reasons[state]}. Without it the twin could reach the real target, the "
        f"host, and the internal network. Run: sudo honeytwin containment-setup "
        f"(or set allow_outbound: true to accept an uncontained twin).",
        err=True,
    )
    raise typer.Exit(code=1)


def run(name: Annotated[str, TWIN_NAME_OPTION]) -> None:
    """Run a generated twin as a Docker container."""
    _refuse_if_root()

    settings = load_global_config()

    try:
        twin_config = load_twin_config(name, settings.data_dir)
    except TwinConfigLoadError as exc:
        typer.echo(f"honeytwin run: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        client = get_client()
    except DockerUnavailableError as exc:
        typer.echo(f"honeytwin run: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if get_twin_container_status(client, name=twin_config.name) is not None:
        typer.echo(
            f"honeytwin run: twin {name!r} is already running "
            f"(stop it first with: honeytwin stop --name {name})",
            err=True,
        )
        raise typer.Exit(code=1)

    _require_containment(settings, twin_config)

    # Warn only once the twin is actually going to start - warning about
    # internet exposure for a run that then refuses would be misleading.
    if twin_config.exposure_scope is ExposureScope.INTERNET:
        print_internet_exposure_warning()
    if twin_config.allow_outbound:
        print_outbound_access_warning()

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
        if twin_config.allow_outbound:
            network_name = BRIDGE_NETWORK_NAME_EGRESS
            subnet = settings.bridge_egress_subnet
        else:
            network_name = BRIDGE_NETWORK_NAME_CONTAINED
            subnet = settings.bridge_subnet
        try:
            network = create_bridge_network(client, name=network_name, subnet=subnet)
        except NetworkSubnetMismatchError as exc:
            typer.echo(f"honeytwin run: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    config_path = twin_dir(name, settings.data_dir) / CONFIG_FILENAME
    log_dir = twin_log_dir(name, settings.data_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    create_twin_container(
        client,
        name=twin_config.name,
        image=TWIN_IMAGE,
        config_path=config_path,
        log_dir=log_dir,
        ports=[p.port for p in twin_config.ports],
        network_mode=twin_config.docker_network_mode,
        network_name=network.name,
        exposure_scope=twin_config.exposure_scope,
        run_as_user=_host_user_spec(),
        mem_limit=twin_config.mem_limit,
        pids_limit=twin_config.pids_limit,
        cpu_quota=twin_config.cpu_quota,
    )
    start_twin_container(client, name=twin_config.name)

    typer.echo(
        f"Twin {name!r} started ({len(twin_config.ports)} port(s), "
        f"{twin_config.docker_network_mode.value} mode)"
    )
