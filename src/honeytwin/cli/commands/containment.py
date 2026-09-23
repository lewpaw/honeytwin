"""`honeytwin containment-setup` / `containment-status` — manage the host
egress restriction that twin containment depends on (Epic 5).

Setup is the one command that *requires* root, which is the exact
inverse of `run`: installing firewall rules needs privilege, and running
a twin must not have it. That split is deliberate (design.md) — the
rules are static per subnet, so they are installed once per host rather
than per twin.
"""

from __future__ import annotations

import os

import typer

from honeytwin.cli.commands._common import load_settings
from honeytwin.containment.firewall import FirewallError, install_rules, rules_installed
from honeytwin.containment.marker import ContainmentState, evaluate, write_marker

NOT_ROOT_MESSAGE = (
    "honeytwin containment-setup: installing the egress restriction requires "
    "root. Re-run it with sudo. (Only this command needs root — 'honeytwin run' "
    "refuses to run as root.)"
)

PERSISTENCE_NOTE = (
    "Note: these rules do not survive a reboot unless you persist them "
    "(e.g. iptables-persistent). HoneyTwin detects a reboot and will refuse to "
    "start egress-denied twins until this command is run again."
)


def _require_root() -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is None or getuid() != 0:
        typer.echo(NOT_ROOT_MESSAGE, err=True)
        raise typer.Exit(code=1)


def containment_setup() -> None:
    """Install the host egress restriction for HoneyTwin's twin network."""
    _require_root()

    settings = load_settings("containment-setup")
    subnet = settings.bridge_subnet

    try:
        added = install_rules(subnet)
    except FirewallError as exc:
        typer.echo(f"honeytwin containment-setup: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    write_marker(settings.data_dir, subnet=subnet)

    if added:
        typer.echo(f"Egress restriction installed for {subnet}:")
        for rule in added:
            typer.echo(f"  {rule}")
    else:
        typer.echo(f"Egress restriction already in place for {subnet}")
    typer.echo(PERSISTENCE_NOTE)


def containment_status() -> None:
    """Report whether the host egress restriction is in effect."""
    settings = load_settings("containment-status")
    subnet = settings.bridge_subnet
    state, marker = evaluate(settings.data_dir, subnet=subnet)

    if state is ContainmentState.ACTIVE:
        typer.echo(f"Egress restriction: active for {subnet} (installed {marker.installed_at})")
    elif state is ContainmentState.STALE:
        typer.echo(
            f"Egress restriction: STALE — recorded for {subnet} at {marker.installed_at}, "
            f"but the host has rebooted since, so the rules are gone. "
            f"Re-run: sudo honeytwin containment-setup"
        )
    elif state is ContainmentState.SUBNET_MISMATCH:
        typer.echo(
            f"Egress restriction: recorded for {marker.subnet}, but twins now use "
            f"{subnet}. Re-run: sudo honeytwin containment-setup"
        )
    else:
        typer.echo(
            f"Egress restriction: not installed for {subnet}. Run: sudo honeytwin containment-setup"
        )

    # The marker is what `run` consults, but the firewall tables are the
    # truth; report them too whenever we have the privilege to read them.
    try:
        live = rules_installed(subnet)
    except FirewallError:
        typer.echo("Live firewall rules: not readable without root (marker shown above)")
    else:
        typer.echo(f"Live firewall rules: {'present' if live else 'ABSENT'} for {subnet}")

    if state is not ContainmentState.ACTIVE:
        raise typer.Exit(code=1)
