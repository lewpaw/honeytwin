"""HoneyTwin CLI entry point.

Registers the fixed top-level command surface (`scan`, `generate`, `run`,
`list`, `stop`, `containment-setup`, `containment-status`) per the `cli`
capability spec. Most commands are stubs
until their owning epic (docs/ROADMAP.md) implements them; Typer still
generates working `--help` text for each from its type-annotated
signature, satisfying the discoverability requirement regardless.
"""

from __future__ import annotations

import typer

from honeytwin.cli.commands import containment, generate, run, scan, stop
from honeytwin.cli.commands import list as list_command

app = typer.Typer(
    name="honeytwin",
    help="nmap-scan-driven honeypot twin generator.",
    no_args_is_help=True,
)

app.command(name="scan", help="Scan a target with nmap and produce a twin profile.")(scan.scan)
app.command(
    name="generate", help="Generate a honeypot twin configuration from a stored twin profile."
)(generate.generate)
app.command(name="run", help="Run a generated twin.")(run.run)
app.command(name="list", help="List running twins, optionally filtered by name.")(
    list_command.list_twins
)
app.command(name="stop", help="Stop a running twin.")(stop.stop)
app.command(
    name="containment-setup",
    help="Install the host egress restriction twins depend on (requires root).",
)(containment.containment_setup)
app.command(
    name="containment-status", help="Report whether the host egress restriction is in effect."
)(containment.containment_status)


if __name__ == "__main__":
    app()
