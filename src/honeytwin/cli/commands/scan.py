"""`honeytwin scan` — scan a target with nmap, or import an existing nmap
XML file, producing a persisted twin profile (Epic 1, docs/ROADMAP.md).
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from honeytwin.cli.commands._warnings import print_authorization_warning
from honeytwin.config.loader import load_global_config
from honeytwin.profile.schema import ScanProfileName
from honeytwin.profile.store import save_profile, save_raw_xml
from honeytwin.scan.import_ import import_xml_file
from honeytwin.scan.nmap_runner import NmapNotFoundError, NmapScanError, run_nmap
from honeytwin.scan.profiles import NmapProfilesError, get_profile_flags
from honeytwin.scan.xml_parser import NmapXmlParseError, parse


class ScanProfileChoice(StrEnum):
    """The nmap scan profiles selectable via --profile (excludes 'imported',
    which the tool sets automatically for the --import path)."""

    LIGHT = "light"
    STANDARD = "standard"
    DEEP = "deep"


def scan(
    target: Annotated[str | None, typer.Argument(help="Target host/IP to scan.")] = None,
    profile: Annotated[
        ScanProfileChoice, typer.Option("--profile", help="nmap scan profile to use.")
    ] = ScanProfileChoice.STANDARD,
    import_path: Annotated[
        Path | None,
        typer.Option("--import", help="Import an existing nmap XML file instead of scanning."),
    ] = None,
) -> None:
    """Scan a target with nmap, or import an existing nmap XML file, producing a twin profile."""
    if target is None and import_path is None:
        typer.echo("honeytwin scan: provide a target or --import <path>", err=True)
        raise typer.Exit(code=1)
    if target is not None and import_path is not None:
        typer.echo("honeytwin scan: provide either a target or --import <path>, not both", err=True)
        raise typer.Exit(code=1)

    print_authorization_warning()

    config = load_global_config()

    try:
        if import_path is not None:
            profile_obj = import_xml_file(import_path, config.data_dir)
        else:
            try:
                flags = get_profile_flags(profile.value)
            except NmapProfilesError as exc:
                typer.echo(f"honeytwin scan: {exc}", err=True)
                raise typer.Exit(code=1) from exc

            try:
                xml = run_nmap(
                    target,
                    flags,
                    config.scan_timeout_seconds,
                    on_progress=lambda line: typer.echo(line, err=True),
                )
            except (NmapNotFoundError, NmapScanError) as exc:
                typer.echo(f"honeytwin scan: {exc}", err=True)
                raise typer.Exit(code=1) from exc

            profile_obj = parse(xml, scan_profile=ScanProfileName(profile.value))
            save_profile(profile_obj, config.data_dir)
            save_raw_xml(xml, profile_obj.target, profile_obj.scanned_at, config.data_dir)
    except NmapXmlParseError as exc:
        typer.echo(f"honeytwin scan: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Scanned {profile_obj.target}; twin profile saved under {config.data_dir}")
