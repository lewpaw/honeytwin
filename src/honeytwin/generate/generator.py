"""Derives a runnable twin configuration from a stored twin profile.

Only `open` ports become listeners — a `closed`/`filtered` port in the
profile gets no entry, so the twin doesn't accept connections there
either. Works from the profile alone: no network access, no nmap.
"""

from __future__ import annotations

from honeytwin.config.schema import GlobalConfig
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.profile.schema import TwinProfile


def generate_twin_config(
    profile: TwinProfile, name: str, twin_settings: GlobalConfig
) -> TwinConfigFile:
    """Build a TwinConfigFile from a twin profile and the settings to run it under."""
    ports = [
        TwinPortConfig(port=p.port, protocol=p.protocol, banner=p.banner)
        for p in profile.ports
        if p.state == "open"
    ]
    return TwinConfigFile(
        name=name,
        target=profile.target,
        ports=ports,
        docker_network_mode=twin_settings.docker_network_mode,
        exposure_scope=twin_settings.exposure_scope,
    )
