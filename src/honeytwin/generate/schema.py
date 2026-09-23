"""The generated twin configuration: what a twin's runtime actually
listens on and replays, derived from a twin profile but stored as its own
artifact (see design.md's "Twin configuration is a separate generated
artifact" decision).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from honeytwin.config.schema import DockerNetworkMode, ExposureScope, SyslogProtocol


class TwinPortConfig(BaseModel):
    """One port this twin's listener binds and what it replays."""

    port: int
    protocol: str
    banner: str | None = None


class TwinConfigFile(BaseModel):
    """A generated, runnable twin configuration."""

    name: str
    target: str
    ports: list[TwinPortConfig] = Field(default_factory=list)
    docker_network_mode: DockerNetworkMode
    exposure_scope: ExposureScope
    max_payload_bytes: int = 65536
    syslog_enabled: bool = False
    syslog_host: str | None = None
    syslog_port: int = 514
    syslog_protocol: SyslogProtocol = SyslogProtocol.UDP
    allow_outbound: bool = False
    mem_limit: str = "256m"
    pids_limit: int = 128
    cpu_quota: int = 50000
