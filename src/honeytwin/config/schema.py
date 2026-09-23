"""Pydantic models for HoneyTwin's YAML configuration.

Covers the fields fixed by docs/PRD.md section 9: data directory, payload
capture cap, network exposure scope, and Docker network mode. Later epics
extend these models with their own fields as they land.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class ExposureScope(StrEnum):
    """Who can reach a twin's listeners."""

    LOCAL = "local"
    INTERNET = "internet"


class DockerNetworkMode(StrEnum):
    """How a twin's container is attached to the network."""

    MACVLAN = "macvlan"
    BRIDGE = "bridge"


class SyslogProtocol(StrEnum):
    """Transport used to forward events to a syslog collector."""

    UDP = "udp"
    TCP = "tcp"


class GlobalConfig(BaseModel):
    """Settings shared by all twins unless a twin overrides them."""

    data_dir: Path = Field(
        default=Path.home() / ".honeytwin",
        description="Directory holding twin profiles, raw nmap XML, and logs.",
    )
    max_payload_bytes: int = Field(
        default=65536,
        ge=0,
        description="Per-session captured payload cap before truncation.",
    )
    exposure_scope: ExposureScope = Field(
        default=ExposureScope.LOCAL,
        description="Default network exposure scope for twins that don't override it.",
    )
    docker_network_mode: DockerNetworkMode = Field(
        default=DockerNetworkMode.BRIDGE,
        description=(
            "Default Docker network mode for twins that don't override it. "
            "Bridge is the default because host firewall rules cannot restrict "
            "macvlan traffic, so a macvlan twin cannot be denied outbound access."
        ),
    )
    scan_timeout_seconds: int = Field(
        default=600,
        gt=0,
        description="Maximum time to wait for an nmap scan to complete.",
    )
    macvlan_parent_interface: str | None = Field(
        default=None,
        description="Host network interface a macvlan-mode twin attaches to.",
    )
    macvlan_subnet: str | None = Field(
        default=None,
        description="Subnet (CIDR) for the macvlan network, e.g. 192.168.1.0/24.",
    )
    macvlan_gateway: str | None = Field(
        default=None,
        description="Gateway IP for the macvlan network.",
    )
    syslog_enabled: bool = Field(
        default=False,
        description="Whether to forward connection events to a syslog collector.",
    )
    syslog_host: str | None = Field(
        default=None,
        description="Syslog collector hostname/IP.",
    )
    syslog_port: int = Field(
        default=514,
        gt=0,
        description="Syslog collector port.",
    )
    syslog_protocol: SyslogProtocol = Field(
        default=SyslogProtocol.UDP,
        description="Transport used to send syslog messages.",
    )
    allow_outbound: bool = Field(
        default=False,
        description=(
            "Whether twins may initiate outbound network connections. Denied "
            "by default so an abused twin cannot reach the real target, the "
            "host, or the internal network. Enabling it weakens containment; "
            "remote syslog forwarding requires it."
        ),
    )
    bridge_subnet: str = Field(
        default="172.31.240.0/24",
        description=(
            "Subnet (CIDR) for the bridge network used by egress-denied twins. "
            "Fixed rather than IPAM-assigned so the host egress restriction can "
            "name it; 'honeytwin containment-setup' installs rules for this subnet."
        ),
    )
    bridge_egress_subnet: str = Field(
        default="172.31.241.0/24",
        description=(
            "Subnet (CIDR) for the bridge network used by twins that opt into "
            "outbound access. Deliberately not covered by the egress restriction."
        ),
    )
    mem_limit: str = Field(
        default="256m",
        description="Memory limit for a twin's container, in Docker's format (e.g. 256m).",
    )
    pids_limit: int = Field(
        default=128,
        gt=0,
        description="Maximum number of processes a twin's container may create.",
    )
    cpu_quota: int = Field(
        default=50000,
        gt=0,
        description=(
            "CPU quota in microseconds per Docker's default 100000us period, "
            "so 50000 is half a CPU."
        ),
    )


class TwinConfig(BaseModel):
    """Per-twin settings; unset fields fall through to GlobalConfig."""

    max_payload_bytes: int | None = Field(default=None, ge=0)
    exposure_scope: ExposureScope | None = None
    docker_network_mode: DockerNetworkMode | None = None
    scan_timeout_seconds: int | None = Field(default=None, gt=0)
    macvlan_parent_interface: str | None = None
    macvlan_subnet: str | None = None
    macvlan_gateway: str | None = None
    syslog_enabled: bool | None = None
    syslog_host: str | None = None
    syslog_port: int | None = Field(default=None, gt=0)
    syslog_protocol: SyslogProtocol | None = None
    allow_outbound: bool | None = None
    mem_limit: str | None = None
    pids_limit: int | None = Field(default=None, gt=0)
    cpu_quota: int | None = Field(default=None, gt=0)
