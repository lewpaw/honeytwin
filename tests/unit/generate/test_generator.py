from datetime import UTC, datetime

from honeytwin.config.schema import (
    DockerNetworkMode,
    ExposureScope,
    GlobalConfig,
    SyslogProtocol,
)
from honeytwin.generate.generator import generate_twin_config
from honeytwin.profile.schema import PortInfo, ScanProfileName, TwinProfile


def _profile_with_mixed_ports() -> TwinProfile:
    return TwinProfile(
        target="192.0.2.10",
        scan_profile=ScanProfileName.STANDARD,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ports=[
            PortInfo(protocol="tcp", port=22, state="open", banner="SSH-2.0-OpenSSH_8.9p1"),
            PortInfo(protocol="tcp", port=80, state="open", banner=None),
            PortInfo(protocol="tcp", port=443, state="closed"),
            PortInfo(protocol="tcp", port=8080, state="filtered"),
        ],
    )


def test_generate_includes_only_open_ports():
    profile = _profile_with_mixed_ports()
    settings = GlobalConfig(
        docker_network_mode=DockerNetworkMode.MACVLAN, exposure_scope=ExposureScope.LOCAL
    )

    config = generate_twin_config(profile, "web-01", settings)

    port_numbers = {p.port for p in config.ports}
    assert port_numbers == {22, 80}


def test_generate_preserves_banner_when_present():
    profile = _profile_with_mixed_ports()
    settings = GlobalConfig()

    config = generate_twin_config(profile, "web-01", settings)

    ssh_port = next(p for p in config.ports if p.port == 22)
    http_port = next(p for p in config.ports if p.port == 80)
    assert ssh_port.banner == "SSH-2.0-OpenSSH_8.9p1"
    assert http_port.banner is None


def test_generate_carries_network_mode_and_exposure_scope():
    profile = _profile_with_mixed_ports()
    settings = GlobalConfig(
        docker_network_mode=DockerNetworkMode.BRIDGE, exposure_scope=ExposureScope.INTERNET
    )

    config = generate_twin_config(profile, "web-01", settings)

    assert config.docker_network_mode is DockerNetworkMode.BRIDGE
    assert config.exposure_scope is ExposureScope.INTERNET
    assert config.name == "web-01"
    assert config.target == "192.0.2.10"


def test_generate_carries_logging_settings():
    profile = _profile_with_mixed_ports()
    settings = GlobalConfig(
        max_payload_bytes=1024,
        syslog_enabled=True,
        syslog_host="syslog.example.com",
        syslog_port=1514,
        syslog_protocol=SyslogProtocol.TCP,
    )

    config = generate_twin_config(profile, "web-01", settings)

    assert config.max_payload_bytes == 1024
    assert config.syslog_enabled is True
    assert config.syslog_host == "syslog.example.com"
    assert config.syslog_port == 1514
    assert config.syslog_protocol is SyslogProtocol.TCP
