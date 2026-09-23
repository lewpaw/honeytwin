from pathlib import Path

from honeytwin.config.schema import (
    DockerNetworkMode,
    ExposureScope,
    GlobalConfig,
    SyslogProtocol,
    TwinConfig,
)


def test_global_config_defaults():
    cfg = GlobalConfig()
    assert cfg.data_dir == Path.home() / ".honeytwin"
    assert cfg.max_payload_bytes == 65536
    assert cfg.exposure_scope is ExposureScope.LOCAL
    # Bridge, not macvlan: host firewall rules cannot restrict macvlan
    # egress, so a macvlan twin cannot honor the default containment
    # guarantee (Epic 5).
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE
    assert cfg.scan_timeout_seconds == 600
    assert cfg.syslog_enabled is False
    assert cfg.syslog_host is None
    assert cfg.syslog_port == 514
    assert cfg.syslog_protocol is SyslogProtocol.UDP


def test_global_config_explicit_values():
    cfg = GlobalConfig(
        data_dir=Path("/tmp/honeytwin"),
        max_payload_bytes=1024,
        exposure_scope=ExposureScope.INTERNET,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        scan_timeout_seconds=120,
        syslog_enabled=True,
        syslog_host="syslog.example.com",
        syslog_port=6514,
        syslog_protocol=SyslogProtocol.TCP,
    )
    assert cfg.data_dir == Path("/tmp/honeytwin")
    assert cfg.max_payload_bytes == 1024
    assert cfg.exposure_scope is ExposureScope.INTERNET
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE
    assert cfg.scan_timeout_seconds == 120
    assert cfg.syslog_enabled is True
    assert cfg.syslog_host == "syslog.example.com"
    assert cfg.syslog_port == 6514
    assert cfg.syslog_protocol is SyslogProtocol.TCP


def test_twin_config_fields_optional():
    cfg = TwinConfig()
    assert cfg.max_payload_bytes is None
    assert cfg.exposure_scope is None
    assert cfg.docker_network_mode is None
    assert cfg.scan_timeout_seconds is None
    assert cfg.syslog_enabled is None
    assert cfg.syslog_host is None
    assert cfg.syslog_port is None
    assert cfg.syslog_protocol is None


def test_twin_config_can_override():
    cfg = TwinConfig(
        max_payload_bytes=2048,
        exposure_scope=ExposureScope.INTERNET,
        scan_timeout_seconds=60,
        syslog_enabled=True,
        syslog_host="syslog.example.com",
        syslog_port=1514,
        syslog_protocol=SyslogProtocol.TCP,
    )
    assert cfg.max_payload_bytes == 2048
    assert cfg.exposure_scope is ExposureScope.INTERNET
    assert cfg.scan_timeout_seconds == 60
    assert cfg.syslog_enabled is True
    assert cfg.syslog_host == "syslog.example.com"
    assert cfg.syslog_port == 1514
    assert cfg.syslog_protocol is SyslogProtocol.TCP


def test_global_config_containment_defaults():
    cfg = GlobalConfig()
    assert cfg.allow_outbound is False
    assert cfg.mem_limit == "256m"
    assert cfg.pids_limit == 128
    assert cfg.cpu_quota == 50000


def test_global_config_containment_settings_can_be_overridden():
    cfg = GlobalConfig(allow_outbound=True, mem_limit="1g", pids_limit=512, cpu_quota=100000)
    assert cfg.allow_outbound is True
    assert cfg.mem_limit == "1g"
    assert cfg.pids_limit == 512
    assert cfg.cpu_quota == 100000


def test_twin_config_containment_fields_optional():
    cfg = TwinConfig()
    assert cfg.allow_outbound is None
    assert cfg.mem_limit is None
    assert cfg.pids_limit is None
    assert cfg.cpu_quota is None


def test_twin_config_can_opt_out_of_egress_denial():
    cfg = TwinConfig(allow_outbound=True, mem_limit="512m", pids_limit=64, cpu_quota=20000)
    assert cfg.allow_outbound is True
    assert cfg.mem_limit == "512m"
    assert cfg.pids_limit == 64
    assert cfg.cpu_quota == 20000
