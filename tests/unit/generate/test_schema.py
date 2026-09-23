from honeytwin.config.schema import DockerNetworkMode, ExposureScope, SyslogProtocol
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig


def test_twin_config_file_constructs_with_ports():
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[
            TwinPortConfig(port=22, protocol="tcp", banner="SSH-2.0-OpenSSH_8.9p1"),
            TwinPortConfig(port=80, protocol="tcp", banner=None),
        ],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
    )
    assert config.name == "web-01"
    assert len(config.ports) == 2
    assert config.ports[0].banner == "SSH-2.0-OpenSSH_8.9p1"
    assert config.ports[1].banner is None


def test_twin_config_file_defaults_empty_ports():
    config = TwinConfigFile(
        name="empty",
        target="192.0.2.20",
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.INTERNET,
    )
    assert config.ports == []


def test_twin_config_file_logging_field_defaults():
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
    )
    assert config.max_payload_bytes == 65536
    assert config.syslog_enabled is False
    assert config.syslog_host is None
    assert config.syslog_port == 514
    assert config.syslog_protocol is SyslogProtocol.UDP


def test_twin_config_file_logging_field_explicit_values():
    config = TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
        max_payload_bytes=1024,
        syslog_enabled=True,
        syslog_host="syslog.example.com",
        syslog_port=1514,
        syslog_protocol=SyslogProtocol.TCP,
    )
    assert config.max_payload_bytes == 1024
    assert config.syslog_enabled is True
    assert config.syslog_host == "syslog.example.com"
    assert config.syslog_port == 1514
    assert config.syslog_protocol is SyslogProtocol.TCP
