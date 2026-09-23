from honeytwin.config.schema import DockerNetworkMode, ExposureScope
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
