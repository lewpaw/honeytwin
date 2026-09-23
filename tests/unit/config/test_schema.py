from pathlib import Path

from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig, TwinConfig


def test_global_config_defaults():
    cfg = GlobalConfig()
    assert cfg.data_dir == Path.home() / ".honeytwin"
    assert cfg.max_payload_bytes == 65536
    assert cfg.exposure_scope is ExposureScope.LOCAL
    assert cfg.docker_network_mode is DockerNetworkMode.MACVLAN
    assert cfg.scan_timeout_seconds == 600


def test_global_config_explicit_values():
    cfg = GlobalConfig(
        data_dir=Path("/tmp/honeytwin"),
        max_payload_bytes=1024,
        exposure_scope=ExposureScope.INTERNET,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        scan_timeout_seconds=120,
    )
    assert cfg.data_dir == Path("/tmp/honeytwin")
    assert cfg.max_payload_bytes == 1024
    assert cfg.exposure_scope is ExposureScope.INTERNET
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE
    assert cfg.scan_timeout_seconds == 120


def test_twin_config_fields_optional():
    cfg = TwinConfig()
    assert cfg.max_payload_bytes is None
    assert cfg.exposure_scope is None
    assert cfg.docker_network_mode is None
    assert cfg.scan_timeout_seconds is None


def test_twin_config_can_override():
    cfg = TwinConfig(
        max_payload_bytes=2048, exposure_scope=ExposureScope.INTERNET, scan_timeout_seconds=60
    )
    assert cfg.max_payload_bytes == 2048
    assert cfg.exposure_scope is ExposureScope.INTERNET
    assert cfg.scan_timeout_seconds == 60
