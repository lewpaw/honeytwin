from pathlib import Path

import pytest

from honeytwin.config.loader import (
    ConfigError,
    load_global_config,
    load_twin_config,
    resolve_twin_config,
)
from honeytwin.config.schema import DockerNetworkMode, ExposureScope, GlobalConfig, TwinConfig


def test_load_global_config_uses_shipped_defaults():
    cfg = load_global_config()
    assert cfg.max_payload_bytes == 65536
    assert cfg.exposure_scope is ExposureScope.LOCAL
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE
    assert cfg.allow_outbound is False


def test_load_global_config_override_file(tmp_path: Path):
    override = tmp_path / "global.yaml"
    override.write_text("max_payload_bytes: 1024\n", encoding="utf-8")
    cfg = load_global_config(override)
    assert cfg.max_payload_bytes == 1024
    # unset fields still come from shipped defaults
    assert cfg.exposure_scope is ExposureScope.LOCAL


def test_load_global_config_missing_file(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_global_config(tmp_path / "does-not-exist.yaml")


def test_load_global_config_malformed_yaml(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("max_payload_bytes: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_global_config(bad)


def test_load_global_config_invalid_value(tmp_path: Path):
    bad = tmp_path / "invalid.yaml"
    bad.write_text("max_payload_bytes: -5\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_global_config(bad)


def test_load_twin_config_invalid_value(tmp_path: Path):
    bad = tmp_path / "twin.yaml"
    bad.write_text("max_payload_bytes: -1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_twin_config(bad)


def test_twin_override_wins_over_global():
    global_cfg = GlobalConfig(max_payload_bytes=65536)
    twin_cfg = TwinConfig(max_payload_bytes=100)
    resolved = resolve_twin_config(twin_cfg, global_cfg)
    assert resolved.max_payload_bytes == 100


def test_unset_twin_value_falls_through_to_global():
    global_cfg = GlobalConfig(max_payload_bytes=65536, exposure_scope=ExposureScope.INTERNET)
    twin_cfg = TwinConfig()
    resolved = resolve_twin_config(twin_cfg, global_cfg)
    assert resolved.max_payload_bytes == 65536
    assert resolved.exposure_scope is ExposureScope.INTERNET
