from pathlib import Path

import pytest

from honeytwin.config.loader import (
    ConfigError,
    load_global_config,
    load_twin_config,
    resolve_twin_config,
    user_config_path,
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


# --- shipped defaults resolve through the package ---


def test_shipped_defaults_load_from_the_package():
    """Read via importlib.resources, so this works from a checkout and an
    installed wheel alike - the check that fails with __file__ walking."""
    from importlib.resources import files

    raw = files("honeytwin.data").joinpath("defaults.yaml").read_text(encoding="utf-8")
    assert "docker_network_mode" in raw


def test_unreadable_shipped_defaults_raise_rather_than_falling_back(monkeypatch):
    """The built-in field defaults happen to match the shipped file, so a
    silent fallback would let an operator edit a config that is never read
    and see neither effect nor warning."""

    def boom(_package):
        raise ModuleNotFoundError("honeytwin.data")

    monkeypatch.setattr("honeytwin.config.loader.files", boom)
    with pytest.raises(ConfigError, match="install is incomplete"):
        load_global_config()


# --- operator config discovery ---


def test_user_config_path_follows_xdg_config_home(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert user_config_path() == tmp_path / "honeytwin" / "config.yaml"


def test_user_config_path_falls_back_to_dot_config(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert user_config_path() == tmp_path / ".config" / "honeytwin" / "config.yaml"


def test_relative_xdg_config_home_is_ignored(monkeypatch, tmp_path: Path):
    """XDG requires an absolute path; a relative one would resolve against
    whatever directory the operator happened to run from."""
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert user_config_path() == tmp_path / ".config" / "honeytwin" / "config.yaml"


def _write_user_config(config_home: Path, body: str) -> Path:
    path = config_home / "honeytwin" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_discovered_user_config_overrides_shipped_defaults(isolated_user_config: Path):
    _write_user_config(isolated_user_config, "exposure_scope: internet\n")
    cfg = load_global_config()
    assert cfg.exposure_scope is ExposureScope.INTERNET


def test_discovered_user_config_only_overrides_what_it_names(isolated_user_config: Path):
    _write_user_config(isolated_user_config, "max_payload_bytes: 4096\n")
    cfg = load_global_config()
    assert cfg.max_payload_bytes == 4096
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE
    assert cfg.allow_outbound is False


def test_no_user_config_is_silent_and_uses_shipped_defaults(isolated_user_config: Path):
    cfg = load_global_config()
    assert cfg.exposure_scope is ExposureScope.LOCAL
    assert cfg.docker_network_mode is DockerNetworkMode.BRIDGE


def test_explicit_config_takes_precedence_over_the_discovered_one(
    isolated_user_config: Path, tmp_path: Path
):
    _write_user_config(isolated_user_config, "max_payload_bytes: 4096\n")
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("max_payload_bytes: 999\n", encoding="utf-8")

    assert load_global_config(explicit).max_payload_bytes == 999


def test_missing_explicit_config_is_an_error_not_a_fallback(
    isolated_user_config: Path, tmp_path: Path
):
    """Someone who typed a path meant that path; quietly using different
    settings could start a twin under a configuration they did not intend."""
    _write_user_config(isolated_user_config, "max_payload_bytes: 4096\n")

    with pytest.raises(ConfigError, match="not found"):
        load_global_config(tmp_path / "typo.yaml")


def test_invalid_user_config_is_rejected_with_the_offending_field(isolated_user_config: Path):
    _write_user_config(isolated_user_config, "max_payload_bytes: -5\n")
    with pytest.raises(ConfigError, match="max_payload_bytes"):
        load_global_config()


def test_malformed_user_config_is_rejected(isolated_user_config: Path):
    _write_user_config(isolated_user_config, "exposure_scope: [unclosed\n")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_global_config()


def test_empty_user_config_is_accepted_as_no_overrides(isolated_user_config: Path):
    _write_user_config(isolated_user_config, "")
    assert load_global_config().exposure_scope is ExposureScope.LOCAL
