from pathlib import Path

import pytest

from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.generate.store import TwinConfigLoadError, load_twin_config, save_twin_config


def _make_config() -> TwinConfigFile:
    return TwinConfigFile(
        name="web-01",
        target="192.0.2.10",
        ports=[TwinPortConfig(port=22, protocol="tcp", banner="SSH-2.0-OpenSSH_8.9p1")],
        docker_network_mode=DockerNetworkMode.MACVLAN,
        exposure_scope=ExposureScope.LOCAL,
    )


def test_save_then_load_round_trip(tmp_path: Path):
    config = _make_config()
    path = save_twin_config(config, tmp_path)

    assert path.exists()
    assert path.parent.name == "web-01"

    loaded = load_twin_config("web-01", tmp_path)
    assert loaded == config


def test_load_missing_twin_raises_clear_error(tmp_path: Path):
    with pytest.raises(TwinConfigLoadError, match="No generated config found"):
        load_twin_config("does-not-exist", tmp_path)


def test_load_invalid_config_raises(tmp_path: Path):
    directory = tmp_path / "twins" / "bad-twin"
    directory.mkdir(parents=True)
    (directory / "config.json").write_text('{"name": "bad-twin"}', encoding="utf-8")

    with pytest.raises(TwinConfigLoadError, match="failed validation"):
        load_twin_config("bad-twin", tmp_path)
