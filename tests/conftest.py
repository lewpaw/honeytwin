"""Shared test fixtures.

The autouse fixture here matters: `load_global_config()` now discovers an
operator config file at `$XDG_CONFIG_HOME/honeytwin/config.yaml`. Without
isolation, a developer who happens to have a real one would see tests fail
in ways that have nothing to do with their change - and worse, tests could
pass on a machine whose config masks a regression. Every test therefore
runs against an empty config directory unless it opts out.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_user_config(tmp_path_factory, monkeypatch) -> Path:
    """Point operator-config discovery at an empty directory."""
    config_home = tmp_path_factory.mktemp("xdg-config")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    return config_home
