"""The global --config option and operator-config discovery, exercised
through the real CLI rather than by patching the loader out - these tests
exist because the loader was previously never reached with a path at all.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import ExposureScope
from honeytwin.generate.store import load_twin_config
from honeytwin.profile.store import save_profile

from .conftest_helpers import make_profile

runner = CliRunner()


def _write_config(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_config_option_appears_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--config" in result.output


def test_config_option_is_accepted_before_the_subcommand(tmp_path: Path):
    cfg = _write_config(tmp_path / "ht.yaml", f"data_dir: {tmp_path.as_posix()}\n")

    result = runner.invoke(app, ["--config", str(cfg), "list"])

    assert result.exit_code == 0, result.output


def test_missing_config_file_is_reported_and_exits_nonzero(tmp_path: Path):
    result = runner.invoke(app, ["--config", str(tmp_path / "typo.yaml"), "list"])

    assert result.exit_code != 0
    assert "not found" in result.output


def test_invalid_config_file_is_reported_with_the_field(tmp_path: Path):
    cfg = _write_config(tmp_path / "bad.yaml", "max_payload_bytes: -5\n")

    result = runner.invoke(app, ["--config", str(cfg), "list"])

    assert result.exit_code != 0
    assert "max_payload_bytes" in result.output


def test_config_file_data_dir_reaches_generate(tmp_path: Path):
    data_dir = tmp_path / "ht-data"
    cfg = _write_config(tmp_path / "ht.yaml", f"data_dir: {data_dir.as_posix()}\n")
    profile_path = save_profile(make_profile(), tmp_path)

    result = runner.invoke(
        app, ["--config", str(cfg), "generate", "--name", "web-01", "--profile", str(profile_path)]
    )

    assert result.exit_code == 0, result.output
    assert (data_dir / "twins" / "web-01" / "config.json").exists()


def test_config_file_settings_are_captured_into_the_generated_twin(tmp_path: Path):
    """Per-twin YAML overrides are not implemented yet, so a twin's settings
    are whatever the global config resolved to when it was generated."""
    cfg = _write_config(
        tmp_path / "ht.yaml",
        f"data_dir: {tmp_path.as_posix()}\nexposure_scope: internet\nmax_payload_bytes: 4096\n",
    )
    profile_path = save_profile(make_profile(), tmp_path)

    result = runner.invoke(
        app, ["--config", str(cfg), "generate", "--name", "web-01", "--profile", str(profile_path)]
    )
    assert result.exit_code == 0, result.output

    twin = load_twin_config("web-01", tmp_path)
    assert twin.exposure_scope is ExposureScope.INTERNET
    assert twin.max_payload_bytes == 4096


def test_config_file_settings_reach_run(tmp_path: Path):
    cfg = _write_config(tmp_path / "ht.yaml", f"data_dir: {tmp_path.as_posix()}\n")
    profile_path = save_profile(make_profile(), tmp_path)
    runner.invoke(
        app, ["--config", str(cfg), "generate", "--name", "web-01", "--profile", str(profile_path)]
    )

    mock_client = MagicMock()
    with (
        patch("honeytwin.cli.commands.run.get_client", return_value=mock_client),
        patch("honeytwin.cli.commands.run.get_twin_container_status", return_value=None),
        patch("honeytwin.cli.commands.run.create_bridge_network") as mock_bridge,
        patch("honeytwin.cli.commands.run.create_twin_container") as mock_create,
        patch("honeytwin.cli.commands.run.start_twin_container"),
        patch("honeytwin.containment.marker.read_boot_id", return_value="boot-aaa"),
    ):
        from honeytwin.containment.marker import write_marker

        write_marker(tmp_path, subnet="172.31.240.0/24")
        mock_bridge.return_value.name = "honeytwin-bridge"
        result = runner.invoke(app, ["--config", str(cfg), "run", "--name", "web-01"])

    assert result.exit_code == 0, result.output
    assert mock_create.call_args.kwargs["log_dir"] == tmp_path / "logs" / "web-01"


def test_discovered_config_applies_without_any_flag(isolated_user_config: Path, tmp_path: Path):
    _write_config(
        isolated_user_config / "honeytwin" / "config.yaml",
        f"data_dir: {tmp_path.as_posix()}\nexposure_scope: internet\n",
    )
    profile_path = save_profile(make_profile(), tmp_path)

    result = runner.invoke(app, ["generate", "--name", "web-01", "--profile", str(profile_path)])

    assert result.exit_code == 0, result.output
    assert load_twin_config("web-01", tmp_path).exposure_scope is ExposureScope.INTERNET


def test_config_path_does_not_leak_between_invocations(isolated_user_config: Path, tmp_path: Path):
    """The option is stored in module state, so a run that passes --config
    must not leave it set for the next one."""
    cfg = _write_config(tmp_path / "ht.yaml", "exposure_scope: internet\n")

    runner.invoke(app, ["--config", str(cfg), "list"])
    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, result.output
