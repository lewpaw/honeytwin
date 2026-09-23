from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import GlobalConfig

runner = CliRunner()


def test_top_level_help_lists_all_subcommands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("scan", "generate", "run", "list", "stop"):
        assert name in result.output


@pytest.mark.parametrize("subcommand", ["scan", "generate", "run", "list", "stop"])
def test_subcommand_help_is_generated_and_nonempty(subcommand):
    result = runner.invoke(app, [subcommand, "--help"])
    assert result.exit_code == 0
    assert result.output.strip() != ""


def test_scan_with_no_target_and_no_import_exits_nonzero():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    assert "provide a target or --import" in result.output


def test_generate_without_required_options_exits_nonzero():
    result = runner.invoke(app, ["generate"])
    assert result.exit_code != 0


def test_run_with_no_generated_twin_config_exits_nonzero(tmp_path: Path):
    settings = GlobalConfig(data_dir=tmp_path)
    with patch("honeytwin.cli.commands.run.load_settings", return_value=settings):
        result = runner.invoke(app, ["run", "--name", "does-not-exist-anywhere"])
    assert result.exit_code != 0
    assert "No generated config found" in result.output


def test_stop_requires_name():
    result = runner.invoke(app, ["stop"])
    assert result.exit_code != 0


def test_list_name_is_optional(tmp_path: Path):
    settings = GlobalConfig(data_dir=tmp_path)
    with patch("honeytwin.cli.commands.list.load_settings", return_value=settings):
        result = runner.invoke(app, ["list"])
    assert result.exit_code == 0


def test_run_and_stop_share_identical_name_flag():
    run_help = runner.invoke(app, ["run", "--help"]).output
    stop_help = runner.invoke(app, ["stop", "--help"]).output
    list_help = runner.invoke(app, ["list", "--help"]).output
    for output in (run_help, stop_help, list_help):
        assert "--name" in output
        assert "-n" in output
