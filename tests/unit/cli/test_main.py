import pytest
from typer.testing import CliRunner

from honeytwin.cli.main import app

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


def test_generate_stub_exits_nonzero_with_message():
    result = runner.invoke(app, ["generate"])
    assert result.exit_code != 0
    assert "not yet implemented" in result.output


def test_run_stub_requires_name_and_exits_nonzero():
    result = runner.invoke(app, ["run", "--name", "web-01"])
    assert result.exit_code != 0
    assert "not yet implemented" in result.output


def test_stop_stub_requires_name_and_exits_nonzero():
    result = runner.invoke(app, ["stop", "--name", "web-01"])
    assert result.exit_code != 0
    assert "not yet implemented" in result.output


def test_list_stub_name_is_optional_and_exits_nonzero():
    result = runner.invoke(app, ["list"])
    assert result.exit_code != 0
    assert "not yet implemented" in result.output


def test_run_and_stop_share_identical_name_flag():
    run_help = runner.invoke(app, ["run", "--help"]).output
    stop_help = runner.invoke(app, ["stop", "--help"]).output
    list_help = runner.invoke(app, ["list", "--help"]).output
    for output in (run_help, stop_help, list_help):
        assert "--name" in output
        assert "-n" in output
