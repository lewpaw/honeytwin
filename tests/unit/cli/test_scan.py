from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import GlobalConfig

runner = CliRunner()

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "fixtures" / "nmap_scan.xml"
FIXTURE_XML = FIXTURE_PATH.read_text(encoding="utf-8")


def _config_for(tmp_path: Path) -> GlobalConfig:
    return GlobalConfig(data_dir=tmp_path)


def test_scan_requires_target_or_import():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    assert "provide a target or --import" in result.output


def test_scan_rejects_both_target_and_import(tmp_path: Path):
    import_file = tmp_path / "existing.xml"
    import_file.write_text(FIXTURE_XML, encoding="utf-8")
    result = runner.invoke(app, ["scan", "192.0.2.10", "--import", str(import_file)])
    assert result.exit_code != 0
    assert "not both" in result.output


def test_scan_live_target_prints_warning_before_nmap(tmp_path: Path):
    with (
        patch(
            "honeytwin.cli.commands.scan.load_settings",
            return_value=_config_for(tmp_path),
        ),
        patch("honeytwin.cli.commands.scan.run_nmap", return_value=FIXTURE_XML) as mock_run_nmap,
    ):
        result = runner.invoke(app, ["scan", "192.0.2.10", "--profile", "light"])

    assert result.exit_code == 0, result.output
    assert "requires authorization" in result.output
    assert result.output.index("requires authorization") < result.output.index("Scanned")
    mock_run_nmap.assert_called_once()

    assert list((tmp_path / "profiles").glob("*.json"))
    assert list((tmp_path / "raw-xml").glob("*.xml"))


def test_scan_forwards_progress_lines_before_final_message(tmp_path: Path):
    def _fake_run_nmap(target, flags, timeout_seconds, on_progress=None):
        if on_progress is not None:
            on_progress("Stats: 0:00:05 elapsed; 0 hosts completed")
            on_progress("Stats: 0:00:10 elapsed; 1 host completed")
        return FIXTURE_XML

    with (
        patch(
            "honeytwin.cli.commands.scan.load_settings",
            return_value=_config_for(tmp_path),
        ),
        patch("honeytwin.cli.commands.scan.run_nmap", side_effect=_fake_run_nmap),
    ):
        result = runner.invoke(app, ["scan", "192.0.2.10", "--profile", "light"])

    assert result.exit_code == 0, result.output
    assert "Stats: 0:00:05 elapsed" in result.output
    assert "Stats: 0:00:10 elapsed" in result.output
    assert result.output.index("Stats: 0:00:05") < result.output.index("Scanned")
    assert result.output.index("Stats: 0:00:10") < result.output.index("Scanned")


def test_scan_import_path_prints_warning_and_skips_nmap(tmp_path: Path):
    import_file = tmp_path / "existing.xml"
    import_file.write_text(FIXTURE_XML, encoding="utf-8")

    with (
        patch(
            "honeytwin.cli.commands.scan.load_settings",
            return_value=_config_for(tmp_path),
        ),
        patch("honeytwin.cli.commands.scan.run_nmap") as mock_run_nmap,
    ):
        result = runner.invoke(app, ["scan", "--import", str(import_file)])

    assert result.exit_code == 0, result.output
    assert "requires authorization" in result.output
    mock_run_nmap.assert_not_called()
    assert list((tmp_path / "profiles").glob("*.json"))


def test_scan_reports_nmap_scan_error(tmp_path: Path):
    from honeytwin.scan.nmap_runner import NmapScanError

    with (
        patch(
            "honeytwin.cli.commands.scan.load_settings",
            return_value=_config_for(tmp_path),
        ),
        patch(
            "honeytwin.cli.commands.scan.run_nmap",
            side_effect=NmapScanError("scan failed"),
        ),
    ):
        result = runner.invoke(app, ["scan", "192.0.2.10"])

    assert result.exit_code != 0
    assert "scan failed" in result.output
