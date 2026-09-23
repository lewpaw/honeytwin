from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from honeytwin.cli.main import app
from honeytwin.config.schema import GlobalConfig

runner = CliRunner()

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "fixtures" / "nmap_scan.xml"
FIXTURE_XML = FIXTURE_PATH.read_text(encoding="utf-8")


def test_rescanning_same_target_keeps_prior_profile_and_adds_a_new_one(tmp_path: Path):
    config = GlobalConfig(data_dir=tmp_path)

    with (
        patch("honeytwin.cli.commands.scan.load_global_config", return_value=config),
        patch("honeytwin.cli.commands.scan.run_nmap", return_value=FIXTURE_XML),
    ):
        first = runner.invoke(app, ["scan", "192.0.2.10"])
        assert first.exit_code == 0, first.output
        first_profiles = sorted((tmp_path / "profiles").glob("*.json"))
        assert len(first_profiles) == 1
        first_content = first_profiles[0].read_text(encoding="utf-8")

        # A second scan can legitimately complete within the same
        # second-resolution timestamp; the collision-safe filename helper
        # in profile/store.py must still avoid overwriting the first.
        second = runner.invoke(app, ["scan", "192.0.2.10"])
        assert second.exit_code == 0, second.output

    second_profiles = sorted((tmp_path / "profiles").glob("*.json"))
    second_xmls = sorted((tmp_path / "raw-xml").glob("*.xml"))

    assert len(second_profiles) == 2
    assert len(second_xmls) == 2
    # the first profile file must be untouched
    assert first_profiles[0].read_text(encoding="utf-8") == first_content
