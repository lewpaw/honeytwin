from pathlib import Path
from unittest.mock import patch

from honeytwin.containment.marker import (
    ContainmentState,
    evaluate,
    read_marker,
    remove_marker,
    write_marker,
)

SUBNET = "172.31.240.0/24"


def _with_boot_id(boot_id: str | None):
    return patch("honeytwin.containment.marker.read_boot_id", return_value=boot_id)


def test_write_then_read_round_trips(tmp_path: Path):
    with _with_boot_id("boot-aaa"):
        written = write_marker(tmp_path, subnet=SUBNET)

    read_back = read_marker(tmp_path)
    assert read_back == written
    assert read_back.subnet == SUBNET
    assert read_back.boot_id == "boot-aaa"
    assert read_back.installed_at.endswith("Z")


def test_evaluate_reports_active_when_boot_id_still_matches(tmp_path: Path):
    with _with_boot_id("boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)
        state, marker = evaluate(tmp_path, subnet=SUBNET)

    assert state is ContainmentState.ACTIVE
    assert marker.subnet == SUBNET


def test_evaluate_reports_stale_after_a_reboot(tmp_path: Path):
    """The rules are gone after a reboot, so a marker that outlived one must
    not be read as containment still holding."""
    with _with_boot_id("boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)
    with _with_boot_id("boot-bbb"):
        state, marker = evaluate(tmp_path, subnet=SUBNET)

    assert state is ContainmentState.STALE
    assert marker.boot_id == "boot-aaa"


def test_evaluate_reports_subnet_mismatch(tmp_path: Path):
    with _with_boot_id("boot-aaa"):
        write_marker(tmp_path, subnet="172.20.0.0/16")
        state, marker = evaluate(tmp_path, subnet=SUBNET)

    assert state is ContainmentState.SUBNET_MISMATCH
    assert marker.subnet == "172.20.0.0/16"


def test_evaluate_reports_missing_when_never_installed(tmp_path: Path):
    state, marker = evaluate(tmp_path, subnet=SUBNET)
    assert state is ContainmentState.MISSING
    assert marker is None


def test_evaluate_reports_missing_after_removal(tmp_path: Path):
    with _with_boot_id("boot-aaa"):
        write_marker(tmp_path, subnet=SUBNET)
    remove_marker(tmp_path)

    state, _ = evaluate(tmp_path, subnet=SUBNET)
    assert state is ContainmentState.MISSING


def test_corrupt_marker_is_treated_as_no_marker(tmp_path: Path):
    """Refusing to start is the safe reading of an unparseable marker."""
    (tmp_path / "containment.json").write_text("{not json", encoding="utf-8")

    assert read_marker(tmp_path) is None
    state, _ = evaluate(tmp_path, subnet=SUBNET)
    assert state is ContainmentState.MISSING


def test_marker_missing_fields_is_treated_as_no_marker(tmp_path: Path):
    (tmp_path / "containment.json").write_text('{"subnet": "x"}', encoding="utf-8")

    assert read_marker(tmp_path) is None


def test_evaluate_stays_active_where_the_host_has_no_boot_id(tmp_path: Path):
    """On a host without a boot id there is nothing to compare, so the marker
    is taken at face value rather than treated as stale on every run."""
    with _with_boot_id(None):
        write_marker(tmp_path, subnet=SUBNET)
        state, _ = evaluate(tmp_path, subnet=SUBNET)

    assert state is ContainmentState.ACTIVE
