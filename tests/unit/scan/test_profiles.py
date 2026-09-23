from pathlib import Path

import pytest

from honeytwin.scan.profiles import NmapProfilesError, get_profile_flags, load_nmap_profiles


def test_shipped_profiles_load():
    profiles = load_nmap_profiles()
    assert set(profiles) == {"light", "standard", "deep"}
    assert profiles["light"] == ["-sS", "-T4", "--top-ports", "100", "--stats-every", "5s"]
    assert profiles["standard"] == [
        "-sS",
        "-sV",
        "-T4",
        "--top-ports",
        "1000",
        "--stats-every",
        "5s",
    ]
    assert profiles["deep"] == [
        "-A",
        "-p-",
        "-T4",
        "--script=default,version,banner",
        "--stats-every",
        "5s",
    ]


def test_get_profile_flags_by_name():
    assert get_profile_flags("light") == [
        "-sS",
        "-T4",
        "--top-ports",
        "100",
        "--stats-every",
        "5s",
    ]


def test_get_profile_flags_unknown_name():
    with pytest.raises(NmapProfilesError):
        get_profile_flags("nonexistent")


def test_operator_can_override_profiles_file(tmp_path: Path):
    custom = tmp_path / "custom.yaml"
    custom.write_text("light:\n  - '-sS'\n  - '--top-ports'\n  - '10'\n", encoding="utf-8")
    profiles = load_nmap_profiles(custom)
    assert profiles == {"light": ["-sS", "--top-ports", "10"]}


def test_malformed_profiles_file_rejected(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("light: not-a-list\n", encoding="utf-8")
    with pytest.raises(NmapProfilesError):
        load_nmap_profiles(bad)


def test_shipped_profiles_resolve_through_the_package():
    """Read via importlib.resources rather than by walking __file__ parents,
    so an installed wheel finds them too - `honeytwin scan` used to raise
    NmapProfilesError for anyone who pip-installed the package."""
    from importlib.resources import files

    raw = files("honeytwin.data").joinpath("nmap_profiles.yaml").read_text(encoding="utf-8")
    assert "light:" in raw


def test_unreadable_packaged_profiles_report_a_broken_install(monkeypatch):
    def boom(_package):
        raise ModuleNotFoundError("honeytwin.data")

    monkeypatch.setattr("honeytwin.scan.profiles.files", boom)
    with pytest.raises(NmapProfilesError, match="install is incomplete"):
        load_nmap_profiles()


def test_explicit_profiles_path_still_wins_over_the_packaged_one(tmp_path: Path):
    custom = tmp_path / "mine.yaml"
    custom.write_text("only-mine:\n  - '-sT'\n", encoding="utf-8")

    profiles = load_nmap_profiles(custom)

    assert profiles == {"only-mine": ["-sT"]}


def test_missing_explicit_profiles_path_names_that_path(tmp_path: Path):
    missing = tmp_path / "nope.yaml"
    with pytest.raises(NmapProfilesError, match="nope.yaml"):
        load_nmap_profiles(missing)
