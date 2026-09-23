import io
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from honeytwin.scan.nmap_runner import (
    NmapNotFoundError,
    NmapScanError,
    ensure_nmap_available,
    run_nmap,
)


class _FakeProcess:
    """Stands in for a subprocess.Popen instance in tests."""

    def __init__(
        self,
        stdout_lines: list[str] | None = None,
        stderr_lines: list[str] | None = None,
        returncode: int = 0,
        timeout_on_first_wait: bool = False,
    ):
        self.stdout = io.StringIO("".join(f"{line}\n" for line in (stdout_lines or [])))
        self.stderr = io.StringIO("".join(f"{line}\n" for line in (stderr_lines or [])))
        self._returncode = returncode
        self._timeout_on_first_wait = timeout_on_first_wait
        self._wait_calls = 0
        self.killed = False

    def wait(self, timeout: float | None = None):
        self._wait_calls += 1
        if self._timeout_on_first_wait and self._wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd="nmap", timeout=timeout)
        return self._returncode

    def kill(self):
        self.killed = True


def _popen_side_effect(
    xml_content: str = "<nmaprun></nmaprun>",
    stdout_lines: list[str] | None = None,
    stderr_lines: list[str] | None = None,
    returncode: int = 0,
    timeout_on_first_wait: bool = False,
):
    """Builds a subprocess.Popen replacement that writes `xml_content` to
    the `-oX <path>` temp file the way real nmap would, before the fake
    process reports completion."""

    def _side_effect(command, **kwargs):
        xml_path = Path(command[command.index("-oX") + 1])
        xml_path.write_text(xml_content, encoding="utf-8")
        return _FakeProcess(
            stdout_lines=stdout_lines,
            stderr_lines=stderr_lines,
            returncode=returncode,
            timeout_on_first_wait=timeout_on_first_wait,
        )

    return _side_effect


def test_ensure_nmap_available_raises_clear_error_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(NmapNotFoundError, match="not found on PATH"):
        ensure_nmap_available()


def test_ensure_nmap_available_returns_path_when_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    path = ensure_nmap_available()
    assert str(path) == "/usr/bin/nmap" or str(path).endswith("nmap")


def test_run_nmap_raises_not_found_when_nmap_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(NmapNotFoundError):
        run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60)


def test_run_nmap_builds_expected_command(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    mock_popen = MagicMock(side_effect=_popen_side_effect())
    monkeypatch.setattr("subprocess.Popen", mock_popen)

    result = run_nmap("192.0.2.10", ["-sS", "-T4"], timeout_seconds=60)

    assert result == "<nmaprun></nmaprun>"
    called_args, called_kwargs = mock_popen.call_args
    command = called_args[0]
    assert command[0] == str(Path("/usr/bin/nmap"))
    assert command[1:3] == ["-sS", "-T4"]
    assert command[3] == "-oX"
    assert command[5] == "192.0.2.10"
    assert called_kwargs["stdout"] == subprocess.PIPE
    assert called_kwargs["stderr"] == subprocess.PIPE
    assert called_kwargs["text"] is True


def test_run_nmap_cleans_up_temp_xml_file(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    captured_path: list[Path] = []

    def _side_effect(command, **kwargs):
        xml_path = Path(command[command.index("-oX") + 1])
        xml_path.write_text("<nmaprun></nmaprun>", encoding="utf-8")
        captured_path.append(xml_path)
        return _FakeProcess(returncode=0)

    monkeypatch.setattr("subprocess.Popen", MagicMock(side_effect=_side_effect))

    run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60)

    assert captured_path
    assert not captured_path[0].exists()


def test_run_nmap_forwards_stdout_progress_lines(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(
        "subprocess.Popen",
        MagicMock(
            side_effect=_popen_side_effect(
                stdout_lines=[
                    "Stats: 0:00:05 elapsed; 0 hosts completed",
                    "Stats: 0:00:10 elapsed; 1 host completed",
                ]
            )
        ),
    )

    received: list[str] = []
    result = run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60, on_progress=received.append)

    assert result == "<nmaprun></nmaprun>"
    assert received == [
        "Stats: 0:00:05 elapsed; 0 hosts completed",
        "Stats: 0:00:10 elapsed; 1 host completed",
    ]


def test_run_nmap_without_on_progress_behaves_as_before(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(
        "subprocess.Popen",
        MagicMock(side_effect=_popen_side_effect(stdout_lines=["some stats line"])),
    )

    result = run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60)

    assert result == "<nmaprun></nmaprun>"


def test_run_nmap_raises_on_timeout(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    fake_process = _FakeProcess(timeout_on_first_wait=True)

    def _side_effect(command, **kwargs):
        return fake_process

    monkeypatch.setattr("subprocess.Popen", MagicMock(side_effect=_side_effect))

    with pytest.raises(NmapScanError, match="did not complete within 60s"):
        run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60)

    assert fake_process.killed is True


def test_run_nmap_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(
        "subprocess.Popen",
        MagicMock(
            side_effect=_popen_side_effect(stderr_lines=["some unrelated failure"], returncode=1)
        ),
    )

    with pytest.raises(NmapScanError, match="failed"):
        run_nmap("192.0.2.10", ["-sS"], timeout_seconds=60)


def test_run_nmap_detects_privilege_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(
        "subprocess.Popen",
        MagicMock(
            side_effect=_popen_side_effect(
                stderr_lines=[
                    "TCP/IP fingerprinting (for OS scan) requires root privileges.",
                    "QUITTING!",
                ],
                returncode=1,
            )
        ),
    )

    with pytest.raises(NmapScanError, match="elevated privileges"):
        run_nmap("192.0.2.10", ["-sS", "-O"], timeout_seconds=60)
