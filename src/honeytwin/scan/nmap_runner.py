"""Runs nmap against a target and returns raw XML output.

Writes XML to a temp file (`-oX <path>`) rather than stdout (`-oX -`),
because a profile's `--stats-every` progress lines are only emitted on
nmap's normal/interactive output channel — and that channel doesn't
exist once `-oX -` claims stdout for XML (verified directly against real
nmap; see design.md). Freeing stdout this way lets the stdout reader
thread forward progress lines live via an optional `on_progress`
callback, while the stderr reader thread accumulates stderr for the
existing non-zero-exit and privilege-error detection logic. Threads (not
`select`) drain the two pipes concurrently because `select` doesn't work
on pipes on Windows, and this project's dev/CI runs on Windows with a
Linux deployment target.

A non-zero exit, a timeout, or a detected privilege error all raise
`NmapScanError` with a clear message rather than surfacing a raw
subprocess failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

_PRIVILEGE_ERROR_MARKERS = (
    "requires root privileges",
    "you requested a scan type which requires root privileges",
    "quitting!",
    "npcap",
)

_THREAD_JOIN_TIMEOUT_SECONDS = 5


class NmapNotFoundError(Exception):
    """Raised when the `nmap` binary is not available on PATH."""


class NmapScanError(Exception):
    """Raised when an nmap invocation fails, times out, or lacks privileges."""


def ensure_nmap_available() -> Path:
    """Verify `nmap` is on PATH and return its resolved path, or raise."""
    resolved = shutil.which("nmap")
    if resolved is None:
        raise NmapNotFoundError(
            "nmap was not found on PATH. Install nmap and ensure it is "
            "reachable before running a scan."
        )
    return Path(resolved)


def _is_privilege_error(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _PRIVILEGE_ERROR_MARKERS)


def _drain_lines(pipe, lines: list[str], on_line: Callable[[str], None] | None) -> None:
    for raw_line in pipe:
        line = raw_line.rstrip("\n")
        lines.append(line)
        if on_line is not None:
            on_line(line)


def run_nmap(
    target: str,
    flags: list[str],
    timeout_seconds: int,
    on_progress: Callable[[str], None] | None = None,
) -> str:
    """Run nmap against `target` with `flags`, returning raw XML output.

    If `on_progress` is given, it is called with each `--stats-every`
    progress line (on stdout) as nmap produces it. `on_progress=None`
    (the default) means no forwarding.

    Raises `NmapNotFoundError` if nmap isn't on PATH, or `NmapScanError` on
    a non-zero exit, a timeout, or a detected privilege error.
    """
    nmap_path = ensure_nmap_available()

    xml_fd, xml_path_str = tempfile.mkstemp(suffix=".xml", prefix="honeytwin-nmap-")
    os.close(xml_fd)
    xml_path = Path(xml_path_str)

    command = [str(nmap_path), *flags, "-oX", str(xml_path), target]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        stdout_thread = threading.Thread(
            target=_drain_lines, args=(process.stdout, stdout_lines, on_progress), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_drain_lines, args=(process.stderr, stderr_lines, None), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            stdout_thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
            stderr_thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
            raise NmapScanError(
                f"nmap scan of {target!r} did not complete within {timeout_seconds}s"
            ) from exc

        stdout_thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
        stderr_thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)

        stderr_text = "\n".join(stderr_lines)

        if returncode != 0:
            if _is_privilege_error(stderr_text):
                raise NmapScanError(
                    f"nmap scan of {target!r} requires elevated privileges "
                    "(root on Linux, Administrator + Npcap on Windows) for the "
                    f"selected scan flags. nmap stderr: {stderr_text.strip()}"
                )
            raise NmapScanError(
                f"nmap scan of {target!r} failed (exit code {returncode}): {stderr_text.strip()}"
            )

        return xml_path.read_text(encoding="utf-8")
    finally:
        xml_path.unlink(missing_ok=True)
