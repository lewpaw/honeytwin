"""Generic per-port TCP listener that replays a twin's captured banners.

One `asyncio.start_server` per configured port. On each connection: write
the port's banner bytes if present, then keep the connection open (no
further protocol logic — banner-fidelity only, per PRD FR9/non-goals).
Each listener's serve loop is wrapped so one port's failure doesn't bring
down the others.

Every connection also produces a structured `ConnectionEvent` (captured
payload, truncated per `max_payload_bytes`, written locally and
optionally forwarded to syslog, then folded into a per-attacker record) —
see the `logging` capability spec. Logging/forwarding failures are caught
independently and never prevent the connection itself from completing
normally (PRD FR16).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.logging.fingerprint import update_attacker_record
from honeytwin.logging.schema import ConnectionEvent
from honeytwin.logging.syslog_forwarder import format_rfc5424, send_syslog
from honeytwin.logging.writer import write_event

logger = logging.getLogger(__name__)


async def _capture_payload(
    reader: asyncio.StreamReader, max_payload_bytes: int
) -> tuple[bytes, bool]:
    """Read from `reader` until it closes, capping retained bytes at
    `max_payload_bytes`. Returns (captured_bytes, truncated)."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        data = await reader.read(4096)
        if not data:
            break
        if total < max_payload_bytes:
            remaining = max_payload_bytes - total
            chunks.append(data[:remaining])
            if len(data) > remaining:
                truncated = True
        else:
            truncated = True
        total += len(data)
    return b"".join(chunks), truncated


async def _record_event(
    event: ConnectionEvent,
    *,
    log_dir: Path,
    log_lock: asyncio.Lock,
    twin_config: TwinConfigFile,
) -> None:
    """Write the event locally, forward to syslog if enabled, and update
    the attacker record — each step independently failure-isolated."""
    async with log_lock:
        try:
            write_event(event, log_dir)
        except Exception:
            logger.warning("failed to write local log event", exc_info=True)

        if twin_config.syslog_enabled and twin_config.syslog_host:
            try:
                message = format_rfc5424(event, hostname=twin_config.name)
                send_syslog(
                    message,
                    host=twin_config.syslog_host,
                    port=twin_config.syslog_port,
                    protocol=twin_config.syslog_protocol.value,
                )
            except Exception:
                logger.warning("failed to forward event to syslog", exc_info=True)

        try:
            update_attacker_record(event.source_ip, twin_config.name, log_dir)
        except Exception:
            logger.warning("failed to update attacker record", exc_info=True)


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    port_config: TwinPortConfig,
    twin_config: TwinConfigFile,
    log_dir: Path,
    log_lock: asyncio.Lock,
) -> None:
    start = time.monotonic()
    peer = writer.get_extra_info("peername")
    source_ip = str(peer[0]) if peer else "unknown"
    source_port = int(peer[1]) if peer else 0

    payload = b""
    truncated = False
    try:
        if port_config.banner is not None:
            writer.write(port_config.banner.encode("utf-8"))
            await writer.drain()
        payload, truncated = await _capture_payload(reader, twin_config.max_payload_bytes)
    except (ConnectionResetError, ConnectionAbortedError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    duration = time.monotonic() - start
    event = ConnectionEvent(
        timestamp=datetime.now(tz=UTC),
        twin_name=twin_config.name,
        source_ip=source_ip,
        source_port=source_port,
        destination_port=port_config.port,
        protocol=port_config.protocol,
        duration_seconds=duration,
        payload_base64=base64.b64encode(payload).decode("ascii"),
        truncated=truncated,
    )
    await _record_event(event, log_dir=log_dir, log_lock=log_lock, twin_config=twin_config)


async def _serve_port(
    port_config: TwinPortConfig,
    host: str,
    twin_config: TwinConfigFile,
    log_dir: Path,
    log_lock: asyncio.Lock,
) -> asyncio.AbstractServer | None:
    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_connection(
            reader,
            writer,
            port_config=port_config,
            twin_config=twin_config,
            log_dir=log_dir,
            log_lock=log_lock,
        )

    try:
        return await asyncio.start_server(_handler, host=host, port=port_config.port)
    except OSError:
        logger.exception("failed to bind listener for port %s", port_config.port)
        return None


async def _serve_forever_safe(server: asyncio.AbstractServer, port: int) -> None:
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("listener for port %s crashed", port)


def make_signal_handler(stop_event: asyncio.Event) -> Callable[[], None]:
    """Build the callback a signal handler invokes to trigger shutdown."""

    def _handler() -> None:
        stop_event.set()

    return _handler


async def run_listeners(
    config: TwinConfigFile,
    *,
    host: str = "0.0.0.0",
    stop_event: asyncio.Event | None = None,
    log_dir: Path,
) -> None:
    """Start one listener per configured port and run until `stop_event` fires."""
    stop_event = stop_event or asyncio.Event()
    log_lock = asyncio.Lock()

    bound: list[tuple[asyncio.AbstractServer, int]] = []
    for port_config in config.ports:
        server = await _serve_port(port_config, host, config, log_dir, log_lock)
        if server is not None:
            bound.append((server, port_config.port))

    servers = [server for server, _ in bound]
    serve_tasks = [asyncio.create_task(_serve_forever_safe(server, port)) for server, port in bound]

    await stop_event.wait()

    for server in servers:
        server.close()
    await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)

    for task in serve_tasks:
        task.cancel()
    await asyncio.gather(*serve_tasks, return_exceptions=True)
