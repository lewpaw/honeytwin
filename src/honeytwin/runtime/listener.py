"""Generic per-port TCP listener that replays a twin's captured banners.

One `asyncio.start_server` per configured port. On each connection: write
the port's banner bytes if present, then keep the connection open (no
further protocol logic — banner-fidelity only, per PRD FR9/non-goals).
Each listener's serve loop is wrapped so one port's failure doesn't bring
down the others.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig

logger = logging.getLogger(__name__)


async def _handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, banner: str | None
) -> None:
    try:
        if banner is not None:
            writer.write(banner.encode("utf-8"))
            await writer.drain()
        while True:
            data = await reader.read(4096)
            if not data:
                break
    except (ConnectionResetError, ConnectionAbortedError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _serve_port(port_config: TwinPortConfig, host: str) -> asyncio.AbstractServer | None:
    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_connection(reader, writer, port_config.banner)

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
) -> None:
    """Start one listener per configured port and run until `stop_event` fires."""
    stop_event = stop_event or asyncio.Event()

    bound: list[tuple[asyncio.AbstractServer, int]] = []
    for port_config in config.ports:
        server = await _serve_port(port_config, host)
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
