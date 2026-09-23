"""`python -m honeytwin.runtime` — the twin container's entrypoint.

Loads a generated twin config from `--config <path>` and runs its
listeners until SIGTERM/SIGINT.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from honeytwin.generate.schema import TwinConfigFile
from honeytwin.runtime.listener import make_signal_handler, run_listeners

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


async def _main(config_path: Path) -> None:
    config = TwinConfigFile.model_validate_json(config_path.read_text(encoding="utf-8"))
    logger.info("starting twin %r with %d listener(s)", config.name, len(config.ports))

    stop_event = asyncio.Event()
    handler = make_signal_handler(stop_event)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, handler)
        except (NotImplementedError, RuntimeError):
            pass  # platform doesn't support this; default signal handling applies

    await run_listeners(config, stop_event=stop_event)
    logger.info("twin %r stopped", config.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a HoneyTwin twin's listeners.")
    parser.add_argument(
        "--config", required=True, type=Path, help="Path to a twin config JSON file."
    )
    args = parser.parse_args()

    if not args.config.exists():
        print(f"honeytwin runtime: config file not found: {args.config}", file=sys.stderr)
        raise SystemExit(1)

    asyncio.run(_main(args.config))


if __name__ == "__main__":
    main()
