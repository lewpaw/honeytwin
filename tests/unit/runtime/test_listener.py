import asyncio
import socket

from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.runtime.listener import make_signal_handler, run_listeners


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _config(ports: list[TwinPortConfig]) -> TwinConfigFile:
    return TwinConfigFile(
        name="test-twin",
        target="127.0.0.1",
        ports=ports,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
    )


def test_listener_sends_banner_on_connection():
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner="SSH-2.0-test")])
        stop_event = asyncio.Event()
        task = asyncio.create_task(run_listeners(config, host="127.0.0.1", stop_event=stop_event))
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        received = await asyncio.wait_for(reader.read(1024), timeout=2)
        writer.close()
        await writer.wait_closed()

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        assert received == b"SSH-2.0-test"

    asyncio.run(scenario())


def test_listener_holds_connection_open_without_banner():
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner=None)])
        stop_event = asyncio.Event()
        task = asyncio.create_task(run_listeners(config, host="127.0.0.1", stop_event=stop_event))
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        received_nothing = False
        try:
            await asyncio.wait_for(reader.read(1024), timeout=0.3)
        except TimeoutError:
            received_nothing = True
        writer.close()
        await writer.wait_closed()

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        assert received_nothing

    asyncio.run(scenario())


def test_one_failed_port_does_not_prevent_others_from_serving():
    async def scenario():
        blocked_port = _free_port()
        working_port = _free_port()

        # Occupy blocked_port so the listener's bind attempt fails with OSError.
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", blocked_port))
        blocker.listen(1)
        try:
            config = _config(
                [
                    TwinPortConfig(port=blocked_port, protocol="tcp", banner="unreachable"),
                    TwinPortConfig(port=working_port, protocol="tcp", banner="still-works"),
                ]
            )
            stop_event = asyncio.Event()
            task = asyncio.create_task(
                run_listeners(config, host="127.0.0.1", stop_event=stop_event)
            )
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.open_connection("127.0.0.1", working_port)
            received = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()

            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

            assert received == b"still-works"
        finally:
            blocker.close()

    asyncio.run(scenario())


def test_signal_handler_sets_stop_event():
    stop_event = asyncio.Event()
    handler = make_signal_handler(stop_event)

    assert not stop_event.is_set()
    handler()
    assert stop_event.is_set()
