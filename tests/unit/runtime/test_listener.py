import asyncio
import base64
import json
import socket
from pathlib import Path
from unittest.mock import patch

from honeytwin.config.schema import DockerNetworkMode, ExposureScope
from honeytwin.generate.schema import TwinConfigFile, TwinPortConfig
from honeytwin.runtime.listener import make_signal_handler, run_listeners


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _config(ports: list[TwinPortConfig], **overrides) -> TwinConfigFile:
    return TwinConfigFile(
        name="test-twin",
        target="127.0.0.1",
        ports=ports,
        docker_network_mode=DockerNetworkMode.BRIDGE,
        exposure_scope=ExposureScope.LOCAL,
        **overrides,
    )


def _read_events(log_dir: Path) -> list[dict]:
    path = log_dir / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_listener_sends_banner_on_connection(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner="SSH-2.0-test")])
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        received = await asyncio.wait_for(reader.read(1024), timeout=2)
        writer.close()
        await writer.wait_closed()

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        assert received == b"SSH-2.0-test"

    asyncio.run(scenario())


def test_listener_holds_connection_open_without_banner(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner=None)])
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
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


def test_one_failed_port_does_not_prevent_others_from_serving(tmp_path: Path):
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
                run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
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


def test_listener_captures_client_payload_and_logs_event(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner=None)])
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello twin")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        events = _read_events(tmp_path)
        assert len(events) == 1
        event = events[0]
        assert event["twin_name"] == "test-twin"
        assert event["destination_port"] == port
        assert event["protocol"] == "tcp"
        assert event["truncated"] is False
        assert base64.b64decode(event["payload_base64"]) == b"hello twin"

    asyncio.run(scenario())


def test_listener_truncates_payload_over_cap(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config(
            [TwinPortConfig(port=port, protocol="tcp", banner=None)], max_payload_bytes=5
        )
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"0123456789")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        events = _read_events(tmp_path)
        assert len(events) == 1
        event = events[0]
        assert event["truncated"] is True
        assert base64.b64decode(event["payload_base64"]) == b"01234"

    asyncio.run(scenario())


def test_listener_payload_under_cap_is_not_truncated(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config(
            [TwinPortConfig(port=port, protocol="tcp", banner=None)], max_payload_bytes=1024
        )
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"short")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        events = _read_events(tmp_path)
        assert events[0]["truncated"] is False
        assert base64.b64decode(events[0]["payload_base64"]) == b"short"

    asyncio.run(scenario())


def test_logging_failure_does_not_prevent_connection_from_completing(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner="still-sent")])
        stop_event = asyncio.Event()

        with patch("honeytwin.runtime.listener.write_event", side_effect=OSError("disk full")):
            task = asyncio.create_task(
                run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
            )
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            received = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()

            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        assert received == b"still-sent"

    asyncio.run(scenario())


def test_syslog_not_sent_when_disabled(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config(
            [TwinPortConfig(port=port, protocol="tcp", banner="hi")], syslog_enabled=False
        )
        stop_event = asyncio.Event()

        with patch("honeytwin.runtime.listener.send_syslog") as mock_send:
            task = asyncio.create_task(
                run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
            )
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.2)

            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        mock_send.assert_not_called()

    asyncio.run(scenario())


def test_syslog_sent_when_enabled(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config(
            [TwinPortConfig(port=port, protocol="tcp", banner="hi")],
            syslog_enabled=True,
            syslog_host="syslog.example.com",
            syslog_port=514,
        )
        stop_event = asyncio.Event()

        with patch("honeytwin.runtime.listener.send_syslog") as mock_send:
            task = asyncio.create_task(
                run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
            )
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.2)

            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args.kwargs
        assert call_kwargs["host"] == "syslog.example.com"
        assert call_kwargs["port"] == 514

    asyncio.run(scenario())


def test_syslog_failure_does_not_prevent_local_write(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config(
            [TwinPortConfig(port=port, protocol="tcp", banner="hi")],
            syslog_enabled=True,
            syslog_host="syslog.example.com",
        )
        stop_event = asyncio.Event()

        with patch("honeytwin.runtime.listener.send_syslog", side_effect=OSError("unreachable")):
            task = asyncio.create_task(
                run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
            )
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            received = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.2)

            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        assert received == b"hi"
        events = _read_events(tmp_path)
        assert len(events) == 1

    asyncio.run(scenario())


def test_two_connections_from_same_source_produce_one_attacker_record(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner="hi")])
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        attackers_dir = tmp_path / "attackers"
        attacker_files = list(attackers_dir.glob("*.json"))
        assert len(attacker_files) == 1
        record = json.loads(attacker_files[0].read_text(encoding="utf-8"))
        assert record["session_count"] == 2
        assert record["twins_targeted"] == ["test-twin"]

    asyncio.run(scenario())


def test_concurrent_connections_do_not_interleave_log_lines(tmp_path: Path):
    async def scenario():
        port = _free_port()
        config = _config([TwinPortConfig(port=port, protocol="tcp", banner="hi")])
        stop_event = asyncio.Event()
        task = asyncio.create_task(
            run_listeners(config, host="127.0.0.1", stop_event=stop_event, log_dir=tmp_path)
        )
        await asyncio.sleep(0.1)

        async def _one_connection():
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()

        await asyncio.gather(*(_one_connection() for _ in range(5)))
        await asyncio.sleep(0.2)

        stop_event.set()
        await asyncio.wait_for(task, timeout=5)

        events = _read_events(tmp_path)
        assert len(events) == 5
        for event in events:
            assert event["twin_name"] == "test-twin"

    asyncio.run(scenario())
