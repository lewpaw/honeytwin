# HoneyTwin

**Scan a real service with nmap, then run a honeypot that looks like it.**

HoneyTwin turns an nmap scan into a *twin*: a containerised decoy that
listens on the same ports as the machine it was cloned from and replays
the same service banners, so a scan of the twin looks like a scan of the
original. Every connection it receives is logged as JSON — source, port,
payload, duration — and optionally forwarded to syslog.

It is built for **research and threat intelligence**: standing a
convincing decoy next to a real service and watching what finds it.

> **Scan only what you are authorised to scan.** HoneyTwin impersonates a
> real machine, and cloning a service you do not own is not yours to do.
> The tool warns you; it does not check, and it cannot know.

---

## TL;DR

Linux host with Docker and nmap. Set up once:

```bash
git clone https://github.com/lewpaw/honeytwin.git && cd honeytwin
pip install .                            # HoneyTwin is not on PyPI yet
docker build -t honeytwin-twin:local .   # the image every twin runs from
sudo honeytwin containment-setup         # egress firewall rules, once per host
```

Then, per twin:

```bash
sudo honeytwin scan 192.0.2.10 --profile standard   # sudo: -sS needs root
honeytwin generate --name web-01 \
  --profile ~/.honeytwin/profiles/192.0.2.10-20260923T124728Z.json
honeytwin run --name web-01                          # NOT sudo - it will refuse
```

Your twin is live. Watch it:

```bash
honeytwin list
# NAME    STATUS   PORTS  NETWORK  EXPOSURE
# web-01  running  22,80  bridge   local

tail -f ~/.honeytwin/logs/web-01/events.jsonl
honeytwin stop --name web-01
```

Two things trip people up, both deliberate:

- **`scan` may need `sudo`; `run` must not.** A twin that inherits root
  would defeat its own containment, so `run` refuses to start as root.
- **`containment-setup` is not optional.** Without it, `run` refuses to
  start a twin rather than start one that could reach your real network.

---

## What you actually get

```
$ nmap -sV 192.0.2.10          $ nmap -sV 192.0.2.77     ← the twin
22/tcp open ssh OpenSSH 8.9p1  22/tcp open ssh OpenSSH 8.9p1
80/tcp open http nginx 1.24.0  80/tcp open http nginx 1.24.0
```

A twin is **not** a working service. It completes the TCP handshake,
sends the captured banner, keeps the connection open and records what
arrives. It does not speak SSH, serve pages, or authenticate anyone. That
is the point: it is convincing to a scan and to a first probe, and there
is nothing behind it to exploit.

Under the hood each twin is a Docker container that runs as a non-root
user, holds one Linux capability, has a read-only filesystem, runs under
memory/PID/CPU limits, and **cannot open outbound connections** — not to
the internet, not to your host, not to the machine it was cloned from.
See [docs/containment.md](docs/containment.md) for what that does and
does not cover.

---

## Common scenarios

### 1. Clone a machine on your LAN and watch who knocks

The core loop. Scan the real host, generate a twin from the profile, run
it, read the log.

```bash
sudo honeytwin scan 192.0.2.10 --profile standard
```

`scan` writes a *twin profile* (open ports, services, banners) to
`~/.honeytwin/profiles/<target>-<timestamp>.json`. Three profiles ship:
`light` (top 100 ports), `standard` (top 1000 with version detection),
`deep` (all ports, full scripts — slow). Progress streams while nmap
runs. Re-scanning the same target keeps the old profile and adds a new
one, so you can see drift.

```bash
honeytwin generate --name web-01 \
  --profile ~/.honeytwin/profiles/192.0.2.10-20260923T124728Z.json
honeytwin run --name web-01
```

`generate` turns the profile into a runnable config — only `open` ports
become listeners. `run` creates the container and starts it. Then:

```bash
honeytwin list
# NAME    STATUS   PORTS  NETWORK  EXPOSURE
# web-01  running  22,80  bridge   local

tail -f ~/.honeytwin/logs/web-01/events.jsonl
```

Each connection is one JSON line:

```json
{"timestamp":"2026-09-23T12:47:28Z","twin_name":"web-01","source_ip":"10.0.0.7",
 "source_port":52732,"destination_port":80,"protocol":"tcp",
 "duration_seconds":0.0018,"payload_base64":"","truncated":false}
```

Anything the client sent is captured base64-encoded in `payload_base64`.
Per-attacker summaries accumulate in `~/.honeytwin/logs/web-01/attackers/`.

### 2. Reuse a scan you already have

Already scanned the target, or only have the XML? Skip the scan — and the
`sudo`:

```bash
honeytwin scan --import /path/to/existing-scan.xml
```

Same twin profile, no network traffic, no authorisation question. This is
also the fastest way to try HoneyTwin without pointing nmap at anything.

### 3. Expose a twin to the internet

By default a twin binds to your LAN address only. To make it reachable
from anywhere, set the scope in your config file:

```yaml
# ~/.config/honeytwin/config.yaml
exposure_scope: internet
```

Regenerate the twin and run it. You will get a warning every time it
starts — that is intentional. Containment still holds: an internet-facing
twin still cannot open outbound connections.

### 4. Ship events to a central collector

```yaml
# ~/.config/honeytwin/config.yaml
syslog_enabled: true
syslog_host: 10.0.0.50
syslog_port: 514
syslog_protocol: tcp
allow_outbound: true     # required - see below
```

Events are forwarded as RFC 5424 messages **in addition to** the local
JSON log; if the collector is unreachable the local log is still written.

**The catch:** forwarding to a collector on another host *is* outbound
traffic, so it needs `allow_outbound: true`, which weakens containment
and warns you on every start. If that trade is not acceptable, run the
collector where the twin can already reach it, or ship the JSON log from
the host instead of from the twin.

### 5. Give the twin its own IP on the LAN

Bridge mode publishes ports on the host, so a scan of the twin also sees
the host's own services. Macvlan gives the twin a distinct MAC and IP —
it looks like a separate machine:

```yaml
docker_network_mode: macvlan
macvlan_parent_interface: eth0
macvlan_subnet: 192.168.1.0/24
allow_outbound: true     # required - macvlan cannot be contained
```

**Read that last line carefully.** Macvlan traffic leaves via the parent
interface without passing through the host firewall, so egress denial
cannot be enforced — verified, not assumed. HoneyTwin refuses to start a
macvlan twin unless you explicitly accept that by enabling outbound
access. Higher fidelity, weaker containment; choose knowingly.

---

## Honest limitations

A honeypot whose documentation overstates it is worse than no honeypot.

- **Fidelity is banner-deep.** The twin answers every probe on a port
  with the same bytes, so a protocol-aware scanner can tell. In testing,
  nmap labelled an nginx twin `http-proxy?` rather than `nginx` for
  exactly this reason.
- **Timing is a tell.** The listener never closes connections, so a full
  scan of a twin takes noticeably longer than a scan of the original.
- **Containment does not cover macvlan.** See scenario 5.
- **Firewall rules do not survive a reboot** unless you persist them
  (e.g. `iptables-persistent`). HoneyTwin detects this and refuses to
  start rather than pretending; re-run `containment-setup`.
- **Remote syslog and egress denial are mutually exclusive.** Scenario 4.
- **No seccomp or AppArmor profiles, and no user-namespace remapping.**
  Worthwhile defence in depth, not yet implemented.
- **One twin at a time.** Running several concurrently is not supported
  yet.

---

## Documentation

| Guide | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Install and first twin, end to end |
| [Configuration](docs/configuration.md) | Every setting, where the config file lives |
| [Containment](docs/containment.md) | The threat model, what is enforced, what is not |
| [Logging](docs/logging.md) | Event schema, attacker records, syslog |
| [Troubleshooting](docs/troubleshooting.md) | When HoneyTwin refuses to do something |

## Requirements

- Linux host (containment relies on Linux firewall rules)
- Docker, and a user in the `docker` group
- nmap, for live scans
- Python 3.11+

## Development

```bash
uv sync
uv run pytest -m "not integration"   # unit tests
uv run pytest -m integration         # needs Docker and the twin image built
uv run ruff check . && uv run ruff format --check .
```

## About

HoneyTwin was built as a project for **BruCon 2026 training**.

It is developed spec-first: every feature begins as a written requirement
and ends with verification on a real Linux host, not just mocked tests.
Several of the limitations listed above were found that way — including
the discovery that the original egress mechanism made twins unreachable,
which sent the whole design back a step.

Licensed under the [MIT License](LICENSE).
