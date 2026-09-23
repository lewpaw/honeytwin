# Logging

Everything a twin sees is recorded. Collecting that is the point of
running one.

```
~/.honeytwin/logs/<twin>/
├── events.jsonl          one line per connection
└── attackers/<ip>.json   per-source summary
```

## Connection events

`events.jsonl` is JSON Lines — one self-contained JSON object per
connection, appended when the connection closes. Grep it, `jq` it, tail
it, ship it.

```json
{"timestamp":"2026-09-23T12:47:28.110406Z","twin_name":"web-01","source_ip":"10.0.0.7","source_port":52732,"destination_port":80,"protocol":"tcp","duration_seconds":0.0018,"payload_base64":"","truncated":false}
```

| Field | Meaning |
|---|---|
| `timestamp` | When the connection closed, UTC, ISO 8601 |
| `twin_name` | Which twin — useful once logs are aggregated |
| `source_ip` | Who connected |
| `source_port` | Their source port |
| `destination_port` | Which of the twin's ports they hit |
| `protocol` | `tcp` |
| `duration_seconds` | How long they stayed connected |
| `payload_base64` | Everything they sent, base64-encoded |
| `truncated` | Whether `max_payload_bytes` cut the payload short |

**Payloads are base64 for a reason.** Attackers send raw binary, invalid
UTF-8, and deliberately malformed input. Base64 keeps every byte intact
and keeps the log file parseable no matter what arrives.

```bash
# what did they actually send?
jq -r 'select(.payload_base64 != "") | .payload_base64' events.jsonl \
  | base64 -d | head -c 400

# busiest sources
jq -r .source_ip events.jsonl | sort | uniq -c | sort -rn | head

# anything that stayed connected a long time
jq 'select(.duration_seconds > 10)' events.jsonl
```

`max_payload_bytes` (default 64 KB) caps what is captured per connection.
Beyond it the payload is cut and `truncated` is `true` — so you can tell a
short payload from a clipped one.

## Attacker records

Alongside the event stream, a rolling summary per source IP:

```json
{
  "source_ip": "10.0.0.7",
  "first_seen": "2026-09-23T12:47:28.110406+00:00",
  "last_seen": "2026-09-23T13:02:11.884219+00:00",
  "session_count": 14,
  "twins_targeted": ["web-01"]
}
```

Answers "have we seen this one before, and how persistent are they"
without re-reading the whole event log.

The filename is the source IP with anything outside `A-Za-z0-9.:_-`
replaced by `_`, so a hostile value cannot escape the directory.

`twins_targeted` is a list because the format anticipates aggregation,
but each twin writes its own file in its own log directory. Correlating
one attacker across several twins means merging those files yourself —
cross-twin correlation is not implemented.

## Syslog forwarding

```yaml
# ~/.config/honeytwin/config.yaml
syslog_enabled: true
syslog_host: 10.0.0.50
syslog_port: 514
syslog_protocol: tcp       # or udp
allow_outbound: true       # required for an off-host collector
```

Messages are RFC 5424, with the event as the message body:

```
<134>1 2026-09-23T12:47:28.110406+00:00 web-01 honeytwin - - - {"timestamp":"...","source_ip":"10.0.0.7",...}
```

`<134>` is facility `local0`, severity `informational`. The framing is
built directly rather than via Python's `SysLogHandler`, which defaults to
the older RFC 3164 format.

Forwarding is **in addition to** the local log, never instead of it.

### Two things to know before enabling it

**It requires `allow_outbound: true`.** Sending to another host is
outbound traffic, which contained twins cannot do. Enabling it weakens
containment and warns on every start. See
[containment](containment.md#remote-syslog-is-incompatible-with-containment).

**A blocked forwarder slows event recording.** The syslog attempt happens
while the event lock is held, with a 5-second socket timeout. If you
enable syslog but the collector is unreachable — including the case where
egress denial blocks it — each event waits out that timeout before the
next is recorded. Fine at low volume, bad under load. This is a known
bug, not a design decision.

## When something fails

Writing the event, forwarding to syslog, and updating the attacker record
are each isolated. A failure in one is logged as a warning and the others
still happen; none of them can stop the twin serving connections.

That is deliberate: a honeypot that stops answering because its log disk
filled is a honeypot that just told the attacker something.

Check the twin's own stderr for these:

```bash
docker logs <twin-name>
```

```
WARNING failed to forward event to syslog
Traceback (most recent call last):
  ...
TimeoutError: timed out
```

## Shipping logs off the host

Since `events.jsonl` is plain JSON Lines on the host, the containment-safe
option is to collect it from **the host**, not from the twin: point
Filebeat, Vector, Promtail, or `rsyslog`'s file input at
`~/.honeytwin/logs/*/events.jsonl`. The twin stays fully contained, and
the shipper runs somewhere that is allowed to talk to your collector.
