# Configuration

## Where the config file goes

Create it yourself at:

```
$XDG_CONFIG_HOME/honeytwin/config.yaml
```

or, if `XDG_CONFIG_HOME` is not set:

```
~/.config/honeytwin/config.yaml
```

Nothing creates it for you, and running without one is perfectly normal —
you get the shipped defaults.

Point at a different file for one invocation with a global `--config`,
which goes **before** the subcommand:

```bash
honeytwin --config /etc/honeytwin/prod.yaml run --name web-01
```

A `--config` path that does not exist is an error, not a fallback — if
you typed a path, you meant that path, and quietly using different
settings could start a twin you did not intend.

## How settings resolve

Lowest to highest:

1. HoneyTwin's built-in defaults
2. the shipped `defaults.yaml` inside the package
3. **your config file** (discovered, or `--config`)
4. per-twin settings

Layers 1 and 2 ship with the tool. Layer 3 is yours; it only needs the
settings you want to change.

**Layer 4 is not a file yet.** Per-twin YAML overrides are not
implemented. Settings are resolved once, when you run `generate`, and
baked into that twin's `~/.honeytwin/twins/<name>/config.json`. To give
one twin different settings, either set them before generating it, or
edit its generated `config.json` and re-run it.

Do not edit the YAML inside the installed package. It gets overwritten on
upgrade, and your config file is the supported way to change anything.

## Example

```yaml
# ~/.config/honeytwin/config.yaml
data_dir: /var/lib/honeytwin
exposure_scope: internet
max_payload_bytes: 131072

syslog_enabled: true
syslog_host: 10.0.0.50
syslog_protocol: tcp
allow_outbound: true      # required for off-host syslog
```

Invalid config is refused before anything runs, naming the field:

```
honeytwin run: Invalid global config (~/.config/honeytwin/config.yaml):
1 validation error for GlobalConfig
max_payload_bytes
  Input should be greater than or equal to 0
```

## Settings

### General

| Setting | Default | What it does |
|---|---|---|
| `data_dir` | `~/.honeytwin` | Root for profiles, twin configs, and logs |
| `scan_timeout_seconds` | `600` | Give up on an nmap scan after this long |

### Exposure and networking

| Setting | Default | What it does |
|---|---|---|
| `exposure_scope` | `local` | `local` binds the twin to your LAN address; `internet` binds `0.0.0.0` and warns at every start |
| `docker_network_mode` | `bridge` | `bridge` publishes ports on the host; `macvlan` gives the twin its own MAC/IP — see below |
| `bridge_subnet` | `172.31.240.0/24` | Subnet for egress-denied twins. The firewall rules name it, so changing it means re-running `containment-setup` |
| `bridge_egress_subnet` | `172.31.241.0/24` | Subnet for twins with `allow_outbound: true`, deliberately not covered by the rules |

`exposure_scope: local` is best-effort: it binds to a discovered LAN
address rather than `0.0.0.0`. Whether your LAN is actually reachable
from outside is a property of your network, which HoneyTwin does not
control.

### macvlan

Only used when `docker_network_mode: macvlan`.

| Setting | Default | What it does |
|---|---|---|
| `macvlan_parent_interface` | none | Host NIC to attach to, e.g. `eth0`. Required |
| `macvlan_subnet` | none | Subnet in CIDR, e.g. `192.168.1.0/24`. Required |
| `macvlan_gateway` | none | Gateway IP, if the default is wrong |

> **Macvlan twins cannot be contained.** Their traffic leaves via the
> parent interface without passing through the host firewall, so egress
> denial has no effect — verified, not assumed. HoneyTwin refuses to start
> a macvlan twin unless you also set `allow_outbound: true`, so the trade
> is explicit. See [containment](containment.md).

### Containment

| Setting | Default | What it does |
|---|---|---|
| `allow_outbound` | `false` | Let the twin open outbound connections. Weakens containment and warns at every start |
| `mem_limit` | `256m` | Container memory limit, Docker format |
| `pids_limit` | `128` | Max processes in the container |
| `cpu_quota` | `50000` | Microseconds per Docker's 100000µs period, so half a CPU |

The defaults are deliberately small — a banner-replay listener needs very
little, and an unbounded default is what makes host denial-of-service
possible. Raise them for unusually busy twins.

### Logging

| Setting | Default | What it does |
|---|---|---|
| `max_payload_bytes` | `65536` | Bytes captured per connection before truncation (the event is flagged `truncated`) |
| `syslog_enabled` | `false` | Forward events to a syslog collector, in addition to the local log |
| `syslog_host` | none | Collector hostname or IP |
| `syslog_port` | `514` | Collector port |
| `syslog_protocol` | `udp` | `udp` or `tcp` |

Forwarding to a collector on another host needs `allow_outbound: true`.
See [logging](logging.md).

## nmap scan profiles

`--profile light|standard|deep` selects a flag set:

| Profile | Flags | Notes |
|---|---|---|
| `light` | `-sS -T4 --top-ports 100` | Fast sweep. Needs root |
| `standard` | `-sS -sV -T4 --top-ports 1000` | Default. Version detection. Needs root |
| `deep` | `-A -p- -T4 --script=default,version,banner` | Everything. Slow |

These are defined in `nmap_profiles.yaml` inside the package. There is no
config-file setting for them yet, and no `--profile-file` flag on the CLI
— the loader supports an alternate path but the CLI does not expose it.
To change the flag sets today, edit the packaged file, and expect an
upgrade to overwrite it.

If you want banners on every port, note that `-sV` alone does not run
nmap's `banner` script; `deep` does, and that is why it captures more.
