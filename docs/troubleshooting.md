# Troubleshooting

Most of what HoneyTwin refuses to do, it refuses on purpose. This page
maps each refusal to what it means and what to do about it.

## Refusals by design

### "refusing to start a twin as root"

```
honeytwin run: refusing to start a twin as root. The container would
inherit uid 0 and run privileged, which defeats containment.
```

You ran `honeytwin run` with `sudo`. The container would inherit uid 0,
so a twin that got compromised would be root.

**Fix:** run it without `sudo`. If that fails with a Docker permission
error, add yourself to the `docker` group (`sudo usermod -aG docker $USER`,
then log out and back in) rather than reaching for `sudo` again.

This is the one that catches people, because `scan` usually *does* need
`sudo` — nmap's `-sS` requires root. Scanning elevated and running
unelevated is correct, not a mistake.

### "the host egress restriction is not installed"

```
honeytwin run: refusing to start twin 'web-01' — the host egress
restriction is not installed for 172.31.240.0/24. Without it the twin
could reach the real target, the host, and the internal network.
Run: sudo honeytwin containment-setup
```

**Fix:** `sudo honeytwin containment-setup`, once per host.

To run an uncontained twin deliberately, set `allow_outbound: true` and
regenerate — you will be warned at every start.

### "the host has rebooted since the egress restriction was installed"

The rules are runtime iptables rules and do not survive a reboot.
HoneyTwin recorded the boot id at setup, sees it no longer matches, and
treats the restriction as gone.

**Fix:** `sudo honeytwin containment-setup` again. To avoid it recurring,
persist the rules (`iptables-persistent` or equivalent).

### "a macvlan twin cannot be denied outbound access"

Macvlan traffic never reaches the host firewall, so the restriction has
no effect on it. See [containment](containment.md#macvlan-twins-are-not-contained).

**Fix, pick one:**
- switch the twin to `docker_network_mode: bridge` and regenerate, or
- set `allow_outbound: true` and accept an uncontained twin

### "the egress restriction was installed for <other subnet>"

You changed `bridge_subnet` after running setup, so the rules protect a
subnet your twins no longer use.

**Fix:** `sudo honeytwin containment-setup` again for the new subnet.

### "Docker network 'honeytwin-bridge' already exists on [...]"

A network with HoneyTwin's name exists on a different subnet — usually
left over from an older version or a hand-created network. A twin on it
would sit outside the firewall rules.

**Fix:** `docker network rm honeytwin-bridge`, then run again.

### "twin 'web-01' is already running"

**Fix:** `honeytwin stop --name web-01` first, or pick another name.

### "twin 'web-01' is not running"

`stop` found no container. It may already be stopped — `honeytwin list`
will tell you.

## Real problems

### `honeytwin: command not found`

Installed into a virtualenv that is not active, or into a user directory
not on `PATH`. Try `python -m honeytwin.cli.main --help`; if that works,
it is a `PATH` problem. `pipx install .` avoids it.

### "Could not read the packaged defaults ... install is incomplete"

The package's own YAML is missing — a broken or partial install.

**Fix:** reinstall (`pip install --force-reinstall .`). If you are working
from a source checkout, make sure `src/honeytwin/data/*.yaml` is present.

### "Config file not found: ..."

You passed `--config` with a path that does not exist. This is an error
rather than a fallback on purpose. Check the spelling; note `--config`
goes **before** the subcommand:

```bash
honeytwin --config /path/to/config.yaml run --name web-01
```

### "Invalid global config (...): 1 validation error"

Your config file has a bad value; the message names the field. Fix it and
re-run — HoneyTwin will not start on a config it cannot fully validate.

### "Docker daemon is not reachable"

Docker is not running, or your user cannot talk to it. `docker ps` will
show the same error. Add yourself to the `docker` group if it is a
permissions issue.

### "nmap was not found on PATH"

Install it (`apt install nmap`, `dnf install nmap`). Or skip scanning
entirely and import an XML file you already have:

```bash
honeytwin scan --import /path/to/scan.xml
```

### The scan needs root but you cannot sudo

`light` and `standard` use `-sS`. Without root, either use `--import`, or
edit the packaged `nmap_profiles.yaml` to use `-sT` (TCP connect), which
works unprivileged and is slower and noisier.

### Nothing in `events.jsonl`

Work down this list:

1. `honeytwin list` — is it actually running?
2. `docker logs <twin>` — did the listener start and bind?
3. Are you connecting to the right address? `local` scope binds a
   discovered LAN address, not `0.0.0.0` or loopback.
4. Events are written when a connection **closes**. A connection you are
   still holding open has not been recorded yet.
5. `docker logs <twin>` again, for write failures — a permissions problem
   on the log directory is logged as a warning and does not stop the twin.

### The twin logs "failed to forward event to syslog"

Expected if `allow_outbound` is `false` — contained twins cannot reach an
off-host collector. The local log is unaffected. See
[logging](logging.md#syslog-forwarding).

Note this also makes event recording slow: each blocked attempt waits out
a 5-second timeout while holding the event lock. If you are not actually
collecting syslog, set `syslog_enabled: false`.

### nmap identifies the twin as `http-proxy?` instead of the real service

Expected. The twin replies with the same bytes to every probe on a port,
so a protocol-aware scanner can tell it is not a real service. Banner
fidelity is what HoneyTwin currently offers; protocol emulation is not
implemented.

Related: a full scan of a twin takes noticeably longer than a scan of the
original, because the listener never closes connections. Both are known
fidelity gaps.

## Getting more detail

```bash
docker logs <twin-name>            # the listener's own stderr
docker inspect <twin-name>         # capabilities, limits, network, mounts
sudo honeytwin containment-status  # live firewall rules
honeytwin list                     # what exists and what is running
```

If something here does not match what you see, please open an issue with
the command you ran, what you expected, and the output.
