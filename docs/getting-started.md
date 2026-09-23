# Getting started

This walks through installing HoneyTwin and running your first twin, on a
Linux host. It should take about ten minutes.

> Scanning and impersonating a machine you do not own is not yours to do.
> HoneyTwin warns you before every scan; it cannot check on your behalf.

## What you need

- **Linux.** Containment is enforced with Linux firewall rules; there is
  no equivalent on macOS or Windows. The CLI runs elsewhere for
  development, but twins are meant for Linux.
- **Docker**, with your user in the `docker` group so you do not need
  `sudo` to use it. Check with `docker ps`.
- **nmap**, for live scans. Not needed if you only import existing XML.
- **Python 3.11 or newer.**

## Install

HoneyTwin is not published to PyPI yet, so install from the repository:

```bash
git clone https://github.com/lewpaw/honeytwin.git
cd honeytwin
pip install .
```

Check it:

```bash
honeytwin --help
```

Then build the image every twin runs from. This is separate from
installing the CLI — the CLI orchestrates containers, and this is what
goes inside them:

```bash
docker build -t honeytwin-twin:local .
```

## Set up containment (once per host)

A twin is deliberately exposed to hostile traffic. Before running one,
install the firewall rules that stop a twin reaching anything else:

```bash
sudo honeytwin containment-setup
```

```
Egress restriction installed for 172.31.240.0/24:
  DOCKER-USER -s 172.31.240.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  DOCKER-USER -s 172.31.240.0/24 -j DROP
  INPUT -s 172.31.240.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  INPUT -s 172.31.240.0/24 -j DROP
Note: these rules do not survive a reboot unless you persist them
(e.g. iptables-persistent). HoneyTwin detects a reboot and will refuse to
start egress-denied twins until this command is run again.
```

This is the **one** command that needs root. Check it any time:

```bash
honeytwin containment-status
```

Run without `sudo` it reports what was recorded; run with `sudo` it also
reads the live firewall rules, which is the authoritative answer.

If you skip this step, `honeytwin run` refuses to start a twin rather
than starting one whose containment does not hold.

## Scan a target

```bash
sudo honeytwin scan 192.0.2.10 --profile standard
```

`sudo` is needed because the `light` and `standard` profiles use nmap's
`-sS` SYN scan, which requires root. Progress streams as nmap works:

```
WARNING: scanning and impersonating a target requires authorization from
the target's owner. Proceeding is the operator's responsibility.
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
...
Scanned 192.0.2.10; twin profile saved under /home/you/.honeytwin
```

The profile lands at
`~/.honeytwin/profiles/192.0.2.10-20260923T124728Z.json` and records the
open ports, detected services, and captured banners.

Scanning the same target again never overwrites the previous profile — you
get a second file, so you can compare and spot drift.

**No nmap, or already have a scan?** Import it instead, no root needed:

```bash
honeytwin scan --import /path/to/scan.xml
```

## Generate the twin

```bash
honeytwin generate --name web-01 \
  --profile ~/.honeytwin/profiles/192.0.2.10-20260923T124728Z.json
```

```
Generated twin 'web-01' (2 port(s)); config saved to
/home/you/.honeytwin/twins/web-01/config.json
```

Only ports the scan found `open` become listeners — `closed` and
`filtered` ports get nothing, so the twin's port profile matches the
original's. The generated `config.json` is a snapshot: it captures your
settings as they were at generate time.

## Run it

```bash
honeytwin run --name web-01
```

```
Twin 'web-01' started (2 port(s), bridge mode)
```

**Do not use `sudo` here.** A container running as root would defeat its
own containment, so `run` refuses:

```
honeytwin run: refusing to start a twin as root...
```

That `scan` wants root and `run` refuses it is awkward, and deliberate.

## Confirm it works

```bash
honeytwin list
```

```
NAME    STATUS   PORTS  NETWORK  EXPOSURE
web-01  running  22,80  bridge   local
```

Connect to it:

```bash
curl -s --max-time 3 http://<your-lan-ip>:80 | head -c 40
nmap -sV -p 22,80 <your-lan-ip>
```

And watch the log fill:

```bash
tail -f ~/.honeytwin/logs/web-01/events.jsonl
```

```json
{"timestamp":"2026-09-23T12:47:28.110406Z","twin_name":"web-01","source_ip":"10.0.0.7","source_port":52732,"destination_port":80,"protocol":"tcp","duration_seconds":0.0018,"payload_base64":"","truncated":false}
```

### Confirm containment, too

Worth doing once, so you trust it rather than taking this document's word:

```bash
docker exec web-01 id
# uid=1001 gid=1001 groups=1001        ← not root

docker exec web-01 python3 -c "
import socket; s=socket.socket(); s.settimeout(3)
try: s.connect(('1.1.1.1', 80)); print('REACHED - containment failure')
except Exception as e: print('blocked:', type(e).__name__)"
# blocked: TimeoutError
```

## Stop it

```bash
honeytwin stop --name web-01
```

The container is removed; the profile, the generated config, and every
collected log stay on disk. Run the same twin again whenever you like —
no re-scan needed.

## Where things live

```
~/.honeytwin/
├── profiles/      scan results (one JSON per scan, plus the raw nmap XML)
├── twins/<name>/  generated twin configs
├── logs/<name>/   events.jsonl and attackers/<ip>.json
└── containment.json   record of the firewall setup
```

Change the root with `data_dir` in your config file.

## Next

- [Configuration](configuration.md) — settings and where to put them
- [Containment](containment.md) — what the isolation actually covers
- [Logging](logging.md) — event schema and syslog forwarding
- [Troubleshooting](troubleshooting.md) — when HoneyTwin refuses
