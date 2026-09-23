# Containment

## What we are afraid of

Every other service you run is one you hope nobody attacks. A honeypot is
software you deliberately advertise to attackers, put where they will
find it, and leave running unattended. Attack is not a risk; it is the
design.

So the only question is what happens when someone gets code execution
inside a twin. Without containment they would find:

- **root**, if you had run HoneyTwin with `sudo`
- **`NET_RAW`** and the rest of Docker's default capabilities
- **the whole network** — the internet, your host's other services, your
  internal network, and the real machine the twin was cloned from, whose
  IP is sitting in `config.json` under `"target"`
- **no resource ceiling**, so a fork bomb takes the host down with it

The failure mode is not "the honeypot breaks". It is **the honeypot
becomes the foothold** — and the shortest path from compromised decoy to
compromised production is one TCP connection, to an address you handed
over.

Two further consequences worth naming. A research honeypot that starts
scanning from your IP is traffic attributed to *you*. And if a twin can
reach the network, you can never fully separate "attacker behaviour we
observed" from "our own twin's traffic" — containment is what makes the
data mean anything.

## What is enforced

Every twin, by default:

| Control | How |
|---|---|
| Never runs as root | `run` refuses to start when the operator is root |
| Minimal capabilities | `cap_drop: ALL`, then `NET_BIND_SERVICE` added back |
| No outbound connections | Host firewall rules on the twin's subnet |
| Bounded resources | 256 MB memory, 128 PIDs, half a CPU |
| Read-only filesystem | `read_only`, with only the log directory writable |

### Verified, not assumed

Measured on a real Linux host (Docker 26.1.5), from inside a running
twin:

```
uid=1001 gid=1004 groups=1004
CapBnd: 0000000000000400          ← NET_BIND_SERVICE only; no NET_RAW
Memory=268435456 PidsLimit=128 CpuQuota=50000 ReadonlyRootfs=true

inbound  → published port      : SERVED
egress   → internet 1.1.1.1:80 : blocked
egress   → host <host-ip>:22   : blocked
egress   → subnet gateway      : blocked
egress   → cloned target       : blocked
egress   → DNS                 : blocked

/tmp and / writes              : Read-only file system
events.jsonl                   : still written
```

## How egress denial works

`containment-setup` installs four rules, scoped to the subnet HoneyTwin
gives its contained twins:

```
DOCKER-USER  -s <subnet> -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
DOCKER-USER  -s <subnet> -j DROP
INPUT        -s <subnet> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
INPUT        -s <subnet> -j DROP
```

Both chains are needed. `DOCKER-USER` sits in `FORWARD` and covers the
twin reaching elsewhere — but traffic from the twin to **the host itself**
never traverses `FORWARD`, so without the `INPUT` pair a twin could still
reach your host's own services. The `ESTABLISHED,RELATED` accept comes
first in each chain so replies to inbound connections still flow: the
twin can answer, it just cannot initiate.

### Why not Docker's `internal` network flag?

That was the original design, and verification rejected it. `internal`
blocks traffic in *both* directions: Docker silently declines to publish
ports for a container on an internal network.

```
HostConfig.PortBindings: {"80/tcp":[{"HostIp":"<host-ip>","HostPort":"80"}]}
NetworkSettings.Ports:   {}
$ ss -ltnp | grep ':80 '   →  (nothing listening)
```

Egress was perfectly denied and the twin was unreachable from anywhere
but the Docker host. A honeypot nothing can connect to is not contained;
it is broken.

## What is *not* covered

### Macvlan twins are not contained

Macvlan traffic leaves via the parent interface and does not traverse the
host's netfilter chains, so the rules cannot touch it. Measured with the
rules installed for a macvlan container's subnet while it actively
connected out:

```
num   pkts bytes target  source
1        0     0 RETURN  <macvlan-subnet>  ctstate RELATED,ESTABLISHED
2        0     0 DROP    <macvlan-subnet>
```

Zero packets. Nothing reached netfilter, and no rule tuning changes that.

HoneyTwin therefore **refuses** a macvlan twin that denies outbound, and
requires `allow_outbound: true` so you accept the trade knowingly. This
is why bridge is the default network mode even though macvlan is the
higher-fidelity option.

### Rules do not survive a reboot

They are runtime iptables rules. Persist them yourself
(`iptables-persistent` or equivalent) if you want them back automatically.

HoneyTwin records the host's boot id when you run `containment-setup`, so
after a reboot it knows the rules are gone and refuses to start
egress-denied twins until you re-run it. A record that outlived its rules
would be exactly the silently-false guarantee this design exists to
avoid.

**Residual hole:** flushing iptables *without* rebooting leaves a record
that still reads valid. `sudo honeytwin containment-status` reads the
live rules and is the authoritative check.

### Remote syslog is incompatible with containment

Forwarding to an off-host collector is outbound traffic. Measured:

| | syslog delivered | local events written |
|---|---|---|
| `allow_outbound: false` | 0 bytes | yes |
| `allow_outbound: true` | 295 bytes | yes |

Either enable `allow_outbound` for that twin, or run the collector where
the twin can already reach it, or ship the local JSON log from the host
instead. There is no way to have both.

### Not implemented

- **seccomp and AppArmor profiles** — worthwhile defence in depth, not yet
  written.
- **User-namespace remapping** — a twin's uid is a real uid on the host.
- **Container-escape 0-days in the runtime** — out of scope for any
  application-level control.
- **Anything about the twin's own listener being exploited.** The listener
  does not parse or execute what it receives, which is why the current
  attack surface is small — but that is a property of today's
  banner-replay implementation, not a guarantee.

## Checking it yourself

```bash
sudo honeytwin containment-status      # live firewall rules
docker exec <twin> id                  # non-root?
docker exec <twin> grep CapBnd /proc/self/status
docker inspect -f '{{.HostConfig.CapDrop}} {{.HostConfig.ReadonlyRootfs}}' <twin>
```

And the one that matters most — try to get out:

```bash
docker exec <twin> python3 -c "
import socket; s=socket.socket(); s.settimeout(3)
try: s.connect(('1.1.1.1', 80)); print('REACHED - containment failure')
except Exception as e: print('blocked:', type(e).__name__)"
```

If that prints `REACHED` on a twin you believe is contained, stop the
twin and check `containment-status` before doing anything else.
