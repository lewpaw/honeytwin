"""The host firewall rules that deny a twin outbound network access.

Docker's own `internal` network flag was the original choice and was
rejected by verification: it blocks inbound port publishing too, leaving
the twin unreachable (see design.md). These rules instead leave the
network normally reachable and deny only traffic *originating* in the
twin's subnet.

Two chains are needed. `DOCKER-USER` sits in `FORWARD` and covers the
twin reaching anywhere else; traffic from the twin to the **host itself**
never traverses `FORWARD`, so without the `INPUT` pair a twin could still
reach the host's own services. Each chain takes an ESTABLISHED,RELATED
accept first so replies to inbound connections still flow.
"""

from __future__ import annotations

import shutil
import subprocess

IPTABLES = "iptables"
FORWARD_CHAIN = "DOCKER-USER"
INPUT_CHAIN = "INPUT"

# Matched by the conntrack module; kept as a constant so install, remove,
# and presence checks can never drift apart.
_CTSTATE = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"]


class FirewallError(Exception):
    """Raised when a firewall rule could not be applied or inspected."""


def egress_rules(subnet: str) -> list[tuple[str, list[str]]]:
    """The (chain, rule-spec) pairs that deny `subnet` outbound access,
    in the order they must appear in their chains.

    Within each chain the ESTABLISHED,RELATED accept has to come before
    the drop, or replies to inbound connections get dropped along with
    the twin's own outbound attempts.
    """
    return [
        (FORWARD_CHAIN, ["-s", subnet, *_CTSTATE, "-j", "RETURN"]),
        (FORWARD_CHAIN, ["-s", subnet, "-j", "DROP"]),
        (INPUT_CHAIN, ["-s", subnet, *_CTSTATE, "-j", "ACCEPT"]),
        (INPUT_CHAIN, ["-s", subnet, "-j", "DROP"]),
    ]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    if shutil.which(IPTABLES) is None:
        raise FirewallError(
            f"{IPTABLES} was not found on this host, so the egress restriction "
            f"cannot be managed here."
        )
    return subprocess.run([IPTABLES, *args], capture_output=True, text=True, check=False)


def _rule_present(chain: str, rule: list[str]) -> bool:
    """Whether `rule` is already in `chain`.

    `iptables -C` exits 0 when present and 1 when not, so a non-zero exit
    is an ordinary "no" rather than an error — but anything else (no
    permission to read the table, a missing chain) is not, and is
    reported instead of being read as absence.
    """
    result = _run(["-C", chain, *rule])
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise FirewallError(f"Could not inspect {chain}: {(result.stderr or result.stdout).strip()}")


def rules_installed(subnet: str) -> bool:
    """Whether every egress rule for `subnet` is currently in place.

    Requires privilege to read the firewall tables; raises FirewallError
    if it cannot read them, rather than guessing.
    """
    return all(_rule_present(chain, rule) for chain, rule in egress_rules(subnet))


def install_rules(subnet: str) -> list[str]:
    """Install the egress rules for `subnet`.

    Idempotent: when every rule is already in place this does nothing and
    returns an empty list. Otherwise any partial leftovers are cleared
    first and the full set is reinstalled, because order matters within
    each chain and inserting only the missing rules could land a drop
    above the accept that has to precede it.

    Returns a description of each rule added, so the caller can tell
    "installed" from "already in place".
    """
    if rules_installed(subnet):
        return []

    remove_rules(subnet)

    added: list[str] = []
    # Each insert goes to position 1, so inserting in reverse leaves the
    # chain in the order egress_rules() declares.
    for chain, rule in reversed(egress_rules(subnet)):
        result = _run(["-I", chain, "1", *rule])
        if result.returncode != 0:
            raise FirewallError(
                f"Could not add rule to {chain}: {(result.stderr or result.stdout).strip()}"
            )
        added.append(f"{chain} {' '.join(rule)}")
    added.reverse()
    return added


def remove_rules(subnet: str) -> list[str]:
    """Remove the egress rules for `subnet`, ignoring any already absent."""
    removed: list[str] = []
    for chain, rule in egress_rules(subnet):
        if not _rule_present(chain, rule):
            continue
        result = _run(["-D", chain, *rule])
        if result.returncode != 0:
            raise FirewallError(
                f"Could not remove rule from {chain}: {(result.stderr or result.stdout).strip()}"
            )
        removed.append(f"{chain} {' '.join(rule)}")
    return removed
