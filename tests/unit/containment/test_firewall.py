import subprocess
from unittest.mock import patch

import pytest

from honeytwin.containment.firewall import (
    FORWARD_CHAIN,
    INPUT_CHAIN,
    FirewallError,
    egress_rules,
    install_rules,
    remove_rules,
    rules_installed,
)

SUBNET = "172.31.240.0/24"


class FakeIptables:
    """Stands in for the host's iptables, tracking rules per chain.

    `-C` exits 1 when a rule is absent, which is iptables' own way of
    saying "no" rather than an error - the code under test depends on
    that distinction, so the fake reproduces it.
    """

    def __init__(self, present: list[tuple[str, tuple[str, ...]]] | None = None):
        self.chains: dict[str, list[tuple[str, ...]]] = {FORWARD_CHAIN: [], INPUT_CHAIN: []}
        for chain, rule in present or []:
            self.chains[chain].append(rule)
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        _, action, chain, *rest = args
        if action == "-C":
            code = 0 if tuple(rest) in self.chains[chain] else 1
            return subprocess.CompletedProcess(args, code, "", "")
        if action == "-I":
            position, *rule = rest
            self.chains[chain].insert(int(position) - 1, tuple(rule))
            return subprocess.CompletedProcess(args, 0, "", "")
        if action == "-D":
            self.chains[chain].remove(tuple(rest))
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected iptables action {action}")


def _patch(fake: FakeIptables):
    return (
        patch("honeytwin.containment.firewall.subprocess.run", fake),
        patch("honeytwin.containment.firewall.shutil.which", return_value="/sbin/iptables"),
    )


def _run_with(fake: FakeIptables, func, *args):
    run_patch, which_patch = _patch(fake)
    with run_patch, which_patch:
        return func(*args)


def test_egress_rules_cover_both_chains_with_accept_before_drop():
    rules = egress_rules(SUBNET)
    assert [chain for chain, _ in rules] == [
        FORWARD_CHAIN,
        FORWARD_CHAIN,
        INPUT_CHAIN,
        INPUT_CHAIN,
    ]
    for chain in (FORWARD_CHAIN, INPUT_CHAIN):
        in_chain = [rule for c, rule in rules if c == chain]
        assert "ESTABLISHED,RELATED" in in_chain[0]
        assert in_chain[1][-1] == "DROP"
    assert all(SUBNET in rule for _, rule in rules)


def test_install_rules_adds_all_four_in_chain_order():
    fake = FakeIptables()
    added = _run_with(fake, install_rules, SUBNET)

    assert len(added) == 4
    expected = egress_rules(SUBNET)
    for chain in (FORWARD_CHAIN, INPUT_CHAIN):
        assert fake.chains[chain] == [tuple(r) for c, r in expected if c == chain]


def test_install_rules_puts_the_established_accept_above_the_drop():
    """Reversed, replies to inbound connections would be dropped too."""
    fake = FakeIptables()
    _run_with(fake, install_rules, SUBNET)

    for chain in (FORWARD_CHAIN, INPUT_CHAIN):
        accept, drop = fake.chains[chain]
        assert "ESTABLISHED,RELATED" in accept
        assert drop[-1] == "DROP"


def test_install_rules_is_idempotent():
    fake = FakeIptables()
    _run_with(fake, install_rules, SUBNET)
    before = {chain: list(rules) for chain, rules in fake.chains.items()}

    added_again = _run_with(fake, install_rules, SUBNET)

    assert added_again == []
    assert fake.chains == before


def test_install_rules_repairs_partial_state_rather_than_appending():
    """Inserting only the missing rule could land a drop above the accept."""
    only_drop = [(chain, tuple(rule)) for chain, rule in egress_rules(SUBNET) if "DROP" in rule]
    fake = FakeIptables(present=only_drop)

    _run_with(fake, install_rules, SUBNET)

    for chain in (FORWARD_CHAIN, INPUT_CHAIN):
        assert len(fake.chains[chain]) == 2
        accept, drop = fake.chains[chain]
        assert "ESTABLISHED,RELATED" in accept
        assert drop[-1] == "DROP"


def test_rules_installed_reports_true_only_when_all_present():
    fake = FakeIptables()
    assert _run_with(fake, rules_installed, SUBNET) is False

    _run_with(fake, install_rules, SUBNET)
    assert _run_with(fake, rules_installed, SUBNET) is True

    fake.chains[INPUT_CHAIN].clear()
    assert _run_with(fake, rules_installed, SUBNET) is False


def test_remove_rules_removes_what_is_there_and_ignores_what_is_not():
    fake = FakeIptables()
    _run_with(fake, install_rules, SUBNET)

    removed = _run_with(fake, remove_rules, SUBNET)
    assert len(removed) == 4
    assert fake.chains[FORWARD_CHAIN] == []
    assert fake.chains[INPUT_CHAIN] == []

    assert _run_with(fake, remove_rules, SUBNET) == []


def test_unreadable_firewall_raises_rather_than_reading_as_absent():
    """Without privilege iptables exits non-zero with a message; reading that
    as "no rules" would let `run` decide containment is missing when it may
    not be - and worse, could mask a misconfiguration."""

    def denied(args, **kwargs):
        return subprocess.CompletedProcess(args, 4, "", "Permission denied")

    with (
        patch("honeytwin.containment.firewall.subprocess.run", denied),
        patch("honeytwin.containment.firewall.shutil.which", return_value="/sbin/iptables"),
        pytest.raises(FirewallError, match="Could not inspect"),
    ):
        rules_installed(SUBNET)


def test_missing_iptables_binary_raises_clearly():
    with (
        patch("honeytwin.containment.firewall.shutil.which", return_value=None),
        pytest.raises(FirewallError, match="was not found"),
    ):
        rules_installed(SUBNET)
