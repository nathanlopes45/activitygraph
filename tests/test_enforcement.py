"""Tests for the only part of ActivityGraph that changes the network.

Everything else observes. These rules drop real packets belonging to real
people, so the properties worth pinning are the ones that decide whether a
mistake is an inconvenience or an outage: that it touches only its own
table, that it fails open, and that it cannot lock anyone out of the machine
doing the blocking.
"""
import pytest

from activitygraph.enforcement import (
    TABLE,
    addresses_for_patterns,
    apply_ruleset,
    render_ruleset,
)

DNS = {
    "1.2.3.4": "tiktok.com",
    "1.2.3.5": "www.tiktok.com",
    "1.2.3.6": "v19-web.tiktokcdn.com",
    "5.6.7.8": "instagram.com",
    "9.9.9.9": "github.com",
}

SAMS_PHONE = "AA:BB:CC:00:00:01"
BOBS_LAPTOP = "AA:BB:CC:00:00:02"
ADDRESSES = {SAMS_PHONE: ["192.168.50.50"], BOBS_LAPTOP: ["192.168.50.60"]}


def group(username, patterns, macs):
    return {"user_id": 1, "username": username, "group": f"{username}'s group",
            "patterns": patterns, "device_macs": macs}


# ---------------- which addresses a domain covers ----------------

def test_a_domain_covers_its_subdomains():
    """Blocking tiktok.com has to reach the CDN hosts under it, which is
    where the traffic actually goes."""
    found = addresses_for_patterns(["tiktok.com"], DNS)
    assert "1.2.3.4" in found and "1.2.3.5" in found


def test_a_different_domain_is_not_swept_up():
    """tiktokcdn.com is a separate registrable domain, and matching on
    substring would also catch nottiktok.com."""
    assert "9.9.9.9" not in addresses_for_patterns(["tiktok.com"], DNS)
    assert addresses_for_patterns(["ok.com"], DNS) == []


def test_nothing_resolved_yet_yields_nothing():
    assert addresses_for_patterns(["neverseen.example"], DNS) == []
    assert addresses_for_patterns([], DNS) == []


# ---------------- what gets written ----------------

def test_the_rule_names_only_that_groups_devices():
    """The whole point of per-group blocking: Sam's list must not touch
    Bob's laptop."""
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, DNS)
    assert "192.168.50.50" in script
    assert "192.168.50.60" not in script


def test_it_touches_only_its_own_table():
    """The setup guide's filter and nat tables carry the household's
    connectivity. Nothing here may name them."""
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, DNS)
    for line in script.splitlines():
        assert TABLE in line, f"line outside our table: {line}"
    assert "table ip nat" not in script
    assert "flush ruleset" not in script, "that would wipe the whole machine"


def test_the_table_is_replaced_rather_than_appended():
    """Without this every refresh would stack another copy of every rule."""
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, DNS)
    assert f"delete table inet {TABLE}" in script
    assert script.index("add table") < script.index("delete table"), \
        "deleting a table that does not exist is an error, so it is created first"


def test_only_forwarded_traffic_is_dropped():
    """Traffic to the Pi itself must survive, or a blocked group loses the
    dashboard, DNS and SSH, and with them any way to undo the block."""
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, DNS)
    assert "hook forward" in script
    assert "hook input" not in script
    assert "hook output" not in script


def test_the_chain_runs_before_the_accept_everything_one():
    """The guide's forward chain accepts at priority 0, so a later chain
    would never see the packet."""
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, DNS)
    assert "priority -10" in script


@pytest.mark.parametrize("groups,why", [
    ([], "no groups"),
    ([group("Sam", [], [SAMS_PHONE])], "a group with an empty list"),
    ([group("Sam", ["tiktok.com"], [])], "a list with no devices to apply it to"),
    ([group("Sam", ["neverseen.example"], [SAMS_PHONE])], "nothing resolved yet"),
])
def test_nothing_to_enforce_produces_no_ruleset(groups, why):
    """None means "remove the table", not "apply an empty one": an empty
    ruleset still costs a rule lookup on every forwarded packet."""
    assert render_ruleset(groups, ADDRESSES, DNS) is None, why


def test_two_groups_get_separate_sets():
    script = render_ruleset([
        group("Sam", ["tiktok.com"], [SAMS_PHONE]),
        group("Bob", ["instagram.com"], [BOBS_LAPTOP]),
    ], ADDRESSES, DNS)
    assert "blocked0" in script and "blocked1" in script
    # Bob's rule must not carry Sam's addresses.
    bob_rule = [ln for ln in script.splitlines() if "192.168.50.60" in ln][0]
    assert "@blocked1" in bob_rule


# ---------------- failing open ----------------

def test_a_rejected_ruleset_leaves_nothing_behind():
    """A half-applied blacklist is a network fault, not a partial feature."""
    calls = []

    def runner(script):
        calls.append(script)
        return (False, "syntax error") if "add rule" in script else (True, "ok")

    applied, message = apply_ruleset("add rule inet activitygraph forward drop\n", runner=runner)
    assert applied is False
    assert "syntax error" in message
    assert any(line.startswith("delete table") for line in calls[-1].splitlines()), \
        "the failure path must clear the table"


def test_nothing_to_enforce_clears_the_table():
    calls = []
    apply_ruleset(None, runner=lambda s: calls.append(s) or (True, "ok"))
    assert "delete table" in calls[0]


def test_a_missing_nft_is_not_fatal():
    """A laptop run has no nft and should not crash for the want of it."""
    applied, message = apply_ruleset("add table inet activitygraph\n",
                                     runner=lambda s: (False, "nft is not installed"))
    assert applied is False
    assert "not installed" in message


def test_addresses_are_capped():
    """A runaway list should degrade rather than produce a ruleset that
    takes seconds to load on every refresh."""
    from activitygraph.enforcement import MAX_ADDRESSES_PER_GROUP

    huge = {f"10.0.{i // 256}.{i % 256}": "tiktok.com" for i in range(MAX_ADDRESSES_PER_GROUP + 500)}
    script = render_ruleset([group("Sam", ["tiktok.com"], [SAMS_PHONE])], ADDRESSES, huge)
    assert script.count("10.0.") <= MAX_ADDRESSES_PER_GROUP
