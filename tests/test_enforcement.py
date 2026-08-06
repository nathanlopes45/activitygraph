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


# ---------------- daily limits ----------------

from activitygraph.enforcement import exhausted_services, quota_patterns  # noqa: E402


def test_a_service_under_its_limit_is_left_alone():
    assert exhausted_services({"YouTube": 3600}, {"YouTube": 1800}) == []


def test_a_service_at_its_limit_is_spent():
    """At, not past: an hour means an hour."""
    assert exhausted_services({"YouTube": 3600}, {"YouTube": 3600}) == ["YouTube"]


def test_only_the_service_that_ran_out_is_affected():
    spent = exhausted_services({"YouTube": 3600, "Instagram": 1800},
                               {"YouTube": 3900, "Instagram": 600})
    assert spent == ["YouTube"]


def test_a_service_with_no_recorded_time_is_not_spent():
    assert exhausted_services({"YouTube": 3600}, {}) == []


# The requirement that shapes the whole design: a limit on watching YouTube
# must not break a video embedded in an article, or a map on a shop's
# contact page. Over TLS the hostname is visible but the path is not, so
# youtube.com/watch and youtube.com/embed cannot be told apart. What can be
# told apart is which hosts each uses.

def test_only_the_front_door_is_blocked():
    assert quota_patterns(["YouTube"]) == ["m.youtube.com", "youtube.com"]


@pytest.mark.parametrize("host", [
    "youtube-nocookie.com",   # the embed-only domain
    "googlevideo.com",        # serves embedded players too
    "ytimg.com",
])
def test_the_hosts_that_serve_embedded_players_are_never_blocked(host):
    assert host not in quota_patterns(["YouTube"])


@pytest.mark.parametrize("host", ["maps.googleapis.com", "maps.gstatic.com"])
def test_the_hosts_that_serve_embedded_maps_are_never_blocked(host):
    """A shop's contact page loads a map from the API host. Blocking it
    would break a page nobody meant to restrict."""
    assert host not in quota_patterns(["Google Maps"])
    assert quota_patterns(["Google Maps"]) == ["maps.google.com"]


def test_a_service_with_no_known_front_door_is_never_blocked():
    """Conservative on purpose: failing to enforce a limit is a much
    smaller harm than breaking something unrelated."""
    assert quota_patterns(["Some Internal Tool"]) == []
    assert quota_patterns(["DNS"]) == []


def test_spent_services_become_ordinary_block_patterns():
    """The limit reuses the blacklist machinery rather than a second path
    through the firewall, so there is one place where rules are written."""
    patterns = quota_patterns(exhausted_services({"TikTok": 600}, {"TikTok": 900}))
    script = render_ruleset(
        [{"username": "Sam", "patterns": patterns, "device_macs": [SAMS_PHONE]}],
        ADDRESSES, {"1.2.3.4": "tiktok.com"})
    assert "192.168.50.50" in script and "1.2.3.4" in script


# ---------------- a blacklist means all of it ----------------

# A phone app does not visit a website. The YouTube app fetches video from
# googlevideo.com and never touches youtube.com, so blocking the domain
# somebody typed left the app working and the block looking broken.

APP_DNS = {
    "1.1.1.1": "www.youtube.com",
    "2.2.2.2": "rr3---sn-abc.googlevideo.com",
    "3.3.3.3": "i.ytimg.com",
    "4.4.4.4": "youtubei.googleapis.com",
    "9.9.9.9": "github.com",
}


def test_blocking_a_site_covers_the_hosts_its_app_uses():
    found = addresses_for_patterns(["youtube.com"], APP_DNS, whole_service=True)
    assert "2.2.2.2" in found, "the app streams from googlevideo and would keep working"
    assert "4.4.4.4" in found, "the app's own API"


def test_a_daily_limit_still_spares_the_embed_hosts():
    """The opposite requirement, and why the two cannot share one rule: a
    limit must leave a video embedded in an article playing."""
    narrow = addresses_for_patterns(quota_patterns(["YouTube"]), APP_DNS, whole_service=False)
    assert narrow == ["1.1.1.1"]


def test_blocking_one_service_does_not_reach_another():
    assert "9.9.9.9" not in addresses_for_patterns(["youtube.com"], APP_DNS, whole_service=True)


def test_a_blocked_site_with_no_known_service_still_blocks_itself():
    """Expanding by service must not be the only thing that works, or an
    ordinary site nobody has a rule for would stop being blockable."""
    dns = {"7.7.7.7": "www.example.invalid", "8.8.8.8": "other.invalid"}
    found = addresses_for_patterns(["example.invalid"], dns, whole_service=True)
    assert found == ["7.7.7.7"]


def test_the_two_kinds_are_merged_into_one_rule():
    script = render_ruleset(
        [{"username": "Sam", "patterns": ["youtube.com"],
          "quota_patterns": ["instagram.com"], "device_macs": [SAMS_PHONE]}],
        ADDRESSES, {**APP_DNS, "5.6.7.8": "instagram.com"})
    assert "2.2.2.2" in script   # blacklist, whole service
    assert "5.6.7.8" in script   # spent limit, front door only


def test_a_group_with_only_a_spent_limit_still_gets_a_rule():
    """Its blacklist is empty, which used to skip the group entirely."""
    script = render_ruleset(
        [{"username": "Sam", "patterns": [],
          "quota_patterns": ["tiktok.com"], "device_macs": [SAMS_PHONE]}],
        ADDRESSES, DNS)
    assert script is not None and "1.2.3.4" in script


# ---------------- naming a service, not a domain ----------------

# Somebody who wants YouTube gone should be able to say "YouTube". Knowing
# that the app streams from googlevideo.com is not something to require.

def test_choosing_a_service_blocks_everything_it_uses():
    found = addresses_for_patterns(["service:YouTube"], APP_DNS)
    assert set(found) == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}


def test_choosing_a_service_leaves_other_services_alone():
    assert "9.9.9.9" not in addresses_for_patterns(["service:YouTube"], APP_DNS)


def test_a_plain_domain_still_works_for_anything_unrecognised():
    """Not every site is a service anyone has a rule for."""
    dns = {"7.7.7.7": "www.example.invalid", "8.8.8.8": "elsewhere.invalid"}
    assert addresses_for_patterns(["example.invalid"], dns) == ["7.7.7.7"]


@pytest.mark.parametrize("typed", [
    "YouTube", "youtube", "YOUTUBE", "youtube.com",
    "https://www.youtube.com/watch?v=abc",
])
def test_every_way_of_saying_youtube_means_the_service(typed):
    """Typing the address is the same intent as naming it, so both reach the
    whole service rather than one host."""
    from activitygraph.accounts import normalise_blocked_pattern

    assert normalise_blocked_pattern(typed) == "service:YouTube"


def test_an_unrecognised_site_is_stored_as_the_domain():
    from activitygraph.accounts import normalise_blocked_pattern

    assert normalise_blocked_pattern("https://example.invalid/page") == "example.invalid"
