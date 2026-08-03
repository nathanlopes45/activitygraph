"""Tests for splitting the generic "HTTPS / Web Browsing" bucket into services.

Two things put traffic in that bucket: no hostname was ever learned for the
IP, or a hostname was learned but no rule matched it. These cover both, plus
the ordering traps in the rule list, where a broad CDN pattern placed before
a narrower one silently swallows it.
"""
from datetime import datetime, timezone

import pytest

from activitygraph.models import Flow, Packet
from activitygraph.service_detector import ServiceDetector
from activitygraph.service_rules import classify_domain, registrable_domain
from activitygraph.storage import HistoryStore
from activitygraph.taxonomy import TaxonomyRegistry


def match(hostname):
    """Classify the way the detector does: full hostname, then registrable."""
    return classify_domain(hostname) or classify_domain(registrable_domain(hostname))


# ---------------- the CDNs that carry the actual bytes ----------------

@pytest.mark.parametrize("hostname,service", [
    # A YouTube session is one request to youtube.com and then minutes of
    # video from googlevideo.com. Missing this missed the watching time.
    ("rr3---sn-4g5e6nez.googlevideo.com", "YouTube"),
    ("i.ytimg.com", "YouTube"),
    ("occ-0-2851-2852.1.nflxvideo.net", "Netflix"),
    ("audio-ak.spotifycdn.com", "Spotify"),
    ("video-weaver.syd03.hls.ttvnw.net", "Twitch"),
    ("scontent-syd2-1.cdninstagram.com", "Instagram"),
    ("scontent.fmel1-1.fna.fbcdn.net", "Facebook"),
    ("pbs.twimg.com", "X (Twitter)"),
    ("preview.redd.it", "Reddit"),
    ("media.licdn.com", "LinkedIn"),
])
def test_content_delivery_hostnames_resolve_to_their_service(hostname, service):
    result = match(hostname)
    assert result is not None, f"{hostname} fell through to the generic bucket"
    assert result.service == service


def test_instagram_cdn_is_not_swallowed_by_the_facebook_rule():
    """Both are Meta-owned and the patterns are adjacent in the list, so
    ordering decides this one."""
    assert match("scontent-syd2-1.cdninstagram.com").service == "Instagram"
    assert match("scontent.fmel1-1.fna.fbcdn.net").service == "Facebook"


def test_youtube_music_still_outranks_youtube():
    """The pre-existing ordering guarantee, re-checked after inserting new
    rules around it."""
    assert match("music.youtube.com").service == "YouTube Music"
    assert match("www.youtube.com").service == "YouTube"


# ---------------- machine traffic stays out of behavioural categories ----

@pytest.mark.parametrize("hostname", [
    "clients2.googleusercontent.com", "ctldl.windowsupdate.com",
    "www.msftconnecttest.com", "d1234.cloudfront.net",
    "e1234.dscb.akamaiedge.net",
])
def test_background_traffic_is_not_counted_as_a_chosen_activity(hostname):
    result = match(hostname)
    assert result is not None
    assert result.category in ("Infrastructure", "System"), (
        f"{hostname} would be counted as time the user chose to spend")


def test_advertising_is_separated_from_the_site_that_triggered_it():
    assert match("securepubads.g.doubleclick.net").category == "Ads and Tracking"
    assert match("www.google-analytics.com").category == "Ads and Tracking"


# ---------------- every service reaches a subcategory ----------------

def test_every_rule_service_has_a_subcategory_or_falls_to_other():
    """A service named in the rules but missing from the taxonomy shows up
    as "Other", which is a silent way to lose a whole service from the
    breakdown. This asserts the two files agree."""
    from activitygraph.service_rules import DOMAIN_RULES

    taxonomy = TaxonomyRegistry()
    unplaced = {
        (category, service)
        for _, service, category in DOMAIN_RULES
        if taxonomy.subcategory_for(category, service) == "Other"
    }
    # Infrastructure and System are deliberately flat: they are not
    # activities, so they have no meaningful subdivision.
    unplaced = {(c, s) for c, s in unplaced if c not in ("Infrastructure", "System")}
    assert unplaced == set(), f"services with no subcategory: {sorted(unplaced)}"


# ---------------- learned hostnames survive a restart ----------------

def dns_packet(hostname, ip):
    return Packet(
        timestamp=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        src_ip="8.8.8.8", dst_ip="192.168.1.10", proto="UDP", length=80,
        src_port=53, dst_port=51234, dns_query=hostname, dns_answers=[ip],
    )


def quic_flow(ip):
    """A QUIC/HTTP3 flow, which carries no SNI we can read."""
    return Flow(src_ip="192.168.1.10", dst_ip=ip, src_port=54321, dst_port=443,
                proto="UDP", byte_count=90000, packet_count=60,
                start_time=datetime(2026, 8, 3, 12, 1, tzinfo=timezone.utc),
                end_time=datetime(2026, 8, 3, 12, 5, tzinfo=timezone.utc))


def test_quic_flow_is_identified_from_the_dns_answer(tmp_path):
    """QUIC has no readable SNI, so the DNS answer is the only thing
    standing between HTTP/3 traffic and the generic HTTPS bucket."""
    detector = ServiceDetector()
    detector.observe(dns_packet("rr1---sn-abc.googlevideo.com", "142.250.66.238"))
    assert detector.classify(quic_flow("142.250.66.238")).service == "YouTube"


def test_unknown_ip_still_falls_back_to_the_generic_bucket():
    """The fallback must stay: an honest "HTTPS" beats a wrong guess."""
    detector = ServiceDetector()
    assert detector.classify(quic_flow("203.0.113.7")).service == "HTTPS"


def test_learned_hostnames_are_reloaded_after_a_restart(tmp_path):
    """The reported symptom's slow burn: without persistence, every restart
    reclassifies known traffic as generic HTTPS until each device happens
    to repeat a DNS lookup, which client-side caching can delay for hours.
    """
    db = str(tmp_path / "history.db")

    store = HistoryStore(db)
    first = ServiceDetector(name_store=store)
    first.observe(dns_packet("rr1---sn-abc.googlevideo.com", "142.250.66.238"))
    first.flush()
    store.close()

    # A fresh process, with no in-memory cache and no new DNS traffic.
    reopened = HistoryStore(db)
    second = ServiceDetector(name_store=reopened)
    assert second.classify(quic_flow("142.250.66.238")).service == "YouTube"
    reopened.close()


def test_flush_without_a_store_is_a_no_op():
    detector = ServiceDetector()
    detector.observe(dns_packet("example.com", "203.0.113.5"))
    detector.flush()  # must not raise


def test_stale_mappings_are_not_reloaded(tmp_path):
    """Cloud addresses get reassigned, so an old mapping is as likely to
    mislabel a flow as to label it."""
    store = HistoryStore(str(tmp_path / "h.db"))
    store._conn.execute(
        "INSERT INTO dns_names (ip, hostname, last_seen) VALUES (?, ?, ?)",
        ("142.250.66.238", "old.example.com", "2020-01-01T00:00:00+00:00"))
    store._conn.commit()

    assert store.load_dns_names(max_age_days=30) == {}
    assert store.prune_dns_names(max_age_days=30) == 1
    store.close()


def test_only_changed_mappings_are_queued_for_writing(tmp_path):
    """Repeated DNS answers for the same IP are the common case, and
    re-writing them on every tick would put pointless disk traffic on a
    gateway that runs continuously."""
    store = HistoryStore(str(tmp_path / "h.db"))
    detector = ServiceDetector(name_store=store)
    for _ in range(5):
        detector.observe(dns_packet("example.com", "203.0.113.5"))
    assert detector._unsaved == {"203.0.113.5": "example.com"}

    detector.flush()
    detector.observe(dns_packet("example.com", "203.0.113.5"))
    assert detector._unsaved == {}, "an unchanged answer should not be re-queued"
    store.close()
