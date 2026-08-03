"""Tests for how a device ends up with the name it displays.

The bug these cover: names used to be sticky on first sight, so a phone
that announced a bare model name over DHCP before its personalised mDNS
name kept the model name for the whole capture. Ordering between those two
announcements is arbitrary, so the display name was effectively a race.
"""
from datetime import datetime, timezone

import pytest

from activitygraph.device_id import DeviceRegistry, name_quality
from activitygraph.models import Packet

MAC = "AA:BB:CC:11:22:33"
IP = "192.168.1.50"


def packet(hint=None, source=None, ip=IP, mac=MAC, when=None):
    return Packet(
        timestamp=when or datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        src_ip=ip, dst_ip="1.1.1.1", proto="UDP", length=100,
        src_mac=mac, hostname_hint=hint, hostname_source=source,
    )


# ---------------- generic vs personalised ----------------

@pytest.mark.parametrize("name", ["iPhone", "iphone", "iPad", "Android", "Galaxy",
                                  "MacBook Pro", "iPhone-2", "iPad (3)", "Android_1234",
                                  "raspberrypi", "Smart TV"])
def test_bare_model_names_score_as_generic(name):
    assert name_quality(name, "mdns") < 10


@pytest.mark.parametrize("name", ["Sams iPhone", "Sam's iPhone 17", "Nathan-Katana",
                                  "DESKTOP-4F2A9", "Alices MacBook Pro", "kitchen-ipad"])
def test_personalised_names_score_as_specific(name):
    assert name_quality(name, "dhcp") >= 10


def test_specificity_outranks_source():
    """A personalised DHCP name beats a generic mDNS one. The point of a
    name is telling two devices apart, which a model name cannot do."""
    assert name_quality("Sams iPhone", "dhcp") > name_quality("iPhone", "mdns")


def test_source_breaks_ties_between_equally_specific_names():
    assert name_quality("Sams iPhone", "mdns") > name_quality("Sams iPhone", "dhcp")


def test_empty_name_scores_below_everything():
    assert name_quality("", "mdns") < name_quality("iPhone", "dhcp")
    assert name_quality("   ", "mdns") < 0


# ---------------- the registry keeps the best name ----------------

def test_personalised_mdns_name_replaces_a_generic_dhcp_name():
    """The reported bug, in the order that triggered it."""
    registry = DeviceRegistry()
    registry.observe(packet(hint="iPhone", source="dhcp"))
    assert registry.get(IP).display_name() == "iPhone"

    registry.observe(packet(hint="Sams iPhone 17", source="mdns"))
    assert registry.get(IP).display_name() == "Sams iPhone 17"


def test_generic_name_does_not_replace_a_personalised_one():
    """The same fix must hold in the opposite order, or it just moves the
    race rather than removing it."""
    registry = DeviceRegistry()
    registry.observe(packet(hint="Sams iPhone 17", source="mdns"))
    registry.observe(packet(hint="iPhone", source="dhcp"))
    assert registry.get(IP).display_name() == "Sams iPhone 17"


def test_a_worse_source_does_not_replace_an_equally_specific_name():
    registry = DeviceRegistry()
    registry.observe(packet(hint="Sams-Laptop", source="mdns"))
    registry.observe(packet(hint="SAMS-LAPTOP-OLD", source="dhcp"))
    assert registry.get(IP).display_name() == "Sams-Laptop"


def test_alias_beats_every_observed_name():
    registry = DeviceRegistry(aliases={MAC: "Kitchen iPad"})
    registry.observe(packet(hint="Sams iPhone 17", source="mdns"))
    assert registry.get(IP).display_name() == "Kitchen iPad"


def test_name_quality_follows_the_device_across_an_ip_change():
    """Quality is tracked per MAC, so a DHCP lease moving the device to a
    new address cannot reset it and let a generic name back in."""
    registry = DeviceRegistry()
    registry.observe(packet(hint="Sams iPhone 17", source="mdns"))
    registry.observe(packet(hint="iPhone", source="dhcp", ip="192.168.1.77"))
    assert registry.get("192.168.1.77").display_name() == "Sams iPhone 17"


def test_device_with_no_announced_name_is_not_invented():
    """An unnamed device must fall back to vendor or IP, never to a guess."""
    registry = DeviceRegistry()
    registry.observe(packet())
    assert registry.get(IP).hostname is None


# ---------------- active resolution ----------------

def test_active_resolution_runs_for_a_device_with_only_a_model_name():
    """Previously it only ran when there was no name at all, so a device
    announcing "iPhone" was never asked for a better one."""
    asked = []
    registry = DeviceRegistry(
        active_resolve=True,
        resolver=lambda ip: asked.append(ip) or "Sams-iPhone",
        run_async=lambda fn: fn(),
    )
    registry.observe(packet(hint="iPhone", source="dhcp"))
    assert asked == [IP]
    assert registry.get(IP).display_name() == "Sams-iPhone"


def test_a_late_active_answer_does_not_overwrite_a_better_passive_name():
    """Active resolution runs off-thread and can finish after a passive
    hint has landed. It must lose that race rather than win it."""
    pending = []
    registry = DeviceRegistry(
        active_resolve=True,
        resolver=lambda ip: "router-dhcp-50",
        run_async=pending.append,
    )
    registry.observe(packet())
    registry.observe(packet(hint="Sams iPhone 17", source="mdns"))

    for fn in pending:  # the lookup completes only now
        fn()
    assert registry.get(IP).display_name() == "Sams iPhone 17"
