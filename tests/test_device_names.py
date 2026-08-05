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
NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


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


# ---------------- addresses that are not devices ----------------

def dhcp_discover(hint, mac=MAC):
    """A DHCP DISCOVER. Its source is 0.0.0.0 by definition: the client is
    asking for an address precisely because it does not have one."""
    return Packet(timestamp=NOW, src_ip="0.0.0.0", dst_ip="255.255.255.255",
                  proto="UDP", length=300, src_port=68, dst_port=67, src_mac=mac,
                  hostname_hint=hint, hostname_source="dhcp")


def lease_entry(ip, hint, mac=MAC):
    """How dhcp_leases.ingest_leases registers a device."""
    return Packet(timestamp=NOW, src_ip=ip, dst_ip=ip, proto="ARP", length=0,
                  src_mac=mac, arp_sender_ip=ip, arp_sender_mac=mac,
                  hostname_hint=hint, hostname_source="lease")


def test_a_dhcp_discover_does_not_create_a_device_at_0_0_0_0():
    """The reported bug: one phone appeared twice, once at its real address
    and once at 0.0.0.0. Python's ipaddress calls 0.0.0.0 private, so it
    passed the local-device test and registered as a device of its own."""
    registry = DeviceRegistry()
    registry.observe(dhcp_discover("Pixel-6a"))
    assert registry.get("0.0.0.0") is None
    assert registry.all_devices() == []


def test_the_name_from_a_discover_survives_to_the_real_device():
    """Refusing the address must not throw away the name with it: option 12
    in a DISCOVER is often the best name a phone ever sends."""
    registry = DeviceRegistry()
    registry.observe(dhcp_discover("Pixel-6a"))
    registry.observe(packet(ip="192.168.50.80"))
    assert registry.get("192.168.50.80").display_name() == "Pixel-6a"


@pytest.mark.parametrize("address", ["0.0.0.0", "255.255.255.255", "224.0.0.251", "::"])
def test_placeholder_addresses_never_become_devices(address):
    registry = DeviceRegistry()
    registry.observe(packet(ip=address))
    assert registry.all_devices() == []


def test_an_arp_probe_does_not_create_a_device_either():
    """An ARP probe also announces 0.0.0.0, while a host checks whether the
    address it wants is already taken."""
    registry = DeviceRegistry()
    registry.observe(Packet(timestamp=NOW, src_ip="0.0.0.0", dst_ip="192.168.50.80",
                            proto="ARP", length=0, src_mac=MAC,
                            arp_sender_ip="0.0.0.0", arp_sender_mac=MAC))
    assert registry.all_devices() == []


# ---------------- one device, several addresses ----------------

def test_a_better_name_reaches_every_address_the_device_holds():
    """Entries are keyed by address, so without this the one that received
    the better name shows it while the rest keep their first guess, and the
    dashboard reads as two different devices."""
    registry = DeviceRegistry()
    registry.observe(lease_entry("192.168.50.80", "Android_PC02UL3Q"))
    registry.observe(packet(ip="192.168.50.81", hint="Sams Pixel", source="mdns"))

    assert registry.get("192.168.50.80").display_name() == "Sams Pixel"
    assert registry.get("192.168.50.81").display_name() == "Sams Pixel"


def test_a_live_dhcp_name_beats_a_lease_table_name():
    """The lease file is the same option 12 value read back from a cache,
    so it keeps whatever the device said last time, which can be stale."""
    registry = DeviceRegistry()
    registry.observe(lease_entry("192.168.50.80", "Android_PC02UL3Q"))
    registry.observe(dhcp_discover("Pixel-6a"))
    assert registry.get("192.168.50.80").display_name() == "Pixel-6a"


def test_the_lease_name_is_kept_when_nothing_better_arrives():
    registry = DeviceRegistry()
    registry.observe(lease_entry("192.168.50.80", "Android_PC02UL3Q"))
    assert registry.get("192.168.50.80").display_name() == "Android_PC02UL3Q"


# ---------------- one device, one entry ----------------

# A device holds several addresses at once: an IPv4 lease, an IPv6
# link-local address, sometimes a second IPv4 after a lease change. Keying
# entries on the address listed a single phone two or three times over.

def at(ip, mac=MAC, hint=None, source=None):
    return Packet(timestamp=NOW, src_ip=ip, dst_ip="192.168.50.1", proto="UDP",
                  length=100, src_mac=mac, hostname_hint=hint, hostname_source=source)


def test_a_phone_with_ipv4_and_ipv6_is_one_device():
    """The reported bug: an iPhone and an Android each appeared twice, once
    per address family."""
    registry = DeviceRegistry()
    registry.observe(at("192.168.50.50", hint="iPhone", source="dhcp"))
    registry.observe(at("fe80::1cc9:2fe8:995:5c9"))

    assert len(registry.all_devices()) == 1
    device = registry.all_devices()[0]
    assert set(device.addresses) == {"192.168.50.50", "fe80::1cc9:2fe8:995:5c9"}


def test_the_routable_address_is_the_one_displayed():
    """A link-local address identifies nothing to a person reading it."""
    registry = DeviceRegistry()
    registry.observe(at("fe80::1cc9:2fe8:995:5c9"))
    registry.observe(at("192.168.50.50"))
    assert registry.all_devices()[0].ip == "192.168.50.50"


def test_a_device_is_found_by_any_of_its_addresses():
    """Claiming resolves the caller's source address to a device, and a
    phone may well reach the dashboard over IPv6."""
    registry = DeviceRegistry()
    registry.observe(at("192.168.50.50", hint="iPhone", source="dhcp"))
    registry.observe(at("fe80::1cc9:2fe8:995:5c9"))

    by_v4 = registry.get("192.168.50.50")
    by_v6 = registry.get("fe80::1cc9:2fe8:995:5c9")
    assert by_v4 is by_v6, "both addresses must resolve to the same device"


def test_two_addresses_on_one_nic_do_not_make_two_devices():
    """The gateway answered on its upstream address over the LAN interface,
    so the Pi itself was listed twice."""
    registry = DeviceRegistry()
    registry.observe(at("192.168.1.106", mac="PI:00:00:00:00:01"))
    registry.observe(at("192.168.50.1", mac="PI:00:00:00:00:01"))
    assert len(registry.all_devices()) == 1


def test_different_macs_stay_separate():
    """The collapse must key on identity, not merge everything in sight."""
    registry = DeviceRegistry()
    registry.observe(at("192.168.50.50", mac="AA:BB:CC:00:00:01"))
    registry.observe(at("192.168.50.51", mac="AA:BB:CC:00:00:02"))
    assert len(registry.all_devices()) == 2


def test_a_device_without_a_mac_is_still_tracked_by_address():
    """Lease and router imports can arrive without one."""
    registry = DeviceRegistry()
    registry.observe(Packet(timestamp=NOW, src_ip="192.168.50.99", dst_ip="1.1.1.1",
                            proto="UDP", length=100, src_mac="", hostname_hint=None))
    assert registry.get("192.168.50.99") is None  # no MAC, no source pairing


def test_flows_on_either_address_count_toward_the_same_device():
    """The join between flows and devices is by address, so a device whose
    traffic is split across two of them must not lose half of it."""
    from activitygraph.analytics import rank_devices
    from activitygraph.models import Flow

    registry = DeviceRegistry()
    registry.observe(at("192.168.50.50", hint="iPhone", source="dhcp"))
    registry.observe(at("fe80::1cc9:2fe8:995:5c9"))

    flows = [
        Flow(src_ip="192.168.50.50", dst_ip="1.1.1.1", src_port=1, dst_port=443,
             proto="TCP", byte_count=1000, packet_count=1, start_time=NOW, end_time=NOW),
        Flow(src_ip="fe80::1cc9:2fe8:995:5c9", dst_ip="2001:db8::1", src_port=2, dst_port=443,
             proto="TCP", byte_count=500, packet_count=1, start_time=NOW, end_time=NOW),
    ]
    ranked = rank_devices(flows, registry.all_devices())
    assert len(ranked) == 1
    assert ranked[0]["byte_count"] == 1500, "traffic on the second address was dropped"
