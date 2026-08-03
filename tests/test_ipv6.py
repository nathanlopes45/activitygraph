"""Tests for IPv6 capture and device attribution.

IPv6 traffic used to be dropped outright, so on a dual-stack network real
usage went uncounted. Counting it is the easy half. The hard half is
attribution: IPv4 relies on NAT, where a private source address proves the
sender is local, and a public one proves the frame was forwarded. Neither
holds for IPv6, where every device has a globally routable address that
looks exactly like a server's.
"""
from datetime import datetime, timezone

from activitygraph.device_id import DeviceRegistry
from activitygraph.models import Packet

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
PHONE_MAC = "AA:BB:CC:11:22:33"
ROUTER_MAC = "11:22:33:44:55:66"

PHONE_V6 = "2001:8003:1234:5600:1c2b:3d4e:5f60:7182"
SERVER_V6 = "2404:6800:4006:80e::200e"


def packet(src_ip, mac, hint=None, source=None):
    return Packet(timestamp=NOW, src_ip=src_ip, dst_ip="2001:4860:4860::8888",
                  proto="TCP", length=500, src_mac=mac,
                  hostname_hint=hint, hostname_source=source)


def registry_with_known_router():
    """A registry that has seen enough traffic to tell the two MACs apart.

    The phone is known local from its private IPv4; the router is known to
    forward because a public IPv4 source arrived bearing its MAC.
    """
    registry = DeviceRegistry()
    registry.observe(packet("192.168.1.50", PHONE_MAC))
    registry.observe(packet("192.168.1.1", ROUTER_MAC))
    registry.observe(packet("142.250.66.238", ROUTER_MAC))  # forwarded reply
    return registry


# ---------------- attribution ----------------

def test_local_device_ipv6_address_is_attributed_to_it():
    """A phone's own IPv6 address is public, so the IPv4 rule would reject
    it. The MAC is what identifies it."""
    registry = registry_with_known_router()
    registry.observe(packet(PHONE_V6, PHONE_MAC))
    assert registry.get(PHONE_V6) is not None
    assert registry.get(PHONE_V6).mac == PHONE_MAC


def test_remote_server_ipv6_is_not_registered_as_a_device():
    """The failure this whole mechanism exists to prevent: every server on
    the internet becoming a "device" wearing the router's MAC."""
    registry = registry_with_known_router()
    registry.observe(packet(SERVER_V6, ROUTER_MAC))
    assert registry.get(SERVER_V6) is None


def test_unknown_mac_with_a_public_ipv6_is_not_trusted():
    """Fail closed. A MAC never seen sourcing local traffic is not assumed
    to be a device just because it appeared."""
    registry = DeviceRegistry()
    registry.observe(packet(SERVER_V6, "99:99:99:99:99:99"))
    assert registry.get(SERVER_V6) is None


def test_link_local_and_unique_local_ipv6_are_local_without_any_mac_history():
    """These ranges are unambiguously local, so they need no MAC evidence."""
    registry = DeviceRegistry()
    registry.observe(packet("fe80::1c2b:3d4e:5f60:7182", PHONE_MAC))
    registry.observe(packet("fd00:1234::5", "DD:EE:FF:11:22:33"))
    assert registry.get("fe80::1c2b:3d4e:5f60:7182") is not None
    assert registry.get("fd00:1234::5") is not None


def test_servers_registered_before_the_router_was_known_are_dropped():
    """Ordering hazard: until the first forwarded packet arrives there is
    nothing marking a MAC as a router, so IPv6 seen before that point can
    register servers as devices. Those must not survive."""
    registry = DeviceRegistry()
    registry.observe(packet("192.168.1.1", ROUTER_MAC))   # router looks local
    registry.observe(packet(SERVER_V6, ROUTER_MAC))       # wrongly accepted
    assert registry.get(SERVER_V6) is not None

    registry.observe(packet("142.250.66.238", ROUTER_MAC))  # now it is known
    assert registry.get(SERVER_V6) is None, "stale entry survived"
    assert registry.get("192.168.1.1") is not None, "the router is still a device"


def test_a_devices_ipv4_and_ipv6_names_come_from_the_same_mac():
    registry = registry_with_known_router()
    registry.observe(packet("192.168.1.50", PHONE_MAC, hint="Sams iPhone", source="mdns"))
    registry.observe(packet(PHONE_V6, PHONE_MAC))
    assert registry.get(PHONE_V6).display_name() == "Sams iPhone"


# ---------------- packet parsing ----------------

def test_ipv6_packets_are_parsed_rather_than_dropped():
    from scapy.layers.inet6 import IPv6
    from scapy.all import Ether, TCP

    from activitygraph.collector import _packet_to_normalized

    frame = Ether(src=PHONE_MAC, dst=ROUTER_MAC) / IPv6(src=PHONE_V6, dst=SERVER_V6) / TCP(
        sport=54321, dport=443)
    parsed = _packet_to_normalized(frame)

    assert parsed is not None, "IPv6 packet was dropped"
    assert parsed.proto == "TCP"
    assert parsed.src_ip == PHONE_V6
    assert parsed.dst_port == 443


def test_icmpv6_is_labelled_as_icmp():
    from scapy.all import Ether
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

    from activitygraph.collector import _packet_to_normalized

    frame = Ether(src=PHONE_MAC, dst=ROUTER_MAC) / IPv6(
        src=PHONE_V6, dst=SERVER_V6) / ICMPv6EchoRequest()
    assert _packet_to_normalized(frame).proto == "ICMP"


def test_aaaa_answers_are_cached_so_ipv6_flows_get_a_hostname():
    """Without AAAA parsing every IPv6 flow is hostname-less and collapses
    into the generic HTTPS bucket."""
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

    from activitygraph.collector import _packet_to_normalized

    frame = (Ether(src=ROUTER_MAC, dst=PHONE_MAC) / IP(src="192.168.1.1", dst="192.168.1.50")
             / UDP(sport=53, dport=51234)
             / DNS(qr=1, qd=DNSQR(qname="www.youtube.com", qtype="AAAA"),
                   an=DNSRR(rrname="www.youtube.com", type="AAAA", rdata=SERVER_V6)))
    # Serialise and re-parse: record counts are computed on the wire, and a
    # hand-built packet has them unset. This is also what capture sees.
    parsed = _packet_to_normalized(Ether(bytes(frame)))

    assert parsed.dns_query == "www.youtube.com"
    assert SERVER_V6 in (parsed.dns_answers or [])
