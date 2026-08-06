from unittest.mock import MagicMock, patch

from scapy.all import ARP

from activitygraph.collector import TrafficCollector, _guess_local_subnet


def _fake_reply(ip: str, mac: str) -> MagicMock:
    received = MagicMock()
    received.psrc = ip
    received.hwsrc = mac
    return received


def test_guess_local_subnet_derives_24_from_interface_ip():
    with patch("activitygraph.collector.get_if_addr", return_value="192.168.1.102"):
        assert _guess_local_subnet("Wi-Fi") == "192.168.1.0/24"


def test_guess_local_subnet_returns_none_when_lookup_fails():
    with patch("activitygraph.collector.get_if_addr", side_effect=OSError):
        assert _guess_local_subnet("Wi-Fi") is None


def test_guess_local_subnet_returns_none_for_unassigned_interface():
    with patch("activitygraph.collector.get_if_addr", return_value="0.0.0.0"):
        assert _guess_local_subnet("Wi-Fi") is None


def test_arp_sweep_returns_ip_mac_pairs_from_replies():
    answered = [(MagicMock(), _fake_reply("192.168.1.1", "AA:BB:CC:00:00:05")),
                (MagicMock(), _fake_reply("192.168.1.102", "AA:BB:CC:00:00:01"))]
    with patch("activitygraph.collector.srp", return_value=(answered, [])) as mock_srp:
        collector = TrafficCollector(interface="Wi-Fi")
        result = collector.arp_sweep(subnet="192.168.1.0/24", timeout=1.0)
    assert result == [("192.168.1.1", "AA:BB:CC:00:00:05"), ("192.168.1.102", "AA:BB:CC:00:00:01")]
    mock_srp.assert_called_once()
    assert mock_srp.call_args.kwargs["timeout"] == 1.0
    assert mock_srp.call_args.kwargs["iface"] == "Wi-Fi"


def test_arp_sweep_auto_detects_subnet_when_not_given():
    with patch("activitygraph.collector.get_if_addr", return_value="192.168.1.102"), \
         patch("activitygraph.collector.srp", return_value=([], [])) as mock_srp:
        collector = TrafficCollector(interface="Wi-Fi")
        collector.arp_sweep(timeout=1.0)
    sent_packet = mock_srp.call_args.args[0]
    assert sent_packet[ARP].pdst == "192.168.1.0/24"


def test_arp_sweep_returns_empty_list_when_subnet_cannot_be_guessed():
    with patch("activitygraph.collector.get_if_addr", side_effect=OSError), \
         patch("activitygraph.collector.srp") as mock_srp:
        collector = TrafficCollector(interface="Wi-Fi")
        result = collector.arp_sweep(timeout=1.0)
    assert result == []
    mock_srp.assert_not_called()


def test_arp_sweep_and_ingest_emits_synthetic_arp_packets():
    collector = TrafficCollector(interface="Wi-Fi")
    with patch.object(collector, "arp_sweep", return_value=[("192.168.1.50", "AA:BB:CC:DD:EE:FF")]):
        received = []
        count = collector.arp_sweep_and_ingest(on_packet=received.append, subnet="192.168.1.0/24")
    assert count == 1
    assert len(received) == 1
    packet = received[0]
    assert packet.proto == "ARP"
    assert packet.arp_sender_ip == "192.168.1.50"
    assert packet.arp_sender_mac == "AA:BB:CC:DD:EE:FF"


# ---------------- DNS record parsing ----------------

# scapy moved the DNS qd/an/ns/ar sections to PacketListFields. The old
# single-record access still works through a shim that emits a
# DeprecationWarning and silently returns only the first record, so these
# cover the behaviour that shim would have quietly broken.

def _dns_response(question, answers):
    """A DNS response, serialised and re-parsed the way capture sees it.

    Record counts are computed on the wire, so a hand-built packet has them
    unset. Answers must be passed as a list: chaining DNSRR objects with "/"
    builds a payload chain, which serialises as a single answer.
    """
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

    frame = (Ether() / IP(src="192.168.1.1", dst="192.168.1.50")
             / UDP(sport=53, dport=51234)
             / DNS(qr=1, qd=DNSQR(qname=question),
                   an=[DNSRR(**kw) for kw in answers]))
    return Ether(bytes(frame))


def test_every_answer_in_a_multi_record_response_is_captured():
    """Real CDN lookups answer with several records at once. Reading only
    the first would leave most of a service's addresses unattributed, and
    that traffic would fall through to the generic HTTPS bucket."""
    from activitygraph.collector import _packet_to_normalized

    packet = _dns_response("www.youtube.com", [
        dict(rrname="www.youtube.com", type="CNAME", rdata="ytcdn.example"),
        dict(rrname="ytcdn.example", type="A", rdata="142.250.66.238"),
        dict(rrname="ytcdn.example", type="A", rdata="142.250.66.239"),
        dict(rrname="ytcdn.example", type="AAAA", rdata="2404:6800:4006::200e"),
    ])
    parsed = _packet_to_normalized(packet)

    assert parsed.dns_query == "www.youtube.com"
    # The CNAME is deliberately absent: it names a host, not an address, and
    # flows are matched to hostnames by IP.
    assert parsed.dns_answers == ["142.250.66.238", "142.250.66.239",
                                  "2404:6800:4006::200e"]


def test_dns_parsing_emits_no_deprecation_warnings():
    """Pinning this so the old single-record access cannot creep back in.
    It works today only through a shim that is on its way out."""
    import warnings

    from activitygraph.collector import _packet_to_normalized

    packet = _dns_response("example.com", [
        dict(rrname="example.com", type="A", rdata="203.0.113.5"),
    ])
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert _packet_to_normalized(packet).dns_answers == ["203.0.113.5"]


def test_a_response_with_no_answers_is_not_an_error():
    """NXDOMAIN and empty responses are routine, not exceptional."""
    from activitygraph.collector import _packet_to_normalized

    parsed = _packet_to_normalized(_dns_response("nowhere.invalid", []))
    assert parsed.dns_query == "nowhere.invalid"
    assert parsed.dns_answers is None


# ---------------- capture filters ----------------

# The capture filter is the difference between a gateway that forwards at
# line rate and one that does not. Every packet the filter admits is copied
# into Python and dissected by scapy, which costs far more per packet than
# the kernel spends forwarding it. These check the filter admits what the
# tool needs and rejects the payload that makes up the bulk of traffic.

import pytest

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from activitygraph.collector import (
    CAPTURE_MODES,
    FULL_FILTER,
    LIGHT_FILTER,
    validate_bpf_filter,
)

LAN, WAN = "192.168.50.20", "142.250.66.238"


def _frame():
    return Ether(src="aa:bb:cc:11:22:33", dst="11:22:33:44:55:66")


def matches(expression, packet):
    """Run a packet through the real compiled BPF program.

    Compiling proves the syntax; only running it proves the offsets, and the
    TLS handshake clause indexes into the TCP payload by computed offset,
    which is exactly the kind of thing that compiles while matching nothing.
    """
    import ctypes

    from scapy.arch.common import compile_filter

    try:
        from scapy.libs.winpcapy import pcap_offline_filter, pcap_pkthdr
    except ImportError:  # pragma: no cover - platform without libpcap bindings
        pytest.skip("libpcap bindings unavailable")

    program = compile_filter(expression)
    raw = bytes(packet)
    header = pcap_pkthdr()
    header.len = header.caplen = len(raw)
    buffer = ctypes.create_string_buffer(raw, len(raw))
    return pcap_offline_filter(
        ctypes.byref(program), ctypes.byref(header),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))) != 0


@pytest.mark.parametrize("name,packet", [
    ("arp", _frame() / ARP(psrc=LAN, pdst="192.168.50.1")),
    ("dns", _frame() / IP(src=LAN, dst="192.168.50.1") / UDP(sport=5000, dport=53)
     / DNS(qd=DNSQR(qname="youtube.com"))),
    ("mdns", _frame() / IP(src=LAN, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS()),
    ("dhcp", _frame() / IP(src="0.0.0.0", dst="255.255.255.255")
     / UDP(sport=68, dport=67) / Raw(b"x" * 40)),
    ("netbios", _frame() / IP(src=LAN, dst="192.168.50.255")
     / UDP(sport=137, dport=137) / Raw(b"x" * 40)),
    ("tcp syn", _frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=443, flags="S")),
    ("tcp fin", _frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=443, flags="FA")),
    # TLS record type 0x16 is a handshake, which is where the SNI hostname
    # lives. Without this the light filter would identify no services at all.
    ("tls clienthello", _frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=443, flags="PA")
     / Raw(bytes([0x16, 3, 1, 0, 200]) + b"x" * 200)),
    ("quic handshake", _frame() / IP(src=LAN, dst=WAN) / UDP(sport=5000, dport=443)
     / Raw(b"x" * 80)),
])
def test_light_filter_keeps_what_identifies_traffic(name, packet):
    assert matches(LIGHT_FILTER, Ether(bytes(packet))), f"{name} would no longer be seen"


@pytest.mark.parametrize("name,packet", [
    # TLS record type 0x17 is application data: the download itself.
    ("tcp bulk data", _frame() / IP(src=WAN, dst=LAN) / TCP(sport=443, dport=5000, flags="A")
     / Raw(bytes([0x17, 3, 3, 5, 0]) + b"x" * 1440)),
    ("bare ack", _frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=443, flags="A")),
    ("quic bulk", _frame() / IP(src=WAN, dst=LAN) / UDP(sport=443, dport=5000) / Raw(b"x" * 1350)),
])
def test_light_filter_drops_bulk_payload(name, packet):
    """These are the overwhelming majority of packets on a busy link, and
    they carry nothing this tool reports beyond their size."""
    assert not matches(LIGHT_FILTER, Ether(bytes(packet))), f"{name} still reaches Python"


def test_full_filter_keeps_everything_including_bulk():
    """The default stays exact. Only --capture-mode light trades that away."""
    bulk = _frame() / IP(src=WAN, dst=LAN) / TCP(sport=443, dport=5000, flags="A") / Raw(b"x" * 1440)
    assert matches(FULL_FILTER, Ether(bytes(bulk)))


def test_full_filter_covers_ipv6():
    """It read "ip or arp" for a long time, which silently excluded IPv6 and
    made the IPv6 parsing below it unreachable in live capture."""
    from scapy.layers.inet6 import IPv6

    packet = _frame() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=5000, dport=443)
    assert matches(FULL_FILTER, Ether(bytes(packet)))


@pytest.mark.parametrize("mode", sorted(CAPTURE_MODES))
def test_every_preset_compiles(mode):
    assert validate_bpf_filter(CAPTURE_MODES[mode]) is None


def test_a_bad_filter_is_reported_rather_than_raised():
    assert validate_bpf_filter("this is not bpf") is not None


# ---------------- names that are not device names ----------------

# A device broadcasts two very different things: what it is called, and what
# it is looking for. Reading the second as the first named every Windows
# machine on the network "wpad", after the proxy-discovery lookup they all
# make constantly.

def test_a_netbios_lookup_does_not_name_the_device_making_it():
    """The reported bug. A laptop asking "where is WPAD?" was named wpad."""
    from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest

    from activitygraph.collector import _extract_hostname_hint

    query = (Ether() / IP(src="192.168.50.20", dst="192.168.50.255")
             / UDP(sport=137, dport=137)
             / NBNSHeader() / NBNSQueryRequest(QUESTION_NAME="WPAD"))
    assert _extract_hostname_hint(Ether(bytes(query)), "UDP", 137, 137) is None


def test_a_netbios_registration_does_name_the_device():
    """Registrations are a host claiming its own name, which is the one
    NetBIOS message that genuinely identifies the sender."""
    from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

    from activitygraph.collector import _extract_hostname_hint

    registration = (Ether() / IP(src="192.168.50.20", dst="192.168.50.255")
                    / UDP(sport=137, dport=137)
                    / NBNSHeader() / NBNSRegistrationRequest(QUESTION_NAME="NATHAN-LAPTOP"))
    hint = _extract_hostname_hint(Ether(bytes(registration)), "UDP", 137, 137)
    assert hint is not None, "a device registering its own name should be read"
    assert hint[0].strip() == "NATHAN-LAPTOP"
    assert hint[1] == "nbns"


def test_an_mdns_question_does_not_name_the_asker():
    """Same mistake, different protocol: wpad.local lookups are equally
    common, and a question is what the sender wants, not what it is."""
    from scapy.all import DNS, DNSQR

    from activitygraph.collector import _mdns_local_name

    query = DNS(qr=0, qd=DNSQR(qname="wpad.local"))
    assert _mdns_local_name(DNS(bytes(query))) is None


def test_an_mdns_announcement_does_name_the_sender():
    from scapy.all import DNS, DNSRR

    from activitygraph.collector import _mdns_local_name

    announcement = DNS(qr=1, an=[DNSRR(rrname="Sams-iPhone.local", type="A",
                                       rdata="192.168.50.31")])
    assert _mdns_local_name(DNS(bytes(announcement))) == "Sams iPhone"


@pytest.mark.parametrize("name", ["wpad", "WPAD", "isatap", "ISATAP", "WORKGROUP", "localhost"])
def test_protocol_names_are_refused_even_from_a_registration(name):
    """Defence in depth: these name a service or a protocol, never a host,
    whichever message they arrive in."""
    from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

    from activitygraph.collector import _extract_hostname_hint

    packet = (Ether() / IP(src="192.168.50.20", dst="192.168.50.255")
              / UDP(sport=137, dport=137)
              / NBNSHeader() / NBNSRegistrationRequest(QUESTION_NAME=name))
    assert _extract_hostname_hint(Ether(bytes(packet)), "UDP", 137, 137) is None


# ---------------- plaintext HTTP ----------------

# HTTPS is identified by its SNI. Plain HTTP had no equivalent, so every
# unencrypted request fell through to the port rule, even though the
# hostname sits in the clear a few bytes into the request.

@pytest.mark.parametrize("request_bytes,expected", [
    (b"GET /watch?v=x HTTP/1.1\r\nHost: www.youtube.com\r\nAccept: */*\r\n\r\n",
     "www.youtube.com"),
    (b"POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\nfield=1", "example.com"),
    # A port in the Host header is not part of the name.
    (b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", "example.com"),
    # Header names are case-insensitive.
    (b"GET / HTTP/1.1\r\nhost: lower.example\r\n\r\n", "lower.example"),
])
def test_the_host_header_names_the_service(request_bytes, expected):
    from activitygraph.collector import _extract_http_host

    assert _extract_http_host(request_bytes) == expected


@pytest.mark.parametrize("payload", [
    b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",          # no Host header
    b"HTTP/1.1 200 OK\r\nHost: notarequest\r\n\r\n",     # a response, not a request
    b"\x16\x03\x01\x00\x50binary",                        # TLS, not HTTP
    b"",
])
def test_non_requests_yield_no_host(payload):
    from activitygraph.collector import _extract_http_host

    assert _extract_http_host(payload) is None


def test_a_host_header_in_a_body_is_not_read():
    """Only the request headers are parsed. A body could contain anything,
    including something that looks like a header."""
    from activitygraph.collector import _extract_http_host

    payload = (b"POST /f HTTP/1.1\r\nHost: real.example\r\n\r\n"
               b"Host: attacker.example\r\n")
    assert _extract_http_host(payload) == "real.example"


def test_an_http_request_carries_its_hostname_through_the_collector():
    from activitygraph.collector import _packet_to_normalized

    frame = (_frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=80, flags="PA")
             / Raw(b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"))
    assert _packet_to_normalized(Ether(bytes(frame))).tls_sni == "neverssl.com"


@pytest.mark.parametrize("method", [b"GET", b"POST"])
def test_light_mode_still_sees_http_requests(method):
    """Without this the Host header never reaches Python in light mode, and
    plain HTTP would be unidentifiable exactly where it matters most."""
    packet = (_frame() / IP(src=LAN, dst=WAN) / TCP(sport=5000, dport=80, flags="PA")
              / Raw(method + b" / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"))
    assert matches(LIGHT_FILTER, Ether(bytes(packet)))


def test_light_mode_still_drops_the_http_response_body():
    body = (_frame() / IP(src=WAN, dst=LAN) / TCP(sport=80, dport=5000, flags="A")
            / Raw(b"x" * 1400))
    assert not matches(LIGHT_FILTER, Ether(bytes(body)))


# ---------------- the name a phone actually broadcasts ----------------

# iOS sends a generic "iPhone" in its DHCP hostname, so Bonjour is the only
# place the name its owner chose appears. It publishes that name as the
# leading label of each service instance it advertises, and advertises those
# constantly while publishing a plain host record rarely.

def _mdns(*rrnames):
    from scapy.all import DNS, DNSRR

    from activitygraph.collector import _mdns_local_name

    records = [DNSRR(rrname=n, type="TXT", rdata="x") for n in rrnames]
    return _mdns_local_name(DNS(bytes(DNS(qr=1, an=records))))


@pytest.mark.parametrize("rrname", [
    "Nathans-iPhone.local",
    "Nathans iPhone._companion-link._tcp.local",
    "Nathans iPhone._rdlink._tcp.local",
    "Nathans iPhone._airplay._tcp.local",
])
def test_the_owners_name_is_read_from_whichever_record_carries_it(rrname):
    """Discarding every name containing "_tcp" threw away the service
    instances too, which on a phone is often the only form announced."""
    assert _mdns(rrname) == "Nathans iPhone"


@pytest.mark.parametrize("rrname", [
    "_companion-link._tcp.local",
    "_airplay._tcp.local",
    "_raop._udp.local",
])
def test_a_service_that_names_no_device_is_still_refused(rrname):
    """These name the protocol, not whoever speaks it. The leading
    underscore is what tells them apart."""
    assert _mdns(rrname) is None


def test_the_host_record_wins_when_both_are_present():
    """Both carry the name; the host record is the canonical one."""
    assert _mdns("Nathans iPhone._rdlink._tcp.local", "Nathans-iPhone.local") == "Nathans iPhone"
