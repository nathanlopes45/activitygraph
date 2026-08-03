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
