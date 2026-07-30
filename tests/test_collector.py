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
