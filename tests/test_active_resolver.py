import socket
from unittest.mock import MagicMock, patch

from scapy.all import DNS, DNSQR, DNSRR
from scapy.layers.netbios import NBNSHeader, NBNSNodeStatusResponse, NBNSNodeStatusResponseService

from activitygraph.active_resolver import _mdns_query, _netbios_query, _reverse_dns, resolve_hostname


def _fake_socket(recv_payload: bytes | None, raises: Exception | None = None) -> MagicMock:
    sock = MagicMock()
    if raises is not None:
        sock.sendto.side_effect = raises
    else:
        sock.recvfrom.return_value = (recv_payload, ("192.168.1.5", 5353))
    return sock


def test_reverse_dns_returns_short_hostname():
    with patch("activitygraph.active_resolver.socket.gethostbyaddr", return_value=("Alice-Laptop.lan", [], ["192.168.1.5"])):
        assert _reverse_dns("192.168.1.5", timeout=1.0) == "Alice-Laptop"


def test_reverse_dns_returns_none_on_failure():
    with patch("activitygraph.active_resolver.socket.gethostbyaddr", side_effect=socket.herror):
        assert _reverse_dns("192.168.1.5", timeout=1.0) is None


def test_mdns_query_parses_ptr_answer():
    arpa = "5.1.168.192.in-addr.arpa."
    response = bytes(DNS(qr=1, qd=DNSQR(qname=arpa, qtype="PTR", qclass="IN"),
                          an=DNSRR(rrname=arpa, type="PTR", rclass="IN", ttl=120, rdata="Kitchen-Speaker.local.")))
    with patch("activitygraph.active_resolver.socket.socket", return_value=_fake_socket(response)):
        assert _mdns_query("192.168.1.5", timeout=1.0) == "Kitchen Speaker"


def test_mdns_query_returns_none_on_timeout():
    with patch("activitygraph.active_resolver.socket.socket", return_value=_fake_socket(None, raises=socket.timeout())):
        assert _mdns_query("192.168.1.5", timeout=1.0) is None


def test_netbios_query_parses_workstation_name():
    header = NBNSHeader(NAME_TRN_ID=1, RESPONSE=1, ANCOUNT=1)
    body = NBNSNodeStatusResponse(
        NUM_NAMES=1,
        NODE_NAME=[NBNSNodeStatusResponseService(NETBIOS_NAME=b"DESKTOP-ABC     ", NAME_FLAGS=4)],
    )
    response = bytes(header / body)
    with patch("activitygraph.active_resolver.socket.socket", return_value=_fake_socket(response)):
        assert _netbios_query("192.168.1.5", timeout=1.0) == "DESKTOP-ABC"


def test_netbios_query_returns_none_when_unreachable():
    with patch("activitygraph.active_resolver.socket.socket", return_value=_fake_socket(None, raises=OSError())):
        assert _netbios_query("192.168.1.5", timeout=1.0) is None


def test_resolve_hostname_falls_through_to_next_method():
    with patch("activitygraph.active_resolver._reverse_dns", return_value=None), \
         patch("activitygraph.active_resolver._mdns_query", return_value="Living Room TV"), \
         patch("activitygraph.active_resolver._netbios_query") as netbios:
        assert resolve_hostname("192.168.1.5") == "Living Room TV"
        netbios.assert_not_called()


def test_resolve_hostname_returns_none_when_nothing_answers():
    with patch("activitygraph.active_resolver._reverse_dns", return_value=None), \
         patch("activitygraph.active_resolver._mdns_query", return_value=None), \
         patch("activitygraph.active_resolver._netbios_query", return_value=None):
        assert resolve_hostname("192.168.1.5") is None


def test_resolve_hostname_swallows_unexpected_errors_from_a_method():
    with patch("activitygraph.active_resolver._reverse_dns", side_effect=RuntimeError("boom")), \
         patch("activitygraph.active_resolver._mdns_query", return_value="Recovered Name"):
        assert resolve_hostname("192.168.1.5") == "Recovered Name"
