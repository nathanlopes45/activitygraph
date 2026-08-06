from unittest.mock import mock_open, patch

from activitygraph.collector import default_route_interface, warn_if_capturing_wan
from activitygraph.dhcp_leases import (
    Lease,
    ingest_leases,
    load_leases,
    parse_dnsmasq_leases,
)

SAMPLE = """\
1785400000 aa:bb:cc:00:00:01 192.168.50.20 Alice-Laptop 01:aa:bb:cc:00:00:01
1785400001 aa:bb:cc:00:00:02 192.168.50.21 iPhone *
1785400002 aa:bb:cc:00:00:03 192.168.50.22 * 01:aa:bb:cc:00:00:03
"""


# ---------------- parsing ----------------

def test_parses_ip_mac_hostname():
    leases = parse_dnsmasq_leases(SAMPLE)
    assert leases[0] == Lease(ip="192.168.50.20", mac="AA:BB:CC:00:00:01", hostname="Alice-Laptop")
    assert leases[1].hostname == "iPhone"


def test_star_hostname_treated_as_unknown():
    """dnsmasq writes '*' when it never learned a name -- that's absent, not
    a device literally called '*'."""
    assert parse_dnsmasq_leases(SAMPLE)[2].hostname is None


def test_macs_are_normalized_uppercase():
    """Grouping and aliases are keyed on uppercase MACs."""
    assert all(lease.mac == lease.mac.upper() for lease in parse_dnsmasq_leases(SAMPLE))


def test_malformed_lines_are_skipped_not_raised():
    """dnsmasq rewrites this file in place, so a half-written line is
    possible and must not take down capture."""
    text = SAMPLE + "garbage\n\n1785400003 not-a-mac 192.168.50.99 Nope\n"
    assert len(parse_dnsmasq_leases(text)) == 3


def test_empty_file_yields_no_leases():
    assert parse_dnsmasq_leases("") == []


def test_lease_without_hostname_field():
    assert parse_dnsmasq_leases("1785400000 aa:bb:cc:dd:ee:ff 192.168.50.30\n") == [
        Lease(ip="192.168.50.30", mac="AA:BB:CC:DD:EE:FF", hostname=None)
    ]


# ---------------- loading ----------------

def test_load_leases_from_explicit_path(tmp_path):
    path = tmp_path / "dnsmasq.leases"
    path.write_text(SAMPLE)
    assert len(load_leases(str(path))) == 3


def test_load_leases_missing_explicit_path_returns_empty():
    assert load_leases("/nonexistent/dnsmasq.leases") == []


def test_load_leases_probes_defaults_when_no_path_given():
    with patch("activitygraph.dhcp_leases.Path") as fake_path:
        fake_path.return_value.expanduser.return_value.read_text.side_effect = [
            FileNotFoundError(), SAMPLE,
        ]
        assert len(load_leases()) == 3


# ---------------- ingestion ----------------

def test_leases_teach_names_without_claiming_devices_are_present(tmp_path):
    """A lease records an address handed out, not who is connected now.
    dnsmasq keeps them for hours after a device leaves, so registering each
    one filled the dashboard with phones that went out this morning."""
    from activitygraph.main import Pipeline

    path = tmp_path / "dnsmasq.leases"
    path.write_text(SAMPLE)
    pipeline = Pipeline(idle_timeout_seconds=5.0)

    assert ingest_leases(pipeline, str(path)) == 3
    assert pipeline.devices.all_devices() == [], "a lease is not a sighting"


def test_the_learned_name_attaches_when_the_device_appears(tmp_path):
    """Dropping the sighting must not drop the name with it: the lease table
    is the only place some phones ever announce one."""
    from datetime import datetime, timezone

    from activitygraph.main import Pipeline
    from activitygraph.models import Packet

    path = tmp_path / "dnsmasq.leases"
    path.write_text(SAMPLE)
    pipeline = Pipeline(idle_timeout_seconds=5.0)
    ingest_leases(pipeline, str(path))

    pipeline.ingest(Packet(
        timestamp=datetime(2026, 8, 4, tzinfo=timezone.utc),
        src_ip="192.168.50.21", dst_ip="1.1.1.1", proto="UDP", length=100,
        src_mac="AA:BB:CC:00:00:02"))

    assert pipeline.devices.get("192.168.50.21").display_name() == "iPhone"


def test_grouping_still_works_for_a_device_named_from_a_lease(tmp_path):
    """Grouping is MAC-keyed. The lease supplies the name and the device
    supplies the MAC when it appears, so both still land on the same entry."""
    from datetime import datetime, timezone

    from activitygraph.main import Pipeline
    from activitygraph.models import Packet

    path = tmp_path / "dnsmasq.leases"
    path.write_text(SAMPLE)
    pipeline = Pipeline(idle_timeout_seconds=5.0,
                        device_groups={"AA:BB:CC:00:00:02": "Alice"})
    ingest_leases(pipeline, str(path))
    pipeline.ingest(Packet(
        timestamp=datetime(2026, 8, 4, tzinfo=timezone.utc),
        src_ip="192.168.50.21", dst_ip="1.1.1.1", proto="UDP", length=100,
        src_mac="AA:BB:CC:00:00:02"))

    device = pipeline.devices.get("192.168.50.21")
    assert device.hostname == "iPhone"
    assert device.group == "Alice"



# ---------------- WAN capture guard ----------------

def test_default_route_interface_parsed_from_proc_net_route():
    proc = "Iface\tDestination\tGateway \tFlags\n" \
           "wlan0\t0032A8C0\t00000000\t0001\n" \
           "eth0\t00000000\t0101A8C0\t0003\n"
    with patch("builtins.open", mock_open(read_data=proc)):
        assert default_route_interface() == "eth0"


def test_default_route_interface_none_when_unreadable():
    with patch("builtins.open", side_effect=OSError):
        assert default_route_interface() is None


def test_warns_when_capturing_the_wan_interface():
    """Regression guard for the worst gateway misconfiguration: capturing
    post-NAT makes every packet look like it came from the gateway, so the
    dashboard fills in normally while all per-device data is wrong."""
    with patch("activitygraph.collector.default_route_interface", return_value="eth0"):
        message = warn_if_capturing_wan("eth0")
    assert message is not None
    assert "WAN" in message and "NAT" in message


def test_no_warning_when_capturing_the_lan_interface():
    with patch("activitygraph.collector.default_route_interface", return_value="eth0"):
        assert warn_if_capturing_wan("wlan0") is None


def test_no_warning_when_default_route_is_unknown():
    with patch("activitygraph.collector.default_route_interface", return_value=None):
        assert warn_if_capturing_wan("eth0") is None


def test_no_warning_without_an_interface():
    assert warn_if_capturing_wan(None) is None
