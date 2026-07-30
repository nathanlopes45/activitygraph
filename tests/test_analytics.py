from datetime import datetime, timezone

from activitygraph.analytics import rank_categories, rank_devices, rank_services
from activitygraph.models import Device, Flow


def _flow(src, dst, byte_count, service, category, src_port=51000, dst_port=443):
    now = datetime.now(timezone.utc)
    return Flow(
        src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port, proto="TCP",
        start_time=now, end_time=now, byte_count=byte_count, packet_count=1,
        service=service, category=category,
    )


def _device(ip, hostname=None, vendor="Unknown"):
    now = datetime.now(timezone.utc)
    return Device(ip=ip, mac="AA:BB:CC:DD:EE:FF", vendor=vendor, hostname=hostname, first_seen=now, last_seen=now)


def test_rank_devices_sums_both_directions():
    devices = [_device("192.168.1.10", hostname="Laptop")]
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 1000, "YouTube", "Entertainment"),
        _flow("1.1.1.1", "192.168.1.10", 500, "YouTube", "Entertainment"),
    ]
    ranked = rank_devices(flows, devices)
    assert len(ranked) == 1
    assert ranked[0]["byte_count"] == 1500
    assert ranked[0]["display_name"] == "Laptop"
    assert ranked[0]["flow_count"] == 2


def test_rank_devices_sorted_most_to_least():
    devices = [_device("192.168.1.10", hostname="Laptop"), _device("192.168.1.11", hostname="Phone")]
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 500, "GitHub", "Software Development"),
        _flow("192.168.1.11", "2.2.2.2", 5000, "YouTube", "Entertainment"),
    ]
    ranked = rank_devices(flows, devices)
    assert [r["display_name"] for r in ranked] == ["Phone", "Laptop"]


def test_rank_devices_ignores_non_device_ips():
    devices = [_device("192.168.1.10", hostname="Laptop")]
    flows = [_flow("192.168.1.10", "8.8.8.8", 1000, "Google Search", "Web Browsing")]
    ranked = rank_devices(flows, devices)
    ips_ranked = {r["device_ip"] for r in ranked}
    assert "8.8.8.8" not in ips_ranked
    assert "192.168.1.10" in ips_ranked


def test_rank_services_segregates_uncategorized_domains_individually():
    """This is the 'segregate uncategorized' behavior: each unrecognized
    domain shows up as its own ranked entry, not lumped into one blob."""
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 3000, "claude.ai", "Uncategorized"),
        _flow("192.168.1.10", "2.2.2.2", 1000, "sync-v2.brave.com", "Uncategorized"),
        _flow("192.168.1.10", "3.3.3.3", 500, "some-other-thing.example", "Uncategorized"),
    ]
    ranked = rank_services(flows)
    assert len(ranked) == 3  # not collapsed into one "Uncategorized" entry
    assert ranked[0]["service"] == "claude.ai"
    assert ranked[0]["byte_count"] == 3000
    assert all(r["category"] == "Uncategorized" for r in ranked)


def test_rank_services_sorted_most_to_least():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 100, "GitHub", "Software Development"),
        _flow("192.168.1.10", "2.2.2.2", 9000, "YouTube", "Entertainment"),
    ]
    ranked = rank_services(flows)
    assert [r["service"] for r in ranked] == ["YouTube", "GitHub"]


def test_rank_services_aggregates_same_service_across_flows():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 1000, "YouTube", "Entertainment"),
        _flow("1.1.1.1", "192.168.1.10", 2000, "YouTube", "Entertainment"),
    ]
    ranked = rank_services(flows)
    assert len(ranked) == 1
    assert ranked[0]["byte_count"] == 3000
    assert ranked[0]["flow_count"] == 2


def test_rank_categories_sorted_most_to_least():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 100, "GitHub", "Software Development"),
        _flow("192.168.1.10", "2.2.2.2", 9000, "YouTube", "Entertainment"),
        _flow("192.168.1.10", "3.3.3.3", 500, "DNS", "Infrastructure", dst_port=53),
    ]
    ranked = rank_categories(flows)
    assert [r["category"] for r in ranked] == ["Entertainment", "Infrastructure", "Software Development"]
