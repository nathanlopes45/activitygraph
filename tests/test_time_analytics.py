from datetime import datetime, timedelta, timezone

from activitygraph.models import Device, Flow
from activitygraph.time_analytics import (
    category_seconds,
    format_duration,
    flow_interval,
    group_time_breakdown,
    activity_intervals_by_device_category,
    merge_intervals,
    time_by_device,
    time_by_group,
    total_active_seconds,
    union_seconds,
)

BASE = datetime(2026, 7, 30, 10, 0, 0, tzinfo=timezone.utc)


def _iv(start_min, end_min):
    return (BASE + timedelta(minutes=start_min), BASE + timedelta(minutes=end_min))


def _flow(src, category, start_min, end_min, service="SomeService", byte_count=100):
    return Flow(
        src_ip=src, dst_ip="1.2.3.4", src_port=51000, dst_port=443, proto="TCP",
        start_time=BASE + timedelta(minutes=start_min),
        end_time=BASE + timedelta(minutes=end_min),
        byte_count=byte_count, packet_count=5,
        service=service, category=category,
    )


def _device(ip, group=None, hostname=None):
    now = datetime.now(timezone.utc)
    return Device(ip=ip, mac="AA:BB:CC:DD:EE:FF", vendor="Unknown", hostname=hostname,
                  first_seen=now, last_seen=now, group=group)


# ---------------- merge_intervals ----------------

def test_merge_intervals_empty():
    assert merge_intervals([]) == []


def test_merge_intervals_single():
    assert merge_intervals([_iv(0, 10)]) == [_iv(0, 10)]


def test_merge_intervals_disjoint_stay_separate():
    assert merge_intervals([_iv(0, 10), _iv(20, 30)]) == [_iv(0, 10), _iv(20, 30)]


def test_merge_intervals_overlapping_are_joined():
    assert merge_intervals([_iv(0, 10), _iv(5, 20)]) == [_iv(0, 20)]


def test_merge_intervals_fully_contained():
    assert merge_intervals([_iv(0, 30), _iv(10, 20)]) == [_iv(0, 30)]


def test_merge_intervals_exactly_adjacent_are_joined():
    """Touching intervals are continuous activity, not two separate events."""
    assert merge_intervals([_iv(0, 10), _iv(10, 20)]) == [_iv(0, 20)]


def test_merge_intervals_handles_unsorted_input():
    assert merge_intervals([_iv(20, 30), _iv(0, 10), _iv(5, 8)]) == [_iv(0, 10), _iv(20, 30)]


# ---------------- union_seconds ----------------

def test_union_seconds_counts_overlap_once():
    """Two parallel connections over the same window are one span of time."""
    assert union_seconds([_iv(0, 30), _iv(0, 30)]) == 30 * 60


def test_union_seconds_sums_disjoint():
    assert union_seconds([_iv(0, 10), _iv(20, 30)]) == 20 * 60


# ---------------- min activity credit (correction C2) ----------------

def test_zero_length_flow_gets_minimum_activity_credit():
    """Regression: a single-packet flow has start_time == end_time, so a
    naive union would credit a burst of them with no time at all."""
    flow = _flow("192.168.1.5", "Study", 0, 0)
    start, end = flow_interval(flow, min_activity_seconds=5.0)
    assert (end - start).total_seconds() == 5.0


def test_min_activity_does_not_shorten_a_longer_flow():
    flow = _flow("192.168.1.5", "Study", 0, 30)
    start, end = flow_interval(flow, min_activity_seconds=5.0)
    assert (end - start).total_seconds() == 30 * 60


def test_two_nearby_zero_length_flows_merge_into_one_span():
    flows = [_flow("192.168.1.5", "Study", 0, 0), _flow("192.168.1.5", "Study", 0, 0)]
    flows[1].start_time = BASE + timedelta(seconds=1)
    flows[1].end_time = BASE + timedelta(seconds=1)
    seconds = category_seconds(flows, {"192.168.1.5"}, min_activity_seconds=5.0)
    assert seconds["Study"] == 6.0  # 0-5s and 1-6s merge to 0-6s


# ---------------- filtering ----------------

def test_infrastructure_and_dns_are_not_counted_as_time():
    flows = [
        _flow("192.168.1.5", "Infrastructure", 0, 30, service="mDNS"),
        _flow("192.168.1.5", "Infrastructure", 0, 30, service="DNS"),
        _flow("192.168.1.5", "Study", 0, 10, service="Canvas"),
    ]
    seconds = category_seconds(flows, {"192.168.1.5"})
    assert "Infrastructure" not in seconds
    assert seconds["Study"] == 10 * 60


def test_inbound_flows_are_not_counted():
    """A server pushing to us isn't the user doing something."""
    flows = [_flow("9.9.9.9", "Entertainment", 0, 30)]
    assert category_seconds(flows, {"192.168.1.5"}) == {}


def test_unclassified_flows_are_not_counted():
    flows = [_flow("192.168.1.5", None, 0, 30)]
    assert category_seconds(flows, {"192.168.1.5"}) == {}


# ---------------- per-category ----------------

def test_category_seconds_unions_parallel_flows_in_same_category():
    """A video stream opens several connections at once; that's one span."""
    flows = [
        _flow("192.168.1.5", "Entertainment", 0, 30, service="YouTube"),
        _flow("192.168.1.5", "Entertainment", 5, 25, service="YouTube"),
        _flow("192.168.1.5", "Entertainment", 10, 40, service="YouTube"),
    ]
    assert category_seconds(flows, {"192.168.1.5"})["Entertainment"] == 40 * 60


def test_total_active_seconds_counts_overlapping_categories_once():
    """Categories are unioned independently, so their totals can exceed the
    wall clock; total_active_seconds is the honest wall-clock figure."""
    flows = [
        _flow("192.168.1.5", "Study", 0, 30),
        _flow("192.168.1.5", "Entertainment", 0, 30),
    ]
    per_category = category_seconds(flows, {"192.168.1.5"})
    assert sum(per_category.values()) == 60 * 60
    assert total_active_seconds(flows, {"192.168.1.5"}) == 30 * 60


# ---------------- group union (the headline semantic) ----------------

def test_group_time_unions_across_devices_not_sums():
    """The decision this whole feature rests on: a phone and a laptop both
    on Entertainment 10:00-10:30 is 30 minutes of the person's life, not 60
    device-minutes -- otherwise a daily total could exceed 24 hours."""
    devices = [_device("192.168.1.5", group="Alice"), _device("192.168.1.6", group="Alice")]
    flows = [
        _flow("192.168.1.5", "Entertainment", 0, 30, service="YouTube"),
        _flow("192.168.1.6", "Entertainment", 0, 30, service="YouTube"),
    ]
    rows = time_by_group(flows, devices)
    assert len(rows) == 1
    assert rows[0]["group"] == "Alice"
    assert rows[0]["seconds"] == 30 * 60          # union: wall-clock
    assert rows[0]["device_seconds"] == 60 * 60   # sum: device-time
    assert rows[0]["device_count"] == 2


def test_group_time_separates_distinct_groups():
    devices = [_device("192.168.1.5", group="Alice"), _device("192.168.1.6", group="Family")]
    flows = [
        _flow("192.168.1.5", "Study", 0, 10),
        _flow("192.168.1.6", "Entertainment", 0, 40),
    ]
    rows = time_by_group(flows, devices)
    assert [r["group"] for r in rows] == ["Family", "Alice"]


def test_ungrouped_devices_still_appear():
    devices = [_device("192.168.1.5", group=None)]
    flows = [_flow("192.168.1.5", "Study", 0, 10)]
    rows = time_by_group(flows, devices)
    assert rows[0]["group"] == "Ungrouped"


def test_group_device_seconds_does_not_double_count_parallel_categories():
    """A device on two categories at once was busy for one span, not two."""
    devices = [_device("192.168.1.5", group="Alice")]
    flows = [
        _flow("192.168.1.5", "Study", 0, 30),
        _flow("192.168.1.5", "Entertainment", 0, 30),
    ]
    rows = time_by_group(flows, devices)
    assert rows[0]["device_seconds"] == 30 * 60


def test_group_time_breakdown_directly():
    nested = activity_intervals_by_device_category(
        [_flow("192.168.1.5", "Study", 0, 20), _flow("192.168.1.6", "Study", 10, 30)],
        {"192.168.1.5", "192.168.1.6"},
    )
    result = group_time_breakdown(nested, ["192.168.1.5", "192.168.1.6"])
    assert result["seconds"] == 30 * 60        # 0-30 unioned
    assert result["device_seconds"] == 40 * 60  # 20 + 20


# ---------------- per-device ----------------

def test_time_by_device_includes_devices_with_no_traffic():
    """A phone discovered via the router but never captured should read
    '0m', not vanish the way it does from byte-based rank_devices."""
    devices = [_device("192.168.1.5", hostname="Laptop"), _device("192.168.1.9", hostname="iPhone")]
    flows = [_flow("192.168.1.5", "Study", 0, 10)]
    rows = time_by_device(flows, devices)
    by_name = {r["display_name"]: r for r in rows}
    assert by_name["iPhone"]["seconds"] == 0
    assert by_name["Laptop"]["seconds"] == 10 * 60


# ---------------- formatting ----------------

def test_format_duration():
    assert format_duration(0) == "0m"
    assert format_duration(38) == "38s"
    assert format_duration(47 * 60) == "47m"
    assert format_duration(2 * 3600 + 14 * 60) == "2h 14m"
    assert format_duration(3 * 3600) == "3h"
