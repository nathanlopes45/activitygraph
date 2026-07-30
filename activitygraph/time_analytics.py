"""Time-based aggregation: how long was spent, not how many bytes moved.

Bytes answer "how much data moved"; they're a poor proxy for attention --
one video stream outweighs hours of reading. This module answers the
question the dashboard actually wants: *where did the time go?*

The core primitive is an **interval union**. A device streaming video
typically has several flows open at once (video, audio, telemetry), each
its own Flow object with its own start/end. Summing their durations would
report far more time than actually elapsed. Instead, for each category we
merge its flows' time ranges into disjoint intervals and sum those -- so
overlapping activity counts once, and a category's total can never exceed
the wall-clock time the device was on.

The same union applies across a *group* of devices: if a phone and a
laptop both stream 10:00-10:30, that's 30 minutes of the person's life,
not 60 device-minutes. Both numbers are reported -- `seconds` (union, the
headline) and `device_seconds` (sum, the per-device detail) -- because
"phone 30m + laptop 30m, 30m of your time" says more than either alone.

One honest limitation: per-category unions are computed independently, so
a device streaming video while a study tab polls in the background counts
toward both. Per-category totals can therefore sum to more than
`total_active_seconds`. We can't know which one had the user's attention,
so we report both rather than inventing an attribution rule.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from .activity_graph import is_session_worthy
from .models import Device, Flow

Interval = tuple[datetime, datetime]

# A flow built from a single packet has start_time == end_time, so its raw
# duration is zero -- a burst of short-lived connections would otherwise
# report no time at all. Credit each flow at least this long. The default
# matches the CLI's --idle-timeout default: that's already the window in
# which packets are treated as one continuous activity, so extending a
# burst to cover it is consistent with how flows are built, not arbitrary.
DEFAULT_MIN_ACTIVITY_SECONDS = 5.0


def merge_intervals(intervals: Iterable[Interval]) -> list[Interval]:
    """Merge overlapping and touching intervals into disjoint ones, sorted
    by start time. Intervals that merely touch (one ends exactly where the
    next begins) are joined -- that's continuous activity, not two events."""
    ordered = sorted(intervals, key=lambda iv: iv[0])
    merged: list[Interval] = []
    for start, end in ordered:
        if end < start:
            start, end = end, start
        if merged and start <= merged[-1][1]:
            last_start, last_end = merged[-1]
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return merged


def union_seconds(intervals: Iterable[Interval]) -> float:
    """Total wall-clock seconds covered by the intervals, counting any
    overlap once."""
    return sum((end - start).total_seconds() for start, end in merge_intervals(intervals))


def flow_interval(flow: Flow, min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS) -> Interval:
    """The time range a flow represents, widened to `min_activity_seconds`
    if the flow is shorter (see DEFAULT_MIN_ACTIVITY_SECONDS)."""
    end = max(flow.end_time, flow.start_time + timedelta(seconds=min_activity_seconds))
    return (flow.start_time, end)


def _relevant_flows(flows: Iterable[Flow], local_ips: set[str]) -> list[Flow]:
    """Device-initiated flows that represent real activity.

    Mirrors group_into_sessions' filtering exactly: outbound only (a server
    pushing to us isn't the user doing something), and worth counting at all
    -- without the second filter, mDNS/NTP/DNS chatter every few seconds
    would make every device look active around the clock and Infrastructure
    would dominate every total.
    """
    return [f for f in flows if f.src_ip in local_ips and is_session_worthy(f)]


def activity_intervals_by_category(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> dict[str, list[Interval]]:
    """category -> merged, disjoint intervals across all local devices."""
    by_category: dict[str, list[Interval]] = {}
    for flow in _relevant_flows(flows, local_ips):
        category = flow.category or "Uncategorized"
        by_category.setdefault(category, []).append(flow_interval(flow, min_activity_seconds))
    return {cat: merge_intervals(ivs) for cat, ivs in by_category.items()}


def activity_intervals_by_device_category(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> dict[str, dict[str, list[Interval]]]:
    """device_ip -> category -> merged, disjoint intervals.

    This is the finest-grained form; group and overall totals are derived
    from it by unioning across the relevant devices, so every number in the
    dashboard traces back to one computation.
    """
    nested: dict[str, dict[str, list[Interval]]] = {}
    for flow in _relevant_flows(flows, local_ips):
        category = flow.category or "Uncategorized"
        nested.setdefault(flow.src_ip, {}).setdefault(category, []).append(
            flow_interval(flow, min_activity_seconds)
        )
    return {
        ip: {cat: merge_intervals(ivs) for cat, ivs in cats.items()}
        for ip, cats in nested.items()
    }


def category_seconds(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> dict[str, float]:
    """category -> unioned active seconds across all local devices."""
    return {
        cat: union_seconds(ivs)
        for cat, ivs in activity_intervals_by_category(flows, local_ips, min_activity_seconds).items()
    }


def total_active_seconds(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> float:
    """Wall-clock seconds where *any* categorized activity was happening.

    Because categories are unioned independently, this is <= the sum of the
    per-category totals whenever categories overlap in time.
    """
    all_intervals = [
        iv
        for ivs in activity_intervals_by_category(flows, local_ips, min_activity_seconds).values()
        for iv in ivs
    ]
    return union_seconds(all_intervals)


def activity_intervals_by_category_service(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> dict[str, dict[str, list[Interval]]]:
    """category -> service -> merged intervals.

    Service is kept (rather than the subcategory) because subcategory is
    derived from it. Aggregating at service level means re-organizing the
    taxonomy re-buckets these totals with no recomputation of the traffic.
    """
    nested: dict[str, dict[str, list[Interval]]] = {}
    for flow in _relevant_flows(flows, local_ips):
        category = flow.category or "Uncategorized"
        service = flow.service or "Unknown"
        nested.setdefault(category, {}).setdefault(service, []).append(
            flow_interval(flow, min_activity_seconds)
        )
    return {
        cat: {svc: merge_intervals(ivs) for svc, ivs in services.items()}
        for cat, services in nested.items()
    }


def activity_intervals_by_device_category_service(
    flows: Iterable[Flow],
    local_ips: set[str],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> dict[str, dict[tuple[str, str], list[Interval]]]:
    """device_ip -> (category, service) -> merged intervals.

    The persistence-shaped view: storing at service granularity is what lets
    a later change to the taxonomy re-bucket *history*, since the subcategory
    is looked up from the stored service rather than frozen at write time.
    """
    nested: dict[str, dict[tuple[str, str], list[Interval]]] = {}
    for flow in _relevant_flows(flows, local_ips):
        key = (flow.category or "Uncategorized", flow.service or "Unknown")
        nested.setdefault(flow.src_ip, {}).setdefault(key, []).append(
            flow_interval(flow, min_activity_seconds)
        )
    return {
        ip: {key: merge_intervals(ivs) for key, ivs in keyed.items()}
        for ip, keyed in nested.items()
    }


def time_by_category_nested(
    flows: Iterable[Flow],
    local_ips: set[str],
    taxonomy=None,
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> list[dict]:
    """Full drill-down: category -> subcategory -> service, each with unioned
    seconds, sorted most time first at every level.

    Every level's total is the union of the level below it, not the sum, so
    a category's figure stays honest even when two of its services were
    active at the same time (music playing while a video buffers).
    """
    from .taxonomy import TaxonomyRegistry

    taxonomy = taxonomy or TaxonomyRegistry()
    by_service = activity_intervals_by_category_service(flows, local_ips, min_activity_seconds)

    rows = []
    for category, services in by_service.items():
        by_subcategory: dict[str, dict[str, list[Interval]]] = {}
        for service, intervals in services.items():
            subcategory = taxonomy.subcategory_for(category, service)
            by_subcategory.setdefault(subcategory, {})[service] = intervals

        subcategory_rows = []
        for subcategory, sub_services in by_subcategory.items():
            service_rows = sorted(
                ({"service": svc, "seconds": union_seconds(ivs)} for svc, ivs in sub_services.items()),
                key=lambda r: -r["seconds"],
            )
            subcategory_rows.append({
                "subcategory": subcategory,
                "seconds": union_seconds([iv for ivs in sub_services.values() for iv in ivs]),
                "services": service_rows,
            })
        subcategory_rows.sort(key=lambda r: -r["seconds"])

        rows.append({
            "category": category,
            "seconds": union_seconds([iv for ivs in services.values() for iv in ivs]),
            "subcategories": subcategory_rows,
        })
    rows.sort(key=lambda r: -r["seconds"])
    return rows


def group_time_breakdown(
    intervals_by_device_category: dict[str, dict[str, list[Interval]]],
    device_ips: Iterable[str],
) -> dict:
    """Union one group's devices together.

    Returns {"seconds", "device_seconds", "by_category": [...]}, where
    `seconds` is the union (wall-clock time the person spent) and
    `device_seconds` is the plain sum (device-time, which double-counts
    simultaneous use). See the module docstring for why both are reported.
    """
    ips = [ip for ip in device_ips if ip in intervals_by_device_category]

    per_category: dict[str, list[Interval]] = {}
    device_seconds_total = 0.0
    for ip in ips:
        categories = intervals_by_device_category[ip]
        for category, intervals in categories.items():
            per_category.setdefault(category, []).extend(intervals)
        # Union across this device's own categories first, so a device
        # streaming video while a study tab polls counts once toward its
        # own device-time -- device_seconds is "how long was each device
        # busy", summed, not "device-category-time".
        device_seconds_total += union_seconds(
            [iv for intervals in categories.values() for iv in intervals]
        )

    by_category = [
        {
            "category": category,
            "seconds": union_seconds(intervals),
            "device_seconds": sum(union_seconds([iv]) for iv in intervals),
        }
        for category, intervals in per_category.items()
    ]
    by_category.sort(key=lambda row: -row["seconds"])

    everything = [iv for intervals in per_category.values() for iv in intervals]
    return {
        "seconds": union_seconds(everything),
        "device_seconds": device_seconds_total,
        "by_category": by_category,
    }


def time_by_group(
    flows: Iterable[Flow],
    devices: list[Device],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
    ungrouped_label: str = "Ungrouped",
) -> list[dict]:
    """[{group, seconds, device_seconds, device_count, by_category}], most
    time first. Groups come from `Device.group`; devices without one fall
    under `ungrouped_label` so they still appear."""
    local_ips = {d.ip for d in devices}
    nested = activity_intervals_by_device_category(flows, local_ips, min_activity_seconds)

    ips_by_group: dict[str, list[str]] = {}
    for device in devices:
        ips_by_group.setdefault(device.group or ungrouped_label, []).append(device.ip)

    rows = []
    for group, ips in ips_by_group.items():
        breakdown = group_time_breakdown(nested, ips)
        rows.append({
            "group": group,
            "device_count": len(ips),
            "seconds": breakdown["seconds"],
            "device_seconds": breakdown["device_seconds"],
            "by_category": breakdown["by_category"],
        })
    rows.sort(key=lambda row: -row["seconds"])
    return rows


def time_by_device(
    flows: Iterable[Flow],
    devices: list[Device],
    min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS,
) -> list[dict]:
    """[{device_ip, display_name, group, seconds, by_category}], most time
    first.

    Built from the device list rather than from the flows, so a device we
    know about but have no traffic for -- a phone discovered via the router,
    say -- appears with `seconds: 0` instead of silently vanishing the way
    it does from the byte-based analytics.rank_devices.
    """
    local_ips = {d.ip for d in devices}
    nested = activity_intervals_by_device_category(flows, local_ips, min_activity_seconds)

    rows = []
    for device in devices:
        per_category = nested.get(device.ip, {})
        by_category = sorted(
            ({"category": cat, "seconds": union_seconds(ivs)} for cat, ivs in per_category.items()),
            key=lambda row: -row["seconds"],
        )
        everything = [iv for ivs in per_category.values() for iv in ivs]
        rows.append({
            "device_ip": device.ip,
            "display_name": device.display_name(),
            "group": device.group,
            "seconds": union_seconds(everything),
            "by_category": by_category,
        })
    rows.sort(key=lambda row: -row["seconds"])
    return rows


def format_duration(seconds: float) -> str:
    """Human-readable duration: '2h 14m', '47m', '38s', '0m'."""
    seconds = int(round(seconds))
    if seconds <= 0:
        return "0m"
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    return f"{minutes}m"
