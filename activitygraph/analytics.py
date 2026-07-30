"""Usage ranking: turns the flat flow/device data into 'most used to least
used' lists for devices, services, and categories.

This also does double duty as the fix for "Uncategorized is a black box":
ranking by *service* (not just category) surfaces each unrecognized domain
individually with its own byte count -- so instead of one opaque
"Uncategorized: 53KB" bucket, you get a ranked list showing exactly which
domains make up that 53KB and how much each one costs, which is what you'd
actually act on (add a rule, or leave it since it's negligible).
"""
from __future__ import annotations

from .models import Device, Flow


def rank_devices(flows: list[Flow], devices: list[Device]) -> list[dict]:
    """Total bytes per device, both directions (sent + received), most to
    least. This is deliberately not limited to "device-initiated" flows
    (unlike Activity Graph sessions) -- it answers "how much has this
    device used, period," which should count replies too.
    """
    totals: dict[str, dict] = {}
    device_by_ip = {d.ip: d for d in devices}

    for flow in flows:
        for ip in (flow.src_ip, flow.dst_ip):
            if ip not in device_by_ip:
                continue
            bucket = totals.setdefault(ip, {"byte_count": 0, "flow_count": 0})
            bucket["byte_count"] += flow.byte_count
            bucket["flow_count"] += 1

    ranked = []
    for ip, bucket in totals.items():
        device = device_by_ip[ip]
        ranked.append({
            "device_ip": ip,
            "display_name": device.display_name(),
            "byte_count": bucket["byte_count"],
            "flow_count": bucket["flow_count"],
        })
    ranked.sort(key=lambda r: -r["byte_count"])
    return ranked


def rank_services(flows: list[Flow]) -> list[dict]:
    """Total bytes per individual service, most to least -- including each
    unrecognized domain as its own entry (its 'service' name is just the
    domain itself, from the service detector's fallback), rather than
    lumping everything unclassified into a single 'Uncategorized' blob.
    """
    totals: dict[str, dict] = {}
    for flow in flows:
        name = flow.service or "Unknown"
        bucket = totals.setdefault(name, {"category": flow.category or "Uncategorized", "byte_count": 0, "flow_count": 0})
        bucket["byte_count"] += flow.byte_count
        bucket["flow_count"] += 1

    ranked = [{"service": name, **bucket} for name, bucket in totals.items()]
    ranked.sort(key=lambda r: -r["byte_count"])
    return ranked


def rank_categories(flows: list[Flow]) -> list[dict]:
    """Total bytes per category, most to least -- the same data
    Pipeline.summary()'s category_breakdown has, reshaped as a sorted list
    instead of a dict, for consistency with the other two rankings."""
    totals: dict[str, dict] = {}
    for flow in flows:
        cat = flow.category or "Uncategorized"
        bucket = totals.setdefault(cat, {"byte_count": 0, "flow_count": 0})
        bucket["byte_count"] += flow.byte_count
        bucket["flow_count"] += 1

    ranked = [{"category": cat, **bucket} for cat, bucket in totals.items()]
    ranked.sort(key=lambda r: -r["byte_count"])
    return ranked
