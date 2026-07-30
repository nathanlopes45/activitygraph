"""Activity Graph stage: turns tagged Flows into meaningful Sessions.

This is where flows stop being a flat list and become the tree shape from
the original spec:

    Laptop
    └── Study Session
        ├── Canvas LMS
        ├── Google Docs
        └── Gmail

A Session is a run of device-initiated flows that are close together in
time. Consecutive flows on the same device get folded into one session as
long as the gap between them stays under `session_gap_seconds`; a longer
gap starts a new session. Each session is labeled with its dominant
category (by bytes) and lists the distinct services seen in it.

This intentionally only looks at flows the local device *initiated*
(src_ip is a known local device) -- that's what "the device did something"
actually means. Response-only traffic (e.g. a DNS server answering) isn't a
session on its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .models import Flow


@dataclass
class Session:
    device_ip: str
    start_time: datetime
    end_time: datetime
    flows: list[Flow] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    @property
    def byte_count(self) -> int:
        return sum(f.byte_count for f in self.flows)

    @property
    def category_breakdown(self) -> dict[str, int]:
        """Bytes per category within this session."""
        breakdown: dict[str, int] = {}
        for f in self.flows:
            cat = f.category or "Uncategorized"
            breakdown[cat] = breakdown.get(cat, 0) + f.byte_count
        return breakdown

    @property
    def category_seconds(self) -> dict[str, float]:
        """Active seconds per category within this session, overlapping
        flows counted once."""
        from .time_analytics import flow_interval, union_seconds

        intervals: dict[str, list] = {}
        for f in self.flows:
            intervals.setdefault(f.category or "Uncategorized", []).append(flow_interval(f))
        return {cat: union_seconds(ivs) for cat, ivs in intervals.items()}

    @property
    def dominant_category(self) -> str:
        """The category this session is mostly about -- by bytes, falling
        back to time.

        The fallback matters for flows that carry no byte counts (e.g. ones
        derived from DNS observation rather than captured packets). With
        every byte count at zero, `max()` over the byte breakdown just
        returns whichever category happened to be inserted first, so the
        same session could be labelled Study or Entertainment depending on
        dict ordering. Time is the meaningful signal in that case.
        """
        breakdown = self.category_breakdown
        if not breakdown:
            return "Uncategorized"
        if any(breakdown.values()):
            return max(breakdown.items(), key=lambda kv: kv[1])[0]
        seconds = self.category_seconds
        return max(seconds.items(), key=lambda kv: kv[1])[0] if seconds else "Uncategorized"

    @property
    def services(self) -> list[str]:
        seen = {f.service for f in self.flows if f.service and f.service not in ("DNS", "DHCP")}
        return sorted(seen)

    @property
    def title(self) -> str:
        cat = self.dominant_category
        return f"{cat} Session" if cat != "Uncategorized" else "Browsing Session"

    def to_dict(self) -> dict:
        return {
            "device_ip": self.device_ip,
            "title": self.title,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "byte_count": self.byte_count,
            "dominant_category": self.dominant_category,
            "category_breakdown": self.category_breakdown,
            "services": self.services,
            "flow_count": len(self.flows),
        }


def is_session_worthy(flow: Flow) -> bool:
    """Filter out low-signal infrastructure noise (DNS/DHCP/NTP) that
    shouldn't spawn or extend a session on their own.

    Also excludes flows that haven't been classified yet (category is
    None). Classification happens when a flow is flushed/closed, not the
    instant it's created -- so on a continuously-polled live dashboard, an
    unclassified flow would otherwise flicker into a session as
    "Uncategorized" and then vanish a poll later once it turns out to be
    Infrastructure/System noise. Waiting for a real category avoids that
    flicker; the flow shows up once, correctly, a few seconds later.
    """
    if flow.category is None:
        return False
    return flow.category not in ("Infrastructure", "System") and flow.service not in ("DNS", "DHCP", "NTP", "mDNS")


def group_into_sessions(
    flows: list[Flow],
    local_ips: set[str],
    session_gap_seconds: float = 300.0,
) -> list[Session]:
    """Group device-initiated flows into per-device sessions.

    Args:
        flows: all flows produced by the Flow Processor stage.
        local_ips: IPs recognized as local devices (from the Device Registry),
                   used to determine which side of each flow is "the device".
        session_gap_seconds: idle gap that closes a session (default 5 min).
    """
    by_device: dict[str, list[Flow]] = {}
    for flow in flows:
        if flow.src_ip not in local_ips:
            continue  # not device-initiated; skip (e.g. a server pushing to us)
        if not is_session_worthy(flow):
            continue
        by_device.setdefault(flow.src_ip, []).append(flow)

    all_sessions: list[Session] = []
    for device_ip, device_flows in by_device.items():
        device_flows.sort(key=lambda f: f.start_time)
        current: Session | None = None
        for flow in device_flows:
            if current is None:
                current = Session(device_ip=device_ip, start_time=flow.start_time, end_time=flow.end_time, flows=[flow])
                continue
            gap = (flow.start_time - current.end_time).total_seconds()
            if gap <= session_gap_seconds:
                current.flows.append(flow)
                current.end_time = max(current.end_time, flow.end_time)
            else:
                all_sessions.append(current)
                current = Session(device_ip=device_ip, start_time=flow.start_time, end_time=flow.end_time, flows=[flow])
        if current is not None:
            all_sessions.append(current)

    all_sessions.sort(key=lambda s: s.start_time)
    return all_sessions
