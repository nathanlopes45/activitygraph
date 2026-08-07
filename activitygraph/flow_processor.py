"""Flow Processor stage: turns a stream of Packets into Flows.

A flow is the standard 5-tuple conversation (src_ip, dst_ip, src_port,
dst_port, proto). Flows are kept "open" and updated as packets arrive, then
"finalized" (moved to the closed list) once they've been idle past
`idle_timeout_seconds`. Call `flush_idle()` periodically (or `flush_all()` at
shutdown) to finalize them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import Flow, Packet


class FlowProcessor:
    def __init__(self, idle_timeout_seconds: float = 30.0) -> None:
        self.idle_timeout_seconds = idle_timeout_seconds
        self._open_flows: dict[tuple, Flow] = {}
        self._closed_flows: list[Flow] = []

    def _flow_key(self, packet: Packet) -> tuple:
        # Normalize direction isn't attempted here: each direction of a TCP/UDP
        # conversation is tracked as its own flow entry, which keeps this stage
        # simple. Session-level grouping (both directions, multiple flows into
        # one "visit") happens later in the Activity Graph stage.
        return (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.proto)

    def process(self, packet: Packet) -> Flow:
        key = self._flow_key(packet)
        flow = self._open_flows.get(key)
        if flow is None:
            flow = Flow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port or 0,
                dst_port=packet.dst_port or 0,
                proto=packet.proto,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            )
            self._open_flows[key] = flow

        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.end_time = packet.timestamp
        return flow

    def apply_accounting(self, entries, now: Optional[datetime] = None) -> int:
        """Replace observed counters with the kernel's exact ones.

        `entries` are ConntrackFlows. Returns how many flows moved, which is
        what the diagnostics report.

        Two rules, both learned the hard way:

        Counters only ever go up, so a smaller number means conntrack has
        recycled the entry for a new connection on the same 5-tuple. Taking
        it would make a flow appear to shrink.

        A flow counts as alive only when its counters *moved* since the last
        poll. Presence is not evidence: conntrack holds an established TCP
        entry for days after its last packet, so treating presence as
        liveness would overstate time as badly as sampling understates it.
        """
        now = now or datetime.now(timezone.utc)
        moved = 0
        for entry in entries:
            for key, packets, byte_count in entry.directions():
                flow = self._open_flows.get(key)
                if flow is None or byte_count is None:
                    continue
                if byte_count <= flow.byte_count:
                    continue
                flow.byte_count = byte_count
                if packets is not None:
                    flow.packet_count = packets
                flow.end_time = now
                moved += 1
        return moved

    def flush_idle(self, now: Optional[datetime] = None) -> list[Flow]:
        """Finalize flows that have been idle past the timeout. Returns them."""
        now = now or datetime.now(timezone.utc)
        finalized = []
        for key in list(self._open_flows.keys()):
            flow = self._open_flows[key]
            if (now - flow.end_time).total_seconds() >= self.idle_timeout_seconds:
                finalized.append(flow)
                self._closed_flows.append(flow)
                del self._open_flows[key]
        return finalized

    def flush_all(self) -> list[Flow]:
        finalized = list(self._open_flows.values())
        self._closed_flows.extend(finalized)
        self._open_flows.clear()
        return finalized

    def open_flows(self) -> list[Flow]:
        return list(self._open_flows.values())

    def closed_flows(self) -> list[Flow]:
        return list(self._closed_flows)

    def all_flows(self) -> list[Flow]:
        return self._closed_flows + list(self._open_flows.values())
