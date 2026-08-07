"""Exact per-flow byte counts from the kernel, without touching a packet.

The tension this resolves: inspecting every packet in Python costs a Pi 4B
most of its throughput (measured: 15 Mbps of a 110 Mbps line), while
filtering in the kernel keeps the line fast but means the byte counts are
built from a sample and a flow that goes quiet can be timed out while it is
still open, understating time.

Both problems come from the same assumption, that the only way to know about
a packet is to look at it. On this gateway that is not true. The Pi already
does NAT, so the kernel's connection tracker holds an entry for every flow
crossing it, and with accounting turned on each entry carries exact packet
and byte counters for both directions. Every packet is therefore already
counted, by code that sees them anyway, at no extra cost per packet. Reading
that table once every few seconds is O(flows), not O(packets).

So the two sources divide cleanly:

  capture (filtered)  ->  *what* a flow is: DNS, SNI, the Host header
  conntrack           ->  *how much* and *how recently*: bytes and liveness

Counter movement, not presence, is what marks a flow as alive. An
established TCP entry lingers in conntrack for days after its last packet,
so treating presence as liveness would overstate time as badly as sampling
understates it.

Counters need `net.netfilter.nf_conntrack_acct=1`. Without it the entries
are still listed but carry no byte fields, which `accounting_status`
reports rather than silently returning zeros.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

CONNTRACK_PATH = "/proc/net/nf_conntrack"

# Everything else on the line (state, timeout, [ASSURED], mark) is noise here.
_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "udplite", "sctp", "dccp"}

# A conntrack entry names both directions with the same keys, so a repeat is
# what separates the original tuple from the reply.
_TUPLE_KEYS = ("src", "dst", "sport", "dport", "packets", "bytes")


@dataclass(frozen=True)
class ConntrackFlow:
    """One tracked connection, both directions."""

    proto: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: Optional[int] = None
    byte_count: Optional[int] = None
    reply_packets: Optional[int] = None
    reply_byte_count: Optional[int] = None

    def directions(self) -> Iterator[tuple]:
        """(flow key, packets, bytes) for each direction.

        Keyed exactly as FlowProcessor keys a flow, so a caller can look one
        up without knowing anything about conntrack. Each direction is a
        separate flow in this project, which happens to match how conntrack
        reports its counters.
        """
        yield ((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto),
               self.packets, self.byte_count)
        yield ((self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.proto),
               self.reply_packets, self.reply_byte_count)


def _as_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tuples(tokens: list[str]) -> list[dict]:
    """Split key=value tokens into the original and reply groups."""
    groups: list[dict] = []
    current: dict = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if not sep or key not in _TUPLE_KEYS:
            continue
        if key in current:
            groups.append(current)
            current = {}
        current[key] = value
    if current:
        groups.append(current)
    return groups


def parse_line(line: str) -> Optional[ConntrackFlow]:
    """One /proc/net/nf_conntrack line, or None if it is not a flow.

    Tolerant of layout: the leading "ipv4 2" columns are absent on some
    kernels and from `conntrack -L`, so the protocol is found by name rather
    than by position.
    """
    tokens = line.split()
    proto = next((t for t in tokens if t in _PROTOCOLS), None)
    if proto is None:
        return None

    groups = _tuples(tokens)
    if not groups:
        return None
    original = groups[0]
    reply = groups[1] if len(groups) > 1 else {}

    src, dst = original.get("src"), original.get("dst")
    if not src or not dst:
        return None

    return ConntrackFlow(
        proto=proto.upper(),
        src_ip=src,
        dst_ip=dst,
        src_port=_as_int(original.get("sport")) or 0,
        dst_port=_as_int(original.get("dport")) or 0,
        packets=_as_int(original.get("packets")),
        byte_count=_as_int(original.get("bytes")),
        reply_packets=_as_int(reply.get("packets")),
        reply_byte_count=_as_int(reply.get("bytes")),
    )


def read_flows(path: str = CONNTRACK_PATH) -> list[ConntrackFlow]:
    """Every tracked flow, or [] where conntrack is not available.

    Returning [] rather than raising keeps this a supplement: a laptop run,
    or a gateway with the module unloaded, loses exact counters and carries
    on with the ones observed from capture.
    """
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return []
    return [flow for flow in (parse_line(line) for line in text.splitlines())
            if flow is not None]


def accounting_status(path: str = CONNTRACK_PATH) -> tuple:
    """(available, message). Says which of the two failures applies.

    A missing table and a table without counters look identical from the
    byte totals, and they need different fixes, so they are named apart.
    """
    try:
        text = Path(path).read_text(errors="ignore")
    except FileNotFoundError:
        return False, ("no connection tracking on this machine "
                       f"({path} does not exist)")
    except PermissionError:
        return False, f"cannot read {path}; this needs to run as root"
    except OSError as exc:
        return False, f"cannot read {path}: {exc}"

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return True, "connection tracking is on but no flows are open yet"
    if not any("bytes=" in line for line in lines):
        return False, ("connection tracking is on but not counting bytes; "
                       "enable it with: sysctl -w net.netfilter.nf_conntrack_acct=1")
    return True, f"counting {len(lines)} tracked flows"
