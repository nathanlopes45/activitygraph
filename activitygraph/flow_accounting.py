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

import subprocess
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


def _read_proc(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(errors="ignore")
    except OSError:
        return None


def _read_command() -> Optional[str]:
    """The same table via `conntrack -L`.

    /proc/net/nf_conntrack only exists when the kernel was built with
    CONFIG_NF_CONNTRACK_PROCFS, and Raspberry Pi OS is one of the
    distributions that leaves it out. Connection tracking is still running
    and still counting; only the proc view is missing. The netlink interface
    that `conntrack -L` uses is always there when the module is loaded, so
    it is the fallback rather than the primary: reading a file needs no
    subprocess and no extra package.
    """
    try:
        result = subprocess.run(["conntrack", "-L"], capture_output=True,
                                text=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.stdout.strip() else None


def read_flows(path: str = CONNTRACK_PATH) -> list[ConntrackFlow]:
    """Every tracked flow, or [] where conntrack is not available.

    Returning [] rather than raising keeps this a supplement: a laptop run,
    or a gateway with the module unloaded, loses exact counters and carries
    on with the ones observed from capture.
    """
    text = _read_proc(path)
    if text is None:
        text = _read_command()
    if text is None:
        return []
    return [flow for flow in (parse_line(line) for line in text.splitlines())
            if flow is not None]


ACCT_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_acct"


def accounting_status(path: str = CONNTRACK_PATH) -> tuple:
    """(available, message). Says which failure applies, and its fix.

    Every one of these looks identical from the byte totals, and each needs
    a different command, so they are named apart rather than collapsed into
    "not available".
    """
    source = "proc"
    text = _read_proc(path)
    if text is None:
        text = _read_command()
        source = "conntrack -L"

    if text is None:
        # Distinguish "tracking is off" from "there is no way to read it".
        # The proc file is absent on Raspberry Pi OS even when tracking is
        # running, because the kernel is built without CONNTRACK_PROCFS, so
        # its absence alone proves nothing.
        if Path(ACCT_SYSCTL).exists():
            return False, ("connection tracking is running but cannot be read: "
                           f"{path} does not exist on this kernel and the "
                           "conntrack tool is not installed. Fix with: "
                           "sudo apt install -y conntrack")
        return False, ("connection tracking is not loaded, so there are no "
                       "per-flow counters to read. On a gateway it loads with "
                       "NAT; force it with: sudo modprobe nf_conntrack, and "
                       "install the reader with: sudo apt install -y conntrack")

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return True, f"connection tracking is on ({source}) but no flows are open yet"
    if not any("bytes=" in line for line in lines):
        return False, ("connection tracking is on but not counting bytes. "
                       "Fix with: sudo sysctl -w net.netfilter.nf_conntrack_acct=1 "
                       "(then restart, so existing flows are recounted)")
    return True, f"counting {len(lines)} tracked flows via {source}"
