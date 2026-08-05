"""Device discovery from the DHCP server's own lease table.

When ActivityGraph runs on a gateway (see docs/raspberry-pi-gateway.md), that
machine *is* the DHCP server -- so it already holds the authoritative list of
every device on the network, complete with the hostname each one reported for
itself in its lease request (DHCP option 12). That's the same source a router
admin page uses when it shows you "iPhone" or "Bob-Phone".

This makes the whole vendor-specific router-login path (router_client.py)
unnecessary on a gateway deployment: reading a local text file works with
**any** router, needs no credentials, can't be rate-limited or locked out,
and returns strictly better data than active probing. active_resolver.py's
mDNS/NBSTAT probes only reach devices willing to answer; a lease covers
every device that got an address.

It also backfills MAC addresses. Device grouping is MAC-keyed, but some
capture setups (notably Linux's `any` pseudo-interface, which yields cooked
SLL frames with no link-layer header) provide no MACs at all. Leases give an
IP -> MAC mapping that restores grouping in those cases.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Packet

# Where dnsmasq keeps leases on Debian/Raspberry Pi OS.
DEFAULT_LEASE_PATHS = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/tmp/dhcp.leases",  # OpenWrt
)


@dataclass
class Lease:
    ip: str
    mac: str
    hostname: Optional[str] = None


def parse_dnsmasq_leases(text: str) -> list[Lease]:
    """Parse dnsmasq's lease file format, one lease per line:

        <expiry-epoch> <mac> <ip> <hostname> <client-id>

    dnsmasq writes "*" for a hostname it never learned, which we treat as
    absent rather than as a device literally named "*". Malformed lines are
    skipped rather than raising -- a half-written line (dnsmasq rewrites this
    file in place as leases change) shouldn't take down capture.
    """
    leases: list[Lease] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        mac, ip = fields[1], fields[2]
        if mac.count(":") != 5:
            continue  # not a lease line
        hostname = fields[3] if len(fields) > 3 else None
        if hostname in ("*", "", None):
            hostname = None
        leases.append(Lease(ip=ip, mac=mac.upper(), hostname=hostname))
    return leases


def load_leases(path: Optional[str] = None) -> list[Lease]:
    """Read leases from `path`, or probe the usual locations if omitted.

    Returns an empty list (with a printed warning only when a path was
    explicitly given) if nothing is readable -- an unreadable lease file
    should degrade device naming, not stop the pipeline.
    """
    candidates = [path] if path else list(DEFAULT_LEASE_PATHS)
    for candidate in candidates:
        try:
            return parse_dnsmasq_leases(Path(candidate).expanduser().read_text())
        except (FileNotFoundError, IsADirectoryError):
            continue
        except OSError as exc:
            print(f"[activitygraph] Warning: could not read DHCP leases at {candidate}: {exc}")
            return []
    if path:
        print(f"[activitygraph] Warning: DHCP lease file not found: {path}")
    return []


def ingest_leases(pipeline, path: Optional[str] = None, announce: bool = True) -> int:
    """Register every leased device with the pipeline.

    Feeds each lease through the same synthetic-ARP path as
    router_client.ingest_router_devices, so leases flow through the normal
    device-registration logic (vendor lookup, aliases, grouping) rather than
    needing a parallel code path. Returns the number of devices registered.

    Safe to call repeatedly: re-registering a known device just refreshes its
    last-seen time, so a long-running gateway can re-read the file on a timer
    and pick up devices that joined after startup.
    """
    leases = load_leases(path)
    now = datetime.now(timezone.utc)
    for lease in leases:
        pipeline.ingest(Packet(
            timestamp=now, src_ip=lease.ip, dst_ip=lease.ip, proto="ARP", length=0,
            src_mac=lease.mac, arp_sender_ip=lease.ip, arp_sender_mac=lease.mac,
            hostname_hint=lease.hostname,
            hostname_source="lease",
        ))
    if announce and leases:
        named = sum(1 for lease in leases if lease.hostname)
        print(f"[activitygraph] DHCP leases: {len(leases)} device(s), {named} with a hostname.")
    return len(leases)
