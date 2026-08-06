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
from pathlib import Path
from typing import Optional


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
    """Learn a name for every leased device. Returns the number of leases read.

    Names only, deliberately. A lease records an address handed out, and
    dnsmasq keeps it for hours after the device disconnects, so treating each
    one as a sighting shows devices that left this morning as present. The
    name is held against the MAC and attaches the moment that device sends
    something, which is also when grouping and vendor lookup apply.

    Safe to call repeatedly, so a long-running gateway can re-read the file
    on a timer and pick up names for devices that joined after startup.
    """
    leases = load_leases(path)
    for lease in leases:
        # Names only. A lease is a record of an address handed out, which
        # outlives the connection by hours, so registering each one as a
        # device would show phones that left this morning as present. The
        # name waits and attaches the moment the device sends something.
        pipeline.devices.remember_name(lease.mac, lease.hostname, source="lease")
    if announce and leases:
        named = sum(1 for lease in leases if lease.hostname)
        print(f"[activitygraph] DHCP leases: {named} name(s) learned from {len(leases)} lease(s). "
              "Devices appear once they send traffic.")
    return len(leases)
