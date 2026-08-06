"""Device identification: builds an IP<->MAC<->vendor table from local traffic.

Devices are discovered passively (from ARP traffic and observed source MACs
on the LAN) rather than by actively scanning, to stay unobtrusive by default.
An active ARP sweep is offered separately for users who want faster discovery.

Device *names* come from several sources, and the registry keeps the best
one rather than the first to arrive (see name_quality):

  1. A user-supplied alias (see load_aliases) -- always wins, since you know
     your own devices better than any protocol guess.
  2. Passively-observed hostnames (mDNS/.local names, NetBIOS names, DHCP
     hostname options -- see collector.py's _extract_hostname_hint).
  3. Active resolution (see active_resolver.py), opt-in via active_resolve=
     True -- asks each newly-seen device directly (reverse DNS / unicast
     mDNS / NBSTAT), the same way a router resolves names for its own
     admin UI. Runs off-thread so it never blocks packet capture.

Sources are ranked because they are not equally good. Phones in particular
tend to announce a bare model name over DHCP ("iPhone") while advertising
the name their owner chose over mDNS ("Sams-iPhone"), and whichever the
capture happens to see first is arbitrary. Scoring specificity above source
means the personalised name wins whenever it appears, in any order.

Not every device announces a name on every network (this varies by OS and
network config), so some devices will still only show a vendor or IP --
that's an honest "we don't know," not a bug. Those are the ones worth
putting in an aliases file.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from .active_resolver import resolve_hostname
from .device_groups import GroupRegistry
from .models import Device, Packet
from .oui_database import lookup_vendor


def _is_local_ip(ip: str) -> bool:
    """True for private/link-local/loopback addresses -- i.e. plausibly a
    device on your own network, not a remote server on the internet.

    This matters because of how Ethernet framing works: when a remote
    server's reply arrives, the frame's source MAC is your router's MAC
    (it's the last hop that delivered it), while the source IP is the
    remote server's real public address. Blindly pairing (src_ip, src_mac)
    from any packet would misidentify every remote server you talk to as
    a "device" wearing your router's MAC address.

    Sufficient on its own for IPv4, where NAT guarantees every device here
    holds a private address. Not sufficient for IPv6, where devices hold
    globally routable addresses and this returns False for them; see
    DeviceRegistry.observe, which falls back to the source MAC there.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _primary_address(addresses: list[str]) -> str:
    """Which of a device's addresses to show as *the* one.

    Routable IPv4 first, because that is the address a person recognises
    and the one the rest of the network refers to the device by. An IPv6
    link-local address is real but useless for identifying anything, so it
    only wins when there is nothing else.
    """
    routable_v4 = [a for a in addresses if not _is_ipv6(a) and not a.startswith("169.254.")]
    if routable_v4:
        return routable_v4[0]
    non_link_local = [a for a in addresses if not a.lower().startswith("fe80:")]
    return (non_link_local or addresses)[0]


def _is_addressable(ip: str) -> bool:
    """False for addresses that cannot belong to a device.

    A device is not its address, but every device entry is keyed by one, so
    a placeholder address becomes a phantom device that never goes away.
    The common one is 0.0.0.0: a DHCP DISCOVER carries it as the source
    because the client has no address yet, and an ARP probe uses it for the
    same reason. Python's ipaddress calls 0.0.0.0 private, so it otherwise
    passes the local-device test and registers a duplicate of whichever
    phone is currently asking for a lease.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_unspecified or address.is_multicast:
        return False
    return ip not in ("255.255.255.255", "::")


def _is_ipv6(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper()


# How much a name source is worth. mDNS names are usually the one the owner
# typed into their device's settings; a DHCP option 12 hostname is often
# just the model. A lease-table entry is the same option 12 value read back
# from the DHCP server's cache, so it ranks below the packet: the file keeps
# whatever the device said last time, which can be an old name or an old
# owner. Active resolution is weakest -- a fallback for devices that
# announced nothing at all.
_SOURCE_RANK = {"mdns": 4, "nbns": 3, "dhcp": 2, "lease": 1, "active": 0}

# Above anything a protocol can produce: you know your own devices better
# than any guess, so an alias is never displaced.
_ALIAS_QUALITY = 100

# Bare model/OS names that identify a *kind* of device rather than a
# particular one. Several devices on a network can announce the identical
# string, so any name carrying an owner or a distinguishing word beats them.
_GENERIC_NAMES = {
    "iphone", "ipad", "ipod", "ipod touch", "apple tv", "macbook", "macbook air",
    "macbook pro", "imac", "mac mini", "mac", "watch", "apple watch", "airpods",
    "android", "android phone", "galaxy", "pixel", "oneplus", "xiaomi", "redmi",
    "localhost", "unknown", "device", "computer", "phone", "tablet", "laptop",
    "desktop", "chromecast", "google home", "google nest", "echo", "amazon echo",
    "fire tv", "roku", "smart tv", "tv", "printer", "raspberrypi", "raspberry pi",
}

# Apple and Android both fall back to "<Model>-2" / "<Model> (3)" when two
# devices announce the same name, which is still not a personalised name.
_TRAILING_COUNTER = re.compile(r"[\s\-_]*[\(\[]?\d{1,4}[\)\]]?$")


def _is_generic_name(name: str) -> bool:
    """True if the name identifies a model rather than a particular device.

    "iPhone" is generic; "Sams iPhone" is not. The test is an exact match on
    the whole name after normalising, never a substring match, because most
    personalised names contain the model name as a word.
    """
    cleaned = re.sub(r"[\s\-_]+", " ", name.strip().lower())
    cleaned = _TRAILING_COUNTER.sub("", cleaned).strip()
    return not cleaned or cleaned in _GENERIC_NAMES


def name_quality(name: str, source: Optional[str]) -> int:
    """Score a candidate device name so the best one wins, not the first.

    Specificity outranks the source: a personalised name from DHCP is worth
    more than a generic one from mDNS, because the point of the name is to
    tell two devices apart. Source only breaks ties between names that are
    equally specific.
    """
    if not name or not name.strip():
        return -1
    return (0 if _is_generic_name(name) else 10) + _SOURCE_RANK.get(source or "", 0)


def load_aliases(path: str) -> dict[str, str]:
    """Load a user-supplied MAC -> friendly name mapping from a JSON file.

    Format: {"AA:BB:CC:DD:EE:FF": "Alice's Laptop", ...}. MAC keys are
    matched case-insensitively. Returns an empty dict (with a printed
    warning) if the file is missing or malformed, rather than crashing --
    a typo in an aliases file shouldn't take down capture.
    """
    try:
        raw = json.loads(Path(path).expanduser().read_text())
        return {_normalize_mac(mac): name for mac, name in raw.items()}
    except FileNotFoundError:
        print(f"[activitygraph] Warning: --device-aliases file not found: {path}")
    except (json.JSONDecodeError, AttributeError, TypeError):
        print(f"[activitygraph] Warning: --device-aliases file is not valid JSON: {path}")
    return {}


class DeviceRegistry:
    def __init__(
        self,
        aliases: Optional[dict[str, str]] = None,
        active_resolve: bool = False,
        resolver: Callable[[str], Optional[str]] = resolve_hostname,
        run_async: Optional[Callable[[Callable[[], None]], None]] = None,
        groups: Optional[GroupRegistry] = None,
        exclude_macs: Optional[set] = None,
    ) -> None:
        self._devices: dict[str, Device] = {}   # keyed by MAC, or address if unknown
        self._by_address: dict[str, Device] = {}  # every address -> its device
        self._aliases = {_normalize_mac(mac): name for mac, name in (aliases or {}).items()}
        self._groups = groups or GroupRegistry()
        self._active_resolve = active_resolve
        self._resolver = resolver
        self._run_async = run_async or _spawn_daemon_thread
        self._resolve_attempted: set[str] = set()
        # Best name seen for each device and its score, keyed by MAC where
        # known so it survives a DHCP lease moving the device to a new IP.
        self._best_name: dict[str, tuple[str, int]] = {}
        # MACs belonging to devices on this network, and MACs observed
        # forwarding traffic from elsewhere. Both are needed to attribute
        # IPv6, where a device's address looks identical to a server's.
        self._local_macs: set[str] = set()
        self._router_macs: set[str] = set()
        # MACs never to register. On a gateway this is the gateway itself:
        # it carries everyone's traffic but is nobody's device, so listing
        # it puts infrastructure in among the household.
        self._excluded_macs = {_normalize_mac(m) for m in (exclude_macs or set())}

    def observe(self, packet: Packet) -> None:
        now = packet.timestamp

        # Checked before anything else, including naming: an excluded device
        # should leave no trace at all, not a nameless entry.
        source_mac = packet.arp_sender_mac or packet.src_mac
        if source_mac and _normalize_mac(source_mac) in self._excluded_macs:
            return

        if packet.arp_sender_ip and packet.arp_sender_mac:
            # An ARP probe announces 0.0.0.0 while a host works out whether
            # the address it wants is free, so this path needs the same
            # guard as the one below.
            if _is_addressable(packet.arp_sender_ip):
                self._local_macs.add(_normalize_mac(packet.arp_sender_mac))
                self._touch(packet.arp_sender_ip, packet.arp_sender_mac, now,
                            packet.hostname_hint, packet.hostname_source)
            return

        if not (packet.src_ip and packet.src_mac):
            return
        if not _is_addressable(packet.src_ip):
            # No device to attach it to, but the packet may still be the best
            # look at this device's name we ever get: a DHCP DISCOVER carries
            # the hostname in option 12 and is sent from 0.0.0.0 by
            # definition. Keep the name, drop the address.
            self._remember_name(packet.src_mac, packet.hostname_hint, packet.hostname_source)
            return
        mac = _normalize_mac(packet.src_mac)

        # Fall back to source IP/MAC on any packet, which covers devices
        # that never show up in ARP traffic during the capture window.
        if _is_local_ip(packet.src_ip):
            self._local_macs.add(mac)
            self._touch(packet.src_ip, packet.src_mac, now,
                        packet.hostname_hint, packet.hostname_source)

        elif not _is_ipv6(packet.src_ip):
            # A public IPv4 source address cannot belong to anything on this
            # side of the NAT, so this frame was forwarded and the source
            # MAC belongs to whatever forwarded it. Recording the pair would
            # invent a "device" for every server on the internet, all
            # wearing the router's MAC.
            self._note_router_mac(mac)

        elif mac in self._local_macs and mac not in self._router_macs:
            # IPv6 has no NAT: a device on this network holds a globally
            # routable address of its own, so a public source address is not
            # evidence of forwarding the way it is for IPv4. The MAC is what
            # separates the two cases, and this one is already known to
            # belong to a device here rather than to a router.
            self._touch(packet.src_ip, packet.src_mac, now,
                        packet.hostname_hint, packet.hostname_source)

    def remember_name(self, mac: Optional[str], hostname: Optional[str],
                      source: Optional[str] = None) -> None:
        """Record what a device is called without claiming it is here.

        A DHCP lease table is a record of addresses handed out, not of who is
        on the network now: leases outlive the connection by hours, so
        treating each one as a sighting fills the dashboard with devices that
        left this morning. The name is worth keeping either way, and attaches
        to the device the moment it does send something.
        """
        self._remember_name(mac, hostname, source)

    def _remember_name(self, mac: Optional[str], hostname_hint: Optional[str],
                       hostname_source: Optional[str] = None,
                       fallback_key: Optional[str] = None):
        """Record the best name known for a device, and return it.

        Keyed by MAC so it survives the device changing address, falling back
        to the address only when no MAC is known.
        """
        key = _normalize_mac(mac) if mac else fallback_key
        if key is None:
            return None

        alias = self._aliases.get(_normalize_mac(mac)) if mac else None
        if alias:
            candidate = (alias, _ALIAS_QUALITY)  # user-configured, always wins
        elif hostname_hint:
            candidate = (hostname_hint, name_quality(hostname_hint, hostname_source))
        else:
            candidate = None

        # Keep the best name seen for this device, not the first. A phone
        # that announces a generic model name over DHCP before its
        # personalised mDNS name would otherwise be stuck with the generic
        # one for the rest of the capture.
        best = self._best_name.get(key)
        if candidate is not None and (best is None or candidate[1] > best[1]):
            best = candidate
            self._best_name[key] = candidate
            # One device can hold several addresses at once, and each is a
            # separate entry. Without this the entries drift apart: the one
            # that happened to receive the better name shows it and the rest
            # keep whatever they were given first, which reads as two
            # different devices.
            for device in self._devices.values():
                if mac and _normalize_mac(device.mac or "") == key:
                    device.hostname = best[0]
        return best

    def _note_router_mac(self, mac: str) -> None:
        """Record a MAC seen forwarding traffic, and undo any damage it did.

        Until the first forwarded packet arrives there is nothing to
        distinguish a router from any other device, so IPv6 traffic seen
        before that point may already have registered remote servers as
        devices under this MAC. Those entries are dropped here rather than
        left to linger, since they would otherwise persist for the whole
        capture.
        """
        if mac in self._router_macs:
            return
        self._router_macs.add(mac)
        stale = [address for address, device in self._by_address.items()
                 if _normalize_mac(device.mac or "") == mac and not _is_local_ip(address)]
        for address in stale:
            device = self._by_address.pop(address)
            if address in device.addresses:
                device.addresses.remove(address)
            if device.addresses:
                device.ip = _primary_address(device.addresses)
            else:
                self._devices.pop(_normalize_mac(device.mac or "") or device.ip, None)

    def _touch(self, ip: str, mac: str, when: datetime, hostname_hint: Optional[str] = None,
               hostname_source: Optional[str] = None) -> None:
        # A device is its MAC. The address is only how it was reached this
        # time, and one device holds several at once.
        identity = _normalize_mac(mac) if mac else ip
        device = self._devices.get(identity)
        is_new = device is None
        if device is None:
            device = Device(ip=ip, addresses=[ip], mac=mac,
                            vendor=lookup_vendor(mac), first_seen=when, last_seen=when)
            self._devices[identity] = device
        else:
            if not device.mac:
                device.mac = mac
                device.vendor = lookup_vendor(mac)
            if ip not in device.addresses:
                device.addresses.append(ip)
                device.ip = _primary_address(device.addresses)
            device.touch(when)
        self._by_address[ip] = device

        best = self._remember_name(mac, hostname_hint, hostname_source, fallback_key=ip)
        if best is not None:
            # Assigned every time rather than only on improvement: the
            # device object is keyed by IP, so a device that picks up a new
            # DHCP lease arrives here as a fresh record with no name.
            device.hostname = best[0]

        # Re-stamped on every touch (not just on creation) so a device that
        # picks up its MAC late, or moves to a new IP, still lands in the
        # right group.
        device.group = self._groups.group_for_mac(mac or device.mac)

        # Worth asking for a name when we have none, and also when all we
        # have is a model name -- reverse DNS or NBSTAT may know the
        # personalised one that the device never broadcast.
        if self._active_resolve and is_new and (best is None or best[1] < 10):
            self._schedule_active_resolution(ip, _normalize_mac(mac) if mac else ip)

    def _schedule_active_resolution(self, ip: str, key: str) -> None:
        # Only worth asking once per IP -- if nobody answers the first
        # time, asking again mid-capture won't change that.
        if ip in self._resolve_attempted:
            return
        self._resolve_attempted.add(ip)

        def resolve_and_apply() -> None:
            name = self._resolver(ip)
            if not name:
                return
            device = self._by_address.get(ip)
            if device is None:
                return
            # Re-check the score rather than the name: a passive hint may
            # have landed while this lookup was in flight, and a slow
            # answer must not overwrite a better one that arrived first.
            quality = name_quality(name, "active")
            known = self._best_name.get(key)
            if known is None or quality > known[1]:
                device.hostname = name
                self._best_name[key] = (name, quality)

        self._run_async(resolve_and_apply)

    def get(self, ip: str) -> Optional[Device]:
        """The device holding this address, whichever of its addresses it is."""
        return self._by_address.get(ip)

    def all_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: d.ip)


def _spawn_daemon_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()
