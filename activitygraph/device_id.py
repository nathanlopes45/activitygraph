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
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper()


# How much a name source is worth. mDNS names are usually the one the owner
# typed into their device's settings; a DHCP option 12 hostname is often
# just the model. Active resolution is the weakest -- it is a fallback for
# devices that announced nothing at all.
_SOURCE_RANK = {"mdns": 3, "nbns": 2, "dhcp": 1, "lease": 1, "active": 0}

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
    ) -> None:
        self._devices: dict[str, Device] = {}  # keyed by IP
        self._aliases = {_normalize_mac(mac): name for mac, name in (aliases or {}).items()}
        self._groups = groups or GroupRegistry()
        self._active_resolve = active_resolve
        self._resolver = resolver
        self._run_async = run_async or _spawn_daemon_thread
        self._resolve_attempted: set[str] = set()
        # Best name seen for each device and its score, keyed by MAC where
        # known so it survives a DHCP lease moving the device to a new IP.
        self._best_name: dict[str, tuple[str, int]] = {}

    def observe(self, packet: Packet) -> None:
        now = packet.timestamp

        if packet.arp_sender_ip and packet.arp_sender_mac:
            self._touch(packet.arp_sender_ip, packet.arp_sender_mac, now,
                        packet.hostname_hint, packet.hostname_source)
            return

        # Fall back to source IP/MAC on any packet, which covers devices
        # that never show up in ARP traffic during the capture window --
        # but only for local IPs (see _is_local_ip). A remote server's IP
        # paired with your router's MAC is not a device.
        if packet.src_ip and packet.src_mac and _is_local_ip(packet.src_ip):
            self._touch(packet.src_ip, packet.src_mac, now,
                        packet.hostname_hint, packet.hostname_source)

    def _touch(self, ip: str, mac: str, when: datetime, hostname_hint: Optional[str] = None,
               hostname_source: Optional[str] = None) -> None:
        device = self._devices.get(ip)
        is_new = device is None
        if device is None:
            device = Device(ip=ip, mac=mac, vendor=lookup_vendor(mac), first_seen=when, last_seen=when)
            self._devices[ip] = device
        else:
            if not device.mac:
                device.mac = mac
                device.vendor = lookup_vendor(mac)
            device.touch(when)

        key = _normalize_mac(mac) if mac else ip
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
            self._schedule_active_resolution(ip, key)

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
            device = self._devices.get(ip)
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
        return self._devices.get(ip)

    def all_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: d.ip)


def _spawn_daemon_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()
