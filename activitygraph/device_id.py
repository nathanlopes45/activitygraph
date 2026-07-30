"""Device identification: builds an IP<->MAC<->vendor table from local traffic.

Devices are discovered passively (from ARP traffic and observed source MACs
on the LAN) rather than by actively scanning, to stay unobtrusive by default.
An active ARP sweep is offered separately for users who want faster discovery.

Device *names* come from three sources, in priority order:
  1. A user-supplied alias (see load_aliases) -- always wins, since you know
     your own devices better than any protocol guess.
  2. Passively-observed hostnames (mDNS/.local names, NetBIOS names, DHCP
     hostname options -- see collector.py's _extract_hostname_hint). Sticky:
     the first successful guess is kept, rather than flip-flopping if a
     device broadcasts slightly different names on different protocols.
  3. Active resolution (see active_resolver.py), opt-in via active_resolve=
     True -- asks each newly-seen device directly (reverse DNS / unicast
     mDNS / NBSTAT), the same way a router resolves names for its own
     admin UI. Runs off-thread so it never blocks packet capture, and only
     fills in a name that's still empty by the time it completes -- so it
     can race with a slightly-later passive hint, but never overrides an
     alias or an already-set hostname.

Not every device announces a name on every network (this varies by OS and
network config), so some devices will still only show a vendor or IP --
that's an honest "we don't know," not a bug.
"""
from __future__ import annotations

import ipaddress
import json
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

    def observe(self, packet: Packet) -> None:
        now = packet.timestamp

        if packet.arp_sender_ip and packet.arp_sender_mac:
            self._touch(packet.arp_sender_ip, packet.arp_sender_mac, now, packet.hostname_hint)
            return

        # Fall back to source IP/MAC on any packet, which covers devices
        # that never show up in ARP traffic during the capture window --
        # but only for local IPs (see _is_local_ip). A remote server's IP
        # paired with your router's MAC is not a device.
        if packet.src_ip and packet.src_mac and _is_local_ip(packet.src_ip):
            self._touch(packet.src_ip, packet.src_mac, now, packet.hostname_hint)

    def _touch(self, ip: str, mac: str, when: datetime, hostname_hint: Optional[str] = None) -> None:
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

        alias = self._aliases.get(_normalize_mac(mac)) if mac else None
        if alias:
            device.hostname = alias  # user-configured, always wins
        elif hostname_hint and not device.hostname:
            device.hostname = hostname_hint  # first passive guess, sticky

        # Re-stamped on every touch (not just on creation) so a device that
        # picks up its MAC late, or moves to a new IP, still lands in the
        # right group.
        device.group = self._groups.group_for_mac(mac or device.mac)

        if self._active_resolve and is_new and not device.hostname:
            self._schedule_active_resolution(ip)

    def _schedule_active_resolution(self, ip: str) -> None:
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
            if device is not None and not device.hostname:
                device.hostname = name

        self._run_async(resolve_and_apply)

    def get(self, ip: str) -> Optional[Device]:
        return self._devices.get(ip)

    def all_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: d.ip)


def _spawn_daemon_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()
