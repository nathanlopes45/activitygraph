"""Device grouping: which devices belong to the same person.

The rest of the pipeline is keyed by IP, which means a person with a phone
and a laptop shows up as two unrelated rows. This module adds the missing
notion of "these devices are all me", so the dashboard can answer "where
did *I* spend my time" rather than "what did this IP do".

Groups are keyed by **MAC**, not IP, for the same reason device aliases are
(see device_id.load_aliases): DHCP hands out different IPs across leases,
but a device's MAC is stable.

The config file is written group -> MACs, because that's the natural way to
think about it ("Alice owns these three things"):

    {"Alice": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"], "Family": [...]}

...and inverted internally to MAC -> group, because that's the natural way
to look it up when a packet arrives.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .models import Device

# Devices with no configured group land here rather than being dropped --
# a dashboard that silently hides your unconfigured devices is worse than
# one that shows them in a catch-all.
UNGROUPED = "Ungrouped"


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper()


def load_device_groups(path: str) -> dict[str, str]:
    """Load a group -> [MACs] JSON file, returning the inverted MAC -> group
    mapping with MACs normalized to uppercase.

    Follows load_aliases' philosophy: a malformed or missing config prints a
    warning and yields an empty mapping rather than crashing. A typo in a
    grouping file shouldn't take down capture.
    """
    try:
        raw = json.loads(Path(path).expanduser().read_text())
    except FileNotFoundError:
        print(f"[activitygraph] Warning: --device-groups file not found: {path}")
        return {}
    except (json.JSONDecodeError, AttributeError, TypeError):
        print(f"[activitygraph] Warning: --device-groups file is not valid JSON: {path}")
        return {}

    if not isinstance(raw, dict):
        print(f"[activitygraph] Warning: --device-groups file must be an object of group -> [MACs]: {path}")
        return {}

    mac_to_group: dict[str, str] = {}
    for group, macs in raw.items():
        if isinstance(macs, str):  # tolerate a single MAC written without a list
            macs = [macs]
        if not isinstance(macs, list):
            print(f"[activitygraph] Warning: group '{group}' in {path} is not a list of MACs; skipping.")
            continue
        for mac in macs:
            if not isinstance(mac, str) or not mac.strip():
                continue
            key = _normalize_mac(mac)
            if key in mac_to_group and mac_to_group[key] != group:
                # One device, one group: multi-membership would make
                # "sum of groups == total" false and the union math ambiguous.
                print(
                    f"[activitygraph] Warning: MAC {key} is listed under both "
                    f"'{mac_to_group[key]}' and '{group}'; keeping '{mac_to_group[key]}'."
                )
                continue
            mac_to_group[key] = group
    return mac_to_group


class GroupRegistry:
    """Looks up which group a device belongs to. Empty registry is valid --
    everything then falls under UNGROUPED, so the zero-config path still
    renders a populated dashboard."""

    def __init__(self, mac_to_group: Optional[dict[str, str]] = None) -> None:
        self._mac_to_group = {
            _normalize_mac(mac): group for mac, group in (mac_to_group or {}).items()
        }

    def mapping(self) -> dict[str, str]:
        """A copy of MAC -> group, so callers can extend it without
        reaching into the registry or losing what a config file set."""
        return dict(self._mac_to_group)

    def group_for_mac(self, mac: Optional[str]) -> str:
        if not mac:
            return UNGROUPED
        return self._mac_to_group.get(_normalize_mac(mac), UNGROUPED)

    def group_for_device(self, device: Device) -> str:
        return self.group_for_mac(device.mac)

    def devices_by_group(self, devices: list[Device]) -> dict[str, list[Device]]:
        grouped: dict[str, list[Device]] = {}
        for device in devices:
            grouped.setdefault(device.group or self.group_for_device(device), []).append(device)
        return grouped