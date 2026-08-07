"""Claiming a device puts it in its owner's group.

It did not. The label goes through the alias mechanism, so a claimed phone
showed "sam's Android-Phone" and a claimed laptop showed "sam's laptop",
and both sat under Ungrouped. AccountStore.group_map() existed and had a
test of its own; nothing in the application ever called it. The dashboard's
whole premise is per-person totals, so the one thing it could not answer was
the thing it is for.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

from activitygraph.accounts import AccountStore
from activitygraph.device_groups import UNGROUPED, GroupRegistry
from activitygraph.device_id import DeviceRegistry
from activitygraph.main import run_demo
from activitygraph.models import Packet
from activitygraph.server import BackgroundCapture, create_app

PHONE = "AA:BB:CC:00:00:11"
LAPTOP = "AA:BB:CC:00:00:12"
OTHER = "AA:BB:CC:00:00:13"


def seen(registry, ip, mac):
    registry.observe(Packet(timestamp=datetime.now(timezone.utc), src_ip=ip,
                            dst_ip="1.1.1.1", src_port=5000, dst_port=443,
                            proto="TCP", length=100, src_mac=mac))


@pytest.fixture
def accounts():
    store = AccountStore(sqlite3.connect(":memory:"))
    store.create_user("theadmin", "password123")
    sam = store.create_user("sam", "password123")
    store.claim_device(sam.id, PHONE, "Android-Phone")
    store.claim_device(sam.id, LAPTOP, "laptop")
    return store


# ---------------- the registry ----------------

def test_two_devices_one_person_land_in_one_group(accounts):
    registry = DeviceRegistry()
    seen(registry, "192.168.50.64", PHONE)
    seen(registry, "192.168.50.137", LAPTOP)

    registry.set_groups(accounts.group_map())
    groups = {d.mac: d.group for d in registry.all_devices()}
    assert groups[PHONE] == groups[LAPTOP] == "sam's group"


def test_an_unclaimed_device_stays_ungrouped(accounts):
    registry = DeviceRegistry()
    seen(registry, "192.168.50.2", OTHER)
    registry.set_groups(accounts.group_map())
    assert registry.all_devices()[0].group == UNGROUPED


def test_a_device_seen_after_the_claim_is_grouped_too(accounts):
    """The order matters: a phone that joins the network later must not need
    claiming a second time."""
    registry = DeviceRegistry()
    registry.set_groups(accounts.group_map())
    seen(registry, "192.168.50.64", PHONE)
    assert registry.all_devices()[0].group == "sam's group"


def test_a_configured_group_file_still_works(accounts):
    """Claims are layered over --device-groups rather than replacing it."""
    registry = DeviceRegistry(groups=GroupRegistry({OTHER: "Household"}))
    seen(registry, "192.168.50.2", OTHER)
    seen(registry, "192.168.50.64", PHONE)

    registry.set_groups(accounts.group_map())
    by_mac = {d.mac: d.group for d in registry.all_devices()}
    assert by_mac[OTHER] == "Household"
    assert by_mac[PHONE] == "sam's group"


def test_a_claim_wins_over_the_file(accounts):
    """The more recent statement, made by somebody holding the device."""
    registry = DeviceRegistry(groups=GroupRegistry({PHONE: "Spare"}))
    seen(registry, "192.168.50.64", PHONE)
    registry.set_groups(accounts.group_map())
    assert registry.all_devices()[0].group == "sam's group"


def test_releasing_a_device_returns_it_to_ungrouped(accounts):
    registry = DeviceRegistry()
    seen(registry, "192.168.50.64", PHONE)
    registry.set_groups(accounts.group_map())

    sam = accounts.get_user(2)
    accounts.release_device(sam.id, PHONE)
    registry.set_groups(accounts.group_map())
    assert registry.all_devices()[0].group == UNGROUPED


# ---------------- wired into the app ----------------

def test_building_the_app_applies_groups(accounts):
    """create_app applies claims at startup, so a restart does not lose
    them."""
    pipeline = run_demo(idle_timeout=5.0)
    seen(pipeline.devices, "192.168.50.64", PHONE)
    create_app(pipeline, live=False, accounts=accounts, secret=b"x" * 32)

    claimed = [d for d in pipeline.devices.all_devices() if d.mac == PHONE][0]
    assert claimed.group == "sam's group"
    assert claimed.display_name() == "sam's Android-Phone", "the name still applies"


def test_a_background_pass_reapplies_groups(accounts):
    """Self-healing, so a device that appears between claims still lands in
    the right group without anyone claiming it twice."""
    pipeline = run_demo(idle_timeout=5.0)
    capture = BackgroundCapture(pipeline, accounts=accounts)
    seen(pipeline.devices, "192.168.50.137", LAPTOP)

    capture._flush_once()
    grouped = [d for d in pipeline.devices.all_devices() if d.mac == LAPTOP][0]
    assert grouped.group == "sam's group"
