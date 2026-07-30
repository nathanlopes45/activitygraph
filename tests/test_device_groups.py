from datetime import datetime, timezone

from activitygraph.device_groups import UNGROUPED, GroupRegistry, load_device_groups
from activitygraph.device_id import DeviceRegistry
from activitygraph.models import Device, Packet


def _write(tmp_path, text):
    path = tmp_path / "groups.json"
    path.write_text(text)
    return str(path)


def _arp(ip, mac, hostname_hint=None):
    return Packet(
        timestamp=datetime.now(timezone.utc), src_ip=ip, dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac=mac, arp_sender_ip=ip, arp_sender_mac=mac, hostname_hint=hostname_hint,
    )


# ---------------- load_device_groups ----------------

def test_load_inverts_group_to_mac_mapping(tmp_path):
    path = _write(tmp_path, '{"Alice": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"], "Family": ["99:88:77:66:55:44"]}')
    assert load_device_groups(path) == {
        "AA:BB:CC:DD:EE:FF": "Alice",
        "11:22:33:44:55:66": "Alice",
        "99:88:77:66:55:44": "Family",
    }


def test_load_normalizes_mac_case(tmp_path):
    path = _write(tmp_path, '{"Alice": ["aa:bb:cc:dd:ee:ff"]}')
    assert load_device_groups(path) == {"AA:BB:CC:DD:EE:FF": "Alice"}


def test_load_missing_file_returns_empty():
    assert load_device_groups("/nonexistent/groups.json") == {}


def test_load_malformed_json_returns_empty(tmp_path):
    assert load_device_groups(_write(tmp_path, "not json {{{")) == {}


def test_load_non_object_returns_empty(tmp_path):
    assert load_device_groups(_write(tmp_path, '["not", "an", "object"]')) == {}


def test_load_duplicate_mac_keeps_first_group(tmp_path):
    """One device, one group -- otherwise 'sum of groups == total' is false
    and the union math becomes ambiguous."""
    path = _write(tmp_path, '{"Alice": ["AA:BB:CC:DD:EE:FF"], "Family": ["AA:BB:CC:DD:EE:FF"]}')
    assert load_device_groups(path) == {"AA:BB:CC:DD:EE:FF": "Alice"}


def test_load_tolerates_bare_string_instead_of_list(tmp_path):
    path = _write(tmp_path, '{"Alice": "AA:BB:CC:DD:EE:FF"}')
    assert load_device_groups(path) == {"AA:BB:CC:DD:EE:FF": "Alice"}


def test_load_skips_group_with_invalid_value(tmp_path):
    path = _write(tmp_path, '{"Alice": 42, "Family": ["11:22:33:44:55:66"]}')
    assert load_device_groups(path) == {"11:22:33:44:55:66": "Family"}


# ---------------- GroupRegistry ----------------

def test_group_for_mac_is_case_insensitive():
    reg = GroupRegistry({"aa:bb:cc:dd:ee:ff": "Alice"})
    assert reg.group_for_mac("AA:BB:CC:DD:EE:FF") == "Alice"


def test_unknown_mac_falls_back_to_ungrouped():
    assert GroupRegistry({}).group_for_mac("AA:BB:CC:DD:EE:FF") == UNGROUPED


def test_missing_mac_falls_back_to_ungrouped():
    assert GroupRegistry({"AA:BB:CC:DD:EE:FF": "Alice"}).group_for_mac(None) == UNGROUPED


def test_devices_by_group():
    now = datetime.now(timezone.utc)
    reg = GroupRegistry({"AA:BB:CC:DD:EE:FF": "Alice"})
    devices = [
        Device(ip="192.168.1.5", mac="AA:BB:CC:DD:EE:FF", first_seen=now, last_seen=now, group="Alice"),
        Device(ip="192.168.1.6", mac="11:22:33:44:55:66", first_seen=now, last_seen=now),
    ]
    grouped = reg.devices_by_group(devices)
    assert [d.ip for d in grouped["Alice"]] == ["192.168.1.5"]
    assert [d.ip for d in grouped[UNGROUPED]] == ["192.168.1.6"]


# ---------------- DeviceRegistry integration ----------------

def test_device_registry_stamps_group_from_mac():
    reg = DeviceRegistry(groups=GroupRegistry({"3C:5A:B4:11:22:33": "Alice"}))
    reg.observe(_arp("192.168.1.5", "3C:5A:B4:11:22:33"))
    assert reg.get("192.168.1.5").group == "Alice"


def test_device_registry_marks_unknown_device_ungrouped():
    reg = DeviceRegistry(groups=GroupRegistry({"3C:5A:B4:11:22:33": "Alice"}))
    reg.observe(_arp("192.168.1.9", "AA:AA:AA:AA:AA:AA"))
    assert reg.get("192.168.1.9").group == UNGROUPED


def test_device_registry_without_groups_still_works():
    reg = DeviceRegistry()
    reg.observe(_arp("192.168.1.5", "3C:5A:B4:11:22:33"))
    assert reg.get("192.168.1.5").group == UNGROUPED


def test_alias_and_group_coexist():
    reg = DeviceRegistry(
        aliases={"3C:5A:B4:11:22:33": "Alice's Laptop"},
        groups=GroupRegistry({"3C:5A:B4:11:22:33": "Alice"}),
    )
    reg.observe(_arp("192.168.1.5", "3C:5A:B4:11:22:33", hostname_hint="passive-name"))
    device = reg.get("192.168.1.5")
    assert device.hostname == "Alice's Laptop"
    assert device.group == "Alice"


def test_device_to_dict_includes_group():
    reg = DeviceRegistry(groups=GroupRegistry({"3C:5A:B4:11:22:33": "Alice"}))
    reg.observe(_arp("192.168.1.5", "3C:5A:B4:11:22:33"))
    assert reg.get("192.168.1.5").to_dict()["group"] == "Alice"
