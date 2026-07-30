from datetime import datetime, timedelta, timezone

from activitygraph.device_id import DeviceRegistry
from activitygraph.flow_processor import FlowProcessor
from activitygraph.models import Packet
from activitygraph.service_detector import ServiceDetector
from activitygraph.service_rules import classify_domain, registrable_domain


def test_classify_domain_study_example():
    match = classify_domain("canvas.instructure.com")
    assert match is not None
    assert match.category == "Study"


def test_classify_domain_entertainment_example():
    match = classify_domain("youtube.com")
    assert match is not None
    assert match.category == "Entertainment"
    assert match.service == "YouTube"


def test_registrable_domain_handles_edu_au():
    assert registrable_domain("canvas.example.edu.au") == "example.edu.au"
    assert registrable_domain("www.google.com") == "google.com"


def test_device_registry_learns_vendor_from_arp():
    reg = DeviceRegistry()
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33",
    ))
    device = reg.get("192.168.1.5")
    assert device is not None
    assert device.vendor == "Google"


def test_device_registry_learns_hostname_from_passive_hint():
    reg = DeviceRegistry()
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33", hostname_hint="Alices MacBook Pro",
    ))
    device = reg.get("192.168.1.5")
    assert device.hostname == "Alices MacBook Pro"
    assert device.display_name() == "Alices MacBook Pro"


def test_device_registry_hostname_is_sticky_first_hint_wins():
    reg = DeviceRegistry()
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33", hostname_hint="First Name",
    ))
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33", hostname_hint="Second Name",
    ))
    assert reg.get("192.168.1.5").hostname == "First Name"


def test_device_alias_overrides_passive_hostname():
    reg = DeviceRegistry(aliases={"3C:5A:B4:11:22:33": "Alice's Laptop"})
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33", hostname_hint="some-passive-name",
    ))
    assert reg.get("192.168.1.5").hostname == "Alice's Laptop"


def test_device_alias_matching_is_case_insensitive():
    reg = DeviceRegistry(aliases={"3c:5a:b4:11:22:33": "Alice's Laptop"})
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33",
    ))
    assert reg.get("192.168.1.5").hostname == "Alice's Laptop"


def test_display_name_falls_back_through_hostname_vendor_ip():
    from activitygraph.models import Device
    now = datetime.now(timezone.utc)
    named = Device(ip="192.168.1.5", mac="3C:5A:B4:11:22:33", vendor="Google", hostname="My Phone", first_seen=now, last_seen=now)
    vendor_only = Device(ip="192.168.1.6", mac="3C:5A:B4:11:22:34", vendor="Apple", hostname=None, first_seen=now, last_seen=now)
    ip_only = Device(ip="192.168.1.7", mac=None, vendor="Unknown", hostname=None, first_seen=now, last_seen=now)
    assert named.display_name() == "My Phone"
    assert vendor_only.display_name() == "Apple"
    assert ip_only.display_name() == "192.168.1.7"


def test_load_aliases_from_json_file(tmp_path):
    from activitygraph.device_id import load_aliases
    alias_file = tmp_path / "aliases.json"
    alias_file.write_text('{"AA:BB:CC:DD:EE:FF": "Router", "11:22:33:44:55:66": "Phone"}')
    aliases = load_aliases(str(alias_file))
    assert aliases["AA:BB:CC:DD:EE:FF"] == "Router"
    assert aliases["11:22:33:44:55:66"] == "Phone"


def test_load_aliases_missing_file_returns_empty_dict():
    from activitygraph.device_id import load_aliases
    aliases = load_aliases("/nonexistent/path/aliases.json")
    assert aliases == {}


def test_load_aliases_malformed_json_returns_empty_dict(tmp_path):
    from activitygraph.device_id import load_aliases
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not valid json {{{")
    aliases = load_aliases(str(bad_file))
    assert aliases == {}


def _sync_run_async(fn):
    """Test stand-in for DeviceRegistry's default background-thread dispatch --
    runs the resolution job immediately, inline, so assertions don't race a thread."""
    fn()


def test_active_resolve_fills_in_name_when_no_alias_or_hint():
    reg = DeviceRegistry(active_resolve=True, resolver=lambda ip: "Kitchen Chromecast", run_async=_sync_run_async)
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33",
    ))
    assert reg.get("192.168.1.5").hostname == "Kitchen Chromecast"


def test_active_resolve_does_not_override_alias():
    reg = DeviceRegistry(
        aliases={"3C:5A:B4:11:22:33": "Alice's Laptop"},
        active_resolve=True,
        resolver=lambda ip: "some-other-name",
        run_async=_sync_run_async,
    )
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33",
    ))
    assert reg.get("192.168.1.5").hostname == "Alice's Laptop"


def test_active_resolve_does_not_override_passive_hint():
    reg = DeviceRegistry(active_resolve=True, resolver=lambda ip: "active-name", run_async=_sync_run_async)
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33", hostname_hint="passive-name",
    ))
    assert reg.get("192.168.1.5").hostname == "passive-name"


def test_active_resolve_only_attempted_once_per_ip():
    calls = []
    reg = DeviceRegistry(
        active_resolve=True,
        resolver=lambda ip: calls.append(ip) or None,
        run_async=_sync_run_async,
    )
    now = datetime.now(timezone.utc)
    for _ in range(3):
        reg.observe(Packet(
            timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
            length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
            arp_sender_mac="3C:5A:B4:11:22:33",
        ))
    assert calls == ["192.168.1.5"]


def test_active_resolve_off_by_default():
    calls = []
    reg = DeviceRegistry(resolver=lambda ip: calls.append(ip) or "name", run_async=_sync_run_async)
    now = datetime.now(timezone.utc)
    reg.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="192.168.1.1", proto="ARP",
        length=42, src_mac="3C:5A:B4:11:22:33", arp_sender_ip="192.168.1.5",
        arp_sender_mac="3C:5A:B4:11:22:33",
    ))
    assert calls == []
    assert reg.get("192.168.1.5").hostname is None


def test_flow_processor_aggregates_packets():
    fp = FlowProcessor(idle_timeout_seconds=1.0)
    now = datetime.now(timezone.utc)
    for i in range(5):
        fp.process(Packet(
            timestamp=now + timedelta(milliseconds=i * 10),
            src_ip="192.168.1.5", dst_ip="93.184.216.34", proto="TCP",
            length=500, src_port=51000, dst_port=443,
        ))
    flows = fp.all_flows()
    assert len(flows) == 1
    assert flows[0].packet_count == 5
    assert flows[0].byte_count == 2500


def test_service_detector_uses_sni_over_dns():
    detector = ServiceDetector()
    now = datetime.now(timezone.utc)
    detector.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="1.2.3.4", proto="TCP",
        length=100, src_port=51000, dst_port=443, tls_sni="canvas.instructure.com",
    ))
    from activitygraph.models import Flow
    flow = Flow(
        src_ip="192.168.1.5", dst_ip="1.2.3.4", src_port=51000, dst_port=443,
        proto="TCP", start_time=now, end_time=now,
    )
    detector.apply(flow)
    assert flow.category == "Study"
    assert flow.service == "Canvas LMS"


def test_service_detector_classifies_reply_direction_flow_correctly():
    """Regression test: a TCP conversation produces two separate Flow
    objects (one per direction). The SNI is only ever observed on the
    client->server packet, but both directions of the same conversation
    must resolve to the same service -- otherwise half of every
    conversation's bytes get miscategorized as generic 'HTTPS'."""
    from activitygraph.models import Flow
    detector = ServiceDetector()
    now = datetime.now(timezone.utc)
    # SNI observed on the outbound (device -> server) packet, as it always is.
    detector.observe(Packet(
        timestamp=now, src_ip="192.168.1.5", dst_ip="1.2.3.4", proto="TCP",
        length=100, src_port=51000, dst_port=443, tls_sni="youtube.com",
    ))

    forward_flow = Flow(
        src_ip="192.168.1.5", dst_ip="1.2.3.4", src_port=51000, dst_port=443,
        proto="TCP", start_time=now, end_time=now,
    )
    reply_flow = Flow(
        src_ip="1.2.3.4", dst_ip="192.168.1.5", src_port=443, dst_port=51000,
        proto="TCP", start_time=now, end_time=now,
    )
    detector.apply(forward_flow)
    detector.apply(reply_flow)

    assert forward_flow.category == "Entertainment"
    assert reply_flow.category == "Entertainment"
    assert forward_flow.service == reply_flow.service == "YouTube"


def test_service_detector_unknown_falls_back_gracefully():
    from activitygraph.models import Flow
    detector = ServiceDetector()
    now = datetime.now(timezone.utc)
    flow = Flow(
        src_ip="192.168.1.5", dst_ip="9.9.9.9", src_port=51000, dst_port=443,
        proto="TCP", start_time=now, end_time=now,
    )
    detector.apply(flow)
    assert flow.service == "HTTPS"
    assert flow.category == "Web Browsing"


def test_summary_keeps_all_original_keys_and_adds_time_totals():
    """The time/grouping work must be purely additive -- the dashboard,
    storage and JSON output all read the original keys."""
    from activitygraph.main import run_demo
    summary = run_demo(idle_timeout=5.0).summary()
    for key in ("generated_at", "devices", "flows", "sessions", "category_breakdown",
                "ranked_devices", "ranked_services", "ranked_categories"):
        assert key in summary, f"regression: summary lost '{key}'"
    assert "time_totals" in summary
    assert "groups" in summary
    assert {"min_activity_seconds", "total_active_seconds", "by_category", "by_group",
            "by_device"} <= set(summary["time_totals"])


def test_summary_time_by_device_includes_every_known_device():
    """A device with no captured traffic must still be listed, so a phone
    found via the router reads '0m' rather than silently disappearing."""
    from activitygraph.main import run_demo
    summary = run_demo(idle_timeout=5.0).summary()
    listed = {r["device_ip"] for r in summary["time_totals"]["by_device"]}
    assert listed == {d["ip"] for d in summary["devices"]}


def test_summary_group_time_is_union_not_sum():
    from activitygraph.main import run_demo
    pipeline = run_demo(idle_timeout=5.0, device_groups={
        "3C:5A:B4:11:22:33": "Alice", "AC:87:A3:44:55:66": "Alice",
    })
    groups = {g["group"]: g for g in pipeline.summary()["time_totals"]["by_group"]}
    alice = groups["Alice"]
    assert alice["device_count"] == 2
    # Overlapping devices: wall-clock union is strictly less than device-time sum.
    assert alice["seconds"] < alice["device_seconds"]
