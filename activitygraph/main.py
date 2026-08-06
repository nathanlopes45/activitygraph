"""ActivityGraph backend core CLI.

    Network -> Traffic Collector -> Flow Processor -> Service Detection -> [Devices]

Two modes:
  --demo            Run against a synthetic packet stream (no root needed).
  --live -i <iface>  Capture real traffic (needs root / CAP_NET_RAW).

This is the "backend core" slice: capture, device identification, and
service-tagged flows. The AI Classification / Activity Graph / Dashboard
stages build on top of the Flow + Device objects produced here.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .activity_graph import Session, group_into_sessions
from .analytics import rank_categories, rank_devices, rank_services
from .collector import TrafficCollector, warn_if_capturing_wan
from .device_groups import GroupRegistry, load_device_groups
from .device_id import DeviceRegistry, load_aliases
from .demo_source import generate as generate_demo_packets
from .flow_processor import FlowProcessor
from .llm_classifier import LocalLLMClassifier
from .models import Packet
from .service_detector import ServiceDetector
from .service_rules import BACKGROUND_CATEGORIES
from .taxonomy import TaxonomyRegistry, load_taxonomy
from .time_analytics import (
    DEFAULT_MIN_ACTIVITY_SECONDS,
    format_duration,
    time_by_category_nested,
    time_by_device,
    time_by_group,
    total_active_seconds,
)


def _all_addresses(devices) -> set:
    """Every address held by any of these devices.

    Flows are matched by address while devices are keyed by MAC, so the
    join between them has to consider all of a device's addresses.
    """
    return {address for d in devices for address in (d.addresses or [d.ip])}


class Pipeline:
    def __init__(self, idle_timeout_seconds: float = 30.0, llm_classifier=None, session_gap_seconds: float = 300.0, device_aliases=None, active_resolve: bool = False, device_groups=None, min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS, taxonomy=None, name_store=None, exclude_macs=None) -> None:
        self.groups = GroupRegistry(device_groups)
        self.taxonomy = TaxonomyRegistry(taxonomy)
        self.devices = DeviceRegistry(aliases=device_aliases, active_resolve=active_resolve, groups=self.groups, exclude_macs=exclude_macs)
        self.flows = FlowProcessor(idle_timeout_seconds=idle_timeout_seconds)
        self.services = ServiceDetector(llm_classifier=llm_classifier, name_store=name_store)
        self.session_gap_seconds = session_gap_seconds
        self.min_activity_seconds = min_activity_seconds

    def ingest(self, packet: Packet) -> None:
        self.devices.observe(packet)
        self.services.observe(packet)
        if packet.proto in ("TCP", "UDP", "ICMP"):
            self.flows.process(packet)

    def finalize(self) -> None:
        for flow in self.flows.flush_all():
            self.services.apply(flow)
        # Also tag any flows that were already closed earlier in a run.
        for flow in self.flows.closed_flows():
            if flow.service is None:
                self.services.apply(flow)

    def sessions(self, local_ips=None) -> list[Session]:
        if local_ips is None:
            local_ips = _all_addresses(self.devices.all_devices())
        return group_into_sessions(self.flows.all_flows(), local_ips, session_gap_seconds=self.session_gap_seconds)

    def summary(self, visible_macs=None, only_macs=None, only_services=None,
                active_within_seconds=None, include_background=False) -> dict:
        """Everything the dashboard renders.

        `visible_macs` limits the result to devices with those MAC addresses,
        which is how a signed-in user is shown only the devices they have
        claimed. Passing None means no restriction, used for the admin view
        and for the CLI.

        `only_macs` and `only_services` narrow that further, and mean
        something different: they are what the viewer asked to look at, not
        what they are allowed to see. Applying them after the permission
        filter keeps that distinction, so a filter can never widen a view.
        Every figure is recomputed against the narrowed set rather than the
        finished payload being hidden, so the time totals answer "how long
        on this service" rather than restating the unfiltered number.
        """
        devices = self.devices.all_devices()
        flows = self.flows.all_flows()

        # Applied before anything else, so every figure below describes the
        # same window. A gateway runs for weeks, and without this the
        # dashboard accumulates every device and service ever seen, which
        # buries what is happening now under what happened on Tuesday. The
        # long view lives in --history-db, which this does not touch.
        if active_within_seconds:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_within_seconds)
            flows = [f for f in flows if f.end_time >= cutoff]
            devices = [d for d in devices if d.last_seen >= cutoff]

        # Restricting the *inputs* rather than filtering the finished payload
        # is what makes per-user scoping safe. Every figure below is derived
        # from `devices` and `flows`, so a panel added later is scoped
        # automatically. Post-filtering the output would leak any field
        # somebody forgot to add to the filter, which is exactly the kind of
        # mistake that stays invisible until it matters.
        if visible_macs is not None:
            allowed = {m.upper() for m in visible_macs}
            devices = [d for d in devices if (d.mac or "").upper() in allowed]
            visible_ips = _all_addresses(devices)
            flows = [f for f in flows
                     if f.src_ip in visible_ips or f.dst_ip in visible_ips]

        # The viewer's own narrowing, applied second so it can only ever
        # subtract from what the permission check already allowed.
        available_services = sorted({f.service for f in flows if f.service})
        available_devices = [
            {"mac": (d.mac or "").upper(), "name": d.display_name(), "ip": d.ip}
            for d in devices
        ]

        if only_macs:
            chosen = {m.upper() for m in only_macs}
            devices = [d for d in devices if (d.mac or "").upper() in chosen]
            chosen_ips = _all_addresses(devices)
            flows = [f for f in flows
                     if f.src_ip in chosen_ips or f.dst_ip in chosen_ips]

        if only_services:
            wanted = set(only_services)
            flows = [f for f in flows if f.service in wanted]
            # Devices with nothing left to show would otherwise sit in the
            # list at zero, which reads as "used it for no time" rather than
            # "did not use it".
            active_ips = {f.src_ip for f in flows} | {f.dst_ip for f in flows}
            devices = [d for d in devices
                       if any(a in active_ips for a in (d.addresses or [d.ip]))]

        # Everything derived below describes chosen activity, so the plumbing
        # comes out first: DNS, DHCP, clock sync, update checks, ad beacons.
        # The raw flows keep all of it, and the totals for what was set aside
        # are reported, so nothing disappears without saying so.
        if include_background:
            activity, background = flows, []
        else:
            activity = [f for f in flows if f.category not in BACKGROUND_CATEGORIES]
            background = [f for f in flows if f.category in BACKGROUND_CATEGORIES]

        by_category: dict[str, dict] = {}
        for f in activity:
            cat = f.category or "Uncategorized"
            bucket = by_category.setdefault(cat, {"flow_count": 0, "byte_count": 0, "services": set()})
            bucket["flow_count"] += 1
            bucket["byte_count"] += f.byte_count
            if f.service:
                bucket["services"].add(f.service)
        for bucket in by_category.values():
            bucket["services"] = sorted(bucket["services"])

        local_ips = _all_addresses(devices)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            # What the viewer could filter by, listed before their filter was
            # applied so the controls do not empty themselves on first use.
            "filter_options": {
                "devices": available_devices,
                "services": available_services,
            },
            # Only the filters that actually applied to something visible.
            # Echoing the request back verbatim would put a MAC belonging to
            # somebody else's device into the payload whenever one was named,
            # which is not a disclosure -- the caller supplied it -- but it
            # breaks the far more useful rule that no other user's
            # identifiers appear here at all, ever.
            "active_filters": {
                "devices": sorted({m.upper() for m in (only_macs or [])}
                                  & {d["mac"] for d in available_devices}),
                "services": sorted(set(only_services or []) & set(available_services)),
            },
            "background": {
                "categories": sorted(BACKGROUND_CATEGORIES),
                "flow_count": len(background),
                "byte_count": sum(f.byte_count for f in background),
                "included": include_background,
            },
            "devices": [d.to_dict() for d in devices],
            "flows": [f.to_dict() for f in flows],
            "sessions": [s.to_dict() for s in
                         group_into_sessions(activity, local_ips,
                                            session_gap_seconds=self.session_gap_seconds)],
            "category_breakdown": by_category,
            "ranked_devices": rank_devices(activity, devices),
            "ranked_services": rank_services(activity),
            "ranked_categories": rank_categories(activity),
            "groups": [
                {"name": name, "device_ips": [d.ip for d in members], "device_count": len(members)}
                for name, members in sorted(self.groups.devices_by_group(devices).items())
            ],
            "time_totals": {
                "min_activity_seconds": self.min_activity_seconds,
                # Wall-clock time any categorized activity was happening.
                # Categories are unioned independently, so the per-category
                # figures can add up to more than this when a device is doing
                # two things at once -- we can't know which had the user's
                # attention, so both numbers are reported rather than one
                # being invented.
                "total_active_seconds": total_active_seconds(activity, local_ips, self.min_activity_seconds),
                "by_category": time_by_category_nested(activity, local_ips, self.taxonomy, self.min_activity_seconds),
                "by_group": time_by_group(activity, devices, self.min_activity_seconds),
                "by_device": time_by_device(activity, devices, self.min_activity_seconds),
            },
        }


def run_demo(idle_timeout: float, llm_classifier=None, session_gap_seconds: float = 300.0, device_aliases=None, active_resolve: bool = False, device_groups=None, min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS, taxonomy=None) -> Pipeline:
    pipeline = Pipeline(idle_timeout_seconds=idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=session_gap_seconds, device_aliases=device_aliases, active_resolve=active_resolve, device_groups=device_groups, min_activity_seconds=min_activity_seconds, taxonomy=taxonomy)
    for packet in generate_demo_packets():
        pipeline.ingest(packet)
    pipeline.finalize()
    return pipeline


def run_live(interface: str | None, duration: float, idle_timeout: float, llm_classifier=None, session_gap_seconds: float = 300.0, device_aliases=None, active_resolve: bool = False, arp_sweep: bool = False, arp_sweep_subnet: str | None = None, arp_sweep_timeout: float = 3.0, router_devices: bool = False, router_credentials: str | None = None, device_groups=None, min_activity_seconds: float = DEFAULT_MIN_ACTIVITY_SECONDS, taxonomy=None, dhcp_leases: str | None = None, bpf_filter: str | None = None, exclude_macs=None) -> Pipeline:
    pipeline = Pipeline(idle_timeout_seconds=idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=session_gap_seconds, device_aliases=device_aliases, active_resolve=active_resolve, device_groups=device_groups, min_activity_seconds=min_activity_seconds, taxonomy=taxonomy, exclude_macs=exclude_macs)
    collector = (TrafficCollector(interface=interface, bpf_filter=bpf_filter)
                 if bpf_filter else TrafficCollector(interface=interface))
    warn_if_capturing_wan(interface)
    if dhcp_leases is not None:
        from .dhcp_leases import ingest_leases
        ingest_leases(pipeline, dhcp_leases or None)
    if router_devices:
        from .router_client import ingest_router_devices
        ingest_router_devices(pipeline, router_credentials)
    if arp_sweep:
        found = collector.arp_sweep_and_ingest(on_packet=pipeline.ingest, subnet=arp_sweep_subnet, timeout=arp_sweep_timeout)
        print(f"[activitygraph] ARP sweep found {found} device(s).")
    collector.run(on_packet=pipeline.ingest, timeout=duration)
    pipeline.finalize()
    return pipeline


def _format_bytes(n: int) -> str:
    if n == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    i = 0
    size = float(n)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.0f} {units[i]}" if i == 0 else f"{size:.1f} {units[i]}"


def print_report(pipeline: Pipeline) -> None:
    devices = pipeline.devices.all_devices()
    flows = pipeline.flows.all_flows()
    summary = pipeline.summary()

    print("\n=== Devices ===")
    for d in devices:
        name = d.display_name()
        suffix = "" if name == d.ip else f"  ({d.ip})"
        print(f"  {name}{suffix}  {d.mac or '?'}")

    print("\n=== Top Devices by Usage ===")
    if not summary["ranked_devices"]:
        print("  (no device traffic recorded)")
    for r in summary["ranked_devices"][:10]:
        print(f"  {r['display_name']:<24} {_format_bytes(r['byte_count']):>10}   {r['flow_count']} flows")

    time_totals = summary["time_totals"]

    print("\n=== Where Your Time Went ===")
    if not time_totals["by_category"]:
        print("  (no categorized activity yet)")
    for r in time_totals["by_category"]:
        print(f"  {r['category']:<24} {format_duration(r['seconds']):>10}")
        for sub in r.get("subcategories", []):
            print(f"    {sub['subcategory']:<22} {format_duration(sub['seconds']):>10}")
            for svc in sub["services"]:
                # Plain ASCII: this report gets piped and redirected, where
                # Windows falls back to cp1252 and box-drawing chars raise.
                print(f"        {svc['service']:<20} {format_duration(svc['seconds']):>10}")
    if time_totals["by_category"]:
        # Categories are unioned independently, so they can add up to more
        # than the wall clock when a device does two things at once.
        print(f"  {'-' * 24} {'-' * 10}")
        print(f"  {'Active (wall clock)':<24} {format_duration(time_totals['total_active_seconds']):>10}")

    print("\n=== Time by Person ===")
    if not time_totals["by_group"]:
        print("  (no devices grouped yet -- see --device-groups)")
    for g in time_totals["by_group"]:
        devices_note = f"{g['device_count']} device(s)"
        print(f"\n  {g['group']}  {format_duration(g['seconds'])}  ({devices_note}, "
              f"{format_duration(g['device_seconds'])} of device time)")
        for c in g["by_category"]:
            print(f"      {c['category']:<22} {format_duration(c['seconds']):>10}")

    print("\n=== Activity Graph ===")
    sessions_by_device: dict[str, list[Session]] = {}
    for s in pipeline.sessions():
        sessions_by_device.setdefault(s.device_ip, []).append(s)

    if not sessions_by_device:
        print("  (no sessions detected)")
    for device_ip, sessions in sessions_by_device.items():
        device = pipeline.devices.get(device_ip)
        label = device.display_name() if device else device_ip
        print(f"\n  {label} ({device_ip})")
        for s in sessions:
            time_range = f"{s.start_time.strftime('%H:%M')}\u2013{s.end_time.strftime('%H:%M')}"
            print(f"  \u2514\u2500\u2500 {s.title}  [{time_range}, {s.byte_count:,}B]")
            for i, svc in enumerate(s.services):
                connector = "\u2514\u2500\u2500" if i == len(s.services) - 1 else "\u251c\u2500\u2500"
                print(f"      {connector} {svc}")

    print("\n=== Flows (top 20 by bytes) ===")
    for f in sorted(flows, key=lambda x: -x.byte_count)[:20]:
        label = f.service or "Unknown"
        print(f"  {f.src_ip:<15} -> {f.dst_ip:<15}:{f.dst_port:<5} "
              f"[{f.proto}] {f.byte_count:>8}B  {label} ({f.category})")

    print("\n=== Top Services (ranked, most to least used) ===")
    print("  This is where 'Uncategorized' gets segregated: each unrecognized")
    print("  domain shows individually, so you can see exactly what to add a rule for.")
    if not summary["ranked_services"]:
        print("  (no services classified yet)")
    for r in summary["ranked_services"][:15]:
        print(f"  {r['service']:<40} {_format_bytes(r['byte_count']):>10}   {r['flow_count']:>3} flows   [{r['category']}]")

    print("\n=== Category Breakdown ===")
    for r in summary["ranked_categories"]:
        cat = r["category"]
        services = ", ".join(sorted(summary["category_breakdown"].get(cat, {}).get("services", []))) or "-"
        print(f"  {cat:<20} {r['flow_count']:>3} flows  {_format_bytes(r['byte_count']):>10}   [{services}]")


def _open_accounts(db_path: str | None, secret_path: str | None):
    """Open the account store and its signing key, or (None, b"") if
    accounts are switched off.

    The key sits beside the database by default and is generated on first
    use. Both live outside the repo, under the user's home directory, so a
    clone never ships with someone else's accounts or a shared key.
    """
    if not db_path:
        return None, b""

    import sqlite3

    from .accounts import AccountStore, load_or_create_secret

    resolved = Path(db_path).expanduser()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    secret = load_or_create_secret(secret_path or str(resolved.with_suffix(".key")))
    accounts = AccountStore(sqlite3.connect(str(resolved), check_same_thread=False))

    if accounts.user_count() == 0:
        print(f"[activitygraph] Accounts enabled ({resolved}). No accounts exist yet -- "
              "the first one registered from the dashboard becomes the admin.")
    return accounts, secret


def main() -> None:
    parser = argparse.ArgumentParser(description="ActivityGraph backend core: capture -> devices + flows.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run against synthetic demo traffic.")
    mode.add_argument("--live", action="store_true", help="Capture live traffic (needs root).")
    mode.add_argument("--list-interfaces", action="store_true", help="List available network interfaces.")
    mode.add_argument("--serve", action="store_true", help="Launch the local web dashboard.")
    parser.add_argument("-i", "--interface", default=None, help="Interface to capture on (live mode).")
    parser.add_argument("-d", "--duration", type=float, default=30.0, help="Live capture duration, seconds.")
    parser.add_argument("--idle-timeout", type=float, default=5.0, help="Flow idle timeout, seconds.")
    parser.add_argument("--session-gap", type=float, default=300.0,
                         help="Idle gap (seconds) that closes an activity session (default 300 = 5min).")
    parser.add_argument("--json", action="store_true", help="Print JSON summary instead of a text report.")
    parser.add_argument("-o", "--output", default=None, help="Write JSON summary to this file.")
    parser.add_argument("--llm", action="store_true",
                         help="Classify domains the rule engine misses using a local LLM (via Ollama).")
    parser.add_argument("--llm-url", default="http://localhost:11434", help="Ollama-compatible API base URL.")
    parser.add_argument("--llm-model", default="qwen2.5:1.5b", help="Model name, as pulled in Ollama.")
    parser.add_argument("--llm-cache", default=None,
                         help="Path to persist LLM classification cache (default: in-memory only).")
    parser.add_argument("--serve-source", choices=["demo", "live"], default="demo",
                         help="Data source for --serve: a one-shot demo snapshot, or continuous live capture.")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard bind host (--serve mode).")
    parser.add_argument("--port", type=int, default=8420, help="Dashboard port (--serve mode).")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard in a browser.")
    parser.add_argument("--history-db", default=None,
                         help="Path to a SQLite file for tracking category trends across runs over time. "
                              "For --demo/--live, records this run's totals. For --serve, reads trends to "
                              "display (and records once, if --serve-source demo).")
    parser.add_argument("--device-aliases", default=None,
                         help="Path to a JSON file mapping MAC addresses to friendly device names, "
                              "e.g. {\"AA:BB:CC:DD:EE:FF\": \"Alice's Laptop\"}. Always takes priority "
                              "over passively-observed hostnames (mDNS/.local, NetBIOS, DHCP).")
    parser.add_argument("--active-resolve", action="store_true",
                         help="For devices with no alias/passive hostname yet, actively ask the device "
                              "for its name (reverse DNS, unicast mDNS, NBSTAT) -- same idea as how your "
                              "router resolves names, at the cost of a few extra packets per new device. "
                              "Off by default to stay passive/unobtrusive.")
    parser.add_argument("--device-groups", default=None,
                         help="Path to a JSON file grouping devices by person, e.g. "
                              "{\"Alice\": [\"AA:BB:CC:DD:EE:FF\", \"11:22:33:44:55:66\"]}. Lets the "
                              "dashboard report time per person across all their devices instead of "
                              "per IP. Devices not listed fall under \"Ungrouped\".")
    parser.add_argument("--dhcp-leases", nargs="?", const="", default=None, metavar="PATH",
                         help="Register every device from the DHCP server's lease table, including the "
                              "hostname each one reported for itself. Use when running on a gateway that "
                              "serves DHCP (see docs/raspberry-pi-gateway.md) -- works with any router, "
                              "needs no credentials, and covers devices that never answer active probes. "
                              "Pass with no value to probe the usual dnsmasq locations.")
    parser.add_argument("--taxonomy", default=None,
                         help="Path to a JSON file organizing services into subcategories within each "
                              "category, e.g. {\"Entertainment\": {\"Music\": [\"Spotify\", \"YouTube "
                              "Music\"], \"Video\": [\"YouTube\", \"Netflix\"]}}. A category you define "
                              "replaces the built-in grouping for that category. Subcategories are "
                              "derived at read time, so reorganizing regroups existing history too.")
    parser.add_argument("--min-activity-seconds", type=float, default=DEFAULT_MIN_ACTIVITY_SECONDS,
                         help="Minimum time credited to a flow when computing time-based totals "
                              f"(default {DEFAULT_MIN_ACTIVITY_SECONDS:g}). A single-packet flow has zero "
                              "duration, so without this a burst of short connections would register as "
                              "no time at all.")
    parser.add_argument("--arp-sweep", action="store_true",
                         help="Before capturing, broadcast ARP requests across the local subnet so devices "
                              "that never send traffic through this host (e.g. another Wi-Fi client, which "
                              "a managed-mode adapter can't otherwise see) still show up in the device list. "
                              "Only registers their presence (IP/MAC/vendor) -- it captures no traffic, so "
                              "a device found only this way will show 0 bytes until it generates traffic "
                              "that happens to cross this host. Live/serve-live modes only.")
    parser.add_argument("--arp-sweep-subnet", default=None,
                         help="CIDR to sweep, e.g. 192.168.1.0/24 (default: auto-detected /24 from the "
                              "capture interface's own IP).")
    parser.add_argument("--arp-sweep-timeout", type=float, default=3.0,
                         help="Seconds to wait for ARP replies during --arp-sweep (default 3.0).")
    parser.add_argument("--router-devices", action="store_true",
                         help="Before capturing, log into your router's admin interface and pull its "
                              "client list -- IP/MAC/hostname straight from its DHCP lease table, which "
                              "covers devices that never answer --active-resolve or show up in --arp-sweep "
                              "(e.g. phones). Requires --router-credentials. Live/serve-live modes only.")
    parser.add_argument("--router-credentials", default=None,
                         help="Path to a JSON file with your router login: "
                              "{\"brand\": \"tplink\", \"host\": \"192.168.1.1\", \"username\": \"admin\", "
                              "\"password\": \"...\"}. Kept in its own file (not a CLI argument) so the "
                              "password never lands in shell history. Currently supported brands: tplink.")
    parser.add_argument("--show-background", action="store_true",
                         help="Include machine traffic in the headline panels: DNS, DHCP, "
                              "clock sync, OS and browser update checks, ad and analytics "
                              "beacons. Left out by default because none of it is something "
                              "a person did, and DNS in particular appears on every device "
                              "and crowds out the answer to where the time went. The raw "
                              "flow list always shows everything either way.")
    parser.add_argument("--active-within", type=float, default=None, metavar="MINUTES",
                         help="Show only what has been active in the last MINUTES. A gateway "
                              "runs for weeks, and without this the dashboard accumulates "
                              "every device, session and service ever seen, burying what is "
                              "happening now. Affects the live view only: --history-db keeps "
                              "the long-term record either way. Try 15.")
    parser.add_argument("--exclude-self", action="store_true",
                         help="Leave this machine out of the device list. On a gateway the "
                              "capturing machine forwards everyone's traffic but is nobody's "
                              "device, so it otherwise appears alongside the phones and laptops, "
                              "sometimes more than once. Do not use it on a laptop capturing its "
                              "own traffic, where that machine is the only thing there is to see.")
    parser.add_argument("--capture-mode", choices=["full", "light"], default="full",
                         help="How much traffic to inspect. 'full' reads every packet and "
                              "gives exact byte totals, but the per-packet cost is far higher "
                              "than the kernel's cost to forward it, so on a gateway carrying a "
                              "whole household it can saturate the CPU and reduce throughput. "
                              "'light' reads only what identifies devices, services and flow "
                              "timing, skipping the payload that makes up the bulk of packets: "
                              "categories and time stay accurate, byte totals become an "
                              "undercount. Use 'light' on a gateway.")
    parser.add_argument("--bpf-filter", default=None, metavar="EXPR",
                         help="Override the capture filter with your own libpcap expression, "
                              "e.g. 'arp or (udp and port 53)'. Takes precedence over "
                              "--capture-mode. Checked before capture starts.")
    parser.add_argument("--accounts", nargs="?", const="~/.activitygraph/accounts.db", default=None,
                         metavar="PATH",
                         help="Require sign-in, and show each account only the devices it has claimed "
                              "(--serve mode). The first account registered becomes the admin and sees "
                              "every device. Everyone else starts with none and claims their own, which "
                              "they can only do from the device itself. Turn this on before binding to "
                              "anything beyond localhost.")
    parser.add_argument("--accounts-secret", default=None, metavar="PATH",
                         help="Where the session-signing key lives (default: alongside --accounts). "
                              "Deleting it signs everyone out.")
    args = parser.parse_args()

    from .collector import CAPTURE_MODES, validate_bpf_filter

    capture_filter = args.bpf_filter or CAPTURE_MODES[args.capture_mode]
    active_window = args.active_within * 60 if args.active_within else None
    excluded_macs = set()
    if args.exclude_self:
        from .collector import local_hardware_addresses
        excluded_macs = local_hardware_addresses()
        print(f"[activitygraph] Hiding this machine from the device list "
              f"({len(excluded_macs)} interface(s)).")
    # Checked here rather than inside the capture thread, where the failure
    # would surface long after the command and behind an already-running,
    # permanently empty dashboard.
    invalid = validate_bpf_filter(capture_filter)
    if invalid:
        parser.error(f"capture filter is not valid: {invalid}\n  filter: {capture_filter}")

    if args.arp_sweep and args.demo:
        print("[activitygraph] Warning: --arp-sweep has no effect in --demo mode (no real interface to sweep).",
              file=sys.stderr)
    if args.router_devices and not args.router_credentials:
        parser.error("--router-devices requires --router-credentials PATH")
    if args.router_devices and args.demo:
        print("[activitygraph] Warning: --router-devices has no effect in --demo mode.", file=sys.stderr)
    if args.dhcp_leases is not None and args.demo:
        print("[activitygraph] Warning: --dhcp-leases has no effect in --demo mode.", file=sys.stderr)

    if args.list_interfaces:
        for iface in TrafficCollector().list_interfaces():
            print(iface)
        return

    llm_classifier = None
    if args.llm:
        llm_classifier = LocalLLMClassifier(base_url=args.llm_url, model=args.llm_model, cache_path=args.llm_cache)
        if not llm_classifier.is_available():
            print(
                f"[activitygraph] Warning: no LLM reachable at {args.llm_url}. "
                f"Continuing with rule-based classification only.",
                file=sys.stderr,
            )

    device_aliases = load_aliases(args.device_aliases) if args.device_aliases else None
    device_groups = load_device_groups(args.device_groups) if args.device_groups else None
    taxonomy = load_taxonomy(args.taxonomy) if args.taxonomy else None

    if args.demo:
        pipeline = run_demo(idle_timeout=args.idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=args.session_gap, device_aliases=device_aliases, active_resolve=args.active_resolve, device_groups=device_groups, min_activity_seconds=args.min_activity_seconds, taxonomy=taxonomy)
    elif args.live:
        try:
            pipeline = run_live(args.interface, args.duration, args.idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=args.session_gap, device_aliases=device_aliases, active_resolve=args.active_resolve, arp_sweep=args.arp_sweep, arp_sweep_subnet=args.arp_sweep_subnet, arp_sweep_timeout=args.arp_sweep_timeout, router_devices=args.router_devices, router_credentials=args.router_credentials, device_groups=device_groups, min_activity_seconds=args.min_activity_seconds, taxonomy=taxonomy, dhcp_leases=args.dhcp_leases, bpf_filter=capture_filter, exclude_macs=excluded_macs)
        except PermissionError:
            print("Live capture requires elevated privileges (try running with sudo).", file=sys.stderr)
            sys.exit(1)
    elif args.serve:
        from .server import BackgroundCapture, serve
        from .storage import HistoryStore

        history_store = HistoryStore(args.history_db) if args.history_db else None
        accounts, secret = _open_accounts(args.accounts, args.accounts_secret)

        if args.serve_source == "demo":
            pipeline = run_demo(idle_timeout=args.idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=args.session_gap, device_aliases=device_aliases, active_resolve=args.active_resolve, device_groups=device_groups, min_activity_seconds=args.min_activity_seconds, taxonomy=taxonomy)
            if history_store is not None:
                history_store.record_sessions_from_summary(pipeline.summary())
                history_store.record_time_from_pipeline(pipeline)
            serve(pipeline, live=False, host=args.host, port=args.port, open_browser=not args.no_browser, history_store=history_store, accounts=accounts, secret=secret, active_within_seconds=active_window, include_background=args.show_background)
        else:
            # The history database doubles as the learned IP -> hostname
            # store, so a restarted gateway keeps recognising services it
            # has already seen instead of relabelling them all as "HTTPS".
            pipeline = Pipeline(idle_timeout_seconds=args.idle_timeout, llm_classifier=llm_classifier, session_gap_seconds=args.session_gap, device_aliases=device_aliases, active_resolve=args.active_resolve, device_groups=device_groups, min_activity_seconds=args.min_activity_seconds, taxonomy=taxonomy, name_store=history_store, exclude_macs=excluded_macs)
            # Grouping and min-activity live on the Pipeline itself, so
            # BackgroundCapture doesn't need to know about them.
            # No exclude_macs here: it belongs to the device registry, which
            # the pipeline above already owns.
            capture = BackgroundCapture(pipeline, interface=args.interface, history_store=history_store, arp_sweep=args.arp_sweep, arp_sweep_subnet=args.arp_sweep_subnet, arp_sweep_timeout=args.arp_sweep_timeout, router_devices=args.router_devices, router_credentials=args.router_credentials, dhcp_leases=args.dhcp_leases, bpf_filter=capture_filter)
            try:
                capture.start()
            except PermissionError:
                print("Live capture requires elevated privileges (try running with sudo).", file=sys.stderr)
                sys.exit(1)
            serve(pipeline, live=True, host=args.host, port=args.port, open_browser=not args.no_browser, history_store=history_store, capture=capture, accounts=accounts, secret=secret, active_within_seconds=active_window, include_background=args.show_background)
        return
    else:
        parser.error("no mode selected")

    if args.history_db:
        from .storage import HistoryStore
        store = HistoryStore(args.history_db)
        n = store.record_sessions_from_summary(pipeline.summary())
        intervals = store.record_time_from_pipeline(pipeline)
        store.close()
        print(f"Recorded {n} session(s) and {intervals} activity interval(s) to {args.history_db}")

    if args.json or args.output:
        summary = pipeline.summary()
        text = json.dumps(summary, indent=2)
        if args.output:
            output_path = Path(args.output).expanduser()
            with open(output_path, "w") as f:
                f.write(text)
            print(f"Wrote summary to {output_path}")
        else:
            print(text)
    else:
        print_report(pipeline)


if __name__ == "__main__":
    main()
