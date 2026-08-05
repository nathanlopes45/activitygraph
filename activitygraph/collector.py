"""Traffic Collector stage: captures live packets and normalizes them.

This is the only module that talks to scapy / the network interface
directly. It never stores payload content beyond what's needed to extract
DNS query/answers and TLS SNI (both of which are already visible in transit
metadata, not encrypted payload) -- consistent with the "no packet content
storage" privacy principle.

Requires elevated privileges (root / CAP_NET_RAW) to run in live mode, since
raw packet capture does.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Callable, Optional

from scapy.all import get_if_list  # noqa: F401  (surface for CLI --list-interfaces)
from scapy.all import ARP, DHCP, DNS, DNSRR, IP, IPv6, TCP, UDP, Ether, conf, get_if_addr, sniff, srp
from scapy.layers.netbios import NBNSRegistrationRequest

from .models import Packet

PacketHandler = Callable[[Packet], None]

# Capture everything, so byte totals are exact. Every packet is copied into
# Python and dissected by scapy, which costs far more per packet than the
# kernel spends forwarding it. Fine on a laptop watching its own traffic;
# on a gateway carrying a household it can saturate the CPU and starve the
# forwarding path, costing real throughput.
FULL_FILTER = "ip or ip6 or arp"

# Enough to identify who is talking to what, and when, without touching the
# bulk of the data. The pieces, in order:
#
#   arp                     device discovery
#   udp ports 53/5353       DNS and mDNS: hostnames, and device names
#   udp ports 67/68, 137    DHCP and NetBIOS: device names
#   tcp syn/fin/rst         flow start and end, which is what timing needs
#   tls handshake bytes     the ClientHello carrying the SNI hostname
#   small udp 443           QUIC handshake and acknowledgements, so an
#                           HTTP/3 stream still shows as ongoing rather
#                           than as a single instant
#
# What it deliberately drops is payload: the 1500-byte packets that make up
# a download, and the bare ACKs answering them. Those are the overwhelming
# majority of packets and they carry no information this tool reports on,
# beyond their size. Byte totals therefore become an undercount, while the
# service and category breakdown and the time figures stay intact.
LIGHT_FILTER = (
    "arp"
    " or (udp and (port 53 or port 5353 or port 67 or port 68 or port 137))"
    " or (tcp and tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0)"
    " or (tcp and (port 443 or port 8443)"
    " and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)"
    " or (udp and port 443 and less 400)"
)

CAPTURE_MODES = {"full": FULL_FILTER, "light": LIGHT_FILTER}


def validate_bpf_filter(expression: str) -> Optional[str]:
    """The libpcap error for a bad filter, or None if it compiles.

    Checked before capture starts rather than left to fail inside the
    sniffing thread, where the traceback surfaces long after the command
    that caused it and the dashboard is already up and empty.
    """
    try:
        from scapy.arch.common import compile_filter

        compile_filter(expression)
        return None
    except ImportError:
        return None  # no libpcap to check against; let capture try anyway
    except Exception as exc:
        return str(exc).strip() or "not a valid capture filter"


def _extract_tls_sni(raw_payload: bytes) -> Optional[str]:
    """Best-effort parse of a TLS ClientHello to pull the SNI hostname.

    This only inspects the handshake metadata (message type + extensions),
    never decrypts anything -- SNI is sent in cleartext in the ClientHello.
    """
    try:
        if len(raw_payload) < 5 or raw_payload[0] != 0x16:  # Handshake record
            return None
        pos = 5
        if raw_payload[pos] != 0x01:  # ClientHello
            return None
        pos += 4  # handshake header
        pos += 2 + 32  # version + random
        session_id_len = raw_payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(raw_payload[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len
        compression_len = raw_payload[pos]
        pos += 1 + compression_len
        if pos >= len(raw_payload):
            return None
        extensions_len = int.from_bytes(raw_payload[pos:pos + 2], "big")
        pos += 2
        end = pos + extensions_len
        while pos < end:
            ext_type = int.from_bytes(raw_payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(raw_payload[pos + 2:pos + 4], "big")
            ext_data = raw_payload[pos + 4:pos + 4 + ext_len]
            if ext_type == 0x00:  # server_name
                # 2 bytes list len, 1 byte type, 2 bytes name len, name
                name_len = int.from_bytes(ext_data[3:5], "big")
                return ext_data[5:5 + name_len].decode("ascii", errors="ignore")
            pos += 4 + ext_len
    except Exception:
        return None
    return None


# Names that name a *service* or a protocol rather than a host. They show up
# constantly on any network with Windows on it, and each one is something a
# device is asking about rather than something it is called.
_NOT_A_DEVICE_NAME = {
    "WPAD",             # web proxy auto-discovery
    "ISATAP",           # IPv6 transition adapter
    "WORKGROUP",        # the workgroup, not a member of it
    "MSBROWSE",
    "__MSBROWSE__",
    "LOCALHOST",
    "ANY",
}


def _dns_records(dns, section: str) -> list:
    """The records of one DNS section ("qd"/"an"/"ns"/"ar") as a plain list.

    scapy >= 2.5 stores these sections in PacketListFields. It still returns
    a compatibility wrapper that forwards attribute access to record 0 with
    a DeprecationWarning, so a record has to be reached by index -- and a
    section is a list to iterate, not a payload chain to walk.
    """
    records = getattr(dns, section, None)
    if records is None:
        return []
    if isinstance(records, list):
        return list(records)
    return [records]


def _mdns_local_name(dns) -> Optional[str]:
    """Pull a device's own "<Name>.local" hostname out of an mDNS message.

    A Bonjour announcement carries several records, and the useful one is
    rarely first. Service-discovery records ("_airplay._tcp.local") name a
    *service*, not the device, and the PTR/SRV chain often leads with those,
    so scan every record and take the first name that is a plain host label
    rather than a service instance.

    Questions are deliberately not scanned. A question is what the sender is
    looking *for*, so reading it names a device after whatever it happened
    to be resolving. Answers and additional records are what the sender is
    publishing about itself, which is the thing worth reading.
    """
    candidates = []
    for section in ("an", "ar"):
        for record in _dns_records(dns, section):
            name = getattr(record, "rrname", None) or getattr(record, "qname", None)
            if name:
                candidates.append(name.decode(errors="ignore").rstrip("."))

    for name in candidates:
        if not name.lower().endswith(".local"):
            continue
        # "_airplay._tcp.local" and "Sams iPhone._raop._tcp.local" both name
        # a service. Only "Sams-iPhone.local" names the device itself.
        if "_tcp" in name.lower() or "_udp" in name.lower():
            continue
        label = name.split(".")[0]
        if label and not label.startswith("_") and label.upper() not in _NOT_A_DEVICE_NAME:
            return label.replace("-", " ").strip()
    return None


def _extract_hostname_hint(scapy_pkt, proto: str, src_port, dst_port) -> Optional[tuple[str, str]]:
    """Best-effort passive device-name discovery. Never sends anything --
    only reads names devices already broadcast/announce on their own:

    - mDNS (UDP 5353): Apple/IoT/Chromecast-style devices announce
      "<Name>.local" hostnames constantly on most home networks.
    - NBNS (UDP 137): Windows machines broadcast their computer name via
      NetBIOS Name Service.
    - DHCP (UDP 67/68): a device's lease request often carries its
      hostname in Option 12.

    Returns (name, source) so the registry can prefer a better source over
    a worse one, rather than keeping whichever arrived first. Sources are
    not equally good: a DHCP option 12 hostname is frequently a generic
    model name, while the mDNS name is usually the one the owner chose.
    """
    if proto != "UDP":
        return None

    if dst_port == 5353 or src_port == 5353:
        if scapy_pkt.haslayer(DNS):
            name = _mdns_local_name(scapy_pkt[DNS])
            if name:
                return name, "mdns"
        return None

    if dst_port == 137 or src_port == 137:
        # Registrations only. A NetBIOS *query* carries the name being looked
        # up, not the name of the host looking, so reading it named devices
        # after whatever they happened to be searching for -- Windows asks
        # for "WPAD" constantly, so every Windows machine came out as "wpad".
        # A registration is a host claiming its own name, which is the one
        # thing here that genuinely identifies the sender.
        if scapy_pkt.haslayer(NBNSRegistrationRequest):
            raw = scapy_pkt[NBNSRegistrationRequest].QUESTION_NAME
            if raw:
                name = raw.decode(errors="ignore").strip()
                if name and name.upper() not in _NOT_A_DEVICE_NAME:
                    return name, "nbns"
        return None

    if dst_port in (67, 68) or src_port in (67, 68):
        if scapy_pkt.haslayer(DHCP):
            for opt in scapy_pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "hostname" and opt[1]:
                    value = opt[1]
                    name = value.decode(errors="ignore") if isinstance(value, bytes) else str(value)
                    if name.strip():
                        return name.strip(), "dhcp"
        return None

    return None


def _packet_to_normalized(scapy_pkt) -> Optional[Packet]:
    ts = datetime.fromtimestamp(float(scapy_pkt.time), tz=timezone.utc)

    if scapy_pkt.haslayer(ARP):
        arp = scapy_pkt[ARP]
        # op 1 = who-has, op 2 = is-at (reply); both tell us IP<->MAC binding
        return Packet(
            timestamp=ts,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            proto="ARP",
            length=len(scapy_pkt),
            src_mac=arp.hwsrc,
            arp_sender_ip=arp.psrc,
            arp_sender_mac=arp.hwsrc,
        )

    # Both address families, because a dual-stack network carries real
    # traffic over each and dropping one silently undercounts it. Modern
    # phones and laptops prefer IPv6 wherever the network offers it, so on
    # some networks the v6 half is the larger half.
    if scapy_pkt.haslayer(IP):
        ip_layer = scapy_pkt[IP]
        next_header = ip_layer.proto
        icmp_protocol = 1  # ICMP
    elif scapy_pkt.haslayer(IPv6):
        ip_layer = scapy_pkt[IPv6]
        next_header = ip_layer.nh
        icmp_protocol = 58  # ICMPv6
    else:
        return None

    src_mac = getattr(scapy_pkt, "src", None) if scapy_pkt.name == "Ethernet" else None
    dst_mac = getattr(scapy_pkt, "dst", None) if scapy_pkt.name == "Ethernet" else None

    proto = "OTHER"
    src_port = dst_port = None
    dns_query = None
    dns_answers = None
    tls_sni = None
    hostname_hint = None
    hostname_source = None

    if scapy_pkt.haslayer(TCP):
        proto = "TCP"
        tcp = scapy_pkt[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        if tcp.payload:
            raw = bytes(tcp.payload)
            if dst_port == 443 or src_port == 443:
                tls_sni = _extract_tls_sni(raw)
    elif scapy_pkt.haslayer(UDP):
        proto = "UDP"
        udp = scapy_pkt[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        if scapy_pkt.haslayer(DNS):
            dns = scapy_pkt[DNS]
            questions = _dns_records(dns, "qd")
            if questions:
                dns_query = questions[0].qname.decode(errors="ignore").rstrip(".")
            if dns.qr == 1:
                answers = []
                # Iterate the section itself rather than ancount: a truncated
                # capture can advertise more answers than it actually carries.
                for rr in _dns_records(dns, "an"):
                    # A and AAAA. Skipping AAAA would leave every IPv6 flow
                    # without a hostname, so it would fall through to the
                    # port rule and land in the generic HTTPS bucket.
                    if isinstance(rr, DNSRR) and rr.type in (1, 28):
                        answers.append(rr.rdata)
                dns_answers = answers or None
        hint = _extract_hostname_hint(scapy_pkt, proto, src_port, dst_port)
        if hint is not None:
            hostname_hint, hostname_source = hint
    elif next_header == icmp_protocol:
        proto = "ICMP"

    return Packet(
        timestamp=ts,
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        proto=proto,
        length=len(scapy_pkt),
        src_port=src_port,
        dst_port=dst_port,
        src_mac=src_mac,
        dst_mac=dst_mac,
        dns_query=dns_query,
        dns_answers=dns_answers,
        tls_sni=tls_sni,
        hostname_hint=hostname_hint,
        hostname_source=hostname_source,
    )


def default_route_interface() -> Optional[str]:
    """The interface carrying the default route (i.e. the WAN side), read
    from /proc/net/route. Returns None off Linux or if it can't be read."""
    try:
        with open("/proc/net/route") as handle:
            next(handle)  # header
            for line in handle:
                fields = line.split()
                # Destination 00000000 with the RTF_GATEWAY flag set = default route
                if len(fields) > 3 and fields[1] == "00000000" and int(fields[3], 16) & 0x2:
                    return fields[0]
    except (OSError, StopIteration, ValueError):
        return None
    return None


def warn_if_capturing_wan(interface: Optional[str]) -> Optional[str]:
    """Warn when the capture interface is the one carrying the default route.

    On a gateway this is the single most damaging misconfiguration available:
    the WAN side is downstream of NAT, so every packet there carries the
    gateway's own source IP. Capture would appear to work -- flows, services,
    categories all populate -- while attributing the entire household's
    traffic to one device, silently destroying the per-device and per-person
    data the gateway deployment exists to provide.

    Returns the warning text (also printed) so callers can surface it, or
    None if the check passed or couldn't run.
    """
    if not interface:
        return None
    wan = default_route_interface()
    if wan is None or interface != wan:
        return None

    message = (
        f"'{interface}' carries the default route, so it is this machine's WAN side. "
        f"Traffic there has already been NAT'd: every packet will look like it came "
        f"from this host, and per-device/per-person attribution will be wrong even "
        f"though the dashboard fills in normally. Capture the LAN-facing interface "
        f"instead (the one your devices connect through)."
    )
    print(f"[activitygraph] Warning: {message}", file=sys.stderr)
    return message


def _guess_local_subnet(interface: Optional[str]) -> Optional[str]:
    """Best-effort /24 for the given interface, from its own IPv4 address.

    Consumer routers are overwhelmingly /24 (255 usable host addresses),
    so this covers the common case without needing a netmask lookup that
    Windows' interface listing doesn't expose. Callers that need a
    different range can always pass an explicit subnet instead.
    """
    try:
        local_ip = get_if_addr(interface) if interface else get_if_addr(conf.iface)
    except Exception:
        return None
    octets = local_ip.split(".")
    if len(octets) != 4 or local_ip == "0.0.0.0":
        return None
    return ".".join(octets[:3]) + ".0/24"


class TrafficCollector:
    """Live packet capture on a given interface, dispatching normalized Packets."""

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = FULL_FILTER) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter

    def list_interfaces(self) -> list[str]:
        """Return interface identifiers suitable for -i.

        On Windows, scapy's raw get_if_list() returns cryptic
        \\Device\\NPF_{GUID} strings that are useless for picking an
        interface by eye. Prefer the friendly name (e.g. "Wi-Fi",
        "Ethernet") when available -- scapy's sniff() accepts those
        directly on Windows.

        Windows also registers a large number of internal NDIS filter
        drivers, QoS packet schedulers, and virtual switch extensions as
        their own pseudo-interfaces (e.g. "Wi-Fi-WFP Native MAC Layer
        LightWeight Filter-0000") -- dozens of entries a human has no use
        for. Only interfaces with an actual assigned IP address are ones
        you could plausibly capture meaningful traffic on, so filter down
        to those when possible.
        """
        try:
            from scapy.arch.windows import get_windows_if_list
            all_ifaces = get_windows_if_list()
            with_ip = [iface.get("name") for iface in all_ifaces if iface.get("name") and iface.get("ips")]
            if with_ip:
                return with_ip
            # Fall back to the full unfiltered list rather than an empty result.
            friendly = [iface.get("name") for iface in all_ifaces if iface.get("name")]
            if friendly:
                return friendly
        except ImportError:
            pass  # not on Windows, or scapy's Windows arch module isn't present

        # On Linux the names are already human-readable, but annotating them
        # with each interface's IP and flagging the WAN side matters on a
        # gateway, where picking the wrong one silently ruins per-device
        # attribution (see warn_if_capturing_wan).
        names = get_if_list()
        wan = default_route_interface()
        annotated = []
        for name in names:
            try:
                address = get_if_addr(name)
            except Exception:
                address = None
            parts = [name]
            if address and address != "0.0.0.0":
                parts.append(f"({address})")
            if wan and name == wan:
                parts.append("[WAN -- do not capture here on a gateway]")
            annotated.append("  ".join(parts))
        return annotated or names

    def run(self, on_packet: PacketHandler, packet_count: int = 0, timeout: Optional[float] = None) -> None:
        """Blocking capture loop. packet_count=0 means unlimited (until timeout/ctrl-c)."""

        def _handle(scapy_pkt):
            normalized = _packet_to_normalized(scapy_pkt)
            if normalized is not None:
                on_packet(normalized)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_handle,
            store=False,
            count=packet_count,
            timeout=timeout,
        )

    def arp_sweep(self, subnet: Optional[str] = None, timeout: float = 3.0) -> list[tuple[str, str]]:
        """Broadcast ARP 'who-has' across the local subnet and collect replies.

        This exists because passive capture alone misses devices that never
        happen to talk *through* this host: on Wi-Fi, a normal adapter in
        managed/infrastructure mode only receives frames addressed to it,
        plus broadcast/multicast -- it can't see another station's unicast
        traffic to the router the way a wired hub (or a mirrored switch
        port) would let it. An ARP reply, though, *is* addressed to us
        (we're the one asking), so it gets through regardless -- the same
        trick tools like `arp-scan`/`nmap -sn` rely on.

        This only tells you a device exists (IP/MAC/vendor) -- it produces
        no traffic for it, so a device found only this way will show 0
        bytes until it generates traffic that happens to cross this host.

        Requires the same elevated privileges as live capture (raw L2 send).
        """
        if subnet is None:
            subnet = _guess_local_subnet(self.interface)
            if subnet is None:
                return []
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(request, timeout=timeout, iface=self.interface, verbose=0)
        return [(received.psrc, received.hwsrc) for _, received in answered]

    def arp_sweep_and_ingest(self, on_packet: PacketHandler, subnet: Optional[str] = None, timeout: float = 3.0) -> int:
        """Run arp_sweep() and feed each discovered (ip, mac) through
        on_packet as a synthetic ARP Packet, so it flows through the same
        device-registration path as a passively-observed ARP reply would.
        Returns how many devices were discovered this way."""
        now = datetime.now(timezone.utc)
        discovered = self.arp_sweep(subnet=subnet, timeout=timeout)
        for ip, mac in discovered:
            on_packet(Packet(
                timestamp=now, src_ip=ip, dst_ip=ip, proto="ARP", length=0,
                src_mac=mac, arp_sender_ip=ip, arp_sender_mac=mac,
            ))
        return len(discovered)
