"""Active hostname resolution: ask a device directly for its own name.

collector.py's passive hint extraction only reads names a device happens
to broadcast on its own during the capture window -- if nothing crosses
the wire, that device stays a bare IP, even though your router's admin
page would show a name for it (a router can afford to ask directly: it's
the DHCP server, and it can query any device on demand).

This module closes that gap the same way: by asking each device directly,
on demand. Three query types are tried in order, cheapest/most-reliable
first:

  1. Reverse DNS (PTR), via whatever resolver this machine is configured
     to use -- often the router itself, which frequently registers DHCP
     client hostnames in its local DNS.
  2. A direct (unicast) mDNS query to the device's own port 5353, asking
     for the PTR record of its reverse-arpa name -- most Apple/IoT/
     Chromecast-style devices answer this about themselves.
  3. A direct NBSTAT query to the device's own port 137 -- Windows
     machines answer with their NetBIOS computer name.

All three are plain, unprivileged UDP request/response exchanges -- no
packet capture, no elevated privileges (unlike collector.py's live
capture path). Each is a single best-effort round trip: no retries, and
any failure (timeout, malformed reply, unreachable host) just falls
through to the next method rather than raising.
"""
from __future__ import annotations

import socket
from typing import Optional

from scapy.all import DNS, DNSQR
from scapy.layers.netbios import NBNSHeader, NBNSNodeStatusRequest, NBNSNodeStatusResponse

_WORKSTATION_SUFFIX = 0  # NBNSNodeStatusResponseService.SUFFIX code for a machine's own name


def resolve_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Best-effort active lookup of a device's name. Tries each method in
    turn and returns the first hit, or None if nobody answers any of them."""
    for method in (_reverse_dns, _mdns_query, _netbios_query):
        try:
            name = method(ip, timeout)
        except Exception:
            name = None
        if name:
            return name
    return None


def _reverse_dns(ip: str, timeout: float) -> Optional[str]:
    """Reverse (PTR) lookup via the system resolver.

    `timeout` is accepted for interface symmetry but not enforced:
    `socket.gethostbyaddr` takes no timeout, and the only lever --
    `socket.setdefaulttimeout` -- is process-global. Setting and restoring it
    here would race with every other socket in the process, since resolution
    runs on background threads, and it is ignored by the platform resolver on
    Windows regardless. Blocking is acceptable because callers already run
    this off the capture thread (see DeviceRegistry._schedule_active_resolution),
    so a slow resolver delays one device's name, not packet capture.
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.split(".")[0] or None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _mdns_query(ip: str, timeout: float) -> Optional[str]:
    arpa_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
    query = bytes(DNS(rd=0, qd=DNSQR(qname=arpa_name, qtype="PTR", qclass="IN")))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()

    response = DNS(data)
    for i in range(response.ancount):
        rr = response.an[i]
        if getattr(rr, "type", None) != 12:  # PTR
            continue
        rdata = rr.rdata
        name = rdata.decode(errors="ignore") if isinstance(rdata, bytes) else str(rdata)
        name = name.rstrip(".")
        if name.endswith(".local"):
            return name.split(".")[0].replace("-", " ") or None
    return None


def _netbios_query(ip: str, timeout: float) -> Optional[str]:
    request = bytes(NBNSHeader(NM_FLAGS=0, QDCOUNT=1) / NBNSNodeStatusRequest())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(request, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()

    status = NBNSHeader(data).payload
    if not isinstance(status, NBNSNodeStatusResponse):
        return None
    for service in status.NODE_NAME or []:
        if service.SUFFIX != _WORKSTATION_SUFFIX:
            continue
        name = service.NETBIOS_NAME
        name = name.decode(errors="ignore") if isinstance(name, bytes) else str(name)
        name = name.strip()
        if name:
            return name
    return None
