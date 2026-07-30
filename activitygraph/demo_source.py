"""Synthetic Packet stream for demo mode.

Live capture needs root and a real interface, neither of which is guaranteed
to be available (or desirable) for a quick look at the pipeline. This module
fabricates a small, realistic sequence of Packets -- ARP discovery, DNS
lookups, and TCP flows -- so the rest of the pipeline (Device Registry,
Flow Processor, Service Detector) can be exercised end-to-end.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Iterator

from .models import Packet

_DEVICES = [
    ("192.168.1.10", "3C:5A:B4:11:22:33"),   # Google device
    ("192.168.1.11", "AC:87:A3:44:55:66"),   # Apple device
    ("192.168.1.12", "B8:27:EB:77:88:99"),   # Raspberry Pi
]

_SESSIONS = [
    # (device_ip, domain, resolved_ip, dst_port, packets, bytes_per_packet)
    ("192.168.1.10", "canvas.instructure.com", "52.63.1.10", 443, 40, 850),
    ("192.168.1.10", "docs.google.com", "142.250.1.20", 443, 25, 600),
    ("192.168.1.10", "mail.google.com", "142.250.1.21", 443, 15, 400),
    ("192.168.1.11", "youtube.com", "142.250.4.14", 443, 500, 1400),
    ("192.168.1.11", "spotify.com", "35.186.1.5", 443, 120, 700),
    ("192.168.1.12", "github.com", "140.82.112.3", 443, 30, 500),
]


def generate(now: datetime | None = None) -> Iterator[Packet]:
    now = now or datetime.now(timezone.utc)
    t = now - timedelta(minutes=20)

    # 1. ARP discovery for each device
    for ip, mac in _DEVICES:
        yield Packet(
            timestamp=t,
            src_ip=ip,
            dst_ip="192.168.1.1",
            proto="ARP",
            length=42,
            src_mac=mac,
            arp_sender_ip=ip,
            arp_sender_mac=mac,
        )
        t += timedelta(seconds=random.uniform(0.1, 1.0))

    # 2. For each "session", emit a DNS query+answer, then a burst of TCP packets
    for device_ip, domain, resolved_ip, port, packet_count, avg_bytes in _SESSIONS:
        device_mac = dict((ip, mac) for ip, mac in _DEVICES)[device_ip]

        # DNS query
        yield Packet(
            timestamp=t, src_ip=device_ip, dst_ip="192.168.1.1", proto="UDP",
            length=70, src_port=random.randint(40000, 60000), dst_port=53,
            src_mac=device_mac, dns_query=domain,
        )
        t += timedelta(milliseconds=20)
        # DNS answer
        yield Packet(
            timestamp=t, src_ip="192.168.1.1", dst_ip=device_ip, proto="UDP",
            length=90, src_port=53, dst_port=random.randint(40000, 60000),
            dns_query=domain, dns_answers=[resolved_ip],
        )
        t += timedelta(milliseconds=30)

        sport = random.randint(40000, 60000)
        for i in range(packet_count):
            length = max(40, int(random.gauss(avg_bytes, avg_bytes * 0.2)))
            yield Packet(
                timestamp=t, src_ip=device_ip, dst_ip=resolved_ip, proto="TCP",
                length=length, src_port=sport, dst_port=port, src_mac=device_mac,
                tls_sni=domain if i == 0 else None,
            )
            t += timedelta(milliseconds=random.uniform(5, 40))
