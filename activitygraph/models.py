"""Core data models shared across the ActivityGraph pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Device:
    """A device on the local network, identified by its MAC.

    One device commonly holds several addresses at once: an IPv4 lease, an
    IPv6 link-local address, sometimes a second IPv4 after a lease change.
    They are all listed in `addresses`, and `ip` is whichever is best to
    show. Keying on the address instead would list a single phone two or
    three times over, once per address it happens to hold.
    """

    ip: str
    addresses: list[str] = field(default_factory=list)
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Which person/group this device belongs to (see device_groups.py).
    # None means ungrouped -- rendered under a synthetic "Ungrouped" group
    # rather than being hidden.
    group: Optional[str] = None

    def touch(self, when: Optional[datetime] = None) -> None:
        self.last_seen = when or datetime.now(timezone.utc)

    def display_name(self) -> str:
        """Best available human-friendly label: hostname/alias, then
        vendor, then falling back to the raw IP."""
        if self.hostname:
            return self.hostname
        if self.vendor and self.vendor != "Unknown":
            return self.vendor
        return self.ip

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "addresses": self.addresses or [self.ip],
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "display_name": self.display_name(),
            "group": self.group,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


@dataclass
class ServiceMatch:
    """The result of matching a domain/port against known services."""

    domain: Optional[str]
    service: str
    category: str
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "service": self.service,
            "category": self.category,
            "confidence": self.confidence,
        }


@dataclass
class Flow:
    """A single network flow: one 5-tuple conversation over time."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "TCP" | "UDP" | "ICMP" | ...
    start_time: datetime
    end_time: datetime
    packet_count: int = 0
    byte_count: int = 0
    domain: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "domain": self.domain,
            "service": self.service,
            "category": self.category,
        }


@dataclass
class Packet:
    """A minimal, protocol-agnostic representation of a captured packet.

    This is what the Collector produces and everything downstream consumes,
    so the rest of the pipeline never has to know about scapy directly.
    """

    timestamp: datetime
    src_ip: str
    dst_ip: str
    proto: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    # Optional payload hints extracted at capture time (no full payload stored)
    dns_query: Optional[str] = None
    dns_answers: Optional[list] = None
    tls_sni: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    # Passively-observed device name, if this packet carried one (DHCP
    # hostname option, NetBIOS name service, or mDNS/.local hostname).
    hostname_hint: Optional[str] = None
    # Which protocol the hint came from ("mdns", "nbns", "dhcp"). Names
    # differ in quality by source, so the registry keeps the best one
    # rather than the first one to arrive.
    hostname_source: Optional[str] = None
