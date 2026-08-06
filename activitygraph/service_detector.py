"""Service Detection stage: maps a Flow to a human-meaningful service/category.

Order of precedence (cheapest & most reliable first):
  1. TLS SNI seen directly on the flow's connection
  2. DNS answer cache (dst_ip -> most recently queried hostname)
  3. Rule-based port fallback (e.g. 443 -> generic "HTTPS")
  4. [future] Local LLM classification for anything still "Unknown"

This module never sends anything off-device: the DNS cache and SNI table
are populated purely from packets already captured locally.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from .models import Flow, Packet, ServiceMatch
from .service_rules import classify_domain, classify_port, registrable_domain

# Signature for a pluggable local-LLM classifier: (hostname_or_None, port) -> ServiceMatch | None
LLMClassifier = Callable[[Optional[str], int], Optional[ServiceMatch]]


class ServiceDetector:
    def __init__(self, llm_classifier: Optional[LLMClassifier] = None,
                 name_store=None) -> None:
        # ip -> hostname, most recent DNS answer wins. Checked against both
        # endpoints of a flow (see _resolve_hostname), since a reply flow's
        # dst_ip is the local device, not the server that was looked up.
        self._dns_cache: dict[str, str] = {}
        # Optional HistoryStore used to carry that cache across restarts.
        # Seeded up front so classification is useful from the first packet
        # rather than only after each device repeats a DNS lookup.
        self._name_store = name_store
        self._unsaved: dict[str, str] = {}
        # (device address, service) -> when that device last used the
        # service's own front door. See _AMBIGUOUS_CDNS.
        self._front_doors: dict[tuple, object] = {}
        if name_store is not None:
            self._dns_cache.update(name_store.load_dns_names())
        # (frozenset({ip_a, ip_b}), server_port) -> SNI hostname. Keyed by an
        # unordered IP pair (not src/dst) so the reply-direction Flow --
        # which has src_ip/dst_ip swapped relative to the ClientHello packet
        # that revealed the SNI -- still finds the same cache entry.
        self._sni_cache: dict[tuple[frozenset, int], str] = {}
        self._llm_classifier = llm_classifier

    # -- cache population -------------------------------------------------
    def observe(self, packet: Packet) -> None:
        """Feed a raw packet in so DNS answers / SNI hints get cached."""
        if packet.dns_query and packet.dns_answers:
            for ip in packet.dns_answers:
                if self._dns_cache.get(ip) != packet.dns_query:
                    self._unsaved[ip] = packet.dns_query
                self._dns_cache[ip] = packet.dns_query

        self._note_front_door(packet)

        if packet.tls_sni and packet.dst_port:
            key = (frozenset((packet.src_ip, packet.dst_ip)), packet.dst_port)
            self._sni_cache[key] = packet.tls_sni

    def flush(self) -> None:
        """Write newly-learned hostnames out.

        Called from the same periodic hook that records sessions, not from
        observe(): a synchronous SQLite write per DNS answer would put disk
        latency directly in the packet-capture path.
        """
        if self._name_store is None or not self._unsaved:
            return
        self._name_store.save_dns_names(self._unsaved)
        self._unsaved.clear()

    # Services that share a content-delivery domain with another service, so
    # the hostname alone cannot tell them apart. YouTube Music streams audio
    # from googlevideo.com, exactly as YouTube streams video, and the CDN
    # name carries no hint of which. What does distinguish them is that the
    # app or tab talks to its own front door alongside the stream, so a
    # device seen using that front door recently is taken to still be using
    # it. A heuristic, and it can misattribute video watched immediately
    # after listening, which is a better failure than filing every minute of
    # music as video.
    _AMBIGUOUS_CDNS = {
        "YouTube": (
            (re.compile(r"(^|\.)music\.youtube\.com$", re.IGNORECASE), "YouTube Music"),
        ),
    }
    _FRONT_DOOR_MEMORY_SECONDS = 900.0

    def _note_front_door(self, packet: Packet) -> None:
        """Remember a device using a service whose CDN it shares with another."""
        hostname = packet.tls_sni or packet.dns_query
        if not hostname:
            return
        for alternatives in self._AMBIGUOUS_CDNS.values():
            for pattern, service in alternatives:
                if pattern.search(hostname):
                    self._front_doors[(packet.src_ip, service)] = packet.timestamp

    def _disambiguate(self, match: ServiceMatch, flow: Flow) -> ServiceMatch:
        alternatives = self._AMBIGUOUS_CDNS.get(match.service)
        if not alternatives:
            return match
        for _, service in alternatives:
            for ip in (flow.src_ip, flow.dst_ip):
                seen = self._front_doors.get((ip, service))
                if seen is not None and \
                        abs((flow.start_time - seen).total_seconds()) <= self._FRONT_DOOR_MEMORY_SECONDS:
                    return ServiceMatch(domain=match.domain, service=service,
                                        category=match.category, confidence=0.6)
        return match

    # -- classification -----------------------------------------------------
    def classify(self, flow: Flow) -> ServiceMatch:
        hostname = self._resolve_hostname(flow)

        if hostname:
            domain = registrable_domain(hostname)
            match = classify_domain(hostname) or classify_domain(domain)
            if match:
                return self._disambiguate(match, flow)

        port_match = classify_port(flow.dst_port) or classify_port(flow.src_port)

        if self._llm_classifier is not None:
            llm_match = self._llm_classifier(hostname, flow.dst_port)
            if llm_match:
                return llm_match

        if hostname:
            # Known hostname, but no rule matched it: still useful signal.
            return ServiceMatch(domain=hostname, service=hostname, category="Uncategorized", confidence=0.3)

        if port_match:
            return port_match

        return ServiceMatch(domain=None, service="Unknown", category="Uncategorized", confidence=0.0)

    def _resolve_hostname(self, flow: Flow) -> Optional[str]:
        ip_pair = frozenset((flow.src_ip, flow.dst_ip))
        # Try both ports as the "server port" -- whichever one the SNI was
        # originally observed on, this flow (in either direction) will match.
        for port in (flow.dst_port, flow.src_port):
            sni = self._sni_cache.get((ip_pair, port))
            if sni:
                return sni
        # DNS answers are keyed by the server's IP, which could be either
        # endpoint of this flow depending on direction.
        for ip in (flow.dst_ip, flow.src_ip):
            hostname = self._dns_cache.get(ip)
            if hostname:
                return hostname
        return None

    def apply(self, flow: Flow) -> Flow:
        """Classify a flow in place and return it, for convenient chaining."""
        match = self.classify(flow)
        flow.domain = match.domain
        flow.service = match.service
        flow.category = match.category
        return flow
