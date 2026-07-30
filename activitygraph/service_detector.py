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

from typing import Callable, Optional

from .models import Flow, Packet, ServiceMatch
from .service_rules import classify_domain, classify_port, registrable_domain

# Signature for a pluggable local-LLM classifier: (hostname_or_None, port) -> ServiceMatch | None
LLMClassifier = Callable[[Optional[str], int], Optional[ServiceMatch]]


class ServiceDetector:
    def __init__(self, llm_classifier: Optional[LLMClassifier] = None) -> None:
        # ip -> hostname, most recent DNS answer wins. Checked against both
        # endpoints of a flow (see _resolve_hostname), since a reply flow's
        # dst_ip is the local device, not the server that was looked up.
        self._dns_cache: dict[str, str] = {}
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
                self._dns_cache[ip] = packet.dns_query

        if packet.tls_sni and packet.dst_port:
            key = (frozenset((packet.src_ip, packet.dst_ip)), packet.dst_port)
            self._sni_cache[key] = packet.tls_sni

    # -- classification -----------------------------------------------------
    def classify(self, flow: Flow) -> ServiceMatch:
        hostname = self._resolve_hostname(flow)

        if hostname:
            domain = registrable_domain(hostname)
            match = classify_domain(hostname) or classify_domain(domain)
            if match:
                return match

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
