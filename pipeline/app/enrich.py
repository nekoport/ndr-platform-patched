"""Enrichment stage (doc section 7.1 step 7).

Phase 0-2 scope:
  * network zone classification from configured CIDRs
  * GeoIP: hook placeholder (Phase later) - intentionally not implemented
    to avoid license/database management until PoC proves the need.
  * TI matching: Phase 3 hook placeholder.
"""

from __future__ import annotations

import ipaddress
import threading

from app.models import CommonEvent


class ZoneEnricher:
    def __init__(self, zones: list[tuple[str, str]]):
        self._lock = threading.Lock()
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        for cidr, name in zones:
            self.add_zone(cidr, name)

    def add_zone(self, cidr: str, name: str) -> None:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        with self._lock:
            self._networks.append((net, name))

    def classify(self, ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        with self._lock:
            for net, name in self._networks:
                if addr in net:
                    return name
        return None

    def enrich(self, ev: CommonEvent) -> CommonEvent:
        """Set event zone from source ip first, then destination ip."""
        ev.zone = self.classify(ev.source_ip) or self.classify(ev.destination_ip)
        return ev
