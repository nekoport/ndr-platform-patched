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


class GamblingWatchlist:
    """v0.16.0 - requirement 18: tag aktivitas Judi Online.

    Matcher ringan (bukan detector baru): mencocokkan keyword gambling
    (GAMBLING_KEYWORDS) dan/atau daftar domain eksplisit
    (GAMBLING_DOMAINS_FILE, satu domain per baris, '#' = komentar)
    pada host HTTP, query DNS, dan SNI TLS. Event yang cocok diberi
    tag ``campaign="judi-online"`` sehingga:
      * event terindeks dengan campaign (agregasi dashboard / API preset),
      * detector gambling_access bisa memancarkan alert berkampanye.

    Match berbasis substring pada label domain - sengaja murah (LRU-free),
    dipanggil per event, O(k) dengan k kecil (belasan keyword).
    """

    campaign = "judi-online"

    def __init__(self, keywords: list[str] | None = None,
                 domains_file: str | None = None):
        self.keywords = [k.lower().strip() for k in (keywords or []) if k.strip()]
        self.domains: set[str] = set()
        self.suffixes: tuple[str, ...] = ()
        if domains_file:
            self._load(domains_file)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    entry = line.strip().lower()
                    if not entry or entry.startswith("#"):
                        continue
                    self.domains.add(entry)
        except OSError:
            # daftar opsional: jangan pernah menghentikan ingest
            pass
        if self.domains:
            self.suffixes = tuple(sorted(self.domains, key=len, reverse=True))

    def match_host(self, host: str | None) -> bool:
        if not host:
            return False
        h = host.lower().strip().strip(".")
        if not h:
            return False
        if h in self.domains:
            return True
        if self.suffixes:
            for d in self.suffixes:
                if h.endswith("." + d) or h == d:
                    return True
        for k in self.keywords:
            if k in h:
                return True
        return False

    def enrich(self, ev: CommonEvent) -> CommonEvent:
        if ev.campaign:
            return ev
        host = ev.http_host or ev.dns_query or ev.tls_sni
        if self.match_host(host):
            ev.campaign = self.campaign
        return ev
