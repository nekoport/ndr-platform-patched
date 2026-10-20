"""Optional GeoIP enrichment (Phase 5).

Design goals (deliberately conservative):
  * OFF by default. No external service calls, no bundled geo database,
    no license management until the deployment actually has one.
  * Two data sources, tried in order:
      1. MaxMind MMDB (GeoLite2-Country/City) via the optional
         `maxminddb` package - enabled when GEOIP_MMDB_PATH is set and
         the package is importable.
      2. A JSON sidecar file (GEOIP_JSON_PATH) with explicit
         CIDR -> geo entries, longest-prefix match. Ops can generate
         this from any MaxMind CSV export; see docs/OPERATIONS.md.
  * Result is APPROXIMATE network geolocation. The pipeline stamps it
    on events as source.geo / destination.geo; the API treats missing
    geo as "not mapped" and never fabricates coordinates.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger("ndr.geoip")

# Address space that never gets geolocated (internal/reserved).
# NOTE: explicit list instead of ipaddress.is_private - since Python
# 3.11 is_private also flags TEST-NET documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) which fixtures use.
_NON_GEO_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",
    "224.0.0.0/4", "240.0.0.0/4", "fc00::/7", "fe80::/10", "::1/128")]


def _geo_doc(country: str | None, iso: str | None, lat, lon,
             asn_org: str | None) -> dict | None:
    if not country and lat is None:
        return None
    doc: dict = {}
    if country:
        doc["country"] = country
    if iso:
        doc["country_iso_code"] = iso
    if asn_org:
        doc["asn_org"] = asn_org
    if lat is not None and lon is not None:
        doc["location"] = {"lat": float(lat), "lon": float(lon)}
    return doc or None


class _MMDBBackend:
    def __init__(self, path: str):
        import maxminddb  # optional dependency

        self.reader = maxminddb.open_database(path)
        self.name = f"mmdb:{path}"

    def lookup(self, ip: str) -> dict | None:
        raw = self.reader.get(ip)
        if not raw:
            return None
        country = raw.get("country", {})
        loc = raw.get("location", {}) or {}
        return _geo_doc(
            country.get("names", {}).get("en"),
            country.get("iso_code"),
            loc.get("latitude"), loc.get("longitude"),
            (raw.get("autonomous_system_organization")
             if "autonomous_system_organization" in raw else None))


class _JSONBackend:
    """CIDR sidecar: {"networks": [{"cidr": "...", "country": "...",
    "country_iso_code": "...", "lat": ..., "lon": ...,
    "asn_org": "..."}]} - longest prefix wins."""

    def __init__(self, path: str):
        data = json.loads(Path(path).read_text())
        entries: list[tuple[ipaddress.IPv4Network, dict]] = []
        for item in data.get("networks", []):
            try:
                net = ipaddress.ip_network(item["cidr"], strict=False)
            except (KeyError, ValueError):
                continue
            entries.append((net, item))
        entries.sort(key=lambda e: e[0].prefixlen, reverse=True)
        self.entries = entries
        self.name = f"json:{path}"

    def lookup(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, item in self.entries:
            if addr.version == net.version and addr in net:
                return _geo_doc(item.get("country"),
                                item.get("country_iso_code"),
                                item.get("lat"), item.get("lon"),
                                item.get("asn_org"))
        return None


class GeoEnricher:
    """Thread-safe enricher; stays a no-op when disabled/broken."""

    def __init__(self, mmdb_path: str | None = None,
                 json_path: str | None = None):
        self._lock = threading.Lock()
        self.backend = None
        self.disabled_reason = "geoip disabled (no data source configured)"
        mmdb_path = mmdb_path or os.environ.get("GEOIP_MMDB_PATH")
        json_path = json_path or os.environ.get("GEOIP_JSON_PATH")
        if mmdb_path:
            try:
                self.backend = _MMDBBackend(mmdb_path)
            except Exception as exc:
                log.warning("GeoIP MMDB unavailable (%s): %s",
                            mmdb_path, exc)
        if self.backend is None and json_path:
            try:
                self.backend = _JSONBackend(json_path)
            except Exception as exc:
                log.warning("GeoIP JSON unavailable (%s): %s",
                            json_path, exc)
        if self.backend is None and (mmdb_path or json_path):
            self.disabled_reason = "geoip data source failed to load"
        if self.backend:
            log.info("GeoIP enrichment enabled via %s", self.backend.name)

    @property
    def enabled(self) -> bool:
        return self.backend is not None

    def lookup(self, ip: str | None) -> dict | None:
        if not ip or not self.backend:
            return None
        # skip internal/reserved space - geolocating RFC1918 is noise
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if any(addr in net for net in _NON_GEO_NETS):
            return None
        try:
            with self._lock:
                return self.backend.lookup(ip)
        except Exception as exc:  # never break ingestion on geo errors
            log.warning("geoip lookup failed for %s: %s", ip, exc)
            return None

    def enrich_event(self, ev) -> None:
        """Attach source.geo / destination.geo when data exists."""
        if not self.backend:
            return
        src_geo = self.lookup(ev.source_ip)
        if src_geo:
            ev.source_geo = src_geo
        dst_geo = self.lookup(ev.destination_ip)
        if dst_geo:
            ev.destination_geo = dst_geo
