"""Attack-phase taxonomy (Phase 4 - attack reconstruction, doc section 10).

Maps detection outputs to a simplified kill-chain so the correlation
engine can reason about attack progression:

    recon -> initial_access -> delivery -> c2 -> lateral -> impact

Design notes (doc 10.1):
  * MITRE ATT&CK remains the classification framework for *labels*; this
    module is NOT an attribution engine, only a coarse phase mapper.
  * Phases are evidence labels, not verdicts: an alert tagged
    `initial_access` means an exploitation attempt was OBSERVED.
  * Unknown categories map to "unknown" instead of guessing.
"""

from __future__ import annotations

# Ordered kill chain (display order in UI + reconstruction).
PHASES: tuple[str, ...] = ("recon", "initial_access", "delivery", "c2",
                           "lateral", "impact")

PHASE_LABELS: dict[str, str] = {
    "recon": "Reconnaissance",
    "initial_access": "Initial Access",
    "delivery": "Payload Delivery",
    "c2": "Command & Control",
    "lateral": "Lateral Movement",
    "impact": "Impact / Exfiltration",
}

# Suricata EVE alert.category -> phase. Matched with exact keys first,
# then substring fallback for vendor variation.
_SURICATA_CATEGORY_MAP: dict[str, str] = {
    # reconnaissance
    "attempted-recon": "recon",
    "unsuccessful-recon-limited": "recon",
    "unsuccessful-recon-largest": "recon",
    "scan": "recon",
    "policy-violation": "unknown",
    # exploitation / initial access
    "web-application-attack": "initial_access",
    "exploit-kit": "initial_access",
    "client-side-exploit": "initial_access",
    "attempted-admin": "initial_access",
    "attempted-user": "initial_access",
    "successful-admin": "initial_access",
    "successful-user": "initial_access",
    "sql-injection": "initial_access",
    "cross-site-scripting": "initial_access",
    "shellcode-detect": "initial_access",
    "suspicious-shellcode-detect": "initial_access",
    "file-format": "initial_access",
    "denial-of-service": "impact",
    "attempted-dos": "impact",
    # malware delivery
    "malware": "delivery",
    "file-download": "delivery",
    # command & control
    "trojan-activity": "c2",
    "command-and-control": "c2",
    "botnet": "c2",
    "malware-cnc": "c2",
    "dns": "c2",
}

# Internal rule name -> phase (baseline + Phase 4 behavior rules).
RULE_PHASE_MAP: dict[str, str] = {
    "portscan_suspected": "recon",
    "dns_nxdomain_burst": "recon",
    "suricata_alert_group": "unknown",   # resolved via category mapping
    "ioc_match": "unknown",              # resolved via ioc type mapping
    "beaconing_possible": "c2",
    "dga_suspected": "c2",
    "dns_tunneling_suspected": "c2",
    "file_transfer_suspected": "delivery",
    "internal_lateral_suspected": "lateral",
    "large_outbound_transfer": "impact",
}

# IOC type -> phase bias (used when no stronger signal exists).
_IOC_PHASE_MAP: dict[str, str] = {
    "md5": "delivery",
    "sha1": "delivery",
    "sha256": "delivery",
    "url": "delivery",
    "domain": "c2",
    "ip": "c2",
}

# Substring fallbacks for unmapped categories (lowercase).
_CATEGORY_SUBSTRINGS: list[tuple[str, str]] = [
    ("recon", "recon"),
    ("scan", "recon"),
    ("exploit", "initial_access"),
    ("injection", "initial_access"),
    ("xss", "initial_access"),
    ("shellcode", "initial_access"),
    ("trojan", "c2"),
    ("botnet", "c2"),
    ("cnc", "c2"),
    ("c2", "c2"),
    ("command", "c2"),
    ("malware", "delivery"),
    ("dos", "impact"),
]


def phase_for_suricata_category(category: str | None,
                                signature: str | None = None) -> str:
    """Map a Suricata alert category (or signature text) to a phase."""
    cat = (category or "").strip().lower()
    if cat in _SURICATA_CATEGORY_MAP:
        return _SURICATA_CATEGORY_MAP[cat]
    for needle, phase in _CATEGORY_SUBSTRINGS:
        if needle in cat:
            return phase
    sig = (signature or "").lower()
    for needle, phase in _CATEGORY_SUBSTRINGS:
        if needle in sig:
            return phase
    return "unknown"


def phase_for_rule(rule_name: str | None) -> str:
    return RULE_PHASE_MAP.get(rule_name or "", "unknown")


def phase_for_ioc(ioc_type: str | None) -> str:
    return _IOC_PHASE_MAP.get((ioc_type or "").lower(), "unknown")


def phase_rank(phase: str) -> int:
    """Kill-chain depth (later phases => deeper progression)."""
    try:
        return PHASES.index(phase)
    except ValueError:
        return -1


def is_internal_check(zones: list[tuple[str, str]]):
    """Build an internal-IP predicate from configured zones.

    Falls back to RFC1918/ULA private addressing when no zones are set so
    the behavior rules remain usable out of the box.
    """
    import ipaddress

    networks = []
    for cidr, _name in zones:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue

    if networks:
        def is_internal(ip: str | None) -> bool:
            if not ip:
                return False
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in net for net in networks)
    else:
        def is_internal(ip: str | None) -> bool:
            if not ip:
                return False
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return addr.is_private and not addr.is_loopback

    return is_internal
