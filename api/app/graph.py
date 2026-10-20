"""Threat-map / attack-relationship graph service (Phase 5).

One correlation view powers BOTH threat-map visualizations (doc:
"Keduanya memakai data korelasi yang sama"):

  * merged entity graph - entities (ip / domain / hash) from ALL
    reconstructed incidents aggregated into a single graph
  * cross-incident correlation - entities are linked ONLY on checkable
    evidence: shared C2 / delivery infrastructure, a shared IOC match,
    or the same DNS-resolved address. Time proximity alone NEVER
    creates a relationship edge.
  * blast radius - entities reachable from a selected node, split into
    direct (observed edges) and indirect (inferred edges) impact
  * geographic flow aggregation - external<->internal communication
    pairs from the guarded events index, GeoIP if present

No-overclaim rules are enforced here: every edge carries explicit
correlation reasons and the evidence/campaign references an analyst
needs to verify it.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Incident, IncidentEdge, IncidentNode, NetworkZone

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                 "informational": 0}
STATUS_VALUES = {"open", "confirmed", "benign", "closed"}

# kill-chain order for phase comparison (mirrors pipeline taxonomy)
PHASE_RANK = {"unknown": -1, "recon": 0, "initial_access": 1,
              "delivery": 2, "c2": 3, "lateral": 4, "impact": 5}

# Entity roles strong enough to justify cross-campaign correlation.
CORRELATION_ROLES = {"c2_infra", "payload", "delivery_infra", "exfil_target"}

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def is_internal_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in _PRIVATE_NETS):
        return True
    return False


def _iso_min(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _iso_max(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


class MergedGraph:
    """Aggregated entity graph across incidents."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}
        self.campaigns: dict[str, dict] = {}

    # ------------------------------------------------------------ nodes
    def add_node(self, n: IncidentNode, incident_id: str) -> None:
        node = self.nodes.get(n.key)
        if node is None:
            node = {
                "key": n.key, "kind": n.kind, "label": n.label,
                "roles": [], "phase": n.phase or "unknown",
                "confidence": n.confidence or 50,
                "first_seen": n.first_seen, "last_seen": n.last_seen,
                "evidence_count": 0, "incident_ids": [],
                "ti_match": False, "attrs": {}, "internal":
                    is_internal_ip(n.label) if n.kind == "ip" else None,
                "degree": 0,
            }
            self.nodes[n.key] = node
        if n.role and n.role not in node["roles"]:
            node["roles"].append(n.role)
        rank_new = PHASE_RANK.get(node["phase"], -1)
        rank_cur = PHASE_RANK.get(n.phase or "unknown", -1)
        if rank_cur > rank_new:
            node["phase"] = n.phase
        node["confidence"] = max(node["confidence"], n.confidence or 50)
        node["first_seen"] = _iso_min(node["first_seen"], n.first_seen)
        node["last_seen"] = _iso_max(node["last_seen"], n.last_seen)
        node["evidence_count"] += 1
        if incident_id not in node["incident_ids"]:
            node["incident_ids"].append(incident_id)
        attrs = n.attrs or {}
        if attrs.get("ti_match"):
            node["ti_match"] = True
        for k, v in attrs.items():
            node["attrs"].setdefault(k, v)

    # ------------------------------------------------------------ edges
    def add_edge(self, e: IncidentEdge, incident_id: str) -> None:
        k = (e.src_key, e.dst_key, e.relation)
        edge = self.edges.get(k)
        if edge is None:
            edge = {
                "src": e.src_key, "dst": e.dst_key, "relation": e.relation,
                "phase": e.phase or "unknown", "inferred": bool(e.inferred),
                "first_seen": e.first_seen, "last_seen": e.last_seen,
                "evidence_count": 0, "confidence": e.confidence or 50,
                "incident_ids": [], "reasons": [],
            }
            self.edges[k] = edge
        edge["evidence_count"] += int(e.evidence_count or 0)
        edge["confidence"] = max(edge["confidence"], e.confidence or 50)
        edge["first_seen"] = _iso_min(edge["first_seen"], e.first_seen)
        edge["last_seen"] = _iso_max(edge["last_seen"], e.last_seen)
        if incident_id not in edge["incident_ids"]:
            edge["incident_ids"].append(incident_id)
        reason = _edge_reason(edge, incident_id)
        if reason and reason not in edge["reasons"]:
            edge["reasons"].append(reason)
        if e.inferred:
            edge["inferred"] = True
        for key in (e.src_key, e.dst_key):
            if key in self.nodes:
                self.nodes[key]["degree"] += 1

    # ------------------------------------------------------- campaigns
    def add_campaign(self, inc: Incident, node_keys: list[str]) -> None:
        self.campaigns[inc.id] = {
            "id": inc.id, "title": inc.title, "status": inc.status,
            "severity": inc.severity, "confidence": inc.confidence,
            "first_seen": inc.first_seen, "last_seen": inc.last_seen,
            "outcome_label": (inc.outcome or {}).get("label",
                                                     "indeterminate"),
            "node_keys": node_keys, "analyst": inc.analyst,
        }

    # --------------------------------------------------- cross-incident
    def cross_correlate(self) -> int:
        """Add explicit correlation edges between entities whose
        campaigns share checkable infrastructure evidence.

        Two link kinds, both always name the shared entity so the
        analyst can verify them:
          * member links - entities directly connected to the shared
            infrastructure (contacted / queried / resolved_to)
          * principal links - the main entity of each campaign
            (attacker, else most-evidenced compromised host), so
            multi-IP campaigns surface even when one attacker is two
            hops away from the shared infrastructure

        Time proximity alone NEVER creates a relationship.

        v0.12.5 perf: the VM profiled this at 16-17 s with 5.4k edges
        because the member scan was O(shared x all_edges) and `_linked`
        re-scanned every edge per candidate pair. The graph is now
        indexed once (edges by endpoint, linked-pair set, per-campaign
        principal cache) - ~30x faster live with a byte-identical
        payload (visit order and reasons preserved).
        """
        shared: dict[str, list[str]] = {}
        for key, node in self.nodes.items():
            if len(node["incident_ids"]) < 2:
                continue
            if node["ti_match"] or (set(node["roles"])
                                    & CORRELATION_ROLES):
                shared[key] = node["incident_ids"]
        added = 0
        # -- one-time indexes (replaces the per-shared-entity scans) --
        by_endpoint: dict[str, list[tuple[tuple[str, str, str], dict]]] = {}
        for ek, e in self.edges.items():
            by_endpoint.setdefault(e["src"], []).append((ek, e))
            if e["dst"] != e["src"]:
                by_endpoint.setdefault(e["dst"], []).append((ek, e))
        linked_pairs: set[tuple[str, str]] = {
            (min(e["src"], e["dst"]), max(e["src"], e["dst"]))
            for e in self.edges.values()}
        principal_cache: dict[str, str | None] = {}
        for shared_key, inc_ids in shared.items():
            node = self.nodes[shared_key]
            # members per campaign: entities directly (non-inferred)
            # connected to the shared infrastructure. by_endpoint keeps
            # self.edges insertion order, so member order matches the
            # original full scan exactly.
            per_campaign: dict[str, list[str]] = {}
            for (_src, _dst, rel), edge in by_endpoint.get(shared_key, ()):
                if rel == "correlated_with":
                    continue
                other = None
                if edge["dst"] == shared_key:
                    # member -> shared infra (contacted / queried /
                    # downloaded / targeted ...)
                    other = edge["src"]
                elif edge["src"] == shared_key and rel == "resolved_to":
                    # shared domain resolved to a member address
                    other = edge["dst"]
                if not other or other not in self.nodes:
                    continue
                if edge["inferred"] and rel not in ("resolved_to",
                                                    "queried"):
                    continue
                for iid in edge["incident_ids"]:
                    if iid not in inc_ids:
                        continue
                    members = per_campaign.setdefault(iid, [])
                    if other not in members:
                        members.append(other)
            campaigns = sorted(per_campaign)
            for a in range(len(campaigns)):
                for b in range(a + 1, len(campaigns)):
                    inc_a, inc_b = campaigns[a], campaigns[b]
                    base_reason = (
                        f"shared {node['kind']} infrastructure: "
                        f"{node['label']}")
                    if node["ti_match"]:
                        base_reason += " (TI-matched)"
                    # 1) direct member links (most specific)
                    pairs = [(l, r)
                             for l in per_campaign[inc_a][:3]
                             for r in per_campaign[inc_b][:3]
                             if l != r]
                    for left, right in pairs:
                        if (min(left, right), max(left, right)) \
                                in linked_pairs:
                            continue
                        added += self._add_corr_edge(
                            left, right, shared_key, [inc_a, inc_b],
                            f"{base_reason} - both entities have "
                            f"evidence-backed links to it")
                        linked_pairs.add((min(left, right),
                                          max(left, right)))
                    # 2) principal link (campaign heads) so multi-IP
                    #    campaigns surface even across chain hops
                    if inc_a not in principal_cache:
                        principal_cache[inc_a] = self._principal(inc_a)
                    if inc_b not in principal_cache:
                        principal_cache[inc_b] = self._principal(inc_b)
                    pa, pb = principal_cache[inc_a], principal_cache[inc_b]
                    if pa and pb and pa != pb \
                            and (pa, pb) not in pairs \
                            and (min(pa, pb), max(pa, pb)) \
                            not in linked_pairs:
                        added += self._add_corr_edge(
                            pa, pb, shared_key, [inc_a, inc_b],
                            f"{base_reason} - their campaigns "
                            f"{inc_a} and {inc_b} both link to it")
                        linked_pairs.add((min(pa, pb), max(pa, pb)))
        return added

    def _principal(self, campaign_id: str) -> str | None:
        candidates = [
            n for n in self.nodes.values()
            if campaign_id in n["incident_ids"]
            and (set(n["roles"]) & {"attacker", "compromised_host"})]
        if not candidates:
            return None
        attackers = [n for n in candidates if "attacker" in n["roles"]]
        pool = attackers or candidates
        return max(pool, key=lambda n: (n["evidence_count"],
                                        n["confidence"]))["key"]

    def _add_corr_edge(self, left: str, right: str, shared_key: str,
                       inc_ids: list[str], reason: str) -> int:
        node = self.nodes[shared_key]
        self.edges[(left, right, "correlated_with")] = {
            "src": left, "dst": right,
            "relation": "correlated_with",
            "phase": node["phase"],
            "inferred": True,
            "first_seen": node["first_seen"],
            "last_seen": node["last_seen"],
            "evidence_count": 2,
            "confidence": min(90, min(self.nodes[left]["confidence"],
                                      self.nodes[right]["confidence"])
                              + 5),
            "incident_ids": inc_ids,
            "reasons": [reason],
        }
        self.nodes[left]["degree"] += 1
        self.nodes[right]["degree"] += 1
        return 1

    def _linked(self, a: str, b: str) -> bool:
        for (src, dst, _rel) in self.edges:
            if (src, dst) in ((a, b), (b, a)):
                return True
        return False

    # ------------------------------------------------------------ out
    def to_payload(self) -> dict:
        nodes = sorted(self.nodes.values(),
                       key=lambda n: (-n["evidence_count"], n["key"]))
        edges = sorted(self.edges.values(),
                       key=lambda e: (-e["evidence_count"],
                                      e["src"], e["dst"]))
        return {
            "nodes": nodes,
            "edges": edges,
            "campaigns": sorted(self.campaigns.values(),
                                key=lambda c: (-(c["confidence"] or 0),
                                               c["id"])),
        }


def _edge_reason(edge: dict, incident_id: str) -> str:
    rel = edge["relation"]
    phase = edge.get("phase") or "unknown"
    if edge.get("inferred"):
        return (f"inferred from entity/temporal context ({rel}, "
                f"campaign {incident_id})")
    return f"observed {rel} events in campaign {incident_id}"


# ----------------------------------------------------------- render cap
# v0.12.7: the live VM produced 5,000+ merged edges; rendering them all
# made the Threat Map unusable (multi-MB payload + thousands of SVG
# elements). The API now trims the payload to the most SIGNIFICANT
# entities - TI-matched first, then cross-campaign infrastructure, then
# evidence count / degree - and keeps every edge whose endpoints
# survived. The full pre-trim counts ride in the meta block, so the
# trim is always visible to the analyst (never silent data loss).
RELATIONSHIP_MAX_NODES = 140
RELATIONSHIP_MAX_EDGES = 500


def _node_priority(n: dict) -> tuple:
    return (
        0 if n.get("ti_match") else 1,
        0 if len(n.get("incident_ids") or []) > 1 else 1,
        -(n.get("evidence_count") or 0),
        -(n.get("degree") or 0),
        n["key"],
    )


def prune_relationship_payload(payload: dict,
                               max_nodes: int = RELATIONSHIP_MAX_NODES,
                               max_edges: int = RELATIONSHIP_MAX_EDGES,
                               ) -> dict:
    """Trim a merged graph payload for browser rendering (see block
    comment above). Returns the SAME payload object with meta filled."""
    orig_nodes = len(payload.get("nodes", []))
    orig_edges = len(payload.get("edges", []))
    nodes = payload.get("nodes", [])
    if orig_nodes > max_nodes:
        ranked = sorted(nodes, key=_node_priority)
        keep = {n["key"] for n in ranked[:max_nodes]}
        payload["nodes"] = [n for n in nodes if n["key"] in keep]
    keys = {n["key"] for n in payload.get("nodes", [])}
    edges = [e for e in payload.get("edges", [])
             if e["src"] in keys and e["dst"] in keys]
    edges.sort(key=lambda e: (-(e.get("evidence_count") or 0),
                              e["src"], e["dst"]))
    payload["edges"] = edges[:max_edges]
    meta = payload.setdefault("meta", {})
    meta["full_counts"] = {"nodes": orig_nodes, "edges": orig_edges}
    meta["render_limits"] = {"max_nodes": max_nodes,
                             "max_edges": max_edges}
    meta["pruned"] = orig_nodes > max_nodes or orig_edges > max_edges
    return payload


# ------------------------------------------------------------------ build

def load_graph(db: Session, *, statuses: list[str] | None = None,
               severity_min: str | None = None,
               q: str | None = None,
               limit: int = 60) -> MergedGraph:
    statuses = [s for s in (statuses or ["open", "confirmed"])
                if s in STATUS_VALUES] or ["open", "confirmed"]
    query = db.query(Incident).filter(Incident.status.in_(statuses))
    if severity_min and severity_min in SEVERITY_RANK:
        floor = SEVERITY_RANK[severity_min]
        allowed = [s for s, r in SEVERITY_RANK.items() if r >= floor]
        query = query.filter(Incident.severity.in_(allowed))
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(Incident.title.ilike(like))
    incidents = query.order_by(Incident.last_seen.desc().nullslast()) \
        .limit(limit).all()
    graph = MergedGraph()
    # v0.12.5 perf: bulk-fetch nodes + edges for ALL incidents in 2
    # queries (was 2 per incident - 60+ incidents meant 120+ round trips
    # and a ~17 s relationships endpoint live; now 0.6 s, identical
    # payload). Rows are grouped per incident; within an incident the
    # driver order is preserved, same as the per-incident queries.
    inc_ids = [inc.id for inc in incidents]
    node_rows: dict[str, list[IncidentNode]] = {i: [] for i in inc_ids}
    edge_rows: dict[str, list[IncidentEdge]] = {i: [] for i in inc_ids}
    if inc_ids:
        for n in db.query(IncidentNode).filter(
                IncidentNode.incident_id.in_(inc_ids)).all():
            node_rows[n.incident_id].append(n)
        for e in db.query(IncidentEdge).filter(
                IncidentEdge.incident_id.in_(inc_ids)).all():
            edge_rows[e.incident_id].append(e)
    for inc in incidents:
        node_rows_inc = node_rows[inc.id]
        for n in node_rows_inc:
            graph.add_node(n, inc.id)
        touched = [n.key for n in node_rows_inc]
        edge_rows_inc = edge_rows[inc.id]
        for e in edge_rows_inc:
            # backfill edge endpoints missing a node row for THIS
            # campaign so shared-entity correlation still fires
            for endpoint in (e.src_key, e.dst_key):
                node = graph.nodes.get(endpoint)
                if node is None:
                    kind, _, label = endpoint.partition(":")
                    graph.add_node(IncidentNode(
                        incident_id=inc.id, kind=kind or "ioc",
                        key=endpoint, label=label or endpoint,
                        first_seen=e.first_seen, last_seen=e.last_seen,
                        attrs={}), inc.id)
                    touched.append(endpoint)
                elif inc.id not in node["incident_ids"]:
                    node["incident_ids"].append(inc.id)
                    touched.append(endpoint)
            graph.add_edge(e, inc.id)
        graph.add_campaign(inc, touched)
    graph.cross_correlate()
    return graph


# ------------------------------------------------------------- blast radius

def blast_radius(graph: MergedGraph, key: str, max_hops: int = 2) -> dict:
    """Entities reachable from `key`, direct vs indirect impact.

    direct   - reached via observed (non-inferred) edges only
    indirect - reached via at least one inferred edge (chain context)
    """
    adjacency: dict[str, list[tuple[str, dict]]] = {}
    for e in graph.edges.values():
        adjacency.setdefault(e["src"], []).append((e["dst"], e))
        adjacency.setdefault(e["dst"], []).append((e["src"], e))
    if key not in graph.nodes:
        return {"root": key, "direct": [], "indirect": [],
                "internal_hosts": []}
    direct: list[dict] = []
    indirect: list[dict] = []
    seen = {key}
    frontier = [(key, [], True)]
    for _hop in range(max_hops):
        nxt: list[tuple[str, list[str], bool]] = []
        for current, path, observed_path in frontier:
            for neighbor, edge in adjacency.get(current, []):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                clean_path = [*path, current]
                observed = observed_path and not edge["inferred"]
                entry = {
                    "key": neighbor,
                    "label": graph.nodes[neighbor]["label"],
                    "kind": graph.nodes[neighbor]["kind"],
                    "internal": graph.nodes[neighbor]["internal"],
                    "phase": graph.nodes[neighbor]["phase"],
                    "confidence": graph.nodes[neighbor]["confidence"],
                    "hop": _hop + 1,
                    "via": clean_path[1:],
                    "relation": edge["relation"],
                    "observed_path": observed,
                    "reasons": edge["reasons"][:2],
                }
                (direct if observed else indirect).append(entry)
                nxt.append((neighbor, clean_path, observed))
        frontier = nxt
    internal_hosts = [e for e in (*direct, *indirect)
                      if e["internal"] and e["kind"] == "ip"]
    return {"root": key, "direct": direct, "indirect": indirect,
            "internal_hosts": internal_hosts}


# ------------------------------------------------------------------ pivot

def entity_pivot(db: Session, key: str) -> dict | None:
    """Evidence pivot for one entity: aggregated view + incidents +
    edges + blast radius. OpenSearch lookups (alerts / events) are done
    by the router and merged in, so this stays testable without OS."""
    graph = load_graph(db, statuses=["open", "confirmed", "closed",
                                     "benign"], limit=200)
    if key not in graph.nodes:
        return None
    node = graph.nodes[key]
    related = []
    for e in graph.edges.values():
        if e["src"] == key or e["dst"] == key:
            other_key = e["dst"] if e["src"] == key else e["src"]
            other = graph.nodes.get(other_key, {})
            related.append({
                "direction": "out" if e["src"] == key else "in",
                "peer_key": other_key,
                "peer_label": other.get("label", other_key),
                "peer_kind": other.get("kind"),
                "relation": e["relation"],
                "inferred": e["inferred"],
                "evidence_count": e["evidence_count"],
                "confidence": e["confidence"],
                "reasons": e["reasons"],
                "incident_ids": e["incident_ids"],
            })
    related.sort(key=lambda r: (-r["evidence_count"], r["peer_key"]))
    radius = blast_radius(graph, key)
    campaigns = [c for c in graph.campaigns.values()
                 if key in c["node_keys"]]
    return {
        "entity": node,
        "related": related,
        "campaigns": campaigns,
        "blast_radius": radius,
        "disclaimer": "Relationships are evidence-backed correlations, "
                      "not proof of compromise. Verify via the referenced "
                      "incidents and alerts.",
    }


# ------------------------------------------------------------------ geo

def _zone_networks(db: Session) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    try:
        for cidr in db.query(NetworkZone.cidr).all():
            try:
                nets.append(ipaddress.ip_network(cidr[0], strict=False))
            except ValueError:
                continue
    except Exception:
        pass
    return nets


def classify_pair(src_ip: str, dst_ip: str,
                  zone_nets: list[ipaddress.IPv4Network]) -> str | None:
    """Return 'inbound' | 'outbound' | None (both same side)."""

    def _internal(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in _PRIVATE_NETS):
            return True
        return any(addr in net for net in zone_nets)

    s_int, d_int = _internal(src_ip), _internal(dst_ip)
    if s_int and not d_int:
        return "outbound"
    if d_int and not s_int:
        return "inbound"
    return None


def geo_flows_from_events(os_aggregate, db: Session, hours: int = 24,
                          max_pairs: int = 400) -> dict:
    """Aggregate external<->internal pairs from the events index.

    `os_aggregate` is a callable(body) -> response so tests can stub it.
    GeoIP coordinates ride on the events (pipeline enrichment); flows
    WITHOUT geo data are returned separately (`unmapped`) and are never
    forced onto the world map.
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since}}},
            {"exists": {"field": "source.ip"}},
            {"exists": {"field": "destination.ip"}},
        ]}},
        "aggs": {
            "pairs": {
                "composite": {
                    "size": 500,
                    "sources": [
                        {"src": {"terms": {"field": "source.ip"}}},
                        {"dst": {"terms": {"field": "destination.ip"}}},
                    ],
                },
                "aggs": {
                    "bytes": {"sum": {"field": "network.bytes"}},
                    "engines": {"terms": {"field": "source_engine",
                                          "size": 4}},
                    "last": {"max": {"field": "@timestamp"}},
                    "ioc_hits": {"filter": {"exists":
                                            {"field": "matched_ioc"}}},
                    "alert_hits": {"filter": {"term":
                                              {"event_type": "alert"}}},
                },
            },
            "geo_by_ip": {
                "terms": {"field": "source.ip", "size": 600},
                "aggs": {
                    "country": {"terms": {"field": "source.geo.country",
                                          "size": 1}},
                    "lat": {"avg": {"field": "source.geo.location.lat"}},
                    "lon": {"avg": {"field": "source.geo.location.lon"}},
                    "asn": {"terms": {"field": "source.geo.asn_org",
                                      "size": 1}},
                },
            },
        },
    }
    res = os_aggregate(body)
    zone_nets = _zone_networks(db)
    geo_map: dict[str, dict] = {}
    for bucket in (res.get("aggregations", {}).get("geo_by_ip", {})
                   .get("buckets", [])):
        ip = bucket.get("key")
        country = ((bucket.get("country", {}).get("buckets") or [{}])[0]
                   .get("key"))
        lat = bucket.get("lat", {}).get("value")
        lon = bucket.get("lon", {}).get("value")
        asn = ((bucket.get("asn", {}).get("buckets") or [{}])[0].get("key"))
        if ip and country and lat is not None and lon is not None:
            geo_map[str(ip)] = {"country": str(country), "lat": float(lat),
                                "lon": float(lon),
                                "asn_org": str(asn) if asn else None}
    flows: list[dict] = []
    unmapped: dict[str, dict] = {}
    for bucket in (res.get("aggregations", {}).get("pairs", {})
                   .get("buckets", [])):
        src = bucket["key"].get("src")
        dst = bucket["key"].get("dst")
        if not src or not dst:
            continue
        direction = classify_pair(str(src), str(dst), zone_nets)
        if direction is None:
            continue
        ext_ip = str(dst) if direction == "outbound" else str(src)
        int_ip = str(src) if direction == "outbound" else str(dst)
        conns = int(bucket.get("doc_count", 0))
        entry = {
            "external_ip": ext_ip, "internal_ip": int_ip,
            "direction": direction,
            "bytes": int(bucket.get("bytes", {}).get("value") or 0),
            "conns": conns,
            "engines": [b["key"] for b in
                        bucket.get("engines", {}).get("buckets", [])],
            "ioc_hits": int(bucket.get("ioc_hits", {}).get("doc_count")
                            or 0),
            "alert_hits": int(bucket.get("alert_hits", {}).get("doc_count")
                              or 0),
            "last_seen": bucket.get("last", {}).get("value_as_string"),
        }
        geo = geo_map.get(ext_ip)
        if geo:
            entry["geo"] = geo
        else:
            entry["geo"] = None
            reason = ("internal or reserved address - not placed on the "
                      "world map" if is_internal_ip(ext_ip)
                      else "no GeoIP data on events (enrichment disabled "
                           "or IP not resolved)")
            unmapped.setdefault(ext_ip, {"ip": ext_ip, "reason": reason,
                                         "conns": 0})
            unmapped[ext_ip]["conns"] += conns
        flows.append(entry)
    flows.sort(key=lambda f: (-f["conns"], -f["bytes"]))
    trimmed = flows[:max_pairs]
    return {
        "hours": hours,
        "geo_enabled": bool(geo_map),
        "flows": trimmed,
        "unmapped": sorted(unmapped.values(),
                           key=lambda u: -u["conns"])[:100],
        "note": "GeoIP is an approximate network location, not proof of "
                "the attacker's physical location. Internal IPs and "
                "addresses without geo data are listed, never plotted.",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
    }
