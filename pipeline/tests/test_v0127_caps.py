"""v0.12.7 specificity-cap tests for the correlation story graph.

The live VM produced reconstructed graphs that read like "every alert
the system ever fired" instead of ONE correlated attack chain. The
context/dns/tracker enrichment is decoration around the SIGNAL chain
and now runs under hard budgets:

  * context-enrichment nodes are capped (MAX_CTX_NODES) while signal
    nodes stay uncapped
  * distinct edges are capped (MAX_EDGES) without losing existing edges
  * the default budgets are tuned for specificity (tracker domains 3,
    dns answer nodes 2, nodes 80, edges 120)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")))

from app.correlation import story as story_mod  # noqa: E402
from app.correlation.story import AttackStory  # noqa: E402


def test_specificity_budget_defaults():
    assert story_mod.MAX_NODES == 80
    assert story_mod.MAX_EDGES == 120
    assert story_mod.MAX_EVIDENCE == 400
    assert story_mod.MAX_CTX_NODES == 36
    assert story_mod.MAX_TRACKER_DOMAINS == 3
    assert story_mod.MAX_DNS_ANSWER_NODES == 2


def test_ctx_node_budget_caps_enrichment_not_signals():
    st = AttackStory("story-cap", gap_seconds=600)
    for i in range(story_mod.MAX_CTX_NODES):
        node = st._ctx_node(f"domain:ctx{i}.example", 1000.0 + i, "c2",
                            "c2_infra")
        assert node is not None
    assert st.ctx_nodes == story_mod.MAX_CTX_NODES

    # a chatty story cannot add MORE context nodes - decoration stops,
    # evidence items keep flowing (no overclaim is lost)
    assert st._ctx_node("domain:overflow.example", 1100.0, "c2") is None
    assert st.ctx_nodes == story_mod.MAX_CTX_NODES
    assert len(st.nodes) == story_mod.MAX_CTX_NODES

    # existing context keys still resolve (no duplicate node accounting)
    again = st._ctx_node("domain:ctx0.example", 1101.0, "c2")
    assert again is not None
    assert st.ctx_nodes == story_mod.MAX_CTX_NODES

    # SIGNAL entities are never subject to the context budget
    sig = st._ensure_node("ip:10.10.0.5", 1102.0, "c2", "compromised_host")
    assert sig is not None
    assert "ip:10.10.0.5" in st.entity_keys


def test_edge_budget_caps_new_edges_keeps_existing():
    st = AttackStory("story-edges", gap_seconds=600)
    for i in range(story_mod.MAX_EDGES):
        edge = st._ensure_edge(f"ip:10.0.0.{i}", f"ip:10.0.0.{i + 1}",
                               "connected_to", 1000.0 + i, "unknown")
        assert edge
    assert len(st.edges) == story_mod.MAX_EDGES

    # further DISTINCT edges are refused once the budget is spent
    assert st._ensure_edge("ip:10.9.9.1", "ip:10.9.9.2", "contacted",
                           1200.0, "c2") is None
    assert len(st.edges) == story_mod.MAX_EDGES

    # EXISTING relations keep accumulating evidence (edge reuse never
    # hits the cap - only the creation of new decoration does)
    reused = st._ensure_edge("ip:10.0.0.0", "ip:10.0.0.1", "connected_to",
                             1300.0, "unknown")
    assert reused
    edge = st.edges[("ip:10.0.0.0", "ip:10.0.0.1", "connected_to")]
    assert edge.evidence_count == 2
    assert edge.last_seen == 1300.0

    # self-edges are structurally impossible regardless of budget
    assert st._ensure_edge("ip:1.1.1.1", "ip:1.1.1.1", "contacted",
                           1400.0, "c2") is None
