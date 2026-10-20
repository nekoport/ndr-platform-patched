"""Incident report generator (doc section 10 - analyst output).

Builds a Markdown incident report from the reconstructed story detail.
The report separates PROVEN / SUSPECTED / UNKNOWN and includes evidence
references (index + doc id) so every claim is traceable. It deliberately
does NOT claim host compromise from network data alone (doc 10.2).
"""

from __future__ import annotations

from datetime import datetime, timezone

PHASE_LABELS = {
    "recon": "1. Reconnaissance",
    "initial_access": "2. Initial Access / Exploitation",
    "delivery": "3. Payload / Malware Delivery",
    "c2": "4. Command and Control (C2)",
    "lateral": "5. Lateral Movement / Internal Activity",
    "impact": "6. Impact / Outcome",
}

OUTCOME_LABELS = {
    "attempted": "Attempted attack (no post-access evidence observed)",
    "suspected_success": "Suspected successful compromise "
                         "(chain continuation observed)",
    "strong_success": "Strong evidence of successful compromise "
                      "(high-confidence TI match on the chain)",
    "indeterminate": "Indeterminate (insufficient evidence)",
}

STATUS_LABELS = {"open": "Open", "confirmed": "Confirmed",
                 "benign": "Benign / false positive", "closed": "Closed"}


def _fmt_ts(value: str | None) -> str:
    if not value:
        return "n/a"
    return str(value).replace("T", " ").replace("Z", " UTC")


def build_report(detail: dict) -> str:
    lines: list[str] = []
    outcome = detail.get("outcome") or {}
    phases = detail.get("phase_progression") or detail.get("phases") or []
    nodes = detail.get("nodes") or []
    edges = detail.get("edges") or []
    evidence = sorted(detail.get("evidence") or [],
                      key=lambda e: str(e.get("ts") or ""))

    lines.append(f"# Incident Report - {detail.get('id', 'unknown')}")
    lines.append("")
    lines.append(f"**Title:** {detail.get('title', 'Attack story')}")
    lines.append("")
    lines.append(f"**Status:** {STATUS_LABELS.get(detail.get('status', 'open'), detail.get('status'))}"
                 f"  |  **Severity:** {detail.get('severity', 'n/a')}"
                 f"  |  **Confidence:** {detail.get('confidence', 0)}/100 "
                 f"(heuristic-uncalibrated)")
    lines.append("")
    lines.append(f"**First seen:** {_fmt_ts(detail.get('first_seen'))}  |  "
                 f"**Last seen:** {_fmt_ts(detail.get('last_seen'))}")
    lines.append("")
    lines.append(f"**Generated:** "
                 f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                 f"  |  **Evidence items:** {len(evidence)}"
                 f"  |  **Entities:** {len(nodes)}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ---- executive summary -------------------------------------------
    lines.append("## Executive Summary")
    lines.append("")
    label = outcome.get("label", "indeterminate")
    lines.append(f"**Attack outcome assessment: {OUTCOME_LABELS.get(label, label)}**")
    lines.append("")
    observed = [p for p in phases if p.get("status") == "observed"]
    if observed:
        chain = " -> ".join(
            PHASE_LABELS.get(p["phase"], p["phase"]).split(". ", 1)[-1]
            for p in observed)
        lines.append(f"The reconstruction correlates {detail.get('signal_count', 0)} "
                     f"signals into one chain covering: {chain}. "
                     f"{len(evidence)} evidence items from Zeek, Suricata "
                     f"and threat intelligence support this timeline.")
    else:
        lines.append("The reconstruction found isolated signals without a "
                     "multi-phase chain. Treat as low-priority context "
                     "until further evidence arrives.")
    lines.append("")

    # ---- outcome ------------------------------------------------------
    lines.append("## Outcome Assessment")
    lines.append("")
    lines.append("### Proven (directly observed)")
    for item in outcome.get("proven") or ["Nothing beyond raw activity."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Suspected (chain-inferred, needs validation)")
    for item in outcome.get("suspected") or ["No suspected items."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Unknown (network-only blindness)")
    for item in outcome.get("unknown") or []:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(f"> {outcome.get('disclaimer', '')}")
    lines.append("")

    # ---- kill chain stage assessment (doc 11) -------------------------
    stages = detail.get("stage_progression") or []
    if stages:
        lines.append("## Kill Chain Stage Assessment (doc 11)")
        lines.append("")
        lines.append("Evidence-based assessment over the 7 Lockheed Martin "
                     "stages. This is NOT a mandatory sequence: stages may "
                     "be skipped, run in parallel, or lack sufficient "
                     "telemetry.")
        lines.append("")
        status_text = {
            "observed": "OBSERVED",
            "suspected": "SUSPECTED",
            "not_observed": "NOT OBSERVED",
            "insufficient_telemetry": "INSUFFICIENT TELEMETRY",
        }
        lines.append("| Stage | Status | Confidence | Evidence | ATT&CK | Reason |")
        lines.append("|-------|--------|------------|----------|--------|--------|")
        for s in stages:
            attck = ", ".join(
                sorted({t.get("technique_id", "")
                        for t in (s.get("attck") or [])})) or "-"
            lines.append(
                f"| {s.get('label', s.get('stage'))} "
                f"| {status_text.get(s.get('status'), s.get('status'))} "
                f"| {s.get('confidence', 0)}% "
                f"| {s.get('evidence_count', 0)} "
                f"| {attck} "
                f"| {str(s.get('reason', ''))[:110]} |")
        lines.append("")
        history = detail.get("stage_history") or []
        if history:
            lines.append("### Assessment changes over time")
            lines.append("")
            lines.append("| Time | Stage | From | To | Evidence ref |")
            lines.append("|------|-------|------|----|--------------|")
            for h in history[:40]:
                lines.append(
                    f"| {_fmt_ts(h.get('ts'))} "
                    f"| {h.get('stage')} "
                    f"| {h.get('from') or '-'} "
                    f"| {h.get('to')} "
                    f"| {str(h.get('evidence_ref') or '')[:40]} |")
            lines.append("")

    # ---- timeline ------------------------------------------------------
    lines.append("## Attack Timeline")
    lines.append("")
    if evidence:
        lines.append("| Time | Phase | Kill-chain stage | Source | Event | Severity |")
        lines.append("|------|-------|------------------|--------|-------|----------|")
        for ev in evidence:
            lines.append(
                f"| {_fmt_ts(ev.get('ts'))} | {ev.get('phase') or '-'} "
                f"| {ev.get('stage') or '-'} "
                f"| {ev.get('source') or '-'} "
                f"| {str(ev.get('title') or '')[:110]} "
                f"| {ev.get('severity') or '-'} |")
    else:
        lines.append("_No evidence recorded._")
    lines.append("")

    # ---- phase detail ---------------------------------------------------
    lines.append("## Evidence per Phase")
    lines.append("")
    for phase_key, label in PHASE_LABELS.items():
        items = [e for e in evidence if e.get("phase") == phase_key]
        status = next((p.get("status") for p in phases
                       if p.get("phase") == phase_key), "none")
        status_text = {"observed": "OBSERVED (direct evidence)",
                       "suspected": "SUSPECTED (indirect/context only)",
                       "none": "not observed"}.get(status, status)
        lines.append(f"### {label} - {status_text}")
        lines.append("")
        if items:
            for ev in items[:10]:
                ref = ""
                if ev.get("ref_index") and ev.get("ref_id"):
                    ref = f" `[{ev['ref_index']}:{ev['ref_id']}]`"
                lines.append(f"- {_fmt_ts(ev.get('ts'))} - "
                             f"{ev.get('title') or '(untitled)'}{ref}")
        else:
            lines.append("_No evidence for this phase._")
        lines.append("")

    # ---- attack graph ----------------------------------------------------
    lines.append("## Attack Graph (entities and relations)")
    lines.append("")
    if nodes:
        lines.append("### Entities")
        lines.append("")
        lines.append("| Entity | Kind | Role | Phase |")
        lines.append("|--------|------|------|-------|")
        for n in nodes[:30]:
            lines.append(f"| {n.get('label')} | {n.get('kind')} "
                         f"| {n.get('role') or '-'} "
                         f"| {n.get('phase') or '-'} |")
        lines.append("")
    if edges:
        lines.append("### Relations")
        lines.append("")
        lines.append("| From | Relation | To | Phase | Evidence |")
        lines.append("|------|----------|----|-------|----------|")
        label_by_key = {n.get("key"): n.get("label")
                        for n in nodes}
        for e in edges[:40]:
            src = label_by_key.get(e.get("src"), e.get("src"))
            dst = label_by_key.get(e.get("dst"), e.get("dst"))
            inferred = " (inferred)" if e.get("inferred") else ""
            lines.append(f"| {src} | {e.get('relation')}{inferred} "
                         f"| {dst} | {e.get('phase') or '-'} "
                         f"| {e.get('evidence_count', 0)} |")
        lines.append("")

    # ---- analyst notes ---------------------------------------------------
    notes = detail.get("notes") or []
    lines.append("## Analyst Notes")
    lines.append("")
    if notes:
        for note in notes:
            lines.append(f"- **{note.get('author', 'unknown')} "
                         f"({_fmt_ts(note.get('created_at'))}):** "
                         f"{note.get('body', '')}")
    else:
        lines.append("_No analyst notes yet._")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by NDR attack reconstruction (Phase 4). "
                 "All conclusions derive from network telemetry and "
                 "threat-intelligence context; they are heuristic and "
                 "uncalibrated. Validate with endpoint/server logs before "
                 "containment actions._")
    return "\n".join(lines)
