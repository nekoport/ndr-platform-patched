"""Lockheed Martin Cyber Kill Chain assessment (doc 11) - API side.

Self-contained mirror of the pipeline's pure classifier
(`pipeline/app/detection/killchain.py`): the API service must be able to
compute the 7-stage assessment directly from stored evidence even for
incidents persisted before doc 11. The four statuses and the reason
wording are identical so UI + reports stay consistent.
"""

from __future__ import annotations

STAGES: tuple[str, ...] = (
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "command_and_control", "actions_on_objectives",
)

STAGE_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "command_and_control": "Command & Control",
    "actions_on_objectives": "Actions on Objectives",
}

NETWORK_BLIND_STAGES = frozenset({"weaponization", "installation"})

PHASE_TO_STAGE: dict[str, str] = {
    "recon": "reconnaissance",
    "initial_access": "exploitation",
    "delivery": "delivery",
    "c2": "command_and_control",
    "lateral": "actions_on_objectives",
    "impact": "actions_on_objectives",
    "unknown": "actions_on_objectives",
}

# inverse mapping (first phase that maps to each stage) - used when an
# entity/evidence is only known by its kill-chain stage, e.g. manual
# escalation from an alert (v0.10)
PHASE_FOR_STAGE: dict[str, str] = {}
for _phase, _stage in PHASE_TO_STAGE.items():
    PHASE_FOR_STAGE.setdefault(_stage, _phase)


def phase_for_stage(stage: str | None) -> str:
    """Closest attack phase for a kill-chain stage (inverse of stage_for_phase)."""
    return PHASE_FOR_STAGE.get(stage or "", "unknown")

ATTCK_FOR_STAGE: dict[str, list[dict]] = {
    "reconnaissance": [{"tactic": "Reconnaissance", "technique_id": "T1595",
                        "technique": "Active Scanning"}],
    "delivery": [{"tactic": "Command and Control", "technique_id": "T1105",
                  "technique": "Ingress Tool Transfer"}],
    "exploitation": [{"tactic": "Initial Access", "technique_id": "T1190",
                      "technique": "Exploit Public-Facing Application"}],
    "command_and_control": [
        {"tactic": "Command and Control", "technique_id": "T1071",
         "technique": "Application Layer Protocol"}],
    "actions_on_objectives": [
        {"tactic": "Exfiltration", "technique_id": "T1041",
         "technique": "Exfiltration Over C2 Channel"}],
    "weaponization": [],
    "installation": [],
}


def stage_for_phase(phase: str | None) -> str:
    return PHASE_TO_STAGE.get(phase or "", "actions_on_objectives")


def deepest_stage(progression: list[dict]) -> str:
    best = ""
    for s in progression or []:
        if s.get("status") in ("observed", "suspected"):
            best = s.get("stage", "")
    return best or "reconnaissance"


def _evidence_stage(ev: dict) -> str:
    stage = ev.get("stage")
    if stage in STAGES:
        return stage
    return stage_for_phase(ev.get("phase"))


def _evidence_attck(ev: dict) -> list[dict]:
    for key in ("attck", "mitre"):
        explicit = ev.get(key)
        if isinstance(explicit, list) and explicit:
            return [t for t in explicit
                    if isinstance(t, dict) and t.get("technique_id")]
    return list(ATTCK_FOR_STAGE.get(_evidence_stage(ev), []))


_DIRECT_KINDS = {"alert", "ioc_event"}


def assess_stages(evidence: list[dict]) -> list[dict]:
    """Evidence-based 7-stage assessment (doc 11) - same rules as the
    pipeline: observed / suspected / not_observed / insufficient_telemetry,
    each with reason + confidence."""
    by_stage: dict[str, list[dict]] = {s: [] for s in STAGES}
    for ev in evidence or []:
        by_stage.setdefault(_evidence_stage(ev), []).append(ev)

    out = []
    for stage in STAGES:
        items = by_stage.get(stage, [])
        direct = [e for e in items if e.get("kind") in _DIRECT_KINDS]
        context = [e for e in items if e.get("kind") not in _DIRECT_KINDS]

        attck: dict[str, dict] = {}
        for e in direct + context:
            for t in _evidence_attck(e):
                attck.setdefault(t["technique_id"], t)

        if direct:
            status = "observed"
        elif context:
            status = "suspected"
        elif stage in NETWORK_BLIND_STAGES:
            status = "insufficient_telemetry"
        else:
            status = "not_observed"

        out.append({
            "stage": stage,
            "label": STAGE_LABELS[stage],
            "status": status,
            "evidence_count": len(items),
            "signal_count": len(direct),
            "context_count": len(context),
            "confidence": _stage_confidence(direct, context),
            "attck": list(attck.values()),
            "reason": _stage_reason(stage, status, direct, context),
        })
    return out


def _stage_confidence(direct: list[dict], context: list[dict]) -> int:
    if direct:
        sev_bonus = sum(
            8 for e in direct if e.get("severity") in ("high", "critical"))
        return min(95, 55 + len(direct) * 6 + sev_bonus)
    if context:
        return min(60, 25 + len(context) * 5)
    return 0


def _stage_reason(stage: str, status: str, direct: list[dict],
                  context: list[dict]) -> str:
    if status == "observed":
        n = len(direct)
        kinds = sorted({e.get("kind") for e in direct})
        return (f"{n} direct signal(s) ({', '.join(kinds)}) mapped to "
                f"this stage")
    if status == "suspected":
        return (f"No direct signal, but {len(context)} context record(s) "
                f"are consistent with this stage")
    if status == "insufficient_telemetry":
        if stage == "weaponization":
            return ("Weaponization happens on attacker infrastructure - "
                    "network traffic cannot observe it")
        return ("Installation requires endpoint telemetry; network-only "
                "data cannot confirm or deny it")
    return ("Network telemetry covers this stage, but no evidence "
            "appeared in this attack story")


def stage_assessment_for_incident(detail_outcome: dict | None,
                                  evidence: list[dict]) -> tuple[
                                      list[dict], list[dict]]:
    """Return (stage_progression, stage_history) for a stored incident.

    Prefers the pipeline-persisted assessment inside the outcome JSON;
    falls back to computing from evidence for legacy incidents.
    """
    outcome = detail_outcome or {}
    progression = outcome.get("stage_progression")
    if not isinstance(progression, list) or not progression:
        progression = assess_stages(evidence)
    history = outcome.get("stage_history")
    if not isinstance(history, list):
        history = []
    return progression, history
