"""Lockheed Martin Cyber Kill Chain - dual-framework stage classifier.

Complements MITRE ATT&CK (doc 11 - never replaces it):

  Cyber Kill Chain : urutan 7 tahap serangan (timeline & progression)
  MITRE ATT&CK     : taktik + teknik spesifik per bukti (mis. T1046)

Design rules (user requirements, doc 11):
  * NOT a mandatory sequence - real attacks skip stages, run stages in
    parallel, or lack the evidence to conclude a stage. The assessment
    therefore carries four evidence-based statuses, not a filled-in chain:
        observed                - direct signals (alerts / IOC events)
        suspected               - context/inferred evidence only
        not_observed            - network telemetry covers this stage, but
                                  no evidence arrived in this story
        insufficient_telemetry  - the stage CANNOT be assessed from
                                  network traffic alone (weaponization
                                  happens on the attacker side; installation
                                  needs endpoint telemetry)
  * Every stage claim carries a reason and a confidence score.
  * Dual mapping: every rule/category maps to BOTH a kill-chain stage and
    MITRE ATT&CK techniques.

The internal 6-phase model (recon/initial_access/...) remains the
reconstruction engine's working model; this module projects it onto the
7-stage chain for classification and presentation.
"""

from __future__ import annotations

# ---------------------------------------------------------------- stages
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

STAGE_SHORT: dict[str, str] = {
    "reconnaissance": "Recon",
    "weaponization": "Weaponize",
    "delivery": "Delivery",
    "exploitation": "Exploit",
    "installation": "Install",
    "command_and_control": "C2",
    "actions_on_objectives": "Actions",
}

STAGE_DESCRIPTIONS: dict[str, str] = {
    "reconnaissance": "Scanning, service mapping, target information "
                      "gathering against the monitored network.",
    "weaponization": "Exploit + payload preparation. Happens on attacker "
                     "infrastructure - not visible in network traffic.",
    "delivery": "Exploit or malicious file transmitted toward the target "
                "via HTTP, mail, or direct connections.",
    "exploitation": "Vulnerability exploitation or code-execution triggers "
                    "observed on the wire.",
    "installation": "Malware / persistence installed on the target. "
                    "Network-only telemetry cannot confirm this stage.",
    "command_and_control": "Beaconing, periodic connections, or traffic to "
                           "known C2 infrastructure.",
    "actions_on_objectives": "Lateral movement, data staging, exfiltration, "
                             "or other goal-directed activity.",
}

# Stages that network-only telemetry fundamentally cannot assess.
NETWORK_BLIND_STAGES: frozenset[str] = frozenset(
    {"weaponization", "installation"})

# ------------------------------------------------- internal phase mapping
# Internal reconstruction phases -> LM kill-chain stage.
PHASE_TO_STAGE: dict[str, str] = {
    "recon": "reconnaissance",
    "initial_access": "exploitation",
    "delivery": "delivery",
    "c2": "command_and_control",
    "lateral": "actions_on_objectives",
    "impact": "actions_on_objectives",
    "unknown": "actions_on_objectives",
}


def stage_for_phase(phase: str | None) -> str:
    return PHASE_TO_STAGE.get(phase or "", "actions_on_objectives")


def stage_rank(stage: str) -> int:
    """Chain depth (later stages = deeper progression; -1 unknown)."""
    try:
        return STAGES.index(stage)
    except ValueError:
        return -1


# ------------------------------------------------- MITRE ATT&CK mapping
# Dual framework: rule name -> ATT&CK techniques (tactic / id / name).
_T = lambda tactic, tid, name: {"tactic": tactic, "technique_id": tid,
                                "technique": name}  # noqa: E731

ATTCK_FOR_RULE: dict[str, list[dict]] = {
    "portscan_suspected": [
        _T("Reconnaissance", "T1046", "Network Service Discovery"),
        _T("Reconnaissance", "T1595.002", "Vulnerability Scanning"),
    ],
    "dns_nxdomain_burst": [
        _T("Reconnaissance", "T1590", "Gather Victim Network Information"),
        _T("Reconnaissance", "T1018", "Remote System Discovery"),
    ],
    "beaconing_possible": [
        _T("Command and Control", "T1071", "Application Layer Protocol"),
        _T("Command and Control", "T1095", "Non-Application Layer Protocol"),
    ],
    "dga_suspected": [
        _T("Command and Control", "T1568.002",
           "Domain Generation Algorithms"),
    ],
    "dns_tunneling_suspected": [
        _T("Command and Control", "T1071.004", "DNS"),
    ],
    "file_transfer_suspected": [
        _T("Command and Control", "T1105", "Ingress Tool Transfer"),
    ],
    "internal_lateral_suspected": [
        _T("Lateral Movement", "T1021", "Remote Services"),
    ],
    "large_outbound_transfer": [
        _T("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        _T("Exfiltration", "T1567", "Exfiltration Over Web Service"),
    ],
    "ioc_match": [],          # resolved per IOC type below
    "suricata_alert_group": [],   # resolved per category below
}

# Suricata alert.category -> ATT&CK techniques (same keys as taxonomy).
ATTCK_FOR_CATEGORY: dict[str, list[dict]] = {
    "attempted-recon": [_T("Reconnaissance", "T1595", "Active Scanning")],
    "scan": [_T("Reconnaissance", "T1046", "Network Service Discovery")],
    "web-application-attack": [
        _T("Initial Access", "T1190", "Exploit Public-Facing Application")],
    "exploit-kit": [_T("Initial Access", "T1189",
                       "Drive-by Compromise")],
    "client-side-exploit": [_T("Initial Access", "T1203",
                               "Exploitation for Client Execution")],
    "attempted-admin": [_T("Initial Access", "T1190",
                           "Exploit Public-Facing Application")],
    "attempted-user": [_T("Initial Access", "T1203",
                          "Exploitation for Client Execution")],
    "successful-admin": [_T("Initial Access", "T1190",
                            "Exploit Public-Facing Application")],
    "successful-user": [_T("Initial Access", "T1203",
                           "Exploitation for Client Execution")],
    "sql-injection": [_T("Initial Access", "T1190",
                         "Exploit Public-Facing Application")],
    "cross-site-scripting": [_T("Initial Access", "T1190",
                                "Exploit Public-Facing Application")],
    "shellcode-detect": [_T("Initial Access", "T1203",
                            "Exploitation for Client Execution")],
    "file-format": [_T("Initial Access", "T1203",
                       "Exploitation for Client Execution")],
    "denial-of-service": [_T("Impact", "T1498",
                             "Network Denial of Service")],
    "attempted-dos": [_T("Impact", "T1498", "Network Denial of Service")],
    "malware": [_T("Command and Control", "T1105",
                   "Ingress Tool Transfer")],
    "file-download": [_T("Command and Control", "T1105",
                         "Ingress Tool Transfer")],
    "trojan-activity": [_T("Command and Control", "T1071",
                           "Application Layer Protocol")],
    "command-and-control": [_T("Command and Control", "T1071",
                               "Application Layer Protocol")],
    "botnet": [_T("Command and Control", "T1071",
                  "Application Layer Protocol")],
    "malware-cnc": [_T("Command and Control", "T1071",
                       "Application Layer Protocol")],
}

# IOC type -> stage bias + ATT&CK (fallback when rule gives nothing).
IOC_PHASE_TO_ATTCK: dict[str, list[dict]] = {
    "delivery": [_T("Command and Control", "T1105",
                    "Ingress Tool Transfer")],
    "c2": [_T("Command and Control", "T1071",
              "Application Layer Protocol")],
}

# Stage-level default ATT&CK (used when evidence carries no explicit
# mapping - keeps the dual framework total over the chain).
ATTCK_FOR_STAGE: dict[str, list[dict]] = {
    "reconnaissance": [_T("Reconnaissance", "T1595", "Active Scanning")],
    "delivery": [_T("Command and Control", "T1105",
                    "Ingress Tool Transfer")],
    "exploitation": [_T("Initial Access", "T1190",
                        "Exploit Public-Facing Application")],
    "command_and_control": [_T("Command and Control", "T1071",
                               "Application Layer Protocol")],
    "actions_on_objectives": [_T("Exfiltration", "T1041",
                                 "Exfiltration Over C2 Channel")],
    "weaponization": [],
    "installation": [],
}

# ---------------------------------------------------------- classification
def classify_rule(alert_type: str | None) -> tuple[str, list[dict]]:
    """Kill-chain stage + ATT&CK techniques for an internal rule name."""
    from app.detection.taxonomy import phase_for_rule
    phase = phase_for_rule(alert_type)
    stage = stage_for_phase(phase)
    return stage, list(ATTCK_FOR_RULE.get(alert_type or "", [])) or \
        list(ATTCK_FOR_STAGE.get(stage, []))


def classify_suricata(category: str | None,
                      signature: str | None = None
                      ) -> tuple[str, list[dict]]:
    """Kill-chain stage + ATT&CK for a Suricata category/signature."""
    from app.detection.taxonomy import phase_for_suricata_category
    phase = phase_for_suricata_category(category, signature)
    stage = stage_for_phase(phase)
    cat = (category or "").strip().lower()
    attck = ATTCK_FOR_CATEGORY.get(cat)
    if not attck:
        for key, techniques in ATTCK_FOR_CATEGORY.items():
            if key in cat:
                attck = techniques
                break
    return stage, list(attck or ATTCK_FOR_STAGE.get(stage, []))


def classify_ioc(ioc_type: str | None) -> tuple[str, list[dict]]:
    """Kill-chain stage + ATT&CK for an IOC type match."""
    from app.detection.taxonomy import phase_for_ioc
    phase = phase_for_ioc(ioc_type)
    stage = stage_for_phase(phase)
    return stage, list(IOC_PHASE_TO_ATTCK.get(phase, [])) or \
        list(ATTCK_FOR_STAGE.get(stage, []))


# ------------------------------------------------------------ assessment
def _evidence_stage(ev: dict) -> str:
    stage = ev.get("stage")
    if stage in STAGES:
        return stage
    return stage_for_phase(ev.get("phase"))


def _evidence_attck(ev: dict) -> list[dict]:
    explicit = ev.get("attck") or ev.get("mitre")
    if isinstance(explicit, list) and explicit:
        return [t for t in explicit
                if isinstance(t, dict) and t.get("technique_id")]
    stage = _evidence_stage(ev)
    return list(ATTCK_FOR_STAGE.get(stage, []))


_DIRECT_KINDS = {"alert", "ioc_event"}


def assess_stages(evidence: list[dict]) -> list[dict]:
    """Evidence-based 7-stage assessment (doc 11).

    Pure function over evidence dicts ({ts_epoch|ts, kind, stage, phase,
    severity, ...}) so the pipeline and the API share identical logic.

    Statuses:
      observed               - >=1 direct signal (alert / ioc_event)
      suspected              - only context/inferred evidence
      not_observed           - network telemetry covers the stage, no
                               evidence in this story
      insufficient_telemetry - stage not assessable from network data
    """
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
    """Uncalibrated per-stage confidence from evidence mix (doc 10.4)."""
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
