PHASES = ("intake", "triage", "map", "hypothesis", "deep-analysis", "validation", "evidence", "report", "final")
GATES = {
    ("intake", "triage"): ("objective", "artifact_inventory"),
    ("triage", "map"): ("triage_summary",),
    ("map", "hypothesis"): ("surface_map",),
    ("hypothesis", "deep-analysis"): ("active_hypothesis",),
    ("deep-analysis", "validation"): ("analysis_result",),
    ("validation", "evidence"): ("validation_result",),
    ("evidence", "report"): ("evidence_manifest",),
    ("report", "final"): ("report",),
}


def validate_transition(current, target, deliverables):
    if target not in PHASES:
        raise ValueError(f"unknown phase: {target}")
    retry = current == "validation" and target == "hypothesis"
    if not retry and PHASES.index(target) != PHASES.index(current) + 1:
        raise ValueError(f"invalid transition: {current} -> {target}")
    required = ("validation_failed",) if retry else GATES.get((current, target), ())
    missing = [name for name in required if not (deliverables or {}).get(name)]
    if missing:
        raise ValueError("missing deliverables: " + ", ".join(missing))
    return {"required": list(required), "satisfied": True, "missing": []}
