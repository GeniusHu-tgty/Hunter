from __future__ import annotations
from .backends import BackendRegistry

COSTS = {"hunter_tools": 1, "reverse_lab_tools": 2, "ghidra": 2, "jshook": 2}


def build_plan(state, registry: BackendRegistry, max_actions=5):
    if state.get("status") == "complete" and state.get("policy", {}).get("stop_on_proof", True):
        return {"workflow_id": state["workflow_id"], "lane": state["lane"], "phase": state["phase"], "actions": [], "requires_confirmation": False, "early_stop": "confirmed-proof"}
    limit = min(max_actions, state["policy"]["max_tool_calls"])
    actions = []
    backends = registry.resolve(state["lane"])
    candidates = []
    for backend in backends:
        for capability in backend["capabilities"]:
            candidates.append((backend, capability))
    if state["lane"] == "mixed":
        ordered = []
        remaining = list(candidates)
        for backend in backends:
            match = next(((b, c) for b, c in remaining if b["server"] == backend["server"]), None)
            if match:
                ordered.append(match); remaining.remove(match)
        candidates = ordered + remaining
    for backend, capability in candidates[:limit]:
        actions.append({"id": f"action-{len(actions)+1:03d}", "server": backend["server"], "tool": capability, "execution": backend["execution"], "phase": state["phase"], "estimated_cost": {"tool_calls": 1, "weight": COSTS.get(backend["server"], 2)}, "risk": "low" if COSTS.get(backend["server"], 2) == 1 and capability in {"hunter_fast_scan", "hunter_scan_plan", "hunter_js_analyze", "hunter_kb_recommend"} else "medium", "status": "ready"})
    return {"workflow_id": state["workflow_id"], "lane": state["lane"], "phase": state["phase"], "actions": actions, "requires_confirmation": state["policy"]["mode"] == "interactive"}
