from __future__ import annotations
import hashlib, json, os, uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import get_ident
from typing import Any, Callable, Mapping, Sequence
from .backends import BackendRegistry
from .locking import WorkflowFileLock
from .models import WorkflowPolicy
from .phases import validate_transition
from .planner import build_plan
from .router import LANES, route


def now(): return datetime.now(timezone.utc).isoformat()

def ident(prefix): return f"{prefix}-{uuid.uuid4().hex[:12]}"


ORCHESTRATOR_STAGES = (
    "memory",
    "recon",
    "attack_surface",
    "attack_execution",
    "vulnerability_confirmation",
    "evidence_learning",
    "report",
)

ORCHESTRATOR_PROFILES = {
    "fast": {"max_endpoints": 20, "max_attack_surfaces": 5, "depth": "shallow"},
    "standard": {"max_endpoints": 100, "max_attack_surfaces": 12, "depth": "standard"},
    "deep": {"max_endpoints": 500, "max_attack_surfaces": 30, "depth": "deep"},
}


class OrchestratorInterrupted(RuntimeError):
    """Raised by an injected stage adapter when external work is interrupted."""

class WorkflowKernel:
    def __init__(self, root, registry=None):
        self.root = Path(root).resolve(); self.registry = registry or BackendRegistry.default()

    def _dir(self, slug):
        if not slug or any(x in slug for x in ("/", "\\", "..")): raise ValueError("invalid workflow slug")
        return self.root / "cases" / slug
    def _events(self, slug): return self._dir(slug) / "workflow.events.jsonl"
    def _state(self, slug): return self._dir(slug) / "workflow.json"
    def _lock(self, slug): return WorkflowFileLock(self._dir(slug) / ".workflow.lock")
    def _orchestrator_lock(self, slug): return WorkflowFileLock(self._dir(slug) / ".orchestrator.lock")
    def _state_tmp(self, slug):
        return self._state(slug).with_name(
            f".{self._state(slug).name}.{os.getpid()}.{get_ident()}.tmp"
        )
    @staticmethod
    def _tmp_for(path, label="tmp"):
        path = Path(path)
        return path.with_name(
            f".{path.name}.{os.getpid()}.{get_ident()}.{label}"
        )
    def _write_json_atomic(self, path, value):
        path = Path(path)
        temporary = self._tmp_for(path)
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(value, ensure_ascii=False, indent=2))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                self._safe_unlink(temporary)
    @staticmethod
    def _safe_unlink(path):
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass
    @staticmethod
    def _valid_event_prefix(lines):
        valid = []
        previous_hash = ""
        expected_revision = 1
        for raw_line in lines:
            if not raw_line.strip():
                continue
            try:
                event = json.loads(raw_line.decode("utf-8"))
                supplied = event.get("event_hash", "")
                unsigned = {
                    key: value
                    for key, value in event.items()
                    if key != "event_hash"
                }
                canonical = json.dumps(
                    unsigned,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                calculated = hashlib.sha256(canonical.encode()).hexdigest()
                if (
                    supplied != calculated
                    or event.get("revision") != expected_revision
                    or event.get("previous_event_hash", "") != previous_hash
                ):
                    break
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
                break
            valid.append(raw_line)
            previous_hash = supplied
            expected_revision += 1
        return valid

    @staticmethod
    def _ensure_orchestrator_defaults(state):
        state.setdefault("orchestrator", {})
        orchestrator = state["orchestrator"]
        orchestrator.setdefault("version", "1.0")
        orchestrator.setdefault("status", "idle")
        orchestrator.setdefault("current_stage", "memory")
        orchestrator.setdefault("profile", "standard")
        orchestrator.setdefault("modules", ["all"])
        orchestrator.setdefault("stage_status", {})
        for stage in ORCHESTRATOR_STAGES:
            orchestrator["stage_status"].setdefault(stage, "pending")
        orchestrator.setdefault("stage_results", {})
        orchestrator.setdefault("confirmation_required", [])
        orchestrator.setdefault("approvals", [])
        orchestrator.setdefault("approval_consumptions", [])
        orchestrator.setdefault("observations", {})
        orchestrator.setdefault("resumed_from", "")
        orchestrator.setdefault(
            "generation",
            {
                "id": f"gen-{hashlib.sha256(str(state.get('slug', '')).encode()).hexdigest()[:12]}",
                "base_slug": state.get("slug", ""),
                "number": 1,
                "config": {},
            },
        )
        state.setdefault("memo", {})
        state.setdefault("target_profile", {})
        state.setdefault("attack_surface", {})
        state.setdefault("attack_queue", [])
        state.setdefault("learning_updates", [])
        state.setdefault("report_path", "")
        return state

    def _append(self, slug, event_type, payload, expected_revision=None):
        with self._lock(slug):
            directory=self._dir(slug); directory.mkdir(parents=True, exist_ok=True)
            existing=[]
            if self._events(slug).exists():
                existing=[json.loads(line) for line in self._events(slug).read_text(encoding="utf-8").splitlines() if line.strip()]
            revision=len(existing)+1
            if expected_revision is not None and expected_revision != len(existing): raise ValueError(f"revision conflict: expected {expected_revision}, current {len(existing)}")
            previous_hash=existing[-1].get("event_hash", "") if existing else ""
            workflow_id = payload.get("state", {}).get("workflow_id") if event_type == "workflow.created" else self.materialize(slug)["workflow_id"]
            event={"event_id": ident("evt"), "schema_version":"1.0", "workflow_id":workflow_id, "actor":"hunter_tools", "type":event_type, "timestamp":now(), "revision":revision, "previous_event_hash":previous_hash, "payload":payload}
            canonical=json.dumps(event,ensure_ascii=False,sort_keys=True,separators=(",",":"))
            event["event_hash"]=hashlib.sha256(canonical.encode()).hexdigest()
            with self._events(slug).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False)+"\n"); fh.flush(); os.fsync(fh.fileno())
            state=self.materialize(slug)
            tmp=self._state_tmp(slug)
            try:
                tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
                os.replace(tmp,self._state(slug))
            except OSError:
                # workflow.json is a derived cache; the fsynced event is authoritative.
                pass
            finally:
                if tmp.exists():
                    self._safe_unlink(tmp)
            return state
    def create(self, slug, objective, inputs=None, mode="interactive", success_conditions=None, proof_types=None):
        with self._lock(slug):
            if self._events(slug).exists(): raise ValueError("workflow already exists")
            routed=self.route(inputs=inputs or []); policy=WorkflowPolicy(mode=mode)
            base={"schema_version":"2.0", "workflow_id":ident("wf"), "slug":slug, "case":{"slug":slug,"created_at":now(),"updated_at":now()}, "objective":{"text":objective,"success_conditions":success_conditions or [],"proof_types":proof_types or []}, "scope":{"targets":inputs or [],"allowed_actions":[],"constraints":[]}, "status":"active", "phase":"intake", "lane":routed["primary_lane"], "lane_history":[], "assets":[], "artifacts":inputs or [], "inputs":inputs or [], "signals":routed["signals"], "hypotheses":[], "decisions":[], "tool_runs":[], "evidence":[], "findings":[], "dead_ends":[], "blockers":[], "checkpoints":[], "next_steps":[], "policy":policy.to_dict(), "metrics":{"tool_calls":0,"checkpoints":0}, "orchestrator":{"version":"1.0","status":"idle","current_stage":"memory","profile":"standard","modules":["all"],"stage_status":{stage:"pending" for stage in ORCHESTRATOR_STAGES},"stage_results":{},"confirmation_required":[],"resumed_from":""}, "memo":{}, "target_profile":{}, "attack_surface":{}, "attack_queue":[], "learning_updates":[], "report_path":"", "created_at":now(), "updated_at":now()}
            return {"state":self._append(slug,"workflow.created",{"state":base}), "route":routed}
    def materialize(self, slug):
        with self._lock(slug):
            path=self._events(slug)
            if not path.exists(): raise FileNotFoundError(f"workflow not found: {slug}")
            state=None; history=[]
            previous_hash=""; expected_revision=1
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip(): continue
                event=json.loads(line)
                supplied=event.get("event_hash",""); unsigned={k:v for k,v in event.items() if k!="event_hash"}; canonical=json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(",",":")); calculated=hashlib.sha256(canonical.encode()).hexdigest()
                if supplied != calculated: raise ValueError("event hash mismatch")
                if event.get("revision") != expected_revision or event.get("previous_event_hash","") != previous_hash: raise ValueError("event chain mismatch")
                previous_hash=supplied; expected_revision+=1
                typ=event["type"]; p=event["payload"]
                if typ=="workflow.created":
                    state=deepcopy(p["state"])
                    self._ensure_orchestrator_defaults(state)
                elif typ=="phase.transitioned": state["phase"]=p["phase"]; state["last_gate"]=p["gate"]
                elif typ=="hypothesis.added": state["hypotheses"].append(p["hypothesis"])
                elif typ=="policy.changed": state["policy"]=p["policy"]
                elif typ=="dead_end.recorded": state["dead_ends"].append(p["dead_end"])
                elif typ=="evidence.registered": state["evidence"].append(p["evidence"])
                elif typ=="finding.promoted":
                    state["findings"].append(p["finding"])
                    conditions=set(state.get("objective",{}).get("success_conditions",[])) if isinstance(state.get("objective"),dict) else set()
                    satisfies=set(p["finding"].get("satisfies",[]))
                    if p["finding"].get("status") == "confirmed" and conditions and conditions <= satisfies and state["policy"].get("stop_on_proof", True):
                        state["status"] = "complete"
                elif typ=="checkpoint.created": state["checkpoints"].append(p["checkpoint"]); state["metrics"]["checkpoints"]+=1
                elif typ=="orchestrator.initialized":
                    self._ensure_orchestrator_defaults(state)
                    state["orchestrator"].update(deepcopy(p.get("orchestrator", {})))
                    self._ensure_orchestrator_defaults(state)
                elif typ=="orchestrator.observations.updated":
                    self._ensure_orchestrator_defaults(state)
                    state["orchestrator"]["observations"].update(
                        deepcopy(p.get("observations", {}))
                    )
                elif typ=="orchestrator.approval.recorded":
                    self._ensure_orchestrator_defaults(state)
                    approval = deepcopy(p["approval"])
                    approval.setdefault("consumed", False)
                    state["orchestrator"]["approvals"].append(approval)
                elif typ=="orchestrator.approval.consumed":
                    self._ensure_orchestrator_defaults(state)
                    consumption = deepcopy(p["consumption"])
                    state["orchestrator"]["approval_consumptions"].append(consumption)
                    for approval in reversed(state["orchestrator"]["approvals"]):
                        if (
                            approval.get("confirmation_id")
                            == consumption.get("confirmation_id")
                            and approval.get("decision_id")
                            == consumption.get("decision_id")
                        ):
                            approval["consumed"] = True
                            approval["consumed_at"] = consumption["consumed_at"]
                            break
                    state["orchestrator"]["confirmation_required"] = [
                        item
                        for item in state["orchestrator"]["confirmation_required"]
                        if item.get("confirmation_id")
                        != consumption.get("confirmation_id")
                    ]
                elif typ=="orchestrator.generation.started":
                    self._ensure_orchestrator_defaults(state)
                    state["orchestrator"]["generation"] = deepcopy(
                        p["generation"]
                    )
                elif typ=="orchestrator.stage.started":
                    self._ensure_orchestrator_defaults(state)
                    stage = p["stage"]
                    state["orchestrator"]["current_stage"] = stage
                    state["orchestrator"]["status"] = "running"
                    state["orchestrator"]["stage_status"][stage] = "running"
                elif typ=="orchestrator.stage.completed":
                    self._ensure_orchestrator_defaults(state)
                    stage = p["stage"]
                    result = deepcopy(p.get("result", {}))
                    state["orchestrator"]["current_stage"] = stage
                    state["orchestrator"]["stage_status"][stage] = "completed"
                    state["orchestrator"]["stage_results"][stage] = result
                    self._apply_orchestrator_result(state, stage, result)
                elif typ=="orchestrator.stage.blocked":
                    self._ensure_orchestrator_defaults(state)
                    stage = p["stage"]
                    state["orchestrator"]["current_stage"] = stage
                    state["orchestrator"]["status"] = p.get("status", "blocked")
                    state["orchestrator"]["stage_status"][stage] = p.get("status", "blocked")
                    if "result" in p:
                        state["orchestrator"]["stage_results"][stage] = deepcopy(p["result"])
                    state["orchestrator"]["confirmation_required"] = deepcopy(
                        p.get("confirmation_required", [])
                    )
                elif typ=="orchestrator.interrupted":
                    self._ensure_orchestrator_defaults(state)
                    state["orchestrator"]["status"] = "interrupted"
                    state["orchestrator"]["current_stage"] = p["stage"]
                    state["orchestrator"]["stage_status"][p["stage"]] = "interrupted"
                elif typ=="orchestrator.completed":
                    self._ensure_orchestrator_defaults(state)
                    state["orchestrator"]["status"] = "completed"
                    state["orchestrator"]["current_stage"] = "complete"
                    state["status"] = "complete" if p.get("complete") else state["status"]
                state["updated_at"]=event["timestamp"]; history.append({"event_id":event["event_id"],"type":typ,"timestamp":event["timestamp"]})
            self._ensure_orchestrator_defaults(state)
            state["history"]=history; return state

    @staticmethod
    def _apply_orchestrator_result(state, stage, result):
        if stage == "memory":
            state["memo"] = deepcopy(result.get("memo", result))
        elif stage == "recon":
            state["target_profile"] = deepcopy(result.get("target_profile", result))
        elif stage == "attack_surface":
            state["attack_surface"] = deepcopy(result.get("attack_surface", result))
            state["attack_queue"] = deepcopy(result.get("attack_queue", []))
        elif stage == "evidence_learning":
            state["learning_updates"] = deepcopy(result.get("learning_updates", []))
        elif stage == "report":
            state["report_path"] = str(result.get("report_path", ""))

    def open(self, slug): return {"state":self.materialize(slug), "events_path":str(self._events(slug)), "state_path":str(self._state(slug))}
    def status(self, slug):
        s=self.materialize(slug)
        return {
            **{k: s[k] for k in ("workflow_id","slug","status","phase","lane","updated_at","metrics")},
            "orchestrator": deepcopy(s.get("orchestrator", {})),
            "stage_results": deepcopy(s.get("orchestrator", {}).get("stage_results", {})),
            "confirmation_required": deepcopy(
                s.get("orchestrator", {}).get("confirmation_required", [])
            ),
        }
    def route(self, inputs): return route(inputs)
    def transition(self, slug, phase, deliverables=None):
        with self._lock(slug):
            state=self.materialize(slug); gate=validate_transition(state["phase"],phase,deliverables or {})
            return {"state":self._append(slug,"phase.transitioned",{"phase":phase,"gate":gate,"deliverables":deliverables or {}}),"gate":gate}
    def add_hypothesis(self, slug, claim, confidence=0.5, validation_step=None, expected_revision=None):
        hyp={"id":ident("hyp"),"claim":claim,"confidence":float(confidence),"status":"proposed","supporting_evidence":[],"contradicting_evidence":[],"validation_step":validation_step or {},"created_at":now()}
        return {"hypothesis":hyp,"state":self._append(slug,"hypothesis.added",{"hypothesis":hyp},expected_revision)}
    def set_policy(self, slug, policy):
        if isinstance(policy, dict): policy=WorkflowPolicy(**policy)
        return {"state":self._append(slug,"policy.changed",{"policy":policy.to_dict()})}
    def plan(self, slug, max_actions=5): return build_plan(self.materialize(slug),self.registry,max_actions)
    def run(self, slug, execute_native, max_actions=5):
        state = self.materialize(slug)
        if state["policy"]["mode"] == "interactive":
            raise ValueError("interactive policy requires confirmation")
        plan = self.plan(slug, max_actions)
        executed, handoffs, pending, confirmations = [], [], [], []
        for action in plan["actions"]:
            if state["policy"]["mode"] == "guided" and action.get("risk") != "low":
                confirmations.append(action); continue
            if action["execution"] != "native":
                handoffs.append(action)
                continue
            result = execute_native(action)
            if result.get("status") == "deferred":
                pending.append(action); continue
            run = {"id": ident("run"), "action": action, "result": result, "created_at": now()}
            executed.append(run)
        return {"workflow_id": state["workflow_id"], "executed": executed, "handoffs": handoffs, "pending_actions": pending, "confirmation_actions": confirmations, "plan": plan}

    def record_dead_end(self, slug, summary, signature):
        with self._lock(slug):
            state=self.materialize(slug)
            if any(x["signature"]==signature for x in state["dead_ends"]): return {"dead_end":next(x for x in state["dead_ends"] if x["signature"]==signature),"deduplicated":True,"state":state}
            item={"id":ident("dead"),"summary":summary,"signature":signature,"created_at":now()}
            return {"dead_end":item,"deduplicated":False,"state":self._append(slug,"dead_end.recorded",{"dead_end":item})}
    def register_evidence(self, slug, summary, source, path_or_url="", evidence_type="note", confidence="medium", sha256="", dedupe_key=""):
        with self._lock(slug):
            state = self.materialize(slug)
            if dedupe_key:
                existing = next(
                    (
                        item
                        for item in state["evidence"]
                        if item.get("dedupe_key") == dedupe_key
                    ),
                    None,
                )
                if existing is not None:
                    return {
                        "evidence": existing,
                        "state": state,
                        "deduplicated": True,
                    }
            if path_or_url and not sha256:
                p=Path(path_or_url)
                if p.is_file(): sha256=hashlib.sha256(p.read_bytes()).hexdigest()
            item={"id":ident("ev"),"type":evidence_type,"source":source,"summary":summary,"path_or_url":path_or_url,"timestamp":now(),"sha256":sha256,"confidence":confidence}
            if dedupe_key:
                item["dedupe_key"] = dedupe_key
            return {"evidence":item,"state":self._append(slug,"evidence.registered",{"evidence":item}),"deduplicated":False}
    def promote_finding(self, slug, title, status, evidence_ids, severity="Info", satisfies=None, proof_type="", dedupe_key=""):
        with self._lock(slug):
            state = self.materialize(slug)
            if dedupe_key:
                existing = next(
                    (
                        item
                        for item in state["findings"]
                        if item.get("dedupe_key") == dedupe_key
                    ),
                    None,
                )
                if existing is not None:
                    return {
                        "finding": existing,
                        "state": state,
                        "deduplicated": True,
                    }
            valid={x["id"] for x in state["evidence"]}
            if status in {"reproduced","confirmed","reported"} and (not evidence_ids or not set(evidence_ids)<=valid): raise ValueError("valid evidence is required")
            item={"id":ident("finding"),"title":title,"severity":severity,"status":status,"evidence_ids":evidence_ids,"satisfies":satisfies or [],"proof_type":proof_type,"created_at":now()}
            if dedupe_key:
                item["dedupe_key"] = dedupe_key
            return {"finding":item,"state":self._append(slug,"finding.promoted",{"finding":item}),"deduplicated":False}
    def checkpoint(self, slug, source_session=""):
        with self._lock(slug):
            state=self.materialize(slug); cp_id=ident("cp"); directory=self._dir(slug)/"checkpoints"; directory.mkdir(parents=True,exist_ok=True); path=directory/f"{cp_id}.json"
            body={"checkpoint_id":cp_id,"schema_version":"1.0","source_session":source_session,"source_event_count":len(state["history"])+1,"created_at":now(),"state":state,"resume_hint":{"objective":state["objective"].get("text", "") if isinstance(state["objective"], dict) else state["objective"],"phase":state["phase"],"lane":state["lane"],"next_steps":state["next_steps"],"dead_end_signatures":[x["signature"] for x in state["dead_ends"]]}}
            self._write_json_atomic(path, body)
            try:
                self._append(slug,"checkpoint.created",{"checkpoint":{"checkpoint_id":cp_id,"path":str(path),"source_session":source_session,"created_at":body["created_at"]}})
            except BaseException:
                self._safe_unlink(path)
                raise
            return {"checkpoint_id":cp_id,"path":str(path),"resume_hint":body["resume_hint"]}
    def resume(self, slug, checkpoint_id=""):
        with self._lock(slug):
            if checkpoint_id:
                if not checkpoint_id.startswith("cp-") or any(
                    item in checkpoint_id for item in ("/", "\\", "..")
                ):
                    raise ValueError("invalid checkpoint id")
                path = self._dir(slug) / "checkpoints" / f"{checkpoint_id}.json"
                body = json.loads(path.read_text(encoding="utf-8"))
                checkpoint_state = body["state"]
                if checkpoint_state.get("slug") != slug:
                    raise ValueError("checkpoint workflow mismatch")
                event_path = self._events(slug)
                lines = event_path.read_bytes().splitlines()
                keep_count = max(0, int(body["source_event_count"]) - 1)
                try:
                    current = self.materialize(slug)
                except (
                    ValueError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    KeyError,
                    TypeError,
                ):
                    current = None
                if current is not None:
                    if checkpoint_state["workflow_id"] != current["workflow_id"]:
                        raise ValueError("checkpoint workflow mismatch")
                    current["resume_metadata"] = {
                        "checkpoint_id": checkpoint_id,
                        "source_event_count": body["source_event_count"],
                        "discarded_events": 0,
                        "events_after_checkpoint": max(
                            0,
                            len(current["history"]) - body["source_event_count"],
                        ),
                    }
                    return {
                        "state": current,
                        "resume_hint": {
                            "objective": current["objective"].get("text", "")
                            if isinstance(current["objective"], dict)
                            else current["objective"],
                            "phase": current["phase"],
                            "lane": current["lane"],
                            "next_steps": current["next_steps"],
                        },
                        "checkpoint_id": checkpoint_id,
                    }
                kept = self._valid_event_prefix(lines)
                if len(kept) < keep_count:
                    raise ValueError("checkpoint event prefix is corrupt")
                temporary = self._tmp_for(event_path, "restore")
                try:
                    with temporary.open("wb") as handle:
                        if kept:
                            handle.write(b"\n".join(kept) + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, event_path)
                finally:
                    if temporary.exists():
                        self._safe_unlink(temporary)
                current = self.materialize(slug)
                if checkpoint_state["workflow_id"] != current["workflow_id"]:
                    raise ValueError("checkpoint workflow mismatch")
                current["resume_metadata"] = {
                    "checkpoint_id": checkpoint_id,
                    "source_event_count": body["source_event_count"],
                    "discarded_events": max(0, len(lines) - len(kept)),
                }
                self._write_json_atomic(self._state(slug), current)
                return {
                    "state": current,
                    "resume_hint": {
                        "objective": current["objective"].get("text", "")
                        if isinstance(current["objective"], dict)
                        else current["objective"],
                        "phase": current["phase"],
                        "lane": current["lane"],
                        "next_steps": current["next_steps"],
                    },
                    "checkpoint_id": checkpoint_id,
                }
            state=self.materialize(slug); return {"state":state,"resume_hint":{"objective":state["objective"].get("text", "") if isinstance(state["objective"], dict) else state["objective"],"phase":state["phase"],"lane":state["lane"],"next_steps":state["next_steps"]}}
    def backend_status(self): return self.registry.status()
    def lane_catalog(self): return {"lanes":list(LANES),"backends":self.registry.status()["backends"]}


class UnifiedOrchestrator:
    """Coordinate Hunter subsystems through resumable, deferred stages."""

    def __init__(
        self,
        kernel: WorkflowKernel,
        adapters: Mapping[str, Callable[[dict[str, Any]], Mapping[str, Any]]] | None = None,
        services: Mapping[str, Any] | None = None,
    ):
        self.kernel = kernel
        self.services = dict(services or {})
        from core.unified_scanner import UnifiedOrchestrationBridge

        self.integration = UnifiedOrchestrationBridge(self.services)
        defaults = self._default_adapters()
        defaults.update(dict(adapters or {}))
        missing = [stage for stage in ORCHESTRATOR_STAGES if stage not in defaults]
        if missing:
            raise ValueError("missing orchestrator adapters: " + ", ".join(missing))
        self.adapters = defaults

    @staticmethod
    def _profile(policy: str) -> dict[str, Any]:
        normalized = str(policy or "standard").strip().lower()
        if normalized not in ORCHESTRATOR_PROFILES:
            raise ValueError("policy must be fast, standard, or deep")
        return {"name": normalized, **ORCHESTRATOR_PROFILES[normalized]}

    @staticmethod
    def _modules(modules: Sequence[str] | None) -> list[str]:
        selected = [str(item).strip().lower() for item in (modules or ["all"]) if str(item).strip()]
        if not selected:
            selected = ["all"]
        allowed = {"all", "web", "api", "js", "reverse"}
        invalid = sorted(set(selected) - allowed)
        if invalid:
            raise ValueError("unknown modules: " + ", ".join(invalid))
        return ["all"] if "all" in selected else list(dict.fromkeys(selected))

    @staticmethod
    def _target_from_state(state: Mapping[str, Any]) -> str:
        for item in state.get("inputs", []):
            if isinstance(item, Mapping) and item.get("type") in {"url", "target"}:
                return str(item.get("value") or item.get("url") or "")
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                return item
        return ""

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): UnifiedOrchestrator._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [UnifiedOrchestrator._json_safe(item) for item in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    @staticmethod
    def _confirmation_digest(stage: str, action: Mapping[str, Any]) -> str:
        canonical_action = {
            "stage": stage,
            "tool": action.get("tool", ""),
            "target": action.get("target", ""),
            "arguments": deepcopy(action.get("arguments", {})),
            "scope": deepcopy(action.get("scope", {})),
        }
        canonical = json.dumps(
            UnifiedOrchestrator._json_safe(canonical_action),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def _normalize_confirmations(
        cls,
        stage: str,
        actions: Sequence[Any],
    ) -> list[dict[str, Any]]:
        normalized = []
        for raw_action in actions:
            action = (
                dict(raw_action)
                if isinstance(raw_action, Mapping)
                else {"description": str(raw_action)}
            )
            action["stage"] = stage
            action["scope"] = cls._json_safe(action.get("scope", {}))
            digest = cls._confirmation_digest(stage, action)
            action["confirmation_id"] = f"confirm-{digest[:20]}"
            action["confirmation_digest"] = digest
            action["requested_at"] = now()
            normalized.append(cls._json_safe(action))
        return normalized

    @staticmethod
    def _validate_approval(
        state: Mapping[str, Any],
        approval: Mapping[str, Any],
    ) -> dict[str, Any]:
        decision = dict(approval)
        stage = str(decision.get("stage", "")).strip()
        decision_id = str(decision.get("decision_id", "")).strip()
        confirmation_id = str(
            decision.get("confirmation_id", "")
        ).strip()
        confirmation_digest = str(
            decision.get("confirmation_digest", "")
        ).strip()
        if stage not in ORCHESTRATOR_STAGES:
            raise ValueError("approval stage is invalid")
        if decision.get("approved") is not True:
            raise ValueError("approval must explicitly set approved=true")
        if not decision_id:
            raise ValueError("approval decision_id is required")
        pending = [
            item
            for item in state.get("orchestrator", {}).get(
                "confirmation_required", []
            )
            if isinstance(item, Mapping)
        ]
        match = next(
            (
                item
                for item in pending
                if item.get("confirmation_id") == confirmation_id
            ),
            None,
        )
        if match is None:
            raise ValueError("approval pending confirmation not found")
        if match.get("stage") != stage:
            raise ValueError("approval stage does not match confirmation")
        if match.get("confirmation_digest") != confirmation_digest:
            raise ValueError("approval confirmation digest mismatch")
        scope = UnifiedOrchestrator._json_safe(
            deepcopy(decision.get("scope", {}))
        )
        if scope != match.get("scope", {}):
            raise ValueError("approval scope does not match confirmation")
        for existing in state.get("orchestrator", {}).get("approvals", []):
            if (
                existing.get("confirmation_id") == confirmation_id
                and existing.get("consumed")
            ):
                raise ValueError("approval confirmation was already consumed")
        return {
            "stage": stage,
            "approved": True,
            "decision_id": decision_id,
            "confirmation_id": confirmation_id,
            "confirmation_digest": confirmation_digest,
            "scope": scope,
            "consumed": False,
            "recorded_at": now(),
        }

    @staticmethod
    def _approval_for_confirmation(
        state: Mapping[str, Any],
        stage: str,
        confirmation: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        approvals = state.get("orchestrator", {}).get("approvals", [])
        return next(
            (
                item
                for item in reversed(approvals)
                if (
                    item.get("approved") is True
                    and item.get("stage") == stage
                    and item.get("confirmation_id")
                    == confirmation.get("confirmation_id")
                    and item.get("confirmation_digest")
                    == confirmation.get("confirmation_digest")
                    and item.get("scope") == confirmation.get("scope", {})
                    and not item.get("consumed")
                )
            ),
            None,
        )

    @classmethod
    def _is_confirmation_approved(
        cls,
        state: Mapping[str, Any],
        stage: str,
        confirmation: Mapping[str, Any],
    ) -> bool:
        return cls._approval_for_confirmation(
            state,
            stage,
            confirmation,
        ) is not None

    def _context(
        self,
        state: Mapping[str, Any],
        target_url: str,
        modules: list[str],
        profile: Mapping[str, Any],
    ) -> dict[str, Any]:
        orchestrator = state.get("orchestrator", {})
        return {
            "workflow_id": state["workflow_id"],
            "slug": state["slug"],
            "target_url": target_url,
            "modules": list(modules),
            "profile": dict(profile),
            "policy": dict(state.get("policy", {})),
            "memo": deepcopy(state.get("memo", {})),
            "target_profile": deepcopy(state.get("target_profile", {})),
            "attack_surface": deepcopy(state.get("attack_surface", {})),
            "attack_queue": deepcopy(state.get("attack_queue", [])),
            "stage_results": deepcopy(orchestrator.get("stage_results", {})),
            "observations": deepcopy(state.get("orchestrator", {}).get("observations", {})),
            "approvals": deepcopy(orchestrator.get("approvals", [])),
            "http_transport": "stealth_http_client",
        }

    def orchestrate(
        self,
        slug: str,
        *,
        target_url: str = "",
        modules: Sequence[str] | None = None,
        policy: str = "standard",
        resume: bool = False,
        observations: Mapping[str, Any] | None = None,
        approval: Mapping[str, Any] | None = None,
        checkpoint_id: str = "",
    ) -> dict[str, Any]:
        with self.kernel._orchestrator_lock(slug):
            return self._orchestrate_locked(
                slug,
                target_url=target_url,
                modules=modules,
                policy=policy,
                resume=resume,
                observations=observations,
                approval=approval,
                checkpoint_id=checkpoint_id,
            )

    def _orchestrate_locked(
        self,
        slug: str,
        *,
        target_url: str = "",
        modules: Sequence[str] | None = None,
        policy: str = "standard",
        resume: bool = False,
        observations: Mapping[str, Any] | None = None,
        approval: Mapping[str, Any] | None = None,
        checkpoint_id: str = "",
    ) -> dict[str, Any]:
        profile = self._profile(policy)
        selected_modules = self._modules(modules)
        if checkpoint_id:
            self.kernel.resume(slug, checkpoint_id)
        state = self.kernel.materialize(slug)
        target = str(target_url or self._target_from_state(state)).strip()
        if not target:
            raise ValueError("target_url is required")

        if observations:
            self.kernel._append(
                slug,
                "orchestrator.observations.updated",
                {"observations": self._json_safe(dict(observations))},
            )
            state = self.kernel.materialize(slug)
        if approval:
            decision = self._validate_approval(state, approval)
            self.kernel._append(
                slug,
                "orchestrator.approval.recorded",
                {"approval": decision},
            )
            state = self.kernel.materialize(slug)

        orchestrator_state = state.get("orchestrator", {})
        stage_status = orchestrator_state.get("stage_status", {})
        resumed_from = next(
            (
                stage
                for stage in ORCHESTRATOR_STAGES
                if stage_status.get(stage) != "completed"
            ),
            "",
        )
        if not resume and orchestrator_state.get("status") == "completed":
            return self._result(self.kernel.materialize(slug), target, 0, "")

        initialized = {
            "version": "1.0",
            "status": "running",
            "current_stage": resumed_from or "memory",
            "profile": profile["name"],
            "modules": selected_modules,
            "stage_status": dict(stage_status),
            "stage_results": deepcopy(orchestrator_state.get("stage_results", {})),
            "confirmation_required": deepcopy(
                orchestrator_state.get("confirmation_required", [])
            ),
            "approvals": deepcopy(orchestrator_state.get("approvals", [])),
            "observations": deepcopy(orchestrator_state.get("observations", {})),
            "resumed_from": resumed_from if resume else "",
            "generation": deepcopy(orchestrator_state.get("generation", {})),
        }
        self.kernel._append(
            slug,
            "orchestrator.initialized",
            {"orchestrator": initialized, "target_url": target},
        )

        checkpoints_created = 0
        for stage in ORCHESTRATOR_STAGES:
            state = self.kernel.materialize(slug)
            if state["orchestrator"]["stage_status"].get(stage) == "completed":
                continue
            context = self._context(state, target, selected_modules, profile)
            self.kernel._append(
                slug,
                "orchestrator.stage.started",
                {"stage": stage, "profile": profile, "modules": selected_modules},
            )
            try:
                external_results = context.get("observations", {}).get(
                    "stage_results", {}
                )
                if isinstance(external_results, Mapping) and stage in external_results:
                    raw_result = external_results[stage]
                else:
                    raw_result = self.adapters[stage](context)
                result = dict(raw_result or {})
            except OrchestratorInterrupted as exc:
                self.kernel._append(
                    slug,
                    "orchestrator.interrupted",
                    {"stage": stage, "reason": str(exc)},
                )
                checkpoint = self.kernel.checkpoint(slug, source_session=f"orchestrator:{stage}")
                return self._result(
                    self.kernel.materialize(slug),
                    target,
                    checkpoints_created + 1,
                    resumed_from,
                    status="interrupted",
                    interrupted_stage=stage,
                    checkpoint_id=checkpoint["checkpoint_id"],
                )
            except Exception as exc:
                self.kernel._append(
                    slug,
                    "orchestrator.stage.blocked",
                    {
                        "stage": stage,
                        "status": "blocked",
                        "reason": str(exc),
                        "confirmation_required": [],
                    },
                )
                checkpoint = self.kernel.checkpoint(slug, source_session=f"orchestrator:{stage}")
                return self._result(
                    self.kernel.materialize(slug),
                    target,
                    checkpoints_created + 1,
                    resumed_from,
                    status="blocked",
                    blocked_stage=stage,
                    checkpoint_id=checkpoint["checkpoint_id"],
                )

            confirmation = result.get("confirmation_required", [])
            if confirmation is True:
                confirmation = result.get("actions", [])
            if not isinstance(confirmation, list):
                confirmation = [confirmation] if confirmation else []
            confirmation = self._normalize_confirmations(stage, confirmation)
            approved_confirmations = [
                item
                for item in confirmation
                if self._is_confirmation_approved(state, stage, item)
            ]
            if confirmation and len(approved_confirmations) != len(confirmation):
                self.kernel._append(
                    slug,
                    "orchestrator.stage.blocked",
                    {
                        "stage": stage,
                        "status": "awaiting_confirmation",
                        "reason": result.get("reason", "analyst confirmation required"),
                        "confirmation_required": confirmation,
                    },
                )
                checkpoint = self.kernel.checkpoint(slug, source_session=f"orchestrator:{stage}")
                return self._result(
                    self.kernel.materialize(slug),
                    target,
                    checkpoints_created + 1,
                    resumed_from,
                    status="awaiting_confirmation",
                    confirmation_required=confirmation,
                    current_stage=stage,
                    checkpoint_id=checkpoint["checkpoint_id"],
                )

            if result.get("status") == "deferred":
                self.kernel._append(
                    slug,
                    "orchestrator.stage.blocked",
                    {
                        "stage": stage,
                        "status": "awaiting_external",
                        "reason": result.get(
                            "reason",
                            "external handoff results are required before continuing",
                        ),
                        "confirmation_required": [],
                        "result": self._json_safe(result),
                    },
                )
                checkpoint = self.kernel.checkpoint(
                    slug,
                    source_session=f"orchestrator:{stage}",
                )
                return self._result(
                    self.kernel.materialize(slug),
                    target,
                    checkpoints_created + 1,
                    resumed_from,
                    status="awaiting_external",
                    current_stage=stage,
                    checkpoint_id=checkpoint["checkpoint_id"],
                )

            if result.get("status") in {"interrupted", "blocked", "awaiting_confirmation", "awaiting_external"}:
                status = result["status"]
                self.kernel._append(
                    slug,
                    "orchestrator.stage.blocked",
                    {
                        "stage": stage,
                        "status": status,
                        "reason": result.get("reason", ""),
                        "confirmation_required": result.get("confirmation_required", []),
                        "result": self._json_safe(result),
                    },
                )
                checkpoint = self.kernel.checkpoint(slug, source_session=f"orchestrator:{stage}")
                return self._result(
                    self.kernel.materialize(slug),
                    target,
                    checkpoints_created + 1,
                    resumed_from,
                    status=status,
                    checkpoint_id=checkpoint["checkpoint_id"],
                    current_stage=stage,
                )

            for confirmation_item in approved_confirmations:
                approved = self._approval_for_confirmation(
                    state,
                    stage,
                    confirmation_item,
                )
                self.kernel._append(
                    slug,
                    "orchestrator.approval.consumed",
                    {
                        "consumption": {
                            "stage": stage,
                            "decision_id": approved["decision_id"],
                            "confirmation_id": confirmation_item[
                                "confirmation_id"
                            ],
                            "confirmation_digest": confirmation_item[
                                "confirmation_digest"
                            ],
                            "consumed_at": now(),
                        }
                    },
                )

            safe_result = self._json_safe(result)
            if stage == "evidence_learning":
                try:
                    self._register_evidence_and_findings(
                        slug,
                        evidence_result=safe_result,
                    )
                except Exception as exc:
                    self.kernel._append(
                        slug,
                        "orchestrator.stage.blocked",
                        {
                            "stage": stage,
                            "status": "blocked",
                            "reason": str(exc),
                            "confirmation_required": [],
                            "result": safe_result,
                        },
                    )
                    checkpoint = self.kernel.checkpoint(
                        slug,
                        source_session=f"orchestrator:{stage}",
                    )
                    return self._result(
                        self.kernel.materialize(slug),
                        target,
                        checkpoints_created + 1,
                        resumed_from,
                        status="blocked",
                        blocked_stage=stage,
                        checkpoint_id=checkpoint["checkpoint_id"],
                    )
            self.kernel._append(
                slug,
                "orchestrator.stage.completed",
                {"stage": stage, "result": safe_result},
            )
            self.kernel.checkpoint(slug, source_session=f"orchestrator:{stage}")
            checkpoints_created += 1

        final_state = self.kernel.materialize(slug)
        self.kernel._append(
            slug,
            "orchestrator.completed",
            {
                "complete": bool(final_state.get("findings")),
                "target_url": target,
            },
        )
        return self._result(
            self.kernel.materialize(slug),
            target,
            checkpoints_created,
            resumed_from,
            status="completed",
        )

    def resume(
        self,
        slug: str,
        *,
        target_url: str = "",
        observations: Mapping[str, Any] | None = None,
        approval: Mapping[str, Any] | None = None,
        checkpoint_id: str = "",
    ) -> dict[str, Any]:
        if checkpoint_id:
            state = self.kernel.resume(slug, checkpoint_id)["state"]
        else:
            state = self.kernel.materialize(slug)
        orchestrator = state.get("orchestrator", {})
        return self.orchestrate(
            slug,
            target_url=target_url or self._target_from_state(state),
            modules=orchestrator.get("modules", ["all"]),
            policy=orchestrator.get("profile", "standard"),
            resume=True,
            observations=observations,
            approval=approval,
        )

    def _result(
        self,
        state: Mapping[str, Any],
        target_url: str,
        checkpoints_created: int,
        resumed_from: str,
        *,
        status: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        orchestrator = state.get("orchestrator", {})
        findings = [deepcopy(item) for item in state.get("findings", [])]
        confirmation = orchestrator.get("confirmation_required", [])
        if not findings:
            seen = set()
            for result in orchestrator.get("stage_results", {}).values():
                for finding in result.get("findings", []) if isinstance(result, Mapping) else []:
                    key = (
                        finding.get("title"),
                        finding.get("type"),
                        finding.get("status"),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(deepcopy(finding))
        output = {
            "status": status or orchestrator.get("status", "idle"),
            "workflow_id": state.get("workflow_id"),
            "slug": state.get("slug"),
            "target_url": target_url,
            "current_stage": orchestrator.get("current_stage"),
            "stage_status": deepcopy(orchestrator.get("stage_status", {})),
            "stage_results": deepcopy(orchestrator.get("stage_results", {})),
            "memo": deepcopy(state.get("memo", {})),
            "target_profile": deepcopy(state.get("target_profile", {})),
            "attack_surface": deepcopy(state.get("attack_surface", {})),
            "attack_queue": deepcopy(state.get("attack_queue", [])),
            "findings": findings,
            "learning_updates": deepcopy(state.get("learning_updates", [])),
            "report_path": state.get("report_path", ""),
            "confirmation_required": deepcopy(confirmation),
            "checkpoints_created": checkpoints_created,
            "resumed_from": resumed_from,
            "generation": deepcopy(orchestrator.get("generation", {})),
            "execution": "deferred",
        }
        output.update(extra)
        return output

    def _register_evidence_and_findings(
        self,
        slug: str,
        evidence_result: Mapping[str, Any] | None = None,
    ) -> None:
        state = self.kernel.materialize(slug)
        stage_results = state.get("orchestrator", {}).get("stage_results", {})
        evidence_items = (
            dict(evidence_result or {}).get("evidence", [])
            if evidence_result is not None
            else stage_results.get("evidence_learning", {}).get("evidence", [])
        )
        evidence_ids = []
        for index, item in enumerate(evidence_items):
            if not isinstance(item, Mapping):
                item = {"summary": str(item)}
            dedupe_key = hashlib.sha256(
                json.dumps(
                    {
                        "workflow_id": state["workflow_id"],
                        "stage": "evidence_learning",
                        "index": index,
                        "item": self._json_safe(item),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            registered = self.kernel.register_evidence(
                slug,
                summary=str(item.get("summary", "orchestrator evidence")),
                source=str(item.get("source", "unified-orchestrator")),
                path_or_url=str(item.get("path_or_url", "")),
                evidence_type=str(item.get("type", "note")),
                confidence=str(item.get("confidence", "medium")),
                sha256=str(item.get("sha256", "")),
                dedupe_key=dedupe_key,
            )
            evidence_ids.append(registered["evidence"]["id"])
        findings = stage_results.get("vulnerability_confirmation", {}).get("findings", [])
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                continue
            finding_evidence = list(evidence_ids)
            if not finding_evidence:
                fallback_key = hashlib.sha256(
                    f"{state['workflow_id']}|pattern|{index}|{finding.get('title', '')}".encode()
                ).hexdigest()
                registered = self.kernel.register_evidence(
                    slug,
                    summary=f"Pattern confirmation for {finding.get('title', 'finding')}",
                    source="pattern_engine",
                    evidence_type="pattern-confirmation",
                    confidence=str(finding.get("confidence", "medium")),
                    dedupe_key=fallback_key,
                )
                finding_evidence.append(registered["evidence"]["id"])
            finding_key = hashlib.sha256(
                json.dumps(
                    {
                        "workflow_id": state["workflow_id"],
                        "stage": "vulnerability_confirmation",
                        "index": index,
                        "finding": self._json_safe(finding),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            self.kernel.promote_finding(
                slug,
                title=str(finding.get("title", "confirmed finding")),
                status=str(finding.get("status", "confirmed")),
                evidence_ids=finding_evidence,
                severity=str(finding.get("severity", "Info")),
                satisfies=list(finding.get("satisfies", [])),
                proof_type=str(finding.get("proof_type", "pattern-confirmation")),
                dedupe_key=finding_key,
            )

    def _default_adapters(self):
        return {
            "memory": self.integration.stage_memory,
            "recon": self.integration.stage_recon,
            "attack_surface": self.integration.stage_attack_surface,
            "attack_execution": self.integration.stage_attack_execution,
            "vulnerability_confirmation": self.integration.stage_confirmation,
            "evidence_learning": self.integration.stage_evidence_learning,
            "report": self._stage_report,
        }

    def _stage_memory(self, context):
        return self.integration.stage_memory(context)

        from core.memory import FingerprintDatabase, TargetMemory, TechniqueMemory

        target_memory = TargetMemory()
        technique_memory = TechniqueMemory()
        history = target_memory.query_target(context["target_url"])
        fingerprints = history.get("fingerprints", {})
        waf = fingerprints.get("waf", "")
        return {
            "memo": {
                "target_seen": history.get("target") is not None,
                "history": history,
                "best_techniques": technique_memory.best_for_waf(waf)[:5] if waf else [],
                "fingerprint_catalog": FingerprintDatabase().counts(),
            }
        }

    def _stage_recon(self, context):
        return self.integration.stage_recon(context)

        modules = set(context["modules"])
        target = context["target_url"]
        handoffs = [
            {
                "tool": "hunter_stealth_request",
                "execution": "deferred",
                "status": "proposed",
                "arguments": {"method": "GET", "url": target},
            },
            {
                "tool": "hunter_fingerprint_detect",
                "execution": "deferred",
                "status": "proposed",
                "arguments": {"target_url": target},
            },
        ]
        if "all" in modules or "js" in modules:
            handoffs.append(
                {
                    "tool": "hunter_js_full_analysis",
                    "execution": "deferred",
                    "status": "proposed",
                    "arguments": {"input_value": target},
                }
            )
        if "all" in modules or "web" in modules:
            handoffs.append(
                {
                    "tool": "hunter_browser_navigate",
                    "execution": "deferred",
                    "status": "proposed",
                    "arguments": {"target_url": target},
                }
            )
        observations = context.get("observations", {})
        profile = {
            "target_url": target,
            "fingerprints": observations.get("fingerprints", {}),
            "api_endpoints": list(observations.get("api_endpoints", []))[
                : context["profile"]["max_endpoints"]
            ],
            "js_bundles": list(observations.get("js_bundles", [])),
            "handoffs": handoffs,
        }
        return {"target_profile": profile}

    def _stage_attack_surface(self, context):
        return self.integration.stage_attack_surface(context)

        endpoints = context["target_profile"].get("api_endpoints", [])
        target = context["target_url"]
        candidates = [str(item.get("url", item) if isinstance(item, Mapping) else item) for item in endpoints]
        if not candidates:
            candidates = [target]
        queue = []
        rules = (
            (("login", "signin", "auth"), "authentication"),
            (("search", "query", "q=", "keyword"), "sqli_xss"),
            (("upload", "file", "avatar", "import"), "file_upload"),
            (("/api/", "graphql", "swagger"), "api_access_control"),
            (("redirect", "callback", "return", "url="), "ssrf_open_redirect"),
            (("register", "signup", "captcha"), "registration"),
        )
        for endpoint in candidates:
            lowered = endpoint.casefold()
            matched = False
            for signals, kind in rules:
                if any(signal in lowered for signal in signals):
                    queue.append({"kind": kind, "target": endpoint, "signals": list(signals)})
                    matched = True
            if not matched:
                queue.append({"kind": "baseline", "target": endpoint, "signals":[]})
        return {
            "attack_surface": {"identified": queue},
            "attack_queue": queue[: context["profile"]["max_attack_surfaces"]],
        }

    def _stage_attack_execution(self, context):
        return self.integration.stage_attack_execution(context)

        tools = {
            "authentication": "hunter_auto_jwt",
            "sqli_xss": "hunter_auto_sqli",
            "file_upload": "hunter_session_execute_chain",
            "api_access_control": "hunter_auto_access_control",
            "ssrf_open_redirect": "hunter_auto_ssrf",
            "registration": "hunter_auto_csrf",
            "baseline": "hunter_scan_plan",
        }
        chains = {
            "authentication": "login_to_admin",
            "sqli_xss": "sqli_to_data_dump",
            "file_upload": "file_upload_to_shell",
            "api_access_control": "jwt_to_account_takeover",
            "ssrf_open_redirect": "ssrf_to_internal_access",
        }
        handoffs = []
        for index, item in enumerate(context["attack_queue"], start=1):
            dependency = f"attack-session-{index}"
            handoffs.append(
                {
                    "id": dependency,
                    "tool": "hunter_session_start",
                    "execution": "deferred",
                    "status": "proposed",
                    "arguments": {"target_url": context["target_url"]},
                }
            )
            if item["kind"] in chains:
                handoffs.append(
                    {
                        "tool": "hunter_session_execute_chain",
                        "execution": "deferred",
                        "status": "proposed",
                        "depends_on": dependency,
                        "arguments": {
                            "session_id": f"${{{dependency}.session_id}}",
                            "chain_name": chains[item["kind"]],
                            "params": {"target": item["target"]},
                        },
                    }
                )
            handoffs.append(
                {
                    "tool": tools.get(item["kind"], "hunter_scan_plan"),
                    "execution": "deferred",
                    "status": "proposed",
                    "depends_on": dependency,
                    "target": item["target"],
                    "attack_surface": item["kind"],
                }
            )
            if item["kind"] in {"authentication", "file_upload", "registration"}:
                browser_dependency = f"browser-session-{index}"
                handoffs.append(
                    {
                        "id": browser_dependency,
                        "tool": "hunter_browser_navigate",
                        "execution": "deferred",
                        "status": "proposed",
                        "arguments": {"target_url": item["target"]},
                    }
                )
                handoffs.append(
                    {
                        "tool": "hunter_browser_interact",
                        "execution": "deferred",
                        "status": "proposed",
                        "depends_on": browser_dependency,
                        "arguments": {
                            "browser_session_id": f"${{{browser_dependency}.browser_session_id}}",
                            "action": "form",
                            "params": {"target": item["target"]},
                        },
                    }
                )
        return {
            "status": "deferred",
            "handoffs": handoffs,
            "attempts": [],
        }

    def _stage_confirmation(self, context):
        return self.integration.stage_confirmation(context)

        from core.memory import PatternEngine

        observations = context.get("observations", {})
        findings = []
        for response in observations.get("responses", []):
            match = PatternEngine().match_response(response)
            if match.get("vulnerability_type"):
                findings.append(
                    {
                        "title": f"{match['vulnerability_type']} response pattern",
                        "type": match["vulnerability_type"],
                        "severity": "high" if match["confidence"] >= 0.9 else "medium",
                        "status": "confirmed",
                        "confidence": match["confidence"],
                        "evidence": match["evidence"],
                    }
                )
        high_impact = [finding for finding in findings if finding.get("type") in {"command_injection", "rce"}]
        post_exploitation_handoffs = [
            {
                "tool": "hunter_post_exploit",
                "execution": "deferred",
                "requires_confirmation": True,
                "arguments": {
                    "session_id": "${confirmed_finding.session_id}",
                    "vuln_type": finding.get("type", "unknown"),
                    "vuln_details": finding,
                },
            }
            for finding in findings
        ]
        if high_impact:
            return {
                "confirmation_required": post_exploitation_handoffs,
                "reason": "post-exploitation requires analyst confirmation",
                "findings": findings,
                "post_exploitation_handoffs": post_exploitation_handoffs,
            }
        return {
            "findings": findings,
            "post_exploitation_handoffs": post_exploitation_handoffs,
        }

    def _stage_evidence_learning(self, context):
        return self.integration.stage_evidence_learning(context)

        from core.memory import TargetMemory, TechniqueMemory

        target_memory = TargetMemory()
        technique_memory = TechniqueMemory()
        profile = context.get("target_profile", {})
        fingerprints = profile.get("fingerprints", {})
        target_memory.record_target(context["target_url"], fingerprints=fingerprints)
        updates = []
        for attempt in context.get("stage_results", {}).get("attack_execution", {}).get("attempts", []):
            if attempt.get("success") is None:
                continue
            technique = attempt.get("technique") or attempt.get("tool")
            if technique:
                technique_memory.record_attempt(
                    target_url=context["target_url"],
                    technique_name=technique,
                    waf_type=fingerprints.get("waf", ""),
                    success=bool(attempt["success"]),
                )
                updates.append({"technique": technique, "success": bool(attempt["success"])})
        evidence = []
        for handoff in context.get("stage_results", {}).get("attack_execution", {}).get("handoffs", []):
            evidence.append(
                {
                    "summary": f"Deferred attack handoff: {handoff.get('tool', 'unknown')}",
                    "source": "unified-orchestrator",
                    "type": "handoff",
                    "confidence": "pending",
                }
            )
        findings = context.get("stage_results", {}).get(
            "vulnerability_confirmation", {}
        ).get("findings", [])
        evidence_handoffs = []
        for finding in findings:
            evidence_handoffs.append(
                {
                    "tool": "hunter_evidence_register",
                    "execution": "deferred",
                    "arguments": {
                        "summary": finding.get("title", "confirmed finding"),
                        "source": "unified-orchestrator",
                        "evidence_type": "request-response",
                    },
                }
            )
            evidence_handoffs.append(
                {
                    "tool": "hunter_browser_snapshot",
                    "execution": "deferred",
                    "condition": "browser_interaction_used",
                    "arguments": {
                        "browser_session_id": "${browser_session.session_id}",
                        "include_network": True,
                    },
                }
            )
        fingerprint_updates = [
            {
                "kind": key,
                "value": value,
                "source": "target_profile",
            }
            for key, value in fingerprints.items()
            if value
        ]
        return {
            "evidence": evidence,
            "evidence_handoffs": evidence_handoffs,
            "learning_updates": updates,
            "fingerprint_updates": fingerprint_updates,
        }

    def _stage_report(self, context):
        directory = self.kernel._dir(context["slug"]) / "reports"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "orchestrator-report.json"
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        raw_findings = context.get("stage_results", {}).get(
            "vulnerability_confirmation", {}
        ).get("findings", [])
        findings = sorted(
            [dict(item) for item in raw_findings],
            key=lambda item: (
                severity_order.get(str(item.get("severity", "info")).casefold(), 5),
                str(item.get("title", "")),
            ),
        )
        templates = {
            "sqli": "templates/report-sqli.md",
            "xss": "templates/report-xss.md",
            "idor": "templates/report-access-control.md",
            "business_logic": "templates/report-business-logic.md",
            "command_injection": "templates/report-command-injection.md",
        }
        for finding in findings:
            finding["report_template"] = templates.get(
                str(finding.get("type", "")).casefold(),
                "templates/report-generic.md",
            )
        report = {
            "workflow_id": context["workflow_id"],
            "target_url": context["target_url"],
            "findings": findings,
            "attack_queue": context.get("attack_queue", []),
            "execution": "deferred",
            "generated_at": now(),
        }
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"report_path": str(path), "findings": report["findings"]}
