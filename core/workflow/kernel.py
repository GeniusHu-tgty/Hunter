from __future__ import annotations
import hashlib, json, os, uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .backends import BackendRegistry
from .models import WorkflowPolicy
from .phases import validate_transition
from .planner import build_plan
from .router import LANES, route


def now(): return datetime.now(timezone.utc).isoformat()

def ident(prefix): return f"{prefix}-{uuid.uuid4().hex[:12]}"

class WorkflowKernel:
    def __init__(self, root, registry=None):
        self.root = Path(root).resolve(); self.registry = registry or BackendRegistry.default()

    def _dir(self, slug):
        if not slug or any(x in slug for x in ("/", "\\", "..")): raise ValueError("invalid workflow slug")
        return self.root / "cases" / slug
    def _events(self, slug): return self._dir(slug) / "workflow.events.jsonl"
    def _state(self, slug): return self._dir(slug) / "workflow.json"
    def _append(self, slug, event_type, payload, expected_revision=None):
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
        state=self.materialize(slug); tmp=self._state(slug).with_suffix(".tmp"); tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"); os.replace(tmp,self._state(slug))
        return state
    def create(self, slug, objective, inputs=None, mode="interactive", success_conditions=None, proof_types=None):
        if self._events(slug).exists(): raise ValueError("workflow already exists")
        routed=self.route(inputs=inputs or []); policy=WorkflowPolicy(mode=mode)
        base={"schema_version":"2.0", "workflow_id":ident("wf"), "slug":slug, "case":{"slug":slug,"created_at":now(),"updated_at":now()}, "objective":{"text":objective,"success_conditions":success_conditions or [],"proof_types":proof_types or []}, "scope":{"targets":inputs or [],"allowed_actions":[],"constraints":[]}, "status":"active", "phase":"intake", "lane":routed["primary_lane"], "lane_history":[], "assets":[], "artifacts":inputs or [], "inputs":inputs or [], "signals":routed["signals"], "hypotheses":[], "decisions":[], "tool_runs":[], "evidence":[], "findings":[], "dead_ends":[], "blockers":[], "checkpoints":[], "next_steps":[], "policy":policy.to_dict(), "metrics":{"tool_calls":0,"checkpoints":0}, "created_at":now(), "updated_at":now()}
        return {"state":self._append(slug,"workflow.created",{"state":base}), "route":routed}
    def materialize(self, slug):
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
            if typ=="workflow.created": state=deepcopy(p["state"])
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
            state["updated_at"]=event["timestamp"]; history.append({"event_id":event["event_id"],"type":typ,"timestamp":event["timestamp"]})
        state["history"]=history; return state
    def open(self, slug): return {"state":self.materialize(slug), "events_path":str(self._events(slug)), "state_path":str(self._state(slug))}
    def status(self, slug):
        s=self.materialize(slug); return {k:s[k] for k in ("workflow_id","slug","status","phase","lane","updated_at","metrics")}
    def route(self, inputs): return route(inputs)
    def transition(self, slug, phase, deliverables=None):
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
        state=self.materialize(slug)
        if any(x["signature"]==signature for x in state["dead_ends"]): return {"dead_end":next(x for x in state["dead_ends"] if x["signature"]==signature),"deduplicated":True,"state":state}
        item={"id":ident("dead"),"summary":summary,"signature":signature,"created_at":now()}
        return {"dead_end":item,"deduplicated":False,"state":self._append(slug,"dead_end.recorded",{"dead_end":item})}
    def register_evidence(self, slug, summary, source, path_or_url="", evidence_type="note", confidence="medium", sha256=""):
        if path_or_url and not sha256:
            p=Path(path_or_url)
            if p.is_file(): sha256=hashlib.sha256(p.read_bytes()).hexdigest()
        item={"id":ident("ev"),"type":evidence_type,"source":source,"summary":summary,"path_or_url":path_or_url,"timestamp":now(),"sha256":sha256,"confidence":confidence}
        return {"evidence":item,"state":self._append(slug,"evidence.registered",{"evidence":item})}
    def promote_finding(self, slug, title, status, evidence_ids, severity="Info", satisfies=None, proof_type=""):
        valid={x["id"] for x in self.materialize(slug)["evidence"]}
        if status in {"reproduced","confirmed","reported"} and (not evidence_ids or not set(evidence_ids)<=valid): raise ValueError("valid evidence is required")
        item={"id":ident("finding"),"title":title,"severity":severity,"status":status,"evidence_ids":evidence_ids,"satisfies":satisfies or [],"proof_type":proof_type,"created_at":now()}
        return {"finding":item,"state":self._append(slug,"finding.promoted",{"finding":item})}
    def checkpoint(self, slug, source_session=""):
        state=self.materialize(slug); cp_id=ident("cp"); directory=self._dir(slug)/"checkpoints"; directory.mkdir(parents=True,exist_ok=True); path=directory/f"{cp_id}.json"
        body={"checkpoint_id":cp_id,"schema_version":"1.0","source_session":source_session,"source_event_count":len(state["history"])+1,"created_at":now(),"state":state,"resume_hint":{"objective":state["objective"].get("text", "") if isinstance(state["objective"], dict) else state["objective"],"phase":state["phase"],"lane":state["lane"],"next_steps":state["next_steps"],"dead_end_signatures":[x["signature"] for x in state["dead_ends"]]}}
        path.write_text(json.dumps(body,ensure_ascii=False,indent=2),encoding="utf-8")
        self._append(slug,"checkpoint.created",{"checkpoint":{"checkpoint_id":cp_id,"path":str(path),"source_session":source_session,"created_at":body["created_at"]}})
        return {"checkpoint_id":cp_id,"path":str(path),"resume_hint":body["resume_hint"]}
    def resume(self, slug, checkpoint_id=""):
        if checkpoint_id:
            path=self._dir(slug)/"checkpoints"/f"{checkpoint_id}.json"; body=json.loads(path.read_text(encoding="utf-8")); current=self.materialize(slug)
            if body["state"]["workflow_id"] != current["workflow_id"]: raise ValueError("checkpoint workflow mismatch")
            current["resume_metadata"]={"checkpoint_id":checkpoint_id,"source_event_count":body["source_event_count"],"events_after_checkpoint":len(current["history"])-body["source_event_count"]}
            return {"state":current,"resume_hint":{"objective":current["objective"].get("text","") if isinstance(current["objective"],dict) else current["objective"],"phase":current["phase"],"lane":current["lane"],"next_steps":current["next_steps"]},"checkpoint_id":checkpoint_id}
        state=self.materialize(slug); return {"state":state,"resume_hint":{"objective":state["objective"].get("text", "") if isinstance(state["objective"], dict) else state["objective"],"phase":state["phase"],"lane":state["lane"],"next_steps":state["next_steps"]}}
    def backend_status(self): return self.registry.status()
    def lane_catalog(self): return {"lanes":list(LANES),"backends":self.registry.status()["backends"]}
