import gc
import json
import multiprocessing
import os
import sys
import threading
import time
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.workflow import WorkflowKernel
from core.workflow.backends import BackendRegistry
from core.workflow.locking import WorkflowFileLock
from core.workflow.models import WorkflowPolicy


def _append_hypothesis_in_process(root, index, queue):
    try:
        WorkflowKernel(root).add_hypothesis("process-race", f"process-{index}")
    except Exception as exc:
        queue.put(f"{type(exc).__name__}: {exc}")
    else:
        queue.put("")


def _create_workflow_in_process(root, queue):
    try:
        WorkflowKernel(root).create("process-create", "proof", [])
    except ValueError as exc:
        queue.put(f"error:{exc}")
    else:
        queue.put("ok")


def _read_events(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_create_persists_v2_state_and_append_only_event(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    result = kernel.create("rev-1", objective="recover flag", inputs=[{"path": "challenge.exe"}], mode="autopilot")
    state = result["state"]
    assert state["schema_version"] == "2.0"
    assert state["lane"] == "pe"
    assert state["phase"] == "intake"
    assert state["policy"]["mode"] == "autopilot"
    events = (tmp_path / "cases" / "rev-1" / "workflow.events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(events) == 1
    assert json.loads(events[0])["type"] == "workflow.created"


def test_concurrent_kernel_instances_preserve_event_chain(tmp_path):
    WorkflowKernel(tmp_path).create("race", objective="proof", inputs=[])

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(
                WorkflowKernel(tmp_path).add_hypothesis,
                "race",
                f"hypothesis-{index}",
            )
            for index in range(32)
        ]
        for future in futures:
            future.result()

    events = _read_events(
        tmp_path / "cases" / "race" / "workflow.events.jsonl"
    )
    assert [event["revision"] for event in events] == list(range(1, 34))
    for previous, current in zip(events, events[1:]):
        assert current["previous_event_hash"] == previous["event_hash"]
    assert len(WorkflowKernel(tmp_path).materialize("race")["hypotheses"]) == 32
    assert not list((tmp_path / "cases" / "race").glob("*.tmp"))


def test_independent_processes_preserve_event_chain(tmp_path):
    WorkflowKernel(tmp_path).create("process-race", objective="proof", inputs=[])
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_append_hypothesis_in_process,
            args=(str(tmp_path), index, queue),
        )
        for index in range(8)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert [queue.get(timeout=2) for _ in processes] == [""] * len(processes)

    events = _read_events(
        tmp_path / "cases" / "process-race" / "workflow.events.jsonl"
    )
    assert [event["revision"] for event in events] == list(range(1, 10))
    assert len(
        WorkflowKernel(tmp_path).materialize("process-race")["hypotheses"]
    ) == 8


def test_concurrent_create_allows_exactly_one_workflow(tmp_path):
    def create():
        return WorkflowKernel(tmp_path).create("create-race", "proof", [])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(create) for _ in range(2)]
    successes = 0
    failures = 0
    for future in futures:
        try:
            future.result()
        except ValueError as exc:
            assert "already exists" in str(exc)
            failures += 1
        else:
            successes += 1
    assert (successes, failures) == (1, 1)
    assert len(
        _read_events(
            tmp_path / "cases" / "create-race" / "workflow.events.jsonl"
        )
    ) == 1


def test_independent_process_create_allows_exactly_one_workflow(tmp_path):
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_create_workflow_in_process,
            args=(str(tmp_path), queue),
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    results = [queue.get(timeout=2) for _ in processes]
    assert results.count("ok") == 1
    assert sum(item.startswith("error:workflow already exists") for item in results) == 3


def test_record_dead_end_deduplicates_concurrent_writers(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("dead-end-race", "proof", [])

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(
                WorkflowKernel(tmp_path).record_dead_end,
                "dead-end-race",
                "same failed path",
                "same-signature",
            )
            for _ in range(32)
        ]
        for future in futures:
            future.result()

    state = WorkflowKernel(tmp_path).materialize("dead-end-race")
    assert [item["signature"] for item in state["dead_ends"]] == [
        "same-signature"
    ]


def test_workflow_file_lock_is_reentrant_for_same_instance(tmp_path):
    path = tmp_path / ".workflow.lock"
    lock = WorkflowFileLock(path, timeout=0.2)
    with lock:
        with lock:
            pass

    acquired = threading.Event()

    def acquire_after_release():
        with WorkflowFileLock(path, timeout=0.2):
            acquired.set()

    thread = threading.Thread(target=acquire_after_release)
    thread.start()
    thread.join(1)
    assert acquired.is_set()


@pytest.mark.skipif(os.name != "nt", reason="Windows path spelling only")
def test_workflow_file_lock_uses_stable_key_when_windows_resolve_spelling_drifts(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    raw_path = tmp_path / ".workflow.lock"
    normal_path = locking.Path(
        os.path.abspath(os.fspath(raw_path))
    )
    extended_path = locking.Path(f"\\\\?\\{normal_path}")
    resolved_paths = iter((extended_path, normal_path))
    original_resolve = locking.Path.resolve

    def drifting_resolve(self, *args, **kwargs):
        if self == raw_path:
            return next(resolved_paths)
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(locking.Path, "resolve", drifting_resolve)
    first = WorkflowFileLock(raw_path, timeout=0.05)
    second = WorkflowFileLock(raw_path, timeout=0.05)

    assert first._key == second._key
    assert first._process_lock is second._process_lock
    with first:
        with second:
            pass


@pytest.mark.skipif(os.name != "nt", reason="Windows path spelling only")
def test_workflow_file_lock_key_normalizes_windows_extended_unc_prefix(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    first_raw_path = tmp_path / "first" / ".workflow.lock"
    second_raw_path = tmp_path / "second" / ".workflow.lock"
    extended_target = locking.Path(
        r"\\?\UNC\server\share\target\.workflow.lock"
    )
    standard_target = locking.Path(
        r"\\server\share\target\.workflow.lock"
    )
    original_resolve = locking.Path.resolve

    def unc_spelling_resolve(self, *args, **kwargs):
        if self == first_raw_path:
            return extended_target
        if self == second_raw_path:
            return standard_target
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(locking.Path, "resolve", unc_spelling_resolve)
    first = WorkflowFileLock(first_raw_path)
    second = WorkflowFileLock(second_raw_path)

    assert first._key == second._key
    assert first._process_lock is second._process_lock


def test_workflow_file_lock_key_uses_resolved_path_identity(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    first_raw_path = tmp_path / "first" / ".workflow.lock"
    second_raw_path = tmp_path / "second" / ".workflow.lock"
    target = (tmp_path / "target" / ".workflow.lock").resolve()
    original_resolve = locking.Path.resolve

    def shared_target_resolve(self, *args, **kwargs):
        if self in (first_raw_path, second_raw_path):
            return target
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(locking.Path, "resolve", shared_target_resolve)
    first = WorkflowFileLock(first_raw_path)
    second = WorkflowFileLock(second_raw_path)

    assert first._key == second._key
    assert first._process_lock is second._process_lock


def test_workflow_file_lock_key_preserves_resolved_path_case(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    first_raw_path = tmp_path / "first" / ".workflow.lock"
    second_raw_path = tmp_path / "second" / ".workflow.lock"
    first_target = Path(
        os.path.abspath(tmp_path / "TARGET" / ".workflow.lock")
    )
    second_target = Path(
        os.path.abspath(tmp_path / "target" / ".workflow.lock")
    )
    original_resolve = locking.Path.resolve

    def case_distinct_resolve(self, *args, **kwargs):
        if self == first_raw_path:
            return first_target
        if self == second_raw_path:
            return second_target
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(locking.Path, "resolve", case_distinct_resolve)
    first = WorkflowFileLock(first_raw_path)
    second = WorkflowFileLock(second_raw_path)

    assert first._key != second._key
    assert first._process_lock is not second._process_lock


def test_workflow_file_lock_uses_one_total_timeout(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    path = tmp_path / ".workflow.lock"
    clock = [0.0]

    class DelayedProcessLock:
        def acquire(self, timeout):
            clock[0] += 0.06
            return True

        def release(self):
            return None

    monkeypatch.setattr(
        locking,
        "_lock_handle",
        lambda handle: (_ for _ in ()).throw(PermissionError("busy")),
    )
    monkeypatch.setattr(locking.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        locking.time,
        "sleep",
        lambda duration: clock.__setitem__(0, clock[0] + duration),
    )
    lock = WorkflowFileLock(path, timeout=0.1)
    lock._process_lock = DelayedProcessLock()
    with pytest.raises(TimeoutError):
        with lock:
            pass
    assert clock[0] == pytest.approx(0.1)


def test_workflow_file_lock_releases_process_lock_after_open_failure(
    tmp_path, monkeypatch
):
    import core.workflow.locking as locking

    path = tmp_path / ".workflow.lock"
    original_open = locking.Path.open

    def fail_open(self, *args, **kwargs):
        if self.resolve() == path.resolve():
            raise OSError("cannot open lock")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(locking.Path, "open", fail_open)
    with pytest.raises(OSError, match="cannot open lock"):
        with WorkflowFileLock(path, timeout=0.1):
            pass
    monkeypatch.setattr(locking.Path, "open", original_open)

    with WorkflowFileLock(path, timeout=0.1):
        pass


def test_workflow_file_lock_unix_branch_uses_flock(monkeypatch, tmp_path):
    import core.workflow.locking as locking

    calls = []
    fake_fcntl = SimpleNamespace(
        LOCK_EX=1,
        LOCK_NB=2,
        LOCK_UN=4,
        flock=lambda fileno, operation: calls.append((fileno, operation)),
    )
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)
    monkeypatch.setattr(locking, "_platform_name", lambda: "posix")

    with (tmp_path / "unix.lock").open("w+b") as handle:
        handle.write(b"\0")
        handle.flush()
        locking._lock_handle(handle)
        locking._unlock_handle(handle)

    assert calls[0][1] == fake_fcntl.LOCK_EX | fake_fcntl.LOCK_NB
    assert calls[1][1] == fake_fcntl.LOCK_UN


def test_materializer_rebuilds_state_from_events(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("case-a", objective="inspect app", inputs=[{"path": "app.apk"}])
    kernel.add_hypothesis("case-a", "native library validates token", confidence=0.6)
    kernel.transition("case-a", "triage", deliverables={"objective": True, "artifact_inventory": True})
    rebuilt = kernel.materialize("case-a")
    assert rebuilt["phase"] == "triage"
    assert rebuilt["hypotheses"][0]["claim"] == "native library validates token"
    assert len(rebuilt["history"]) == 3


def test_event_append_succeeds_when_derived_state_cache_replace_fails(
    tmp_path, monkeypatch
):
    import core.workflow.kernel as kernel_module

    kernel = WorkflowKernel(tmp_path)
    kernel.create("cache-failure", "proof", [])
    original_replace = kernel_module.os.replace

    def fail_state_replace(source, destination):
        if Path(destination).name == "workflow.json":
            raise OSError("state cache unavailable")
        return original_replace(source, destination)

    monkeypatch.setattr(kernel_module.os, "replace", fail_state_replace)
    result = kernel.add_hypothesis("cache-failure", "event survives")

    assert result["hypothesis"]["claim"] == "event survives"
    events = _read_events(kernel._events("cache-failure"))
    assert [event["revision"] for event in events] == [1, 2]
    assert kernel.materialize("cache-failure")["hypotheses"][0]["claim"] == (
        "event survives"
    )
    assert not list(kernel._dir("cache-failure").glob("*.tmp"))


def test_checkpoint_removes_snapshot_when_event_append_fails(
    tmp_path, monkeypatch
):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("checkpoint-failure", "proof", [])

    def fail_append(*args, **kwargs):
        raise OSError("event append unavailable")

    monkeypatch.setattr(kernel, "_append", fail_append)
    with pytest.raises(OSError, match="event append unavailable"):
        kernel.checkpoint("checkpoint-failure")

    checkpoint_dir = kernel._dir("checkpoint-failure") / "checkpoints"
    assert not list(checkpoint_dir.glob("*.json"))
    assert not list(checkpoint_dir.glob("*.tmp"))


def test_checkpoint_survives_derived_cache_cleanup_failure(
    tmp_path, monkeypatch
):
    import core.workflow.kernel as kernel_module

    kernel = WorkflowKernel(tmp_path)
    kernel.create("checkpoint-cache-failure", "proof", [])
    original_replace = kernel_module.os.replace
    original_unlink = kernel_module.Path.unlink

    def fail_state_replace(source, destination):
        if Path(destination).name == "workflow.json":
            raise OSError("state cache unavailable")
        return original_replace(source, destination)

    def fail_state_tmp_cleanup(self, *args, **kwargs):
        if self.name.startswith(".workflow.json.") and self.suffix == ".tmp":
            raise OSError("state cache cleanup unavailable")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(kernel_module.os, "replace", fail_state_replace)
    monkeypatch.setattr(kernel_module.Path, "unlink", fail_state_tmp_cleanup)

    checkpoint = kernel.checkpoint("checkpoint-cache-failure")

    assert Path(checkpoint["path"]).exists()
    state = kernel.materialize("checkpoint-cache-failure")
    assert state["checkpoints"][0]["checkpoint_id"] == checkpoint["checkpoint_id"]


def test_lane_router_uses_strongest_signal_and_supports_mixed(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    assert kernel.route(inputs=[{"path": "a.exe"}])["primary_lane"] == "pe"
    assert kernel.route(inputs=[{"path": "a.apk"}])["primary_lane"] == "apk"
    assert kernel.route(inputs=[{"url": "https://x.test/app.js"}])["primary_lane"] == "javascript"
    mixed = kernel.route(inputs=[{"path": "a.apk"}, {"url": "https://x.test/api"}])
    assert mixed["primary_lane"] == "mixed"
    assert {"apk", "api"} <= set(mixed["secondary_lanes"])


def test_phase_gate_rejects_missing_deliverables(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("gate", objective="solve", inputs=[{"path": "a.exe"}])
    with pytest.raises(ValueError, match="missing deliverables"):
        kernel.transition("gate", "triage")
    state = kernel.transition("gate", "triage", deliverables={"objective": True, "artifact_inventory": True})["state"]
    assert state["phase"] == "triage"


def test_backend_registry_adapts_without_executing_reverse_tools():
    registry = BackendRegistry.default()
    pe = registry.resolve("pe")
    apk = registry.resolve("apk")
    js = registry.resolve("javascript")
    mixed = registry.resolve("mixed")
    assert pe[0]["server"] == "reverse_lab_tools"
    assert "triage_pe" in pe[0]["capabilities"]
    assert apk[0]["server"] == "reverse_lab_tools"
    assert js[0]["server"] == "jshook"
    assert {item["server"] for item in mixed} >= {"hunter_tools", "reverse_lab_tools", "jshook"}


def test_planner_is_budgeted_and_policy_aware(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("plan", objective="solve", inputs=[{"path": "a.apk"}], mode="interactive")
    plan = kernel.plan("plan", max_actions=2)
    assert len(plan["actions"]) <= 2
    assert plan["requires_confirmation"] is True
    assert all("estimated_cost" in action for action in plan["actions"])
    kernel.set_policy("plan", WorkflowPolicy(mode="autopilot", max_tool_calls=1))
    plan = kernel.plan("plan", max_actions=5)
    assert len(plan["actions"]) == 1
    assert plan["requires_confirmation"] is False


def test_checkpoint_and_resume_preserve_delta_and_dead_ends(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("resume", objective="solve", inputs=[{"url": "https://x.test"}])
    kernel.record_dead_end("resume", "sqli on id", signature="sqli:id:quote")
    checkpoint = kernel.checkpoint("resume", source_session="codex-1")
    assert Path(checkpoint["path"]).exists()
    resumed = kernel.resume("resume", checkpoint["checkpoint_id"])
    assert resumed["state"]["dead_ends"][0]["signature"] == "sqli:id:quote"
    assert resumed["resume_hint"]["objective"] == "solve"


def test_evidence_and_finding_lifecycle(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("proof", objective="prove", inputs=[{"url": "https://x.test"}])
    evidence = kernel.register_evidence("proof", summary="response differs", source="burp", path_or_url="evidence/r.json")
    finding = kernel.promote_finding("proof", title="IDOR", status="reproduced", evidence_ids=[evidence["evidence"]["id"]])
    assert finding["finding"]["status"] == "reproduced"
    with pytest.raises(ValueError, match="evidence"):
        kernel.promote_finding("proof", title="No proof", status="confirmed", evidence_ids=[])


def test_guided_policy_and_validation_retry_are_supported(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("guided", objective="solve", inputs=[{"url": "https://x.test"}], mode="guided")
    assert kernel.plan("guided")["requires_confirmation"] is False
    kernel.transition("guided", "triage", {"objective": True, "artifact_inventory": True})
    kernel.transition("guided", "map", {"triage_summary": True})
    kernel.transition("guided", "hypothesis", {"surface_map": True})
    kernel.transition("guided", "deep-analysis", {"active_hypothesis": True})
    kernel.transition("guided", "validation", {"analysis_result": True})
    state = kernel.transition("guided", "hypothesis", {"validation_failed": True})["state"]
    assert state["phase"] == "hypothesis"


def test_router_respects_magic_over_ambiguous_extension():
    kernel = WorkflowKernel(".")
    routed = kernel.route(inputs=[{"path": "sample.bin", "magic": "MZ"}])
    assert routed["primary_lane"] == "pe"
    assert routed["signals"][0]["source"] == "magic"


def test_all_catalog_lanes_have_backend_contracts():
    registry = BackendRegistry.default()
    for lane in ("source", "firmware", "script", "document", "protocol", "capture", "pwn", "crypto"):
        resolved = registry.resolve(lane)
        assert resolved, lane
        assert all(item["capabilities"] for item in resolved)


def test_proof_early_stop_marks_workflow_complete(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("early", objective="obtain proof", inputs=[{"url": "https://x.test"}], mode="autopilot", success_conditions=["flag"])
    ev = kernel.register_evidence("early", "flag captured", "test")
    result = kernel.promote_finding("early", "CTF proof", "confirmed", [ev["evidence"]["id"]], satisfies=["flag"], proof_type="flag")
    assert result["state"]["status"] == "complete"
    assert kernel.plan("early")["actions"] == []


def test_autopilot_run_executes_native_actions_and_defers_external(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("run", objective="map api", inputs=[{"url": "https://x.test/api"}], mode="autopilot")
    calls=[]
    def execute(action):
        calls.append(action["tool"]); return {"status":"ok","summary":"signal","signals":["api"]}
    result=kernel.run("run", execute_native=execute, max_actions=2)
    assert len(calls)==2
    assert len(result["executed"])==2


def test_autopilot_run_returns_external_handoffs(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("handoff", objective="triage pe", inputs=[{"path":"a.exe"}], mode="autopilot")
    result=kernel.run("handoff", execute_native=lambda action: {}, max_actions=2)
    assert result["executed"]==[]
    assert result["handoffs"]
    assert result["handoffs"][0]["server"]=="reverse_lab_tools"


def test_mixed_plan_prioritizes_backend_diversity(tmp_path):
    kernel=WorkflowKernel(tmp_path)
    kernel.create("diverse", objective="solve mixed", inputs=[{"url":"https://x.test"},{"path":"a.exe"}], mode="autopilot")
    actions=kernel.plan("diverse", max_actions=4)["actions"]
    assert len({a["server"] for a in actions}) >= 2


def test_state_matches_open_tgtylab_v2_contract(tmp_path):
    state=WorkflowKernel(tmp_path).create("contract", "proof", [{"path":"a.exe"}], mode="guided")["state"]
    assert state["case"]["slug"]=="contract"
    assert state["objective"]["text"]=="proof"
    assert state["scope"]["targets"]==[{"path":"a.exe"}]
    assert state["policy"]["mode"]=="guided"


def test_event_matches_open_tgtylab_event_contract(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("event-contract","proof",[])
    event=json.loads((tmp_path/"cases"/"event-contract"/"workflow.events.jsonl").read_text().splitlines()[0])
    assert event["schema_version"]=="1.0"
    assert event["workflow_id"].startswith("wf-")
    assert event["actor"]=="hunter_tools"


def test_deferred_native_action_is_pending_not_executed(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("defer","proof",[{"url":"https://x.test"}],mode="autopilot")
    result=kernel.run("defer", execute_native=lambda action:{"status":"deferred"}, max_actions=1)
    assert result["executed"]==[]
    assert result["pending_actions"][0]["server"]=="hunter_tools"


def test_confirmed_finding_only_stops_when_it_satisfies_success_condition(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("proof-condition","get flag",[{"url":"https://x.test"}],mode="autopilot",success_conditions=["flag"] )
    ev=kernel.register_evidence("proof-condition","nginx","test")
    ordinary=kernel.promote_finding("proof-condition","nginx","confirmed",[ev["evidence"]["id"]])
    assert ordinary["state"]["status"]=="active"
    proof=kernel.promote_finding("proof-condition","flag captured","confirmed",[ev["evidence"]["id"]],satisfies=["flag"],proof_type="flag")
    assert proof["state"]["status"]=="complete"


def test_resume_replays_events_after_checkpoint(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("tail","proof",[{"url":"https://x.test"}])
    cp=kernel.checkpoint("tail")
    kernel.add_hypothesis("tail","later event")
    resumed=kernel.resume("tail",cp["checkpoint_id"])["state"]
    assert resumed["hypotheses"][0]["claim"]=="later event"
    assert resumed["resume_metadata"]["events_after_checkpoint"]==1


def test_checkpoint_resume_discards_invalid_utf8_tail(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("utf8-tail", "proof", [])
    checkpoint = kernel.checkpoint("utf8-tail")
    with kernel._events("utf8-tail").open("ab") as handle:
        handle.write(b'{"partial":"\xff')

    resumed = kernel.resume("utf8-tail", checkpoint["checkpoint_id"])

    assert resumed["state"]["workflow_id"]
    assert resumed["state"]["resume_metadata"]["discarded_events"] >= 1
    kernel.materialize("utf8-tail")


def test_checkpoint_resume_preserves_valid_events_before_corrupt_tail(
    tmp_path,
):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("valid-prefix", "proof", [])
    checkpoint = kernel.checkpoint("valid-prefix")
    kernel.add_hypothesis("valid-prefix", "preserve me")
    with kernel._events("valid-prefix").open("ab") as handle:
        handle.write(b'{"partial":"\xff')

    resumed = kernel.resume("valid-prefix", checkpoint["checkpoint_id"])

    assert resumed["state"]["hypotheses"][0]["claim"] == "preserve me"
    assert resumed["state"]["resume_metadata"]["discarded_events"] == 1


def test_concurrent_transitions_revalidate_under_workflow_lock(
    tmp_path, monkeypatch
):
    import core.workflow.kernel as kernel_module

    kernel = WorkflowKernel(tmp_path)
    kernel.create("transition-race", "proof", [])
    kernel.transition(
        "transition-race",
        "triage",
        {"objective": True, "artifact_inventory": True},
    )
    kernel.transition("transition-race", "map", {"triage_summary": True})
    kernel.transition(
        "transition-race", "hypothesis", {"surface_map": True}
    )
    kernel.transition(
        "transition-race",
        "deep-analysis",
        {"active_hypothesis": True},
    )
    kernel.transition(
        "transition-race", "validation", {"analysis_result": True}
    )
    original_validate = kernel_module.validate_transition

    def slow_validate(current, target, deliverables):
        if current == "validation":
            time.sleep(0.05)
        return original_validate(current, target, deliverables)

    monkeypatch.setattr(kernel_module, "validate_transition", slow_validate)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                WorkflowKernel(tmp_path).transition,
                "transition-race",
                "hypothesis",
                {"validation_failed": True},
            ),
            pool.submit(
                WorkflowKernel(tmp_path).transition,
                "transition-race",
                "evidence",
                {"validation_result": True},
            ),
        ]
    successes = 0
    failures = 0
    for future in futures:
        try:
            future.result()
        except ValueError:
            failures += 1
        else:
            successes += 1
    assert (successes, failures) == (1, 1)


def test_process_lock_registry_releases_unused_paths(tmp_path):
    import core.workflow.locking as locking

    baseline = len(locking._PROCESS_LOCKS)
    for index in range(50):
        with WorkflowFileLock(tmp_path / f"lock-{index}", timeout=0.2):
            pass
    gc.collect()
    assert len(locking._PROCESS_LOCKS) <= baseline + 1


def test_events_have_revision_and_hash_chain(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("hash-chain","proof",[])
    kernel.add_hypothesis("hash-chain","x")
    events=[json.loads(x) for x in (tmp_path/"cases"/"hash-chain"/"workflow.events.jsonl").read_text().splitlines()]
    assert [e["revision"] for e in events]==[1,2]
    assert events[1]["previous_event_hash"]==events[0]["event_hash"]


def test_guided_run_defers_expensive_actions(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("guided-run","proof",[{"url":"https://x.test"}],mode="guided")
    result=kernel.run("guided-run", execute_native=lambda action:{"status":"ok"}, max_actions=3)
    assert result["executed"]
    assert result["confirmation_actions"]


def test_materializer_rejects_tampered_event_chain(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("tamper","proof",[])
    path=tmp_path/"cases"/"tamper"/"workflow.events.jsonl"
    event=json.loads(path.read_text().splitlines()[0]); event["payload"]["state"]["status"]="tampered"
    path.write_text(json.dumps(event)+"\n")
    with pytest.raises(ValueError,match="event hash"):
        kernel.materialize("tamper")


def test_append_rejects_stale_expected_revision(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("revision","proof",[])
    with pytest.raises(ValueError,match="revision conflict"):
        kernel.add_hypothesis("revision","x",expected_revision=0)
