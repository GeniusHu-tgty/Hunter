from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from core.workflow.event_kernel import (
    ActionProposal,
    AttemptStart,
    CommandMeta,
    IllegalTransitionError,
    ProcessOutput,
    ProcessStart,
    ProcessStream,
    ProcessTerminal,
    SensitiveOutputRejectedError,
    WorkflowOwnershipClaim,
)
from core.workflow.event_kernel.service import EventKernel


def _meta(kernel: EventKernel, slug: str, command_id: str) -> CommandMeta:
    head = kernel.head(slug)
    return CommandMeta(
        command_id=command_id,
        expected_revision=head.revision,
        expected_event_hash=head.event_hash,
        generation=1,
        correlation_id="corr-process",
    )


def _started_attempt(tmp_path: Path) -> tuple[EventKernel, str, str]:
    kernel = EventKernel(tmp_path)
    slug = "process"
    kernel.claim_workflow(
        slug,
        _meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("cutover", "stage6", "a" * 64),
    )
    action = kernel.propose_action(
        slug,
        _meta(kernel, slug, "propose"),
        ActionProposal(
            tool="hunter_auto_sqli",
            target="https://example.test/login",
            kind="sqli",
            arguments={"param": "username"},
        ),
    )
    attempt = kernel.start_attempt(
        slug,
        _meta(kernel, slug, "start-attempt"),
        AttemptStart(action.action_id, "executor", "process-test"),
    )
    assert attempt.attempt_id is not None
    return kernel, slug, attempt.attempt_id


def _output(
    process_id: str,
    attempt_id: str,
    stream: ProcessStream,
    excerpt: str,
    *,
    stdout: int,
    stderr: int,
    combined: int,
    stdout_omitted: int = 0,
    stderr_omitted: int = 0,
    combined_omitted: int = 0,
    truncated: bool = False,
) -> ProcessOutput:
    return ProcessOutput(
        process_id=process_id,
        attempt_id=attempt_id,
        stream=stream,
        redacted_excerpt=excerpt,
        redaction_applied=True,
        truncated=truncated,
        stdout_bytes_total=stdout,
        stderr_bytes_total=stderr,
        combined_bytes_total=combined,
        stdout_omitted_bytes_total=stdout_omitted,
        stderr_omitted_bytes_total=stderr_omitted,
        combined_omitted_bytes_total=combined_omitted,
    )


def test_process_output_sequence_spans_interleaved_streams_and_digest_is_kernel_generated(
    tmp_path: Path,
) -> None:
    kernel, slug, attempt_id = _started_attempt(tmp_path)
    started = kernel.start_process(
        slug,
        _meta(kernel, slug, "start-process"),
        ProcessStart(attempt_id, "worker"),
    )
    assert started.process_id is not None

    kernel.record_process_output(
        slug,
        _meta(kernel, slug, "stdout-1"),
        _output(
            started.process_id,
            attempt_id,
            ProcessStream.STDOUT,
            "stdout-one",
            stdout=10,
            stderr=0,
            combined=10,
        ),
    )
    kernel.record_process_output(
        slug,
        _meta(kernel, slug, "stderr-1"),
        _output(
            started.process_id,
            attempt_id,
            ProcessStream.STDERR,
            "stderr-one",
            stdout=10,
            stderr=12,
            combined=22,
        ),
    )
    kernel.record_process_output(
        slug,
        _meta(kernel, slug, "stdout-2"),
        _output(
            started.process_id,
            attempt_id,
            ProcessStream.STDOUT,
            "stdout-two",
            stdout=21,
            stderr=12,
            combined=33,
        ),
    )

    state = kernel.materialize(slug)
    process = state.processes[0]
    assert process.last_sequence == 3
    assert process.stdout_bytes_total == 21
    assert process.stderr_bytes_total == 12
    assert process.combined_bytes_total == 33
    assert process.redacted_head_excerpt == "stdout-one"
    assert process.redacted_tail_excerpt == "stdout-two"
    assert not hasattr(process, "sequence")
    assert not hasattr(process, "raw_output")

    events = [
        json.loads(line)
        for line in kernel._store.event_log_path(slug).read_text(encoding="utf-8").splitlines()
    ]
    output_events = [event for event in events if event["type"] == "event_kernel.process.output_recorded"]
    assert [event["payload"]["process_output"]["sequence"] for event in output_events] == [1, 2, 3]
    assert [event["payload"]["process_output"]["stream"] for event in output_events] == [
        "stdout",
        "stderr",
        "stdout",
    ]
    assert output_events[0]["payload"]["process_output"]["excerpt_digest"] == hashlib.sha256(
        b"stdout-one"
    ).hexdigest()
    assert "raw" not in output_events[0]["payload"]["process_output"]


def test_process_counters_are_absolute_monotonic_and_terminal_totals_cannot_shrink(
    tmp_path: Path,
) -> None:
    kernel, slug, attempt_id = _started_attempt(tmp_path)
    process_id = kernel.start_process(
        slug,
        _meta(kernel, slug, "start-process"),
        ProcessStart(attempt_id, "worker"),
    ).process_id
    assert process_id is not None
    first = _output(
        process_id,
        attempt_id,
        ProcessStream.STDOUT,
        "first",
        stdout=10,
        stderr=2,
        combined=12,
        stdout_omitted=3,
        stderr_omitted=1,
        combined_omitted=4,
        truncated=True,
    )
    kernel.record_process_output(slug, _meta(kernel, slug, "output-1"), first)

    with pytest.raises(IllegalTransitionError):
        kernel.record_process_output(
            slug,
            _meta(kernel, slug, "output-decrease"),
            replace(first, stdout_bytes_total=9, combined_bytes_total=11),
        )

    with pytest.raises(IllegalTransitionError):
        kernel.terminate_process(
            slug,
            _meta(kernel, slug, "terminate-decrease"),
            ProcessTerminal(process_id, attempt_id, 1, "exited", 9, 2, 11, 3, 1, 4),
        )

    kernel.terminate_process(
        slug,
        _meta(kernel, slug, "terminate"),
        ProcessTerminal(process_id, attempt_id, 0, "exited", 12, 4, 16, 4, 2, 6),
    )
    process = kernel.materialize(slug).processes[0]
    assert process.state.value == "terminated"
    assert process.stdout_bytes_total == 12
    assert process.stderr_bytes_total == 4
    assert process.combined_bytes_total == 16
    assert process.stdout_omitted_bytes_total == 4
    assert process.stderr_omitted_bytes_total == 2
    assert process.combined_omitted_bytes_total == 6


def test_process_rejects_markers_oversize_and_mismatched_attempt(tmp_path: Path) -> None:
    kernel, slug, attempt_id = _started_attempt(tmp_path)
    process_id = kernel.start_process(
        slug,
        _meta(kernel, slug, "start-process"),
        ProcessStart(attempt_id, "worker"),
    ).process_id
    assert process_id is not None

    with pytest.raises(SensitiveOutputRejectedError):
        _output(
            process_id,
            attempt_id,
            ProcessStream.STDOUT,
            "authorization: bearer secret",
            stdout=1,
            stderr=0,
            combined=1,
        )
    with pytest.raises(SensitiveOutputRejectedError):
        _output(
            process_id,
            attempt_id,
            ProcessStream.STDOUT,
            "é" * 2049,
            stdout=4098,
            stderr=0,
            combined=4098,
        )

    valid = _output(
        process_id,
        attempt_id,
        ProcessStream.STDOUT,
        "safe",
        stdout=4,
        stderr=0,
        combined=4,
    )
    with pytest.raises(IllegalTransitionError):
        kernel.record_process_output(
            slug,
            _meta(kernel, slug, "mismatched-attempt"),
            replace(valid, attempt_id="att-g000001-0123456789abcdef-000001"),
        )
    assert kernel.materialize(slug).processes[0].last_sequence == 0


def test_process_and_attempt_terminals_are_immutable_and_no_os_process_is_launched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    calls: list[tuple[object, ...]] = []

    def fail_if_called(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError("EventKernel must not launch an OS process")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    monkeypatch.setattr(subprocess, "run", fail_if_called)

    kernel, slug, attempt_id = _started_attempt(tmp_path)
    process_id = kernel.start_process(
        slug,
        _meta(kernel, slug, "start-process"),
        ProcessStart(attempt_id, "worker"),
    ).process_id
    assert process_id is not None
    terminal = ProcessTerminal(process_id, attempt_id, 0, "exited", 0, 0, 0, 0, 0, 0)
    kernel.terminate_process(slug, _meta(kernel, slug, "terminate"), terminal)
    revision = kernel.head(slug).revision

    with pytest.raises(IllegalTransitionError):
        kernel.record_process_output(
            slug,
            _meta(kernel, slug, "late-output"),
            _output(
                process_id,
                attempt_id,
                ProcessStream.STDERR,
                "late",
                stdout=0,
                stderr=4,
                combined=4,
            ),
        )
    with pytest.raises(IllegalTransitionError):
        kernel.terminate_process(slug, _meta(kernel, slug, "late-terminal"), terminal)
    assert kernel.head(slug).revision == revision

    from core.workflow.event_kernel import AttemptComplete

    kernel.complete_attempt(
        slug,
        _meta(kernel, slug, "complete-attempt"),
        AttemptComplete(attempt_id, "ok", "b" * 64),
    )
    with pytest.raises(IllegalTransitionError):
        kernel.start_process(
            slug,
            _meta(kernel, slug, "start-after-attempt-terminal"),
            ProcessStart(attempt_id, "late-worker"),
        )
    assert calls == []
