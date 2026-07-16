from __future__ import annotations

from core.request_broker.mitm_controller import MitmController, MitmStatus


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0


class FakeChild:
    def __init__(self):
        self.terminated = False

    def terminate_tree(self):
        self.terminated = True


def test_dead_sidecar_kills_registered_cli_and_records_audit(tmp_path):
    process = FakeProcess(returncode=1)
    controller = MitmController(tmp_path, process_factory=lambda *_args, **_kwargs: process)
    child = FakeChild()
    controller.process = process
    controller.status = MitmStatus.HEALTHY
    controller.register_dependent(child)

    assert controller.check_health() is False
    assert controller.status is MitmStatus.UNAVAILABLE
    assert child.terminated is True
    assert controller.audit_events()[-1]["event"] == "mitm_sidecar_crash"


def test_unavailable_sidecar_rejects_protected_cli(tmp_path):
    controller = MitmController(tmp_path, process_factory=lambda *_args, **_kwargs: FakeProcess())

    allowed, missing = controller.can_run_protected_cli("nuclei")

    assert allowed is False
    assert missing == ["mitm_sidecar_available", "tool_mitm_trust:nuclei"]


def test_verified_tool_can_run_when_sidecar_is_healthy(tmp_path):
    process = FakeProcess()
    controller = MitmController(tmp_path, process_factory=lambda *_args, **_kwargs: process)
    controller.process = process
    controller.status = MitmStatus.HEALTHY
    controller.record_tool_trust("nuclei", "verified")

    allowed, missing = controller.can_run_protected_cli("nuclei")

    assert allowed is True
    assert missing == []


def test_ca_install_failure_enters_candidate_only_with_recovery_diagnostics(tmp_path):
    controller = MitmController(
        tmp_path,
        command_runner=lambda *_args, **_kwargs: (1, "Access is denied"),
    )

    result = controller.install_root_ca(tmp_path / "hunter-root-ca.cer")

    assert result["status"] == "untrusted"
    assert controller.candidate_only is True
    assert result["store"] == "CurrentUser\\Root"
    assert "certutil -user -addstore Root" in result["remediation"]


def test_health_poll_runs_synthetic_probe_at_five_second_interval(tmp_path):
    now = [100.0]
    probes = []
    process = FakeProcess()
    controller = MitmController(
        tmp_path,
        process_factory=lambda *_args, **_kwargs: process,
        health_probe=lambda: probes.append(now[0]) or True,
        now=lambda: now[0],
    )
    controller.process = process

    assert controller.poll_health() is True
    now[0] = 101.0
    assert controller.poll_health() is True
    now[0] = 105.0
    assert controller.poll_health() is True

    assert probes == [100.0, 105.0]


def test_tool_trust_probe_persists_untrusted_result(tmp_path):
    controller = MitmController(tmp_path)

    result = controller.probe_tool_trust("nuclei", lambda: False)

    assert result == "untrusted"
    assert MitmController(tmp_path).tool_trust()["nuclei"] == "untrusted"
