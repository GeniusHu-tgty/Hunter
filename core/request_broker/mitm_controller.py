from __future__ import annotations

import json
import shutil
import subprocess
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol


class MitmStatus(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    UNAVAILABLE = "UNAVAILABLE"


class DependentProcess(Protocol):
    def terminate_tree(self) -> None: ...


class MitmController:
    """Fail-closed controller for the optional mitmdump sidecar."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        mitmdump_path: str = "mitmdump",
        process_factory: Callable[..., Any] = subprocess.Popen,
        health_probe: Callable[[], bool] | None = None,
        command_runner: Callable[..., tuple[int, str]] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.mitmdump_path = mitmdump_path
        self.process_factory = process_factory
        self.health_probe = health_probe
        self.command_runner = command_runner or self._run_command
        self.now = now
        self.process: Any | None = None
        self.status = MitmStatus.STOPPED
        self.candidate_only = False
        self._dependents: list[DependentProcess] = []
        self.audit_path = self.state_dir / "mitm_audit.jsonl"
        self.trust_path = self.state_dir / "mitm_tool_trust.json"
        self.ca_trust_path = self.state_dir / "mitm_ca_trust.json"
        self._last_synthetic_probe_at: float | None = None

    @staticmethod
    def _run_command(command: list[str]) -> tuple[int, str]:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return completed.returncode, (completed.stdout + completed.stderr).strip()

    def install_root_ca(self, certificate_path: str | Path) -> dict[str, str]:
        """Install Hunter's generated CA for the current user only.

        Trust failures deliberately degrade the controller rather than attempting a
        machine-wide installation or silently allowing direct protected scans.
        """
        certificate = str(Path(certificate_path))
        command = ["certutil", "-user", "-addstore", "Root", certificate]
        try:
            returncode, output = self.command_runner(command)
        except OSError as exc:
            returncode, output = 1, str(exc)
        if returncode == 0:
            result = {
                "status": "verified",
                "store": "CurrentUser\\Root",
                "certificate": certificate,
                "detail": output,
                "remediation": "",
            }
            self.candidate_only = False
        else:
            result = {
                "status": "untrusted",
                "store": "CurrentUser\\Root",
                "certificate": certificate,
                "detail": output,
                "remediation": f"Run certutil -user -addstore Root \"{certificate}\" in the affected user session.",
            }
            self.candidate_only = True
            self._audit("mitm_ca_untrusted", detail=output)
        self.ca_trust_path.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        return result

    def _audit(self, event: str, **data: Any) -> None:
        row = {"at": time.time(), "event": event, **data}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def audit_events(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]

    def start(self, *, port: int) -> bool:
        executable = shutil.which(self.mitmdump_path)
        if executable is None:
            self.status = MitmStatus.UNAVAILABLE
            self._audit("mitm_sidecar_unavailable", reason="mitmdump_not_found")
            return False
        self.status = MitmStatus.STARTING
        self.process = self.process_factory(
            [executable, "--listen-host", "127.0.0.1", "--listen-port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        if self.check_health():
            return True
        self.status = MitmStatus.UNAVAILABLE
        return False

    def register_dependent(self, child: DependentProcess) -> None:
        self._dependents.append(child)

    def record_tool_trust(self, tool: str, status: str) -> None:
        if status not in {"verified", "untrusted", "unknown"}:
            raise ValueError("invalid MITM tool trust status")
        values = self.tool_trust()
        values[str(tool)] = status
        self.trust_path.write_text(json.dumps(values, sort_keys=True) + "\n", encoding="utf-8")

    def probe_tool_trust(self, tool: str, probe: Callable[[], bool]) -> str:
        """Persist the outcome of a tool's local HTTPS MITM fixture probe."""
        try:
            status = "verified" if probe() else "untrusted"
        except Exception:
            status = "unknown"
        self.record_tool_trust(tool, status)
        self._audit("mitm_tool_trust_probe", tool=tool, status=status)
        return status

    def tool_trust(self) -> dict[str, str]:
        if not self.trust_path.exists():
            return {}
        try:
            raw = json.loads(self.trust_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        return {str(key): str(value) for key, value in raw.items()}

    def can_run_protected_cli(self, tool: str) -> tuple[bool, list[str]]:
        missing: list[str] = []
        if self.status is not MitmStatus.HEALTHY:
            missing.append("mitm_sidecar_available")
        if self.tool_trust().get(tool) != "verified":
            missing.append(f"tool_mitm_trust:{tool}")
        return not missing, missing

    def check_health(self) -> bool:
        if self.process is None or self.process.poll() is not None:
            self._fail_closed("process_exited")
            return False
        if self.health_probe is not None and not self.health_probe():
            self._fail_closed("synthetic_probe_failed")
            return False
        self.status = MitmStatus.HEALTHY
        return True

    def poll_health(self) -> bool:
        """Run the cheap sidecar liveness check every poll and the synthetic check every five seconds."""
        if self.process is None or self.process.poll() is not None:
            self._fail_closed("process_exited")
            return False
        current = self.now()
        due = self._last_synthetic_probe_at is None or current - self._last_synthetic_probe_at >= 5.0
        if due:
            self._last_synthetic_probe_at = current
            return self.check_health()
        self.status = MitmStatus.HEALTHY
        return True

    def _fail_closed(self, reason: str) -> None:
        was_healthy = self.status is MitmStatus.HEALTHY
        self.status = MitmStatus.UNAVAILABLE
        for child in self._dependents:
            child.terminate_tree()
        self._dependents.clear()
        if was_healthy:
            self._audit("mitm_sidecar_crash", reason=reason)
