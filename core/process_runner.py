from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from typing import Any


class ExternalProcessRunner:
    def __init__(self, cleanup_timeout: float = 3.0):
        self.cleanup_timeout = max(0.1, float(cleanup_timeout))

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        env: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        command = [str(value) for value in argv]
        started = time.monotonic()
        creationflags = 0
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen(
            command,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=dict(env) if env is not None else None,
            cwd=cwd,
            creationflags=creationflags,
            **popen_kwargs,
        )
        try:
            stdout, stderr = process.communicate(timeout=max(0.01, float(timeout)))
            return {
                "status": "success" if process.returncode == 0 else "error",
                "stdout": stdout,
                "stderr": stderr,
                "returncode": int(process.returncode or 0),
                "pid": process.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "cleanup": {"tree_terminated": False, "method": "not-required"},
            }
        except subprocess.TimeoutExpired as exc:
            cleanup = self._terminate_tree(process)
            stdout, stderr = self._bounded_collect(process)
            partial_stdout = self._text(exc.stdout)
            partial_stderr = self._text(exc.stderr)
            return {
                "status": "timeout",
                "stdout": stdout or partial_stdout,
                "stderr": stderr or partial_stderr or "Command timed out",
                "returncode": -1,
                "pid": process.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timeout_seconds": float(timeout),
                "cleanup": cleanup,
            }

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _bounded_collect(self, process: subprocess.Popen) -> tuple[str, str]:
        try:
            return process.communicate(timeout=self.cleanup_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                return process.communicate(timeout=self.cleanup_timeout)
            except subprocess.TimeoutExpired:
                return "", "Process output pipes did not close after termination"

    def _terminate_tree(self, process: subprocess.Popen) -> dict[str, Any]:
        if process.poll() is not None:
            return {"tree_terminated": True, "method": "already-exited"}
        if os.name == "nt":
            try:
                completed = subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=self.cleanup_timeout,
                    check=False,
                )
            except (
                subprocess.TimeoutExpired,
                FileNotFoundError,
                PermissionError,
                OSError,
            ) as exc:
                if process.poll() is None:
                    try:
                        process.kill()
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                return {
                    "tree_terminated": process.poll() is not None,
                    "method": "taskkill-tree-fallback",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            if process.poll() is None:
                try:
                    process.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            return {
                "tree_terminated": completed.returncode == 0 or process.poll() is not None,
                "method": "taskkill-tree",
                "returncode": completed.returncode,
                "stderr": completed.stderr.strip(),
            }
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return {"tree_terminated": True, "method": "killpg"}
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
            return {"tree_terminated": process.poll() is not None, "method": "process-kill"}
