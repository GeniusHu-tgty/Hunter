import os
import subprocess
import sys
import time

import pytest

from core.process_runner import ExternalProcessRunner


def _pid_exists(pid):
    if os.name == "nt":
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return str(pid) in completed.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree regression")
def test_timeout_kills_descendant_process_tree(tmp_path):
    child_pid_file = tmp_path / "child.pid"
    helper = tmp_path / "spawn_child.py"
    helper.write_text(
        "import pathlib, subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )

    result = ExternalProcessRunner(cleanup_timeout=2).run(
        [sys.executable, str(helper), str(child_pid_file)],
        timeout=0.5,
    )

    assert result["status"] == "timeout"
    assert result["cleanup"]["tree_terminated"] is True
    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and (
        _pid_exists(result["pid"]) or _pid_exists(child_pid)
    ):
        time.sleep(0.1)
    assert not _pid_exists(result["pid"])
    assert not _pid_exists(child_pid)


def test_success_returns_process_metadata():
    result = ExternalProcessRunner().run(
        [sys.executable, "-c", "print('ok')"],
        timeout=5,
    )

    assert result["status"] == "success"
    assert result["stdout"].strip() == "ok"
    assert result["pid"] > 0
    assert result["elapsed_seconds"] >= 0



def test_windows_taskkill_failure_falls_back_to_direct_kill(monkeypatch):
    class Process:
        pid = 424242

        def __init__(self):
            self.returncode = None
            self.killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    def taskkill_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=0.1)

    process = Process()
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", taskkill_timeout)

    cleanup = ExternalProcessRunner(cleanup_timeout=0.1)._terminate_tree(process)

    assert process.killed is True
    assert cleanup["tree_terminated"] is True
    assert cleanup["method"] == "taskkill-tree-fallback"
    assert cleanup["error_type"] == "TimeoutExpired"
