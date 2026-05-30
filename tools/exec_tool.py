# tools/exec_tool.py
"""Hunter v4 — Python Code Executor

Sandboxed Python code execution for custom exploits and tool integration.
"""

import io
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr


def exec_impl(code: str, timeout: int = 30) -> dict:
    """Execute Python code in a sandboxed environment."""
    start = time.time()
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    exec_globals = {"__builtins__": __builtins__}

    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            compiled = compile(code, "<hunter_exec>", "exec")
            exec(compiled, exec_globals)
        elapsed_ms = int((time.time() - start) * 1000)
        return {"stdout": stdout_capture.getvalue(), "stderr": stderr_capture.getvalue(),
                "exit_code": 0, "execution_time_ms": elapsed_ms}
    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return {"stdout": stdout_capture.getvalue(),
                "stderr": f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
                "exit_code": 1, "execution_time_ms": elapsed_ms}
