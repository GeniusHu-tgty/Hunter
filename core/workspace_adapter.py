"""OpenTgtyLab workspace integration for Hunter.

Keeps Hunter independent while sharing case state, project knowledge, and
artifact conventions with an Open-tgtylab checkout.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_ENV_NAMES = ("OPEN_TGTYLAB_ROOT", "OPEN_TGTYLAB_WORKSPACE", "TGTYLAB_ROOT")
_BOARDS = {
    "ctf-website": Path("kb/ctf-website/techniques"),
    "web": Path("kb/ctf-website/techniques"),
    "apk-reverse": Path("kb/apk-reverse/techniques"),
    "android": Path("kb/apk-reverse/techniques"),
    "pe-reverse": Path("kb/pe-reverse/techniques"),
    "pe": Path("kb/pe-reverse/techniques"),
    "general": Path("kb/general/techniques"),
}
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class OpenTgtyLabWorkspaceAdapter:
    def __init__(self, root: Optional[str | Path] = None):
        self.root = self.discover_root(root)

    @classmethod
    def discover_root(cls, explicit: Optional[str | Path] = None) -> Path:
        candidates: List[Path] = []
        if explicit:
            candidates.append(Path(explicit).expanduser())
        for name in _ENV_NAMES:
            if os.environ.get(name):
                candidates.append(Path(os.environ[name]).expanduser())
        cwd = Path.cwd().resolve()
        candidates.extend([cwd, *cwd.parents])
        candidates.extend([Path(r"D:\Open-tgtylab"), Path.home() / "Open-tgtylab"])
        for candidate in candidates:
            resolved = candidate.resolve()
            if cls._looks_like_workspace(resolved):
                return resolved
        return (Path(explicit).expanduser().resolve() if explicit else Path(r"D:\Open-tgtylab").resolve())

    @staticmethod
    def _looks_like_workspace(path: Path) -> bool:
        return path.is_dir() and (path / "cases").is_dir() and ((path / "kb").is_dir() or (path / "AGENTS.md").exists())

    @staticmethod
    def _ok(tool: str, data: Optional[Dict[str, Any]] = None, **extra: Any) -> Dict[str, Any]:
        out = {"tool": tool, "status": "ok", "data": data or {}, "evidence": {}, "next_actions": []}
        out.update(extra)
        return out

    @staticmethod
    def _error(tool: str, exc: Exception | str) -> Dict[str, Any]:
        return {"tool": tool, "status": "error", "error_type": type(exc).__name__ if isinstance(exc, Exception) else "Error", "error": str(exc), "data": {}, "evidence": {}, "next_actions": []}

    @staticmethod
    def _safe_slug(value: str, label: str = "slug") -> str:
        if not value or not _SLUG.fullmatch(value):
            raise ValueError(f"Invalid {label}: {value!r}")
        return value

    @staticmethod
    def _within(base: Path, relative: str | Path) -> Path:
        base = base.resolve()
        candidate = (base / relative).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise ValueError("Path escapes the allowed workspace directory") from exc
        return candidate

    def _case_file(self, slug: str) -> Path:
        return self.root / "cases" / self._safe_slug(slug, "case slug") / "state.json"

    def health(self) -> Dict[str, Any]:
        checks = {
            "root": self.root.is_dir(), "cases": (self.root / "cases").is_dir(),
            "kb": (self.root / "kb").is_dir(), "exports": (self.root / "exports").is_dir(),
            "notes": (self.root / "exports/notes").is_dir(), "reports": (self.root / "exports/reports").is_dir(),
        }
        boards = {name: str((self.root / rel).resolve()) for name, rel in _BOARDS.items() if name in {"ctf-website", "apk-reverse", "pe-reverse", "general"} and (self.root / rel).is_dir()}
        return self._ok("hunter_workspace_health", {"available": all(checks[k] for k in ("root", "cases", "kb")), "root": str(self.root), "checks": checks, "boards": boards, "env_names": list(_ENV_NAMES)})

    def case_open(self, slug: str) -> Dict[str, Any]:
        try:
            path = self._case_file(slug)
            state = json.loads(path.read_text(encoding="utf-8-sig"))
            return self._ok("hunter_case_open", {"slug": slug, "path": str(path), "state": state})
        except Exception as exc: return self._error("hunter_case_open", exc)

    def case_status(self, slug: str) -> Dict[str, Any]:
        opened = self.case_open(slug)
        if opened["status"] != "ok": return {**opened, "tool": "hunter_case_status"}
        state = opened["data"]["state"]
        return self._ok("hunter_case_status", {"slug": slug, "status": state.get("status"), "target": state.get("target"), "updated_at": state.get("updated_at"), "path": opened["data"]["path"]})

    def case_next_steps(self, slug: str) -> Dict[str, Any]:
        opened = self.case_open(slug)
        if opened["status"] != "ok": return {**opened, "tool": "hunter_case_next_steps"}
        return self._ok("hunter_case_next_steps", {"slug": slug, "next_steps": opened["data"]["state"].get("next_steps", []), "path": opened["data"]["path"]})

    def case_update(self, slug: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not isinstance(updates, dict): raise ValueError("updates must be an object")
            path = self._case_file(slug)
            state = json.loads(path.read_text(encoding="utf-8-sig"))
            protected = {"slug", "created_at"}
            for key, value in updates.items():
                if key not in protected: state[key] = value
            state.setdefault("slug", slug)
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            temp = path.with_suffix(".json.tmp")
            temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temp.replace(path)
            return self._ok("hunter_case_update", {"slug": slug, "path": str(path), "state": state})
        except Exception as exc: return self._error("hunter_case_update", exc)

    def _board_root(self, board: str) -> Path:
        key = (board or "general").lower()
        if key not in _BOARDS: raise ValueError(f"Unknown KB board: {board}")
        root = (self.root / _BOARDS[key]).resolve()
        if not root.is_dir(): raise FileNotFoundError(f"KB board not found: {key}")
        return root

    @staticmethod
    def _tokens(query: str) -> List[str]:
        return [x for x in re.findall(r"[A-Za-z0-9_\-\u4e00-\u9fff]+", query.lower()) if len(x) > 1]

    def kb_search(self, query: str, board: str = "general", limit: int = 20) -> Dict[str, Any]:
        try:
            root = self._board_root(board); tokens = self._tokens(query)
            if not tokens: raise ValueError("query must contain searchable terms")
            hits=[]; searched=0
            for path in root.rglob("*.md"):
                searched += 1
                text = path.read_text(encoding="utf-8", errors="replace")
                lower = text.lower(); rel = path.relative_to(root).as_posix()
                score = sum(lower.count(t) * 2 + rel.lower().count(t) * 5 for t in tokens)
                if score:
                    pos=min((lower.find(t) for t in tokens if lower.find(t)>=0), default=0)
                    hits.append({"path": rel, "board": board, "score": score, "snippet": text[max(0,pos-100):pos+300].replace("\n", " ")})
            hits.sort(key=lambda x: (-x["score"], x["path"])); hits=hits[:max(1,min(limit,100))]
            return self._ok("hunter_project_kb_search", {"query": query, "board": board, "results": hits, "returned": len(hits)}, evidence={"searched_files": searched})
        except Exception as exc: return self._error("hunter_project_kb_search", exc)

    def kb_read(self, technique_path: str, board: str = "general", max_chars: int = 12000) -> Dict[str, Any]:
        try:
            root=self._board_root(board); path=self._within(root, technique_path)
            if path.suffix.lower() != ".md" or not path.is_file(): raise FileNotFoundError(technique_path)
            content=path.read_text(encoding="utf-8", errors="replace"); limit=max(1,min(max_chars,100000))
            return self._ok("hunter_project_kb_read", {"board": board, "path": path.relative_to(root).as_posix(), "content": content[:limit], "truncated": len(content)>limit})
        except Exception as exc: return self._error("hunter_project_kb_read", exc)

    def _write(self, tool: str, base: Path, relative: str, content: str, append: bool = False) -> Dict[str, Any]:
        try:
            path=self._within(base, relative); path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a" if append else "w", encoding="utf-8", newline="") as handle: handle.write(content)
            return self._ok(tool, {"path": str(path), "bytes": len(content.encode("utf-8")), "append": append}, evidence={"artifacts": [str(path)]})
        except Exception as exc: return self._error(tool, exc)

    def evidence_save(self, case_slug: str, relative_path: str, content: str, append: bool = False) -> Dict[str, Any]:
        try: base=self.root / "exports/evidence" / self._safe_slug(case_slug, "case slug")
        except Exception as exc: return self._error("hunter_evidence_save", exc)
        return self._write("hunter_evidence_save", base, relative_path, content, append)

    def note_write(self, relative_path: str, content: str, append: bool = False) -> Dict[str, Any]:
        return self._write("hunter_note_write", self.root / "exports/notes", relative_path, content, append)

    def report_publish(self, relative_path: str, content: str, append: bool = False) -> Dict[str, Any]:
        return self._write("hunter_report_publish", self.root / "exports/reports", relative_path, content, append)

    def recommend(self, case_slug: str = "", signals: Optional[List[str]] = None, finding: str = "", target: str = "", limit: int = 8) -> Dict[str, Any]:
        signals=signals or []; raw=" ".join(signals+[finding]).lower(); case={}; steps=[]
        if case_slug:
            opened=self.case_open(case_slug)
            if opened["status"] == "ok": case=opened["data"]["state"]; steps=case.get("next_steps", [])
        query=" ".join(signals+[finding]).strip() or "evidence proof"
        hits=[]
        for board in ("ctf-website", "general"):
            result=self.kb_search(query, board=board, limit=limit)
            if result["status"] == "ok": hits.extend(result["data"]["results"])
        hits=sorted(hits,key=lambda x:-x["score"])[:limit]
        rec=[]
        mapping=(("jwt", "hunter_auto_jwt"),("token", "hunter_auto_jwt"),("idor", "hunter_auto_idor"),("authorization", "hunter_auto_access_control"),("cors", "hunter_auto_cors"),("graphql", "hunter_auto_graphql"),("xss", "hunter_auto_xss"),("sql", "hunter_auto_sqli"),("ssrf", "hunter_auto_ssrf"))
        for token,tool in mapping:
            if token in raw and tool not in [x["tool"] for x in rec]: rec.append({"tool":tool,"reason":f"Observed {token} signal"})
        if not rec: rec=[{"tool":"hunter_recon","reason":"No specific vulnerability signal yet"}]
        return self._ok("hunter_workspace_recommend", {"target": target or case.get("target", ""), "case": case, "case_next_steps": steps, "project_kb_hits": hits, "tool_recommendations": rec, "protocol": {"http_priority": ["Burp send_http2_request", "http_probe"], "source_priority": ["search_in_sources"], "evidence_required": True}, "artifact_routes": {"evidence": str(self.root / "exports/evidence" / (case_slug or "<case>")), "notes": str(self.root / "exports/notes"), "reports": str(self.root / "exports/reports")}})
