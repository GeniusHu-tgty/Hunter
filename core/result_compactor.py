"""Compact large scanner results while retaining raw evidence on disk."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any


class ResultCompactor:
    def __init__(self, artifact_dir: str | Path, output_limit_bytes: int = 24000, top_findings: int = 10):
        self.artifact_dir = Path(artifact_dir)
        self.output_limit_bytes = max(512, int(output_limit_bytes))
        self.top_findings_limit = max(1, int(top_findings))
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _severity(item: dict[str, Any]) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(str(item.get("severity", "")).lower(), 0)

    @staticmethod
    def _signals(value: Any) -> list[str]:
        text = json.dumps(value, ensure_ascii=False, default=str).lower()
        known = ["sql", "xss", "ssrf", "ssti", "xxe", "jwt", "cors", "idor", "graphql", "websocket", "race", "api", "javascript", "waf"]
        return sorted({signal for signal in known if signal in text})

    def compact(self, *, target: str, profile: str, results: list[dict[str, Any]], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_obj = {"target": target, "profile": profile, "created_at": time.time(), "results": results, "metrics": metrics or {}}
        raw_bytes = json.dumps(raw_obj, ensure_ascii=False, default=str).encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.artifact_dir / f"adaptive-{profile}-{stamp}-{digest[:10]}.json"
        path.write_bytes(raw_bytes)

        findings = []
        summaries = []
        for result in results:
            agent = result.get("agent", "unknown")
            status = result.get("status", "unknown")
            summary = result.get("summary") or result.get("message") or result.get("error") or ""
            summaries.append({"agent": agent, "status": status, "summary": str(summary)[:300]})
            candidates = result.get("findings", [])
            if result.get("reportable") and not candidates:
                candidates = [result]
            if isinstance(candidates, dict):
                candidates = [candidates]
            for finding in candidates if isinstance(candidates, list) else []:
                if isinstance(finding, dict):
                    clean = {k: finding.get(k) for k in ("name", "title", "type", "severity", "url", "description", "evidence") if finding.get(k) not in (None, "")}
                    clean["agent"] = agent
                    findings.append(clean)
        findings.sort(key=self._severity, reverse=True)
        envelope = {
            "summary": {"target": target, "profile": profile, "agents": len(results), "success": sum(r.get("status") in {"success", "ok", "complete"} for r in results), "errors": sum(r.get("status") in {"error", "timeout"} for r in results)},
            "signals": self._signals(results),
            "top_findings": findings[: self.top_findings_limit],
            "agent_summaries": summaries,
            "artifact_path": str(path),
            "artifact_sha256": digest,
            "metrics": metrics or {},
        }
        encoded = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")
        if len(encoded) > self.output_limit_bytes:
            envelope["agent_summaries"] = summaries[:max(1, self.output_limit_bytes // 400)]
            encoded = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")
        envelope["bytes"] = {"raw": len(raw_bytes), "returned": len(encoded), "saved": max(0, len(raw_bytes) - len(encoded)), "ratio": round(len(encoded) / max(1, len(raw_bytes)), 4)}
        return envelope
