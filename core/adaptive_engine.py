"""Adaptive, budgeted and cache-aware Hunter scan orchestration."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from .recon_cache import ReconCache
from .result_compactor import ResultCompactor

Runner = Callable[..., Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class ModeProfile:
    name: str
    wall_time_s: int
    max_tools: int
    concurrency: int
    output_limit_bytes: int
    cache_ttl_s: int
    top_findings: int
    layers: tuple[tuple[str, ...], ...]


_PROFILES = {
    "fast": ModeProfile("fast", 180, 10, 4, 16000, 1800, 6, (
        ("tech-detect", "port-scan", "subdomain"),
        ("js-analyze", "dir-enum", "info-leak"),
    )),
    "standard": ModeProfile("standard", 240, 24, 6, 32000, 7200, 12, (
        ("tech-detect", "port-scan", "subdomain", "dns-info"),
        ("js-analyze", "dir-enum", "api-discover", "endpoint-map"),
        ("auth-analysis", "info-leak", "cors-vuln", "jwt-vuln", "idor-vuln", "sqli-vuln", "xss-vuln", "ssrf-vuln"),
    )),
    "deep": ModeProfile("deep", 285, 50, 8, 64000, 21600, 20, (
        ("tech-detect", "port-scan", "subdomain", "dns-info"),
        ("js-analyze", "dir-enum", "api-discover", "param-discover", "endpoint-map", "auth-analysis"),
        ("sqli-vuln", "xss-vuln", "ssrf-vuln", "ssti-vuln", "lfi-vuln", "rce-vuln", "jwt-vuln", "upload-vuln", "xxe-vuln", "deser-vuln", "cors-vuln", "idor-vuln", "info-leak"),
        ("evidence-collect", "cvss-score"),
    )),
}
_ALIASES = {"quick": "fast", "aggressive": "deep"}


def get_mode_profile(name: str) -> ModeProfile:
    normalized = _ALIASES.get(str(name).lower(), str(name).lower())
    if normalized not in _PROFILES:
        raise ValueError(f"Unknown adaptive scan mode: {name}. Use fast, standard, or deep.")
    return _PROFILES[normalized]


@dataclass
class ScanBudget:
    wall_time_s: float
    max_tools: int
    concurrency: int
    output_limit_bytes: int
    started_at: float = field(default_factory=time.monotonic)
    tools_started: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def remaining_s(self) -> float:
        return max(0.0, self.wall_time_s - self.elapsed_s)

    @property
    def remaining_tools(self) -> int:
        return max(0, self.max_tools - len(self.tools_started))

    def reserve_tool(self, name: str) -> bool:
        if self.remaining_s <= 0 or self.remaining_tools <= 0:
            return False
        self.tools_started.append(name)
        return True

    def clamp_output(self, text: str) -> str:
        raw = text.encode("utf-8")
        if len(raw) <= self.output_limit_bytes:
            return text
        suffix = b"...[truncated]"
        return (raw[: max(0, self.output_limit_bytes - len(suffix))] + suffix).decode("utf-8", errors="ignore")


class AdaptiveEngine:
    def __init__(self, cache: ReconCache, artifact_dir: str | Path):
        self.cache = cache
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def plan(self, target: str, mode: str = "fast", phases: list[str] | None = None) -> dict[str, Any]:
        profile = get_mode_profile(mode)
        layers = profile.layers
        if phases:
            phase_map = {
                "pre-recon": {"tech-detect", "port-scan", "subdomain", "dns-info"},
                "recon": {"js-analyze", "dir-enum", "api-discover", "param-discover", "endpoint-map", "auth-analysis"},
                "vulnerability-analysis": set(sum((_PROFILES["deep"].layers[2],), ())),
                "reporting": {"evidence-collect", "cvss-score", "report-generate", "compliance-check"},
            }
            allowed = set().union(*(phase_map.get(p, set()) for p in phases))
            layers = tuple(tuple(agent for agent in layer if agent in allowed) for layer in layers)
            layers = tuple(layer for layer in layers if layer)
        return {"target": target, "profile": profile.name, "profile_data": asdict(profile), "layers": layers, "agents": [a for layer in layers for a in layer]}

    @staticmethod
    def _signature(plan: dict[str, Any]) -> str:
        raw = json.dumps(plan.get("layers", []), ensure_ascii=False, sort_keys=True, default=list)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    async def execute(self, target: str, *, mode: str = "fast", phases: list[str] | None = None, plan: dict[str, Any] | None = None, runner: Runner, use_cache: bool = True, adaptive_routing: bool = False, stop_on_proof: bool = False) -> dict[str, Any]:
        plan = plan or self.plan(target, mode, phases)
        profile = get_mode_profile(plan.get("profile", mode))
        signature = self._signature(plan)
        if use_cache:
            cached = self.cache.get(target, profile.name, signature, ttl_s=profile.cache_ttl_s)
            if cached:
                data = cached["data"]
                data.setdefault("metrics", {})["cache_hit"] = True
                data["metrics"]["cache_path"] = cached["cache_path"]
                return data

        budget = ScanBudget(profile.wall_time_s, profile.max_tools, profile.concurrency, profile.output_limit_bytes)
        results: list[dict[str, Any]] = []
        tool_time_ms = 0.0
        skipped: list[str] = []
        timed_out = 0
        observed_signals: set[str] = set()
        routing_skipped = 0
        early_stop_reason = ""

        async def run_one(agent: str, semaphore: asyncio.Semaphore) -> tuple[dict[str, Any], float]:
            if not budget.reserve_tool(agent):
                return {"agent": agent, "status": "skipped", "message": "scan budget exhausted"}, 0.0
            started = time.monotonic()
            async with semaphore:
                try:
                    result = await asyncio.wait_for(runner(agent, target, mode=profile.name, timeout=max(0.01, budget.remaining_s)), timeout=max(0.01, budget.remaining_s))
                except asyncio.TimeoutError:
                    result = {"status": "timeout", "message": "adaptive wall-time budget exceeded"}
                except Exception as exc:
                    result = {"status": "error", "message": str(exc)}
            result = dict(result or {})
            result.setdefault("agent", agent)
            return result, (time.monotonic() - started) * 1000

        semaphore = asyncio.Semaphore(profile.concurrency)
        wall_started = time.monotonic()
        signal_routes = {"jwt-vuln": {"jwt", "token", "api"}, "idor-vuln": {"idor", "authorization", "object", "api"}, "sqli-vuln": {"sql", "database", "parameter"}, "xss-vuln": {"xss", "javascript", "html", "parameter"}, "ssrf-vuln": {"ssrf", "url", "callback", "webhook"}, "ssti-vuln": {"ssti", "template"}, "xxe-vuln": {"xxe", "xml"}, "cors-vuln": {"cors", "origin", "api"}}
        for layer in plan.get("layers", []):
            selected = []
            for agent in layer:
                if adaptive_routing and agent in signal_routes and observed_signals and not (signal_routes[agent] & observed_signals):
                    skipped.append(agent); routing_skipped += 1
                elif budget.remaining_tools <= 0 or budget.remaining_s <= 0:
                    skipped.append(agent)
                else:
                    selected.append(agent)
            if not selected:
                continue
            completed = await asyncio.gather(*(run_one(agent, semaphore) for agent in selected))
            for result, duration in completed:
                results.append(result)
                tool_time_ms += duration
                timed_out += result.get("status") == "timeout"
                signals = result.get("signals", [])
                if isinstance(signals, str): signals = [signals]
                observed_signals.update(str(x).lower() for x in signals)
            if stop_on_proof and any(str(r.get("proof_status", "")).lower() in {"confirmed", "reproduced"} for r in results):
                early_stop_reason = "confirmed_proof"
                break
            if budget.remaining_s <= 0:
                break
        wall_time_ms = (time.monotonic() - wall_started) * 1000
        metrics = {
            "profile": profile.name, "wall_time_ms": round(wall_time_ms, 3), "tool_time_ms": round(tool_time_ms, 3),
            "parallelism_saved_ms": round(max(0.0, tool_time_ms - wall_time_ms), 3), "tools_started": len(budget.tools_started),
            "tools_skipped": len(skipped), "skipped_agents": skipped, "timeouts": timed_out, "cache_hit": False,
            "routing_skipped": routing_skipped, "observed_signals": sorted(observed_signals), "early_stop_reason": early_stop_reason,
            "budget": {"wall_time_s": profile.wall_time_s, "max_tools": profile.max_tools, "concurrency": profile.concurrency, "output_limit_bytes": profile.output_limit_bytes},
        }
        envelope = ResultCompactor(self.artifact_dir, profile.output_limit_bytes, profile.top_findings).compact(target=target, profile=profile.name, results=results, metrics=metrics)
        output = {"status": "complete", "target": target, "profile": profile.name, "plan": {"layers": plan.get("layers", []), "signature": signature}, "results": results, "compact": envelope, "metrics": metrics}
        if use_cache:
            path = self.cache.put(target, profile.name, output, signature)
            output["metrics"]["cache_path"] = str(path)
        return output

    async def benchmark(self, agent_delay_s: float = 0.05, payload_bytes: int = 10000) -> dict[str, Any]:
        agents = ("bench-a", "bench-b", "bench-c", "bench-d")
        async def runner(name: str, target: str, **kwargs):
            await asyncio.sleep(agent_delay_s)
            return {"agent": name, "status": "success", "signals": ["benchmark"], "stdout": "X" * payload_bytes, "findings": [{"name": name, "severity": "medium"}]}

        serial_start = time.monotonic()
        serial_results = []
        for agent in agents:
            serial_results.append(await runner(agent, "benchmark.local"))
        serial_ms = (time.monotonic() - serial_start) * 1000
        plan = {"profile": "fast", "layers": [agents]}
        parallel = await self.execute("benchmark.local", plan=plan, runner=runner, use_cache=False)
        self.cache.clear(target="benchmark-cache.local", profile="fast")
        first = await self.execute("benchmark-cache.local", plan=plan, runner=runner, use_cache=True)
        second = await self.execute("benchmark-cache.local", plan=plan, runner=runner, use_cache=True)
        compact = ResultCompactor(self.artifact_dir, 8000, 3).compact(target="benchmark.local", profile="fast", results=serial_results)
        parallel_ms = parallel["metrics"]["wall_time_ms"]
        return {"serial": {"wall_time_ms": round(serial_ms, 3)}, "parallel": {"wall_time_ms": parallel_ms, "parallelism_saved_ms": parallel["metrics"]["parallelism_saved_ms"]}, "speedup": round(serial_ms / max(0.001, parallel_ms), 3), "cache": {"first_hit": first["metrics"]["cache_hit"], "hit": second["metrics"]["cache_hit"]}, "compression": compact["bytes"], "agents": len(agents), "delay_s": agent_delay_s, "payload_bytes": payload_bytes}
