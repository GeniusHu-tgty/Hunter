from concurrent.futures import ThreadPoolExecutor
import asyncio
import json
from pathlib import Path

import pytest

from core.adaptive_engine import AdaptiveEngine, ScanBudget, get_mode_profile
from core.recon_cache import ReconCache
from core.result_compactor import ResultCompactor


def test_mode_profiles_are_distinct_and_aliases_work():
    fast = get_mode_profile("fast")
    standard = get_mode_profile("standard")
    deep = get_mode_profile("deep")
    assert get_mode_profile("quick") == fast
    assert get_mode_profile("aggressive") == deep
    assert fast.wall_time_s < standard.wall_time_s < deep.wall_time_s
    assert fast.max_tools < standard.max_tools < deep.max_tools
    assert fast.concurrency <= standard.concurrency <= deep.concurrency
    assert fast.layers and all(isinstance(layer, tuple) for layer in fast.layers)


def test_scan_budget_enforces_tool_and_output_limits():
    budget = ScanBudget(wall_time_s=60, max_tools=2, concurrency=1, output_limit_bytes=100)
    assert budget.reserve_tool("a")
    assert budget.reserve_tool("b")
    assert not budget.reserve_tool("c")
    assert budget.remaining_tools == 0
    assert budget.clamp_output("x" * 500).encode().__len__() <= 100


@pytest.mark.asyncio
async def test_dag_executes_each_layer_in_parallel(tmp_path):
    async def runner(name, target, **kwargs):
        await asyncio.sleep(0.08)
        return {"status": "success", "agent": name, "signals": [name]}

    engine = AdaptiveEngine(cache=ReconCache(tmp_path / "cache"), artifact_dir=tmp_path / "artifacts")
    plan = {"layers": [("a", "b", "c"), ("d",)], "profile": "fast"}
    result = await engine.execute("https://example.test", plan=plan, runner=runner, use_cache=False)
    assert result["metrics"]["tools_started"] == 4
    assert result["metrics"]["parallelism_saved_ms"] > 100
    assert result["metrics"]["wall_time_ms"] < 260


@pytest.mark.asyncio
async def test_cache_hit_skips_runner(tmp_path):
    calls = 0
    async def runner(name, target, **kwargs):
        nonlocal calls
        calls += 1
        return {"status": "success", "agent": name}

    cache = ReconCache(tmp_path / "cache")
    engine = AdaptiveEngine(cache=cache, artifact_dir=tmp_path / "artifacts")
    plan = {"layers": [("a", "b")], "profile": "fast"}
    first = await engine.execute("https://example.test/path", plan=plan, runner=runner)
    second = await engine.execute("https://example.test/path", plan=plan, runner=runner)
    assert calls == 2
    assert first["metrics"]["cache_hit"] is False
    assert second["metrics"]["cache_hit"] is True



def test_recon_cache_supports_concurrent_same_key_writers(tmp_path):
    cache = ReconCache(tmp_path / "cache")

    def write(index):
        return cache.put(
            "https://same.example.test",
            "fast",
            {"writer": index},
            "same-plan",
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        paths = list(executor.map(write, range(32)))

    assert len(set(paths)) == 1
    record = cache.get(
        "https://same.example.test",
        "fast",
        "same-plan",
    )
    assert record is not None
    assert record["data"]["writer"] in range(32)
    assert list((tmp_path / "cache").glob("*.tmp")) == []


def test_result_compactor_persists_raw_and_returns_small_envelope(tmp_path):
    raw = [{"agent": f"a{i}", "status": "success", "stdout": "Z" * 5000, "findings": [{"name": f"f{i}", "severity": "high"}]} for i in range(8)]
    compactor = ResultCompactor(tmp_path, output_limit_bytes=3000, top_findings=3)
    envelope = compactor.compact(target="https://example.test", profile="fast", results=raw)
    assert Path(envelope["artifact_path"]).exists()
    assert envelope["bytes"]["raw"] > envelope["bytes"]["returned"]
    assert envelope["bytes"]["ratio"] < 0.25
    assert len(envelope["top_findings"]) <= 3


@pytest.mark.asyncio
async def test_benchmark_proves_speed_cache_and_compression(tmp_path):
    engine = AdaptiveEngine(cache=ReconCache(tmp_path / "cache"), artifact_dir=tmp_path / "artifacts")
    result = await engine.benchmark(agent_delay_s=0.04, payload_bytes=5000)
    assert result["parallel"]["wall_time_ms"] < result["serial"]["wall_time_ms"]
    assert result["speedup"] > 1.3
    assert result["cache"]["hit"] is True
    assert result["compression"]["ratio"] < 0.4
import asyncio
import pytest
from core.adaptive_engine import AdaptiveEngine
from core.recon_cache import ReconCache

@pytest.mark.asyncio
async def test_signal_routing_skips_irrelevant_vulnerability_agents(tmp_path):
    calls=[]
    async def runner(name,target,**kwargs):
        calls.append(name)
        if name=='recon': return {'status':'success','signals':['jwt','api']}
        return {'status':'success'}
    engine=AdaptiveEngine(ReconCache(tmp_path/'cache'),tmp_path/'artifacts')
    plan={'profile':'standard','layers':[('recon',),('jwt-vuln','idor-vuln','sqli-vuln','xss-vuln')]}
    result=await engine.execute('x.test',plan=plan,runner=runner,use_cache=False,adaptive_routing=True)
    assert 'jwt-vuln' in calls and 'sqli-vuln' not in calls and 'xss-vuln' not in calls
    assert result['metrics']['routing_skipped']>=2

@pytest.mark.asyncio
async def test_confirmed_proof_stops_later_layers(tmp_path):
    calls=[]
    async def runner(name,target,**kwargs):
        calls.append(name)
        return {'status':'success','proof_status':'confirmed'} if name=='proof' else {'status':'success'}
    engine=AdaptiveEngine(ReconCache(tmp_path/'cache'),tmp_path/'artifacts')
    plan={'profile':'fast','layers':[('proof',),('late-a','late-b')]}
    result=await engine.execute('x.test',plan=plan,runner=runner,use_cache=False,stop_on_proof=True)
    assert calls==['proof']; assert result['metrics']['early_stop_reason']=='confirmed_proof'
