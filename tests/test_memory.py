import asyncio
import json
import sqlite3

import mcp_server
import pytest

from core.memory.fingerprint_database import FingerprintDatabase
from core.memory.pattern_engine import PatternEngine
from core.memory.target_memory import TargetMemory
from core.memory.technique_memory import TechniqueMemory


def test_target_memory_creates_schema_records_history_and_regression(tmp_path):
    db_path = tmp_path / "targets.db"
    memory = TargetMemory(db_path)

    memory.record_target(
        "https://shop.example.test",
        fingerprints={"waf": "Cloudflare", "framework": "Django"},
    )
    memory.record_endpoint(
        "https://shop.example.test",
        "/api/search",
        method="GET",
        parameters=["q"],
        injection_points=["q"],
    )
    memory.record_vulnerability(
        "https://shop.example.test",
        vuln_type="sqli",
        severity="high",
        status="confirmed",
        poc_path="evidence/sqli.json",
    )
    memory.record_attack(
        "https://shop.example.test",
        tool="hunter_auto_sqli",
        payload_metadata={"family": "case-variation"},
        success=True,
        bypass_strategy="case-variation",
    )

    history = memory.query_target("shop.example.test")
    assert history["target"]["url"] == "https://shop.example.test"
    assert history["endpoints"][0]["injection_points"] == ["q"]
    assert history["vulnerabilities"][0]["type"] == "sqli"
    assert history["attack_history"][0]["success"] is True

    baseline = memory.snapshot("https://shop.example.test")
    memory.record_endpoint(
        "https://shop.example.test",
        "/admin",
        method="GET",
        parameters=[],
    )
    comparison = memory.compare_regression(
        "https://shop.example.test",
        baseline,
    )
    assert "/admin" in comparison["new"]["endpoints"]
    assert comparison["fixed"]["vulnerabilities"] == []
    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {
        "targets",
        "fingerprints",
        "endpoints",
        "vulnerabilities",
        "attack_history",
    } <= tables


def test_technique_memory_ranks_waf_success_and_retires_low_success(tmp_path):
    db_path = tmp_path / "targets.db"
    memory = TechniqueMemory(db_path)

    memory.register_technique(
        "case-variation",
        "waf_bypass",
        "Change keyword case while preserving syntax.",
    )
    memory.register_technique(
        "double-encoding",
        "waf_bypass",
        "Apply a second URL-encoding pass.",
    )
    for success in [True, True, True, False]:
        memory.record_attempt(
            target_url="https://target.example",
            technique_name="case-variation",
            waf_type="Cloudflare",
            success=success,
        )
    for _ in range(10):
        memory.record_attempt(
            target_url="https://target.example",
            technique_name="double-encoding",
            waf_type="Cloudflare",
            success=False,
        )

    ranked = memory.best_for_waf("Cloudflare")
    assert ranked[0]["name"] == "case-variation"
    assert ranked[0]["success_rate"] == pytest.approx(0.75)

    retired = memory.retire_low_success(threshold=0.10, minimum_attempts=5)
    assert "double-encoding" in retired


def test_pattern_engine_matches_parameters_responses_and_stack_strategy():
    engine = PatternEngine()

    parameter = engine.match_parameter("callback", context="GET /redirect")
    response = engine.match_response("Warning: mysql_fetch_array() expects parameter")
    strategy = engine.recommend_stack(
        {
            "server": "IIS",
            "framework": "ASP.NET",
            "database": "SQL Server",
        }
    )

    assert parameter["vulnerability_types"] == ["ssrf", "open_redirect"]
    assert response["vulnerability_type"] == "sqli"
    assert strategy["primary"]["name"] == "ASPX webshell + xp_cmdshell"
    assert strategy["confidence"] > 0.5


def test_fingerprint_database_has_seeded_catalog_and_detects_passive_observations():
    database = FingerprintDatabase()
    counts = database.counts()

    assert counts["waf"] >= 30
    assert counts["cms"] >= 50
    assert counts["framework"] >= 30

    result = database.detect(
        {
            "headers": {
                "server": "cloudflare",
                "cf-ray": "abc",
                "x-powered-by": "PHP/8.2",
            },
            "body": '<meta name="generator" content="WordPress 6.4">',
            "paths": ["/wp-admin/", "/wp-content/"],
        }
    )
    assert result["waf"]["name"] == "Cloudflare"
    assert result["cms"]["name"] == "WordPress"
    assert result["confidence"] > 0.7



def test_fingerprint_database_rejects_generic_path_only_product_match():
    result = FingerprintDatabase().detect(
        {
            "url": "https://generic.example.test/login",
            "headers": {"Content-Type": "text/html"},
            "body": "<title>Sign in</title>",
            "paths": ["/login"],
        }
    )

    assert result["cms"] is None
    assert result["framework"] is None


def test_memory_mcp_tools_record_query_recommend_detect_and_stats(tmp_path):
    mcp_server._reset_memory_store(tmp_path / "targets.db")

    recorded = json.loads(
        asyncio.run(
            mcp_server.hunter_memory_record(
                "attack",
                {
                    "target_url": "https://api.example.test",
                    "tool": "hunter_auto_sqli",
                    "technique": "case-variation",
                    "waf_type": "Cloudflare",
                    "success": True,
                    "payload_metadata": {"family": "case-variation"},
                },
            )
        )
    )
    assert recorded["status"] == "ok"

    queried = json.loads(
        asyncio.run(
            mcp_server.hunter_memory_query(
                "target",
                "api.example.test",
            )
        )
    )
    assert queried["status"] == "ok"

    recommended = json.loads(
        asyncio.run(
            mcp_server.hunter_memory_recommend(
                "https://api.example.test",
            )
        )
    )
    assert recommended["status"] == "ok"
    assert "recommendations" in recommended["data"]

    detected = json.loads(
        asyncio.run(
            mcp_server.hunter_fingerprint_detect(
                "https://api.example.test",
                {
                    "headers": {"server": "cloudflare", "cf-ray": "abc"},
                    "body": "",
                    "paths": [],
                },
            )
        )
    )
    assert detected["status"] == "ok"
    assert detected["data"]["waf"]["name"] == "Cloudflare"

    stats = json.loads(asyncio.run(mcp_server.hunter_memory_stats()))
    assert stats["status"] == "ok"
    assert stats["data"]["database_path"].endswith("targets.db")


def test_memory_recommend_reuses_success_from_similar_target(tmp_path):
    target_memory, _ = mcp_server._reset_memory_store(tmp_path / "targets.db")
    target_memory.record_target(
        "https://first.example.test",
        fingerprints={"server": "nginx", "framework": "Express"},
    )
    target_memory.record_attack(
        "https://first.example.test",
        tool="hunter_auto_sqli",
        payload_metadata={"family": "json-operator"},
        success=True,
        bypass_strategy="json-operator",
    )
    target_memory.record_target(
        "https://second.example.test",
        fingerprints={"server": "nginx", "framework": "Express"},
    )

    recommendation = json.loads(
        asyncio.run(
            mcp_server.hunter_memory_recommend(
                "https://second.example.test",
            )
        )
    )

    similar = [
        item
        for item in recommendation["data"]["recommendations"]
        if item["kind"] == "similar-target"
    ]
    assert similar[0]["name"] == "json-operator"
