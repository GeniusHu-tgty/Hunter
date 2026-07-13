import json
import subprocess
import sys
from pathlib import Path

from core.memory.fingerprint_database import FingerprintDatabase
from core.memory.pattern_engine import PatternEngine
from core.memory.target_memory import TargetMemory
from core.memory.technique_memory import TechniqueMemory
from scripts import seed_memory


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_seed_collections_meet_minimum_counts_and_schema():
    assert len(seed_memory.CMS_SEEDS) >= 50
    assert len(seed_memory.EDU_SYSTEM_SEEDS) >= 8
    assert len(seed_memory.FRAMEWORK_SEEDS) >= 30
    assert len(seed_memory.STACK_SEEDS) >= 50
    assert len(seed_memory.PARAMETER_SEEDS) >= 30

    for item in seed_memory.CMS_SEEDS:
        assert item["name"]
        assert isinstance(item["paths"], list)
        assert isinstance(item["cookies"], list)
        assert isinstance(item["meta"], list)
        assert isinstance(item["headers"], list)
        assert item["category"]

    for item in seed_memory.EDU_SYSTEM_SEEDS:
        assert item["name"]
        assert item["category"]
        assert isinstance(item["headers"], list)
        assert isinstance(item["cookies"], list)
        assert isinstance(item["body"], list)
        assert isinstance(item["paths"], list)
        assert isinstance(item["hosts"], list)
        assert item["minimum_evidence"] >= 2

    for item in seed_memory.FRAMEWORK_SEEDS:
        assert item["name"]
        assert isinstance(item["headers"], list)
        assert isinstance(item["cookies"], list)
        assert isinstance(item["paths"], list)
        assert item["category"]

    for item in seed_memory.STACK_SEEDS:
        assert item["stack_pattern"]
        assert item["common_issues"]
        assert item["assessment_focus"]

    for item in seed_memory.PARAMETER_SEEDS:
        assert item["param_pattern"]
        assert item["related_issue_type"]
        assert 0.0 <= item["confidence"] <= 1.0


def test_fingerprint_database_loads_seeded_cookie_meta_and_header_features():
    database = FingerprintDatabase()

    result = database.detect(
        {
            "headers": {
                "X-Generator": "WordPress 6.5",
                "X-Powered-By": "PHP/8.2",
                "Set-Cookie": "wordpress_logged_in_abc=opaque; Path=/",
            },
            "body": '<meta name="generator" content="WordPress 6.5">',
            "paths": ["/wp-content/themes/example/style.css"],
        }
    )

    assert result["cms"]["name"] == "WordPress"
    assert result["cms"]["version"] == "6.5"
    sources = {item["source"] for item in result["cms"]["evidence"]}
    assert {"header", "cookie", "meta"} <= sources


def test_fingerprint_seed_boundaries_avoid_generic_false_positives():
    result = FingerprintDatabase().detect(
        {
            "headers": {
                "X-Powered-By": "PHP/8.2",
                "Set-Cookie": "session=abc; Path=/",
            },
            "body": "sanity check",
            "paths": [],
        }
    )

    names = {
        item["name"]
        for candidates in result["matches"].values()
        for item in candidates
    }
    assert not {"Laravel", "Falcon", "Backdrop CMS", "Sanity"} & names


def test_pattern_engine_loads_seeded_parameter_and_stack_patterns():
    engine = PatternEngine()

    parameter = engine.match_parameter("tenant_scope")
    assert "authorization_bypass" in parameter["vulnerability_types"]

    strategy = engine.recommend_stack(
        {
            "server": "Caddy",
            "framework": "Laravel",
            "database": "PostgreSQL",
        }
    )
    assert strategy["primary"]["name"] == "Caddy + Laravel + PostgreSQL"


def test_seed_cli_check_does_not_create_a_missing_database(tmp_path):
    database_path = tmp_path / "missing.db"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/seed_memory.py",
            "--check",
            "--database",
            str(database_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "missing" in completed.stdout.lower()
    assert not database_path.exists()


def test_seed_fill_uses_memory_apis_and_reset_is_repeatable(tmp_path):
    database_path = tmp_path / "seeded.db"

    first = seed_memory.populate_memory(database_path, reset=True)
    second = seed_memory.populate_memory(database_path, reset=True)

    assert first["counts"] == {
        "cms": len(seed_memory.CMS_SEEDS),
        "edu": len(seed_memory.EDU_SYSTEM_SEEDS),
        "frameworks": len(seed_memory.FRAMEWORK_SEEDS),
        "stack_patterns": len(seed_memory.STACK_SEEDS),
        "parameter_patterns": len(seed_memory.PARAMETER_SEEDS),
    }
    assert second["counts"] == first["counts"]

    target_stats = TargetMemory(database_path).stats()
    technique_stats = TechniqueMemory(database_path).stats()
    assert target_stats["targets"] == (
        len(seed_memory.CMS_SEEDS)
        + len(seed_memory.EDU_SYSTEM_SEEDS)
        + len(seed_memory.FRAMEWORK_SEEDS)
    )
    assert technique_stats["techniques"] == len(seed_memory.STACK_SEEDS) + len(
        seed_memory.PARAMETER_SEEDS
    )


def test_seed_attempts_are_queryable_by_inferred_waf_type(tmp_path):
    database_path = tmp_path / "waf-seeded.db"

    seed_memory.populate_memory(database_path, reset=True)

    memory = TechniqueMemory(database_path)
    attempts = memory.attempts(limit=200)
    by_technique = {item["technique_name"]: item for item in attempts}
    specifically_mapped = [
        item
        for item in attempts
        if item["waf_type"] not in {"*", "custom/unknown"}
    ]

    assert len(attempts) == len(seed_memory.STACK_SEEDS) + len(
        seed_memory.PARAMETER_SEEDS
    )
    assert all(item["waf_type"] != "*" for item in attempts)
    assert len(specifically_mapped) >= 40
    assert by_technique["Apache + PHP + MySQL"]["waf_type"] == "ModSecurity"
    assert (
        by_technique["IIS + ASP.NET + SQL Server"]["waf_type"]
        == "custom/unknown"
    )
    assert (
        by_technique["Nginx + Node.js + CouchDB"]["waf_type"]
        == "custom/unknown"
    )
    assert memory.best_for_waf("Alibaba Cloud WAF")


def test_seed_check_rejects_stale_wildcard_attempts(tmp_path):
    database_path = tmp_path / "stale-wildcard.db"
    seed_memory.populate_memory(database_path, reset=True)
    memory = TechniqueMemory(database_path)
    technique = "Apache + PHP + MySQL"
    memory.record_attempt(
        target_url=seed_memory._seed_technique_target_url(
            f"stack-{technique}"
        ),
        technique_name=technique,
        waf_type="*",
        success=True,
        metadata={"seed": True, "legacy": True},
    )

    result = seed_memory._check_database(database_path)

    assert result["status"] == "incomplete"
    assert technique in result["missing_techniques"]


def test_seed_fill_refreshes_stale_baseline_records(tmp_path):
    database_path = tmp_path / "stale.db"
    seed_memory.populate_memory(database_path, reset=True)
    target_url = "https://seed.hunter.local/cms/wordpress"
    memory = TargetMemory(database_path)
    memory.record_target(
        target_url,
        fingerprints={
            "cms": "WordPress",
            "paths": ["/stale"],
            "cookies": [],
            "meta": [],
            "headers": [],
        },
        technology_stack={"cms": "WordPress"},
    )

    seed_memory.populate_memory(database_path)

    assert memory.query_target(target_url)["fingerprints"]["paths"] == [
        "/wp-admin/",
        "/wp-content/",
    ]


def test_seed_cli_reports_per_category_statistics(tmp_path):
    database_path = tmp_path / "cli-seeded.db"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/seed_memory.py",
            "--reset",
            "--database",
            str(database_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    output = completed.stdout.lower()
    assert "cms:" in output
    assert "edu:" in output
    assert "frameworks:" in output
    assert "stack_patterns:" in output
    assert "parameter_patterns:" in output
    assert f"cms: {len(seed_memory.CMS_SEEDS)}" in output
    assert f"edu: {len(seed_memory.EDU_SYSTEM_SEEDS)}" in output
    assert json.loads(completed.stderr or "null") is None
