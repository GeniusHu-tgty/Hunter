import asyncio
import json

import mcp_server

from core.memory.fingerprint_database import FingerprintDatabase
from core.memory.pattern_engine import PatternEngine
from core.memory.target_memory import TargetMemory
from core.memory.technique_memory import TechniqueMemory
from scripts import seed_memory


EXPECTED_EDU_SYSTEMS = {
    "正方教务管理系统",
    "强智教务管理系统",
    "青果教务管理系统",
    "金智 CAS",
    "艾卡 CAS",
    "正方统一身份认证",
    "博达 CMS/VSB Portal",
    "超星智慧门户",
}


def test_edu_seed_catalog_has_required_products_and_three_features_each():
    records = {
        record["name"]: record
        for record in seed_memory.EDU_SYSTEM_SEEDS
    }

    assert EXPECTED_EDU_SYSTEMS <= records.keys()
    for name in EXPECTED_EDU_SYSTEMS:
        record = records[name]
        feature_count = sum(
            len(record[key])
            for key in (
                "headers",
                "absent_headers",
                "cookies",
                "body",
                "paths",
                "hosts",
            )
        )
        assert feature_count >= 3
        assert record["minimum_evidence"] >= 2


def test_edu_fingerprints_detect_each_supported_system():
    scenarios = (
        (
            "正方教务管理系统",
            {
                "headers": {"Set-Cookie": "JSESSIONID=abc; Path=/"},
                "body": "<title>正方教务管理系统</title>",
                "paths": ["/jwglxt/xtgl/login_slogin.html"],
            },
        ),
        (
            "强智教务管理系统",
            {
                "cookies": {"JSESSIONID": "abc"},
                "body": "<footer>强智科技</footer>",
                "paths": ["/jsxsd/framework/xsMain.jsp"],
            },
        ),
        (
            "青果教务管理系统",
            {
                "headers": {"X-Powered-By": "KINGOSOFT"},
                "body": "<title>青果教务管理系统</title>",
                "paths": ["/kingosoft/login"],
            },
        ),
        (
            "金智 CAS",
            {
                "headers": {"Content-Type": "text/html"},
                "body": (
                    "<title>统一身份认证平台</title>"
                    '<input type="hidden" name="service">'
                ),
                "paths": ["/lyuapServer/login"],
            },
        ),
        (
            "艾卡 CAS",
            {
                "headers": {"X-CAS-Engine": "Apereo CAS"},
                "cookies": {"TGC": "opaque"},
                "paths": ["/authserver/login"],
            },
        ),
        (
            "正方统一身份认证",
            {
                "body": (
                    "<title>正方软件统一身份认证</title>"
                    '<script src="/zfcas/app.js"></script>'
                ),
                "paths": ["/zfcas/login"],
            },
        ),
        (
            "博达 CMS/VSB Portal",
            {
                "headers": {"X-Protected-By": "WebberRASP"},
                "body": "<footer>Announced by Visual SiteBuilder</footer>",
                "paths": ["/system/resource/js/vsb.js"],
            },
        ),
        (
            "超星智慧门户",
            {
                "url": "https://lib.example.edu.cn/index.html",
                "headers": {
                    "Location": "https://passport2.chaoxing.com/login"
                },
                "body": '<script src="https://static.chaoxing.com/app.js"></script>',
            },
        ),
    )
    database = FingerprintDatabase()

    for expected_name, observations in scenarios:
        result = database.detect(observations)
        assert result["edu"]["name"] == expected_name
        assert len(result["edu"]["evidence"]) >= 2


def test_edu_fingerprints_do_not_identify_a_product_from_jsessionid_alone():
    result = FingerprintDatabase().detect(
        {"headers": {"Set-Cookie": "JSESSIONID=abc; Path=/"}}
    )

    assert result["edu"] is None


def test_fingerprint_mcp_uses_target_url_for_edu_domain_evidence():
    result = json.loads(
        asyncio.run(
            mcp_server.hunter_fingerprint_detect(
                "https://lib.example.edu.cn/index.html",
                {
                    "body": (
                        '<script src="https://static.chaoxing.com/app.js">'
                        "</script>"
                    ),
                },
            )
        )
    )

    assert result["data"]["edu"]["name"] == "超星智慧门户"


def test_edu_stack_associations_have_aliases_and_are_recommended():
    assert len(seed_memory.EDU_STACK_SEEDS) >= 20
    patterns = {
        record["tech_stack_pattern"]: record
        for record in seed_memory.EDU_STACK_SEEDS
    }
    assert {
        "正方教务 + Java + Oracle",
        "金智 CAS + Java",
        "超星智慧门户",
    } <= patterns.keys()
    for record in seed_memory.EDU_STACK_SEEDS:
        assert record["stack_pattern"] == record["tech_stack_pattern"]
        assert record["common_issues"]
        assert record["assessment_focus"]

    strategy = PatternEngine().recommend_stack(
        {
            "edu_system": "正方教务管理系统",
            "runtime": "Java",
            "database": "Oracle",
        }
    )
    assert strategy["primary"]["name"] == "正方教务 + Java + Oracle"


def test_seed_reset_persists_edu_targets_and_stack_assessment_metadata(tmp_path):
    database_path = tmp_path / "edu-seeded.db"

    result = seed_memory.populate_memory(database_path, reset=True)

    assert result["counts"]["edu"] == len(seed_memory.EDU_SYSTEM_SEEDS)
    target_memory = TargetMemory(database_path)
    target = target_memory.query_target(
        seed_memory._seed_target_url("edu", "正方教务管理系统")
    )
    assert target["fingerprints"]["edu"] == "正方教务管理系统"

    technique_memory = TechniqueMemory(database_path)
    attempts = technique_memory.attempts(
        technique_name="正方教务 + Java + Oracle",
        limit=10,
    )
    metadata = attempts[0]["metadata"]
    assert metadata["tech_stack_pattern"] == "正方教务 + Java + Oracle"
    assert "SQL 注入" in metadata["common_issues"]
    assert metadata["assessment_focus"]
