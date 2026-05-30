# tests/test_knowledge.py
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.knowledge import KnowledgeGraph


def test_create_session():
    kg = KnowledgeGraph(target="10.10.90.2")
    assert kg.session["target"] == "10.10.90.2"
    assert kg.session["session_id"].startswith("sess_")
    assert kg.session["findings"] == []
    assert kg.session["attempts"] == []
    assert kg.session["shells"] == []


def test_add_finding():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(
        type="info_leak",
        severity="critical",
        title="API 无认证信息泄露",
        detail="/api/online_list 返回所有在线用户数据",
        evidence={"url": "http://10.10.90.2/api/online_list", "status": 200},
        tool="dir_enum"
    )
    assert len(kg.session["findings"]) == 1
    f = kg.session["findings"][0]
    assert f["type"] == "info_leak"
    assert f["severity"] == "critical"
    assert f["id"] == "f001"
    assert "timestamp" in f


def test_add_attempt():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_attempt(
        action="sqli_union",
        target="/login",
        payload="' UNION SELECT 1,2,3--",
        result="blocked by WAF",
        success=False,
        waf_rule="UNION keyword detection"
    )
    assert len(kg.session["attempts"]) == 1
    a = kg.session["attempts"][0]
    assert a["action"] == "sqli_union"
    assert a["success"] is False
    assert a["waf_rule"] == "UNION keyword detection"


def test_add_shell():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_shell(
        session_id="shell_001",
        type="reverse",
        info="bash on CentOS 6.8"
    )
    assert len(kg.session["shells"]) == 1
    s = kg.session["shells"][0]
    assert s["session_id"] == "shell_001"
    assert s["status"] == "active"


def test_summary():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="test1", detail="d", evidence={}, tool="t")
    kg.add_finding(type="sqli", severity="high", title="test2", detail="d", evidence={}, tool="t")
    kg.add_finding(type="xss", severity="low", title="test3", detail="d", evidence={}, tool="t")
    summary = kg.summary()
    assert summary["findings_count"] == 3
    assert summary["findings_summary"]["critical"] == 1
    assert summary["findings_summary"]["high"] == 1
    assert summary["findings_summary"]["low"] == 1


def test_query_findings():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="leak", detail="d", evidence={}, tool="t")
    kg.add_finding(type="sqli", severity="high", title="sqli", detail="d", evidence={}, tool="t")
    results = kg.query_findings(type="sqli")
    assert len(results) == 1
    assert results[0]["title"] == "sqli"


def test_save_and_load(tmp_path):
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="test", detail="d", evidence={}, tool="t")
    filepath = kg.save(str(tmp_path))
    assert os.path.exists(filepath)

    kg2 = KnowledgeGraph.load(filepath)
    assert kg2.session["target"] == "10.10.90.2"
    assert len(kg2.session["findings"]) == 1
    assert kg2.session["findings"][0]["title"] == "test"
