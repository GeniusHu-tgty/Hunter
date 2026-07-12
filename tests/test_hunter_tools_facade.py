
import pytest

from core.hunter_tools_facade import HunterToolsFacade


@pytest.fixture()
def facade():
    return HunterToolsFacade()


def test_kb_list_includes_markdown_and_payload_yaml(facade):
    result = facade.kb_list()
    assert result["status"] == "ok"
    assert result["tool"] == "hunter_kb_list"
    assert result["data"]["total_markdown"] >= 40
    assert result["data"]["total_payload_yaml"] >= 8
    paths = {item["path"] for item in result["data"]["markdown_files"]}
    assert "jwt/jwt-attack-techniques.md" in paths
    assert "ssrf/ssrf-techniques.md" in paths


def test_kb_search_returns_ranked_snippets_and_payload_hits(facade):
    result = facade.kb_search("jwt alg none weak signing key", limit=5)
    assert result["status"] == "ok"
    hits = result["data"]["results"]
    assert hits
    assert hits[0]["score"] > 0
    assert any("jwt" in hit["path"].lower() for hit in hits)
    assert any(hit["snippets"] for hit in hits)
    assert result["evidence"]["searched_files"] >= result["data"]["returned"]


def test_kb_read_reads_exact_file_and_blocks_traversal(facade):
    result = facade.kb_read("jwt/jwt-attack-techniques.md", max_chars=500)
    assert result["status"] == "ok"
    assert result["data"]["path"] == "jwt/jwt-attack-techniques.md"
    assert "JWT Attack Techniques" in result["data"]["content"]
    assert result["data"]["truncated"] in {True, False}

    blocked = facade.kb_read("../SKILL.md")
    assert blocked["status"] == "error"
    assert blocked["error_type"] == "ValueError"


def test_burp_bridge_repeater_and_proxy_search_are_action_plans(facade):
    repeater = facade.burp_repeater(
        url="https://example.test/api/user?id=1",
        method="POST",
        headers={"Authorization": "Bearer REDACTED"},
        body='{"id":1}',
        tab_name="Hunter IDOR proof",
        http2=True,
    )
    assert repeater["status"] == "ok"
    assert repeater["data"]["action"]["tool"] == "create_repeater_tab_http2"
    assert repeater["data"]["action"]["params"]["pseudoHeaders"][":method"] == "POST"
    assert "execute this plan" in " ".join(repeater["next_actions"]).lower()

    proxy = facade.burp_proxy_search(regex="Authorization|/api/", count=25, offset=5)
    assert proxy["status"] == "ok"
    assert proxy["data"]["action"]["tool"] == "get_proxy_http_history_regex"
    assert proxy["data"]["action"]["params"]["regex"] == "Authorization|/api/"


def test_burp_collaborator_workflows_use_existing_bridge(facade):
    ssrf = facade.burp_collaborator_workflow(
        workflow="blind_ssrf",
        url="https://example.test/fetch?url=x",
        param="url",
        method="GET",
    )
    assert ssrf["status"] == "ok"
    assert ssrf["data"]["workflow"] == "blind_ssrf"
    assert "step1_generate_collaborator" in ssrf["data"]["plan"]

    bad = facade.burp_collaborator_workflow(workflow="not-a-workflow", url="https://example.test")
    assert bad["status"] == "error"


def test_kb_recommend_combines_kb_payload_and_burp_next_steps(facade):
    result = facade.kb_recommend(
        signals=["jwt", "idor", "cors"],
        finding="API exposes userId and Authorization bearer token with CORS",
        target="https://example.test/api/user/1",
        limit=6,
    )
    assert result["status"] == "ok"
    data = result["data"]
    tools = [item["tool"] for item in data["tool_recommendations"]]
    assert "hunter_auto_idor" in tools
    assert "hunter_auto_jwt" in tools
    assert any(hit["path"].endswith(".md") for hit in data["kb_hits"])
    assert data["payload_hits"]
    assert any(action["tool"].startswith("hunter_burp") for action in data["burp_actions"])


def test_facade_capabilities_and_health_include_reverse_lab_style(facade):
    health = facade.health()
    assert health["status"] == "ok"
    assert health["data"]["tool_style"] == "reverse_lab_tools-compatible"
    assert health["data"]["kb"]["total_markdown"] >= 40

    caps = facade.capabilities()
    assert caps["status"] == "ok"
    assert caps["data"]["server_name"] == "hunter_tools"
    assert "hunter_kb_search" in caps["data"]["tools"]
    assert caps["data"]["tools"]["hunter_burp_repeater"]["category"] == "burp-bridge"



def test_generic_burp_bridge_filters_irrelevant_wrapper_kwargs(facade):
    repeater = facade.burp_bridge(
        "repeater",
        url="https://example.test/path",
        method="GET",
        headers={},
        body="",
        http2=True,
        regex=None,
        count=50,
        offset=0,
        severity_filter="",
        tab_name="Generic repeater",
    )
    assert repeater["status"] == "ok"
    assert repeater["data"]["action"]["tool"] == "create_repeater_tab_http2"

    proxy = facade.burp_bridge(
        "proxy_search",
        url=None,
        method="GET",
        headers={},
        body="",
        http2=True,
        regex="Authorization",
        count=10,
        offset=0,
        severity_filter="",
        tab_name="",
    )
    assert proxy["status"] == "ok"
    assert proxy["data"]["action"]["tool"] == "get_proxy_http_history_regex"
from core.hunter_tools_facade import HunterToolsFacade


def test_facade_exposes_workflow_kernel_capabilities():
    result = HunterToolsFacade().capabilities()
    tools = result["data"]["tools"]
    assert "hunter_workflow_create" in tools
    assert "hunter_workflow_plan" in tools
    assert "hunter_backend_status" in tools
    assert result["data"]["workflow_kernel"]["schema_version"] == "2.0"
    assert {"pe", "apk", "javascript", "mixed"} <= set(result["data"]["workflow_kernel"]["lanes"])
