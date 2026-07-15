import asyncio
import json

import mcp_server


def test_port_scan_timeout_uses_passive_fallback(monkeypatch):
    async def timed_out(*args, **kwargs):
        return {"status": "timeout", "target": "target.test"}

    async def passive(*args, **kwargs):
        return {
            "status": "success",
            "scan_type": "passive_scan",
            "open_ports": [443],
            "count": 1,
            "timeline": [{"event": "port_scan_timeout"}],
        }

    monkeypatch.setattr(mcp_server, "_execute_agent_async", timed_out)
    monkeypatch.setattr(mcp_server, "_passive_port_scan", passive)

    result = json.loads(asyncio.run(mcp_server.hunter_port_scan("target.test")))

    assert result["scan_type"] == "passive_scan"
    assert result["open_ports"] == [443]
    assert result["timeline"][0]["event"] == "port_scan_timeout"


def test_fast_recon_collects_edu_spring_and_basic_paths(monkeypatch):
    class Client:
        def stealth_request(self, method, url, options=None):
            if url.endswith("/favicon.ico"):
                return {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {"Content-Type": "image/x-icon"},
                    "body": "icon",
                }
            if url.endswith("/actuator"):
                return {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"_links":{"health":{}}}',
                }
            if url.endswith("/login"):
                return {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {"Set-Cookie": "JSESSIONID=abc"},
                    "body": "<title>CAS Login</title>",
                }
            return {
                "status": "blocked",
                "status_code": 403,
                "headers": {"Server": "nginx"},
                "body": "",
            }

    monkeypatch.setattr(mcp_server, "_get_stealth_client", lambda: Client())
    monkeypatch.setattr(mcp_server, "COMMON_WEB_PORTS", (443,))

    result = json.loads(
        asyncio.run(mcp_server.hunter_fast_recon("https://target.test"))
    )

    assert result["scan_type"] == "passive_scan"
    assert result["open_ports"] == [443]
    assert result["basic_paths"]["/actuator"] == 200
    assert result["basic_paths"]["/login"] == 200
    assert result["favicon"]["hash"]
    assert "Spring Boot" in result["technology_stack"]
    assert "CAS" in result["technology_stack"]



def test_passive_port_scan_respects_explicit_target_port(monkeypatch):
    requested = []

    class Client:
        def stealth_request(self, method, url, options=None):
            requested.append(url)
            return {
                "status": "ok",
                "status_code": 200,
                "headers": {"Server": "fixture"},
                "body": "ok",
            }

    monkeypatch.setattr(mcp_server, "_get_stealth_client", lambda: Client())
    monkeypatch.setattr(mcp_server, "COMMON_WEB_PORTS", (80, 443, 8080))

    result = asyncio.run(
        mcp_server._passive_port_scan("https://target.test:9443", "test")
    )

    assert requested == ["https://target.test:9443/"]
    assert result["open_ports"] == [9443]
    assert result["probes"][0]["port"] == 9443


def test_fast_recon_ignores_404_probe_paths_for_fingerprints(monkeypatch):
    class Client:
        def stealth_request(self, method, url, options=None):
            if url.rstrip("/") == "http://target.test:8765":
                return {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": (
                        '<meta name="generator" content="WordPress 6.5">'
                        '<form action="/login"><input name="username"></form>'
                    ),
                }
            return {
                "status": "ok",
                "status_code": 404,
                "headers": {"Content-Type": "text/html"},
                "body": "not found",
            }

    async def passive(*args, **kwargs):
        return {
            "status": "success",
            "open_ports": [8765],
            "probes": [],
            "timeline": [],
        }

    monkeypatch.setattr(mcp_server, "_get_stealth_client", lambda: Client())
    monkeypatch.setattr(mcp_server, "_passive_port_scan", passive)

    result = asyncio.run(mcp_server._fast_recon_impl("http://target.test:8765"))

    assert "WordPress" in result["technology_stack"]
    assert "Jenkins" not in result["technology_stack"]
    assert "Spring Boot" not in result["technology_stack"]
    assert result["fingerprints"]["cms"]["name"] == "WordPress"
    assert result["fingerprints"]["framework"] is None
    assert result["favicon"]["hash"] == ""


def test_tech_detect_timeout_uses_fast_recon(monkeypatch):
    async def timed_out(*args, **kwargs):
        return {"status": "timeout", "target": "target.test"}

    async def fast(target):
        return {
            "target": "https://target.test",
            "technology_stack": ["CAS", "Spring Boot"],
            "fingerprints": {"edu": {"name": "CAS"}},
            "open_ports": [443],
        }

    monkeypatch.setattr(mcp_server, "_execute_agent_async", timed_out)
    monkeypatch.setattr(mcp_server, "_fast_recon_impl", fast)

    result = json.loads(asyncio.run(mcp_server.hunter_tech_detect("target.test")))

    assert result["scan_type"] == "passive_scan"
    assert result["technology_stack"] == ["CAS", "Spring Boot"]
    assert result["timeline"][0]["event"] == "tech_detect_timeout"
