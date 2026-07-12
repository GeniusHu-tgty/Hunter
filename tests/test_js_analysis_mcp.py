import asyncio
import inspect
import json
from pathlib import Path

import mcp_server
import pytest


JS_TOOLS = {
    "hunter_js_unpack",
    "hunter_js_deobfuscate",
    "hunter_js_extract_api",
    "hunter_js_extract_signature",
    "hunter_js_full_analysis",
}


def run(tool, *args, **kwargs):
    return json.loads(asyncio.run(tool(*args, **kwargs)))


def test_js_tools_registered_and_capability_declared():
    registered = {
        name for name, value in vars(mcp_server).items()
        if name.startswith("hunter_") and callable(value)
    }
    assert JS_TOOLS <= registered
    capabilities = run(mcp_server.hunter_capabilities)
    assert JS_TOOLS <= set(capabilities["tools"])
    health = run(mcp_server.hunter_healthcheck)
    assert JS_TOOLS <= set(health["mcp_tools"]["required"])
    assert not (JS_TOOLS & set(health["mcp_tools"]["missing"]))


def test_js_deobfuscate_accepts_inline_code():
    result = run(
        mcp_server.hunter_js_deobfuscate,
        "var _0xabc=['hello']; function _0xdec(i){return _0xabc[i];} use(_0xdec(0));",
    )
    assert result["status"] == "ok"
    assert "hello" in result["data"]["code_preview"]
    assert result["evidence"]["input"]["kind"] == "code"


def test_js_unpack_accepts_local_path(tmp_path):
    bundle = tmp_path / "app.js"
    bundle.write_text(
        "var __webpack_modules__={1:function(module){module.exports='ok';}};"
        "function __webpack_require__(id){return __webpack_modules__[id];}",
        encoding="utf-8",
    )
    result = run(mcp_server.hunter_js_unpack, str(bundle))
    assert result["status"] == "ok"
    assert result["data"]["bundler"] == "webpack"
    assert Path(result["evidence"]["artifact_dir"]).is_dir()


def test_js_extract_api_fetches_html_scripts(monkeypatch):
    pages = {
        "https://example.test/": ("text/html", '<script src="/assets/app.js"></script>'),
        "https://example.test/assets/app.js": ("application/javascript", "fetch('/api/users')"),
    }
    monkeypatch.setattr(mcp_server, "_fetch_js_analysis_url", lambda url, **kwargs: (*pages[url], url))
    result = run(mcp_server.hunter_js_extract_api, "https://example.test/")
    assert result["status"] == "ok"
    assert result["data"]["endpoints"][0]["url"] == "/api/users"
    assert result["evidence"]["input"]["script_count"] == 1


def test_js_signature_writes_replay_script(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "JS_REPLAY_DIR", tmp_path)
    result = run(
        mcp_server.hunter_js_extract_signature,
        "function sign(p){return md5(Object.keys(p).sort().join('&') + 'salt');}",
        "sign",
    )
    assert result["status"] == "ok"
    replay = Path(result["evidence"]["replay_script"])
    assert replay.is_file()
    assert replay.parent == tmp_path


def test_js_tool_errors_use_envelope():
    result = run(mcp_server.hunter_js_unpack, "C:/definitely/missing/app.js")
    assert result["status"] == "error"
    assert result["tool"] == "hunter_js_unpack"
    assert result["data"] == {}


def test_all_js_tools_expose_allow_private_parameter():
    for name in JS_TOOLS:
        assert "allow_private" in inspect.signature(getattr(mcp_server, name)).parameters


def test_private_url_is_blocked_by_default_and_explicitly_allowed(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "_fetch_js_analysis_url",
        lambda url, **kwargs: ("application/javascript", "fetch('/api/private')", url),
    )

    blocked = run(mcp_server.hunter_js_extract_api, "http://127.0.0.1/app.js")
    monkeypatch.setenv("HUNTER_ALLOW_PRIVATE_JS_ANALYSIS", "1")
    allowed = run(
        mcp_server.hunter_js_extract_api,
        "http://127.0.0.1/app.js",
        allow_private=True,
    )

    assert blocked["status"] == "error"
    assert "blocked address" in blocked["error"]
    assert allowed["status"] == "ok"
    assert allowed["data"]["endpoints"][0]["url"] == "/api/private"


def test_redirect_handler_revalidates_destination():
    handler = mcp_server._JSAnalysisRedirectHandler(allow_private=False)

    with pytest.raises(ValueError, match="blocked address"):
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "http://169.254.169.254/latest/meta-data",
        )


def test_html_rejects_more_than_32_scripts(monkeypatch):
    html = "".join(f'<script src="/assets/{index}.js"></script>' for index in range(33))

    def fake_fetch(url, **kwargs):
        if url == "https://example.test/":
            return "text/html", html, url
        return "application/javascript", "void 0", url

    monkeypatch.setattr(mcp_server, "_fetch_js_analysis_url", fake_fetch)

    with pytest.raises(ValueError, match="32"):
        mcp_server._load_js_analysis_input("https://example.test/")


def test_html_enforces_cumulative_10mb_limit(monkeypatch):
    html = '<script src="/one.js"></script><script src="/two.js"></script>'
    raw_chunk_size = mcp_server.JS_ANALYSIS_MAX_BYTES // 2 + 1

    def fake_fetch(url, **kwargs):
        if url == "https://example.test/":
            return "text/html", html, url, len(html.encode("utf-8"))
        return "application/javascript", "void 0", url, raw_chunk_size

    monkeypatch.setattr(mcp_server, "_fetch_js_analysis_url", fake_fetch)

    with pytest.raises(ValueError, match="cumulative"):
        mcp_server._load_js_analysis_input("https://example.test/")
