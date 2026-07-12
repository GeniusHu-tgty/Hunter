from pathlib import Path
import asyncio
import json
import urllib.parse

import pytest

from core.js_analysis.bundle_unpacker import unpack_bundle
from core.js_analysis.deobfuscator import deobfuscate
from core.js_analysis.api_extractor import extract_api
from core.js_analysis.signature_extractor import extract_signature
import mcp_server


def test_vite_esm_bundle_splits_top_level_modules():
    source = """import { api } from './api.js';
export const page = api('/users');
export default page;
"""
    result = unpack_bundle(source, source_name="assets/index.js")
    assert result["bundler"] == "vite"
    assert len(result["modules"]) >= 2
    assert any("./api.js" in module["path"] for module in result["modules"])
    assert any(edge["to"] == "./api.js" for edge in result["edges"])


def test_rollup_bundle_splits_logical_exports():
    source = "/*! Rollup */\nconst one = 1;\nexport { one };\nconst two = 2;\nexport { two };"
    result = unpack_bundle(source, source_name="bundle.js")
    assert result["bundler"] == "rollup"
    assert len(result["modules"]) >= 2
    assert result["logical_modules"] is True


def test_deobfuscator_decodes_base64_and_reports_variable_rename():
    source = "var _0xabc = ['aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20=', 'token']; fetch(_0xabc[0]); var _0xreq = new XMLHttpRequest(); _0xreq.send(data);"
    result = deobfuscate(source)
    assert "https://api.example.com" in result["code"]
    assert result["transformations"]["variables_renamed"] >= 1
    assert result["rename_map"]


def test_api_extractor_finds_next_routes_and_router_metadata():
    source = """const router = createBrowserRouter([{path: '/dashboard'}, {path: '/users/:id'}]);
const api = '/api/users/[id]';
export async function GET() { return fetch(api); }
"""
    result = extract_api(source, source_name="app/api/users/[id]/route.js")
    paths = {item["path"] for item in result["routes"]}
    assert "/dashboard" in paths
    assert "/users/:id" in paths
    assert any(item.get("framework") == "next" for item in result["routes"])


def test_signature_refuses_unresolved_aes_replay():
    result = extract_signature("function sign(data) { return AES.encrypt(data, key); }", parameter_name="sign")
    assert result["algorithm"] == "aes"
    assert result["replay_status"] == "unavailable"
    assert result["replay_code"] is None
    assert any(item["type"] == "replay_blocked" for item in result["unresolved"])


def test_full_analysis_feeds_deobfuscated_code_to_api_extractor():
    source = "var _0xabc=['/api/private']; function _0xdec(i){return _0xabc[i];} fetch(_0xdec(0));"
    result = json.loads(asyncio.run(mcp_server.hunter_js_full_analysis(source)))
    assert result["status"] == "ok"
    assert result["data"]["api"]["endpoints"][0]["url"] == "/api/private"
    assert result["data"]["pipeline"]["deobfuscated_sources"] >= 1


def test_dynamic_observation_confirms_added_signature_parameter():
    source = "function build(p){ return md5(Object.keys(p).sort().join('&')); }"
    result = extract_signature(source, observations=[{"added_parameters": {"signature": "abc"}}])
    assert result["parameter_name"] == "signature"
    assert any(item["type"] == "signature_parameter" for item in result["confirmed"])


def test_vite_map_deps_are_exposed_in_module_tree():
    source = """const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/a.js","assets/b.js"])))=>i.map(i=>d[i]);
export const load = () => import("./feature.js");
"""
    result = unpack_bundle(source, source_name="assets/index.js")
    assert result["bundler"] == "vite"
    assert result["vite_dependencies"] == ["assets/a.js", "assets/b.js"]


def test_html_inline_script_is_analyzed(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "_fetch_js_analysis_url",
        lambda url, **kwargs: ("text/html", "<script>fetch('/api/inline')</script>", url),
    )
    result = json.loads(asyncio.run(mcp_server.hunter_js_extract_api("https://inline.test/")))
    assert result["status"] == "ok"
    assert result["data"]["endpoints"][0]["url"] == "/api/inline"


def test_mcp_signature_accepts_dynamic_observations():
    result = json.loads(asyncio.run(mcp_server.hunter_js_extract_signature(
        "function build(p){return md5(Object.keys(p).sort().join('&'));}",
        observations=[{"added_parameters": {"signature": "abc"}}],
    )))
    assert result["status"] == "ok"
    assert result["data"]["parameter_name"] == "signature"
    assert result["data"]["analysis_mode"] == "static+observed"


def test_nested_signature_operations_are_semantically_ordered():
    result = extract_signature("function sign(data){ return base64(AES.encrypt(md5(data), key)); }", parameter_name="sign")
    assert result["operations"] == ["md5", "aes", "base64"]
    assert result["replay_status"] == "unavailable"


def test_hardcoded_literal_salt_is_traced_into_replay():
    result = extract_signature(
        "function sign(p){ return md5(Object.keys(p).sort().join('&') + 'fixed-salt'); }",
        parameter_name="sign",
    )
    assert {"source": "hardcoded", "value": "fixed-salt"} in result["key_sources"]
    assert result["replay_status"] == "signing-scaffold"
    assert "fixed-salt" in result["replay_code"]


@pytest.mark.parametrize(
    ("placement", "transport_fragment"),
    [
        ("query", "query.extend((str(key), str(value)) for key, value in signed_params.items())"),
        ("json", "json.dumps(signed_params"),
        ("body", "urllib.parse.urlencode(signed_params).encode('utf-8')"),
        ("header", "headers.update({str(key): str(value) for key, value in signed_params.items()})"),
    ],
)
def test_replay_transport_requires_and_preserves_observed_request_context(
    placement,
    transport_fragment,
):
    request_context = {
        "method": "PATCH",
        "url": "https://api.example.test/v1/items?existing=1",
        "headers": {
            "Authorization": "Bearer observed-token",
            "X-Observed": "yes",
        },
        "placement": placement,
    }
    result = extract_signature(
        "function sign(p){ return md5(Object.keys(p).sort().join('&') + 'fixed-salt'); }",
        parameter_name="sign",
        target_url="https://ignored.example.test/",
        observations=[{"request_context": request_context}],
    )

    assert result["replay_status"] == "transport-replay"
    assert result["request_context"] == request_context
    assert "def send(params):" in result["replay_code"]
    assert "REQUEST_METHOD = 'PATCH'" in result["replay_code"]
    assert "REQUEST_URL = 'https://api.example.test/v1/items?existing=1'" in result["replay_code"]
    assert (
        "REQUEST_HEADERS = {'Authorization': 'Bearer observed-token', 'X-Observed': 'yes'}"
        in result["replay_code"]
    )
    assert transport_fragment in result["replay_code"]

    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return b"ok"

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

    namespace = {}
    exec(compile(result["replay_code"], "<generated-replay>", "exec"), namespace)
    namespace["urllib"].request.build_opener = lambda *handlers: Opener()

    assert namespace["send"]({"alpha": "one"}) == "ok"
    request = captured["request"]
    assert request.method == "PATCH"
    assert request.get_header("Authorization") == "Bearer observed-token"
    assert request.get_header("X-observed") == "yes"
    assert captured["timeout"] == 15

    if placement == "query":
        parsed = urllib.parse.urlsplit(request.full_url)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        assert query["existing"] == "1"
        assert query["alpha"] == "one"
        assert "sign" in query
        assert request.data is None
    elif placement == "json":
        assert request.full_url == request_context["url"]
        assert json.loads(request.data) == {
            "alpha": "one",
            "sign": namespace["calculate_signature"]({"alpha": "one"}),
        }
    elif placement == "body":
        assert request.full_url == request_context["url"]
        assert dict(urllib.parse.parse_qsl(request.data.decode("utf-8"))) == {
            "alpha": "one",
            "sign": namespace["calculate_signature"]({"alpha": "one"}),
        }
    else:
        assert request.full_url == request_context["url"]
        assert request.get_header("Alpha") == "one"
        assert request.get_header("Sign") == namespace["calculate_signature"]({"alpha": "one"})
        assert request.data is None


def test_websocket_message_formats_are_extracted():
    result = extract_api("const ws=new WebSocket('wss://example.test/ws'); ws.send(JSON.stringify({type:'ping', token})); io('/chat').emit('join',{room});")
    formats = [item for socket in result["websockets"] for item in socket["message_formats"]]
    assert any(item.get("kind") == "json" and "type" in item["fields"] for item in formats)
    assert any(item.get("event") == "join" for item in formats)


def test_signature_mcp_emits_jshook_handoff_plan():
    result = json.loads(asyncio.run(mcp_server.hunter_js_extract_signature(
        "function sign(p){return md5(p + 'salt');}",
        "sign",
    )))
    plan = result["data"]["dynamic_hook_plan"]
    assert plan["server"] == "jshook"
    assert {"fetch", "XMLHttpRequest.send", "axios"} <= set(plan["hooks"])
