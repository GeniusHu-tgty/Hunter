import asyncio
import inspect
import json

import mcp_server


AUTO_TOOL_NAMES = [
    "hunter_auto_sqli",
    "hunter_auto_xss",
    "hunter_auto_ssrf",
    "hunter_auto_xxe",
    "hunter_auto_csrf",
    "hunter_auto_graphql",
    "hunter_auto_websocket",
    "hunter_auto_ssti",
    "hunter_auto_cmd",
    "hunter_auto_idor",
    "hunter_auto_race",
    "hunter_auto_cors",
    "hunter_auto_jwt",
    "hunter_auto_access_control",
    "hunter_auto_pentest",
]


def run_async(coro):
    return asyncio.run(coro)


def test_all_auto_tools_expose_optional_session_id():
    for name in AUTO_TOOL_NAMES:
        parameter=inspect.signature(getattr(mcp_server,name)).parameters["session_id"]
        assert parameter.default is None
        assert str(parameter.annotation) in {
            "typing.Optional[str]",
            "str | None",
            "Optional[str]",
        }


def test_direct_auto_tools_forward_session_id_to_shared_adapter(monkeypatch):
    calls=[]

    async def fake_runner(
        tool_name,
        module,
        func,
        *args,
        session_id=None,
        timeout=120,
        **kwargs,
    ):
        calls.append((tool_name,session_id,module.__name__))
        return json.dumps({"status":"success","tool":tool_name})

    monkeypatch.setattr(mcp_server,"_safe_auto_json_tool",fake_runner,raising=False)

    invocations=[
        mcp_server.hunter_auto_sqli("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_xss("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_ssrf("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_xxe("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_csrf("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_graphql("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_websocket("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_ssti("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_cmd("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_idor("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_race("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_cors("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_jwt("https://t",session_id="stealth-1"),
        mcp_server.hunter_auto_access_control("https://t",session_id="stealth-1"),
    ]
    for invocation in invocations:
        run_async(invocation)

    assert [item[0] for item in calls]==AUTO_TOOL_NAMES[:-1]
    assert all(item[1]=="stealth-1" for item in calls)


def test_session_aware_auto_tool_uses_stealth_backed_session(monkeypatch):
    import core.auto_sqli as auto_sqli

    class Response:
        status_code=200
        text="authenticated"

    class DetectionSession:
        def __init__(self):
            self.calls=[]

        def get(self,url,**kwargs):
            self.calls.append((url,kwargs))
            return Response()

    detection_session=DetectionSession()

    class FakeStealthClient:
        def detection_session(self,session_id):
            assert session_id=="stealth-known"
            return detection_session

    def fake_impl(base_url,param="category",method="GET"):
        response=auto_sqli._get_session().get(base_url)
        return {"scanner":"sqli","body":response.text}

    monkeypatch.setattr(mcp_server,"_get_stealth_client",lambda:FakeStealthClient())
    monkeypatch.setattr(auto_sqli,"auto_sqli_impl",fake_impl)

    result=json.loads(run_async(
        mcp_server.hunter_auto_sqli(
            "https://t/admin",
            session_id="stealth-known",
        )
    ))
    assert result["body"]=="authenticated"
    assert detection_session.calls[0][0]=="https://t/admin"


def test_unknown_auto_tool_session_returns_clear_error(monkeypatch):
    class FakeStealthClient:
        def detection_session(self,session_id):
            raise LookupError(f"Stealth session '{session_id}' not found")

    monkeypatch.setattr(mcp_server,"_get_stealth_client",lambda:FakeStealthClient())
    result=json.loads(run_async(
        mcp_server.hunter_auto_sqli(
            "https://t/admin",
            session_id="stealth-missing",
        )
    ))
    assert result["status"]=="error"
    assert "stealth-missing" in result["error"]


def test_race_scanner_can_use_session_aware_http_path(monkeypatch):
    import core.auto_race as auto_race

    class Response:
        status_code=200
        text="<form action='/login'></form>"
        headers={}

    class DetectionSession:
        def __init__(self):
            self.headers={}
            self.calls=[]

        def get(self,url,**kwargs):
            self.calls.append(("GET",url,kwargs))
            return Response()

        def post(self,url,**kwargs):
            self.calls.append(("POST",url,kwargs))
            return Response()

    detection_session=DetectionSession()

    class FakeStealthClient:
        def detection_session(self,session_id):
            return detection_session

    monkeypatch.setattr(mcp_server,"_get_stealth_client",lambda:FakeStealthClient())
    monkeypatch.setattr(auto_race.time,"sleep",lambda _:None)

    result=json.loads(run_async(
        mcp_server.hunter_auto_race(
            "https://t/login",
            session_id="stealth-known",
        )
    ))
    assert result["status"]=="success"
    assert detection_session.calls
