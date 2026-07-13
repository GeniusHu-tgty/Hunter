import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests as native_requests

from core.stealth import fingerprint_manager
from core.stealth.fingerprint_manager import FingerprintManager
from core.stealth import stealth_http_client
from core.stealth.stealth_http_client import StealthHTTPClient


ROOT = Path(__file__).resolve().parents[1]
FALLBACK_WARNING = (
    "curl_cffi not installed, falling back to requests "
    "(TLS fingerprint WILL be detected)"
)


def _probe_fresh_import(block_curl_cffi):
    script = """
import builtins
import json

real_import = builtins.__import__
block = __BLOCK__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if block and (name == "curl_cffi" or name.startswith("curl_cffi.")):
        raise ImportError("blocked curl_cffi for fallback test")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
from core.stealth import stealth_http_client
print(json.dumps({
    "curl_cffi_available": stealth_http_client.CURL_CFFI_AVAILABLE,
    "backend": stealth_http_client.requests.__name__,
}))
""".replace("__BLOCK__", "True" if block_curl_cffi else "False")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(completed.stdout.strip())


def test_import_prefers_curl_cffi_when_installed():
    pytest.importorskip("curl_cffi")

    result = _probe_fresh_import(block_curl_cffi=False)

    assert result == {
        "curl_cffi_available": True,
        "backend": "curl_cffi.requests",
    }


def test_import_falls_back_to_native_requests_when_curl_cffi_is_missing():
    result = _probe_fresh_import(block_curl_cffi=True)

    assert result == {
        "curl_cffi_available": False,
        "backend": "requests",
    }


def test_fingerprint_pool_exposes_curl_impersonation_metadata():
    CURL_IMPERSONATE_MAPPINGS = getattr(
        fingerprint_manager,
        "CURL_IMPERSONATE_MAPPINGS",
        {},
    )
    assert len(CURL_IMPERSONATE_MAPPINGS) >= 6
    assert CURL_IMPERSONATE_MAPPINGS[("Chrome", 110)] == "chrome110"
    assert CURL_IMPERSONATE_MAPPINGS[("Chrome", 120)] == "chrome120"
    assert CURL_IMPERSONATE_MAPPINGS[("Edge", 99)] == "edge99"
    assert CURL_IMPERSONATE_MAPPINGS[("Edge", 101)] == "edge101"
    assert CURL_IMPERSONATE_MAPPINGS[("Safari", 15)] == "safari15_3"
    assert CURL_IMPERSONATE_MAPPINGS[("Safari", 17)] == "safari17_0"

    manager = FingerprintManager(seed=7)
    pool = manager.fingerprints()

    assert all("impersonate" in fingerprint for fingerprint in pool)
    assert all(
        fingerprint["impersonate"] is None
        for fingerprint in pool
        if fingerprint["browser"] == "Firefox"
    )
    assert manager.choose(require_impersonate=True)["impersonate"]


@pytest.mark.parametrize(
    ("browser", "version", "expected"),
    [
        ("Chrome", 109, None),
        ("Chrome", 119, "chrome110"),
        ("Chrome", 129, "chrome120"),
        ("Edge", 100, "edge99"),
        ("Edge", 126, "edge101"),
        ("Safari", 16, "safari15_3"),
        ("Safari", 19, "safari17_0"),
        ("Firefox", 122, None),
    ],
)
def test_curl_impersonate_uses_nearest_supported_floor(
    browser,
    version,
    expected,
):
    assert fingerprint_manager.curl_impersonate_for(browser, version) == expected


def test_imported_browser_records_compatible_impersonation():
    manager = FingerprintManager()

    chrome = manager.import_browser(
        {"userAgent": "Mozilla/5.0 Chrome/129.0.0.0 Safari/537.36"}
    )
    firefox = manager.import_browser(
        {"userAgent": "Mozilla/5.0 Firefox/122.0"}
    )

    assert chrome["impersonate"] == "chrome120"
    assert firefox["impersonate"] is None


def test_session_keeps_non_impersonatable_fingerprint_until_explicit_rotation():
    manager = FingerprintManager(seed=5)
    firefox = next(
        item
        for item in manager.fingerprints()
        if item["browser"] == "Firefox"
    )
    manager.bind_session("fixture", firefox["id"])

    with pytest.raises(RuntimeError, match="rotate_fingerprint"):
        manager.for_session("fixture", require_impersonate=True)

    assert manager.for_session("fixture")["id"] == firefox["id"]
    assert manager.get(firefox["id"])["impersonate"] is None


class FakeCookies(dict):
    def get_dict(self):
        return dict(self)


class FakeCurlSession:
    created = []

    def __init__(self, **kwargs):
        self.kwargs = dict(kwargs)
        self.impersonate = kwargs.get("impersonate")
        self.cookies = FakeCookies()
        self.__class__.created.append(self)


class FakeCurlRequests:
    Session = FakeCurlSession
    Cookies = FakeCookies


class FakeResponse:
    def __init__(self, status=200, text="ok", headers=None, url="https://fixture"):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()
        self.cookies = FakeCookies()
        self.history = []


class RecordingCurlSession(FakeCurlSession):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return FakeResponse(url=url)


class RecordingCurlRequests:
    Session = RecordingCurlSession
    Cookies = FakeCookies


def test_default_curl_transport_uses_persisted_fingerprint_impersonate(
    tmp_path,
    monkeypatch,
):
    FakeCurlSession.created.clear()
    monkeypatch.setattr(stealth_http_client, "requests", FakeCurlRequests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    manager = FingerprintManager(seed=3)
    client = StealthHTTPClient(
        state_dir=tmp_path,
        fingerprint_manager=manager,
        sleep=lambda _: None,
    )

    state = client.session_create(
        "https://fixture",
        resume=False,
        fingerprint_strategy="round-robin",
    )

    assert state["impersonate"]
    assert FakeCurlSession.created[0].kwargs == {
        "impersonate": state["impersonate"],
    }


def test_manual_rotation_rebuilds_default_curl_transport_and_keeps_cookies(
    tmp_path,
    monkeypatch,
):
    FakeCurlSession.created.clear()
    monkeypatch.setattr(stealth_http_client, "requests", FakeCurlRequests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    manager = FingerprintManager(seed=3)
    client = StealthHTTPClient(
        state_dir=tmp_path,
        fingerprint_manager=manager,
        sleep=lambda _: None,
    )
    client.session_create(
        "https://fixture",
        resume=False,
        fingerprint_strategy="round-robin",
    )
    first_transport = FakeCurlSession.created[0]
    first_transport.cookies["sid"] = "persisted"

    event = client.rotate_fingerprint(
        "https://fixture",
        reason="manual-curl-test",
    )

    assert len(FakeCurlSession.created) == 2
    second_transport = FakeCurlSession.created[1]
    assert event["previous_browser"] != event["new_browser"]
    assert first_transport.impersonate != second_transport.impersonate
    assert second_transport.cookies["sid"] == "persisted"


def test_explicit_impersonate_override_is_persisted_and_applied(
    tmp_path,
    monkeypatch,
):
    FakeCurlSession.created.clear()
    monkeypatch.setattr(stealth_http_client, "requests", FakeCurlRequests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    client = StealthHTTPClient(
        state_dir=tmp_path,
        impersonate="edge101",
        sleep=lambda _: None,
    )

    constructor_override = client.session_create(
        "https://constructor.test",
        resume=False,
    )
    session_override = client.session_create(
        "https://session.test",
        resume=False,
        impersonate="safari17_0",
    )

    assert constructor_override["impersonate"] == "edge101"
    assert session_override["impersonate"] == "safari17_0"
    assert [session.impersonate for session in FakeCurlSession.created] == [
        "edge101",
        "safari17_0",
    ]


def test_constructor_impersonate_override_applies_when_resuming_session(
    tmp_path,
    monkeypatch,
):
    FakeCurlSession.created.clear()
    monkeypatch.setattr(stealth_http_client, "requests", FakeCurlRequests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    first = StealthHTTPClient(
        state_dir=tmp_path,
        impersonate="chrome120",
        sleep=lambda _: None,
    )
    first.session_create("https://resume.test", resume=False)

    second = StealthHTTPClient(
        state_dir=tmp_path,
        impersonate="edge101",
        sleep=lambda _: None,
    )
    resumed = second.session_create("https://resume.test", resume=True)

    assert resumed["impersonate"] == "edge101"
    assert FakeCurlSession.created[-1].impersonate == "edge101"


def test_curl_protocol_switch_reaches_request_http_version(
    tmp_path,
    monkeypatch,
):
    RecordingCurlSession.created.clear()
    monkeypatch.setattr(
        stealth_http_client,
        "requests",
        RecordingCurlRequests,
    )
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    client = StealthHTTPClient(state_dir=tmp_path, sleep=lambda _: None)
    strategy = {"id": "protocol-version-switch", "description": "fixture"}

    first = client.stealth_request(
        "POST",
        "https://fixture/api",
        data="x",
        options={"max_retries": 0, "initial_strategy": strategy},
    )
    second = client.stealth_request(
        "POST",
        "https://fixture/api",
        data="x",
        options={"max_retries": 0, "initial_strategy": strategy},
    )

    transport = RecordingCurlSession.created[0]
    assert transport.calls[0]["kwargs"]["http_version"] == "v2"
    assert transport.calls[1]["kwargs"]["http_version"] == "v1"
    assert first["timeline"][0]["transport_backend"] == "curl_cffi"
    assert second["timeline"][0]["transport_backend"] == "curl_cffi"


def test_legacy_session_id_restore_preserves_persisted_fingerprint(
    tmp_path,
    monkeypatch,
):
    FakeCurlSession.created.clear()
    monkeypatch.setattr(stealth_http_client, "requests", FakeCurlRequests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", True)
    manager = FingerprintManager(seed=11)
    firefox = next(
        item
        for item in manager.fingerprints()
        if item["browser"] == "Firefox"
    )
    client = StealthHTTPClient(
        state_dir=tmp_path,
        fingerprint_manager=manager,
        sleep=lambda _: None,
    )
    state = {
        "session_id": "stealth-legacy",
        "target": "https://legacy.test:443",
        "fingerprint_id": firefox["id"],
        "cookies": {"sid": "persisted"},
    }
    client._path(state["target"]).write_text(
        json.dumps(state),
        encoding="utf-8",
    )

    runtime = client._runtime_for_session_id("stealth-legacy")

    assert runtime["state"]["fingerprint_id"] == firefox["id"]
    assert runtime["state"]["impersonate"] is None
    assert FakeCurlSession.created[0].kwargs == {}
    assert FakeCurlSession.created[0].cookies["sid"] == "persisted"


def test_curl_chunked_request_is_not_nested_on_the_wire(tmp_path):
    pytest.importorskip("curl_cffi")
    records = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            chunk_sizes = []
            chunks = []
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                while True:
                    size = int(self.rfile.readline().split(b";", 1)[0], 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    chunk_sizes.append(size)
                    chunks.append(self.rfile.read(size))
                    self.rfile.read(2)
                body = b"".join(chunks)
            else:
                body = self.rfile.read(
                    int(self.headers.get("Content-Length", "0"))
                )
            records.append(
                {
                    "body": body,
                    "chunk_sizes": chunk_sizes,
                    "transfer_encoding": self.headers.get(
                        "Transfer-Encoding",
                        "",
                    ),
                }
            )
            status = 403 if len(records) == 1 else 200
            payload = b"forbidden" if status == 403 else b"ok"
            self.send_response(status)
            if status == 403:
                self.send_header("X-Tencent-WAF", "1")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api"
        client = StealthHTTPClient(
            state_dir=tmp_path,
            impersonate="chrome120",
            sleep=lambda _: None,
        )
        client.waf.strategies_for = lambda _: [
            {"id": "chunked-body", "description": "fixture"}
        ]

        result = client.stealth_request(
            "POST",
            url,
            data="x" * 300,
            options={"max_retries": 1, "jitter": False},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result["status_code"] == 200
    assert records[1]["transfer_encoding"].lower() == "chunked"
    assert records[1]["body"] == b"x" * 300
    assert records[1]["chunk_sizes"]


def test_retry_persists_cookies_from_transport_jar(tmp_path):
    class CookieRetryTransport:
        def __init__(self):
            self.cookies = FakeCookies()
            self.calls = 0

        def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls == 1:
                self.cookies["sid"] = "intermediate"
                return FakeResponse(
                    status=403,
                    text="forbidden",
                    headers={"CF-Ray": "fixture"},
                    url=url,
                )
            return FakeResponse(url=url)

    transport = CookieRetryTransport()
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.waf.strategies_for = lambda _: [
        {"id": "header-consistency", "description": "fixture"}
    ]

    result = client.stealth_request(
        "GET",
        "https://fixture",
        options={"max_retries": 1},
    )

    assert result["status_code"] == 200
    assert client.session_state("https://fixture")["cookies"] == {
        "sid": "intermediate"
    }


def test_detection_session_keeps_transport_cookie_jar_canonical(
    tmp_path,
):
    class NativeSession(native_requests.Session):
        def send(self, request, **kwargs):
            self.cookies.set("sid", "native")
            response = native_requests.Response()
            response.status_code = 200
            response._content = b"ok"
            response.headers = {}
            response.url = request.url
            response.request = request
            return response

    transport = NativeSession()
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    state = client.session_create("https://fixture", resume=False)
    session = client.detection_session(state["session_id"])

    response = session.get("https://fixture")
    session.cookies.update({"extra": "value"})

    assert response.cookies is session.cookies
    assert {cookie.name for cookie in response.cookies} == {"sid", "extra"}
    assert transport.cookies.get_dict() == {
        "sid": "native",
        "extra": "value",
    }


def test_custom_transport_factory_remains_zero_argument(tmp_path):
    transport = object()
    calls = []

    def factory():
        calls.append(True)
        return transport

    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=factory,
        impersonate="chrome120",
        sleep=lambda _: None,
    )

    client.session_create("https://fixture", resume=False)

    assert calls == [True]
    assert client._runtime("https://fixture")["transport"] is transport


def test_requests_fallback_logs_exact_warning_only_once(
    tmp_path,
    monkeypatch,
    caplog,
):
    monkeypatch.setattr(stealth_http_client, "requests", native_requests)
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", False)
    monkeypatch.setattr(
        stealth_http_client,
        "_FALLBACK_WARNING_EMITTED",
        False,
        raising=False,
    )
    caplog.set_level(logging.WARNING)

    first = StealthHTTPClient(state_dir=tmp_path / "one")
    second = StealthHTTPClient(state_dir=tmp_path / "two")
    first.session_create("https://one.test", resume=False)
    second.session_create("https://two.test", resume=False)

    assert [record.message for record in caplog.records].count(
        FALLBACK_WARNING
    ) == 1
    assert isinstance(
        first._runtime("https://one.test")["transport"],
        native_requests.Session,
    )


def test_fallback_timeline_does_not_claim_impersonation(
    tmp_path,
    monkeypatch,
):
    RecordingCurlSession.created.clear()
    monkeypatch.setattr(
        stealth_http_client,
        "requests",
        RecordingCurlRequests,
    )
    monkeypatch.setattr(stealth_http_client, "CURL_CFFI_AVAILABLE", False)
    monkeypatch.setattr(
        stealth_http_client,
        "_FALLBACK_WARNING_EMITTED",
        False,
    )
    client = StealthHTTPClient(state_dir=tmp_path, sleep=lambda _: None)

    result = client.stealth_request(
        "GET",
        "https://fixture",
        options={"max_retries": 0},
    )

    row = result["timeline"][0]
    assert row["transport_backend"] == "requests-fallback"
    assert row["requested_impersonate"]
    assert row["impersonate"] is None


def test_pyproject_declares_optional_curl_cffi_dependency():
    document = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert document["project"]["optional-dependencies"]["stealth"] == [
        "curl_cffi>=0.6.0"
    ]
