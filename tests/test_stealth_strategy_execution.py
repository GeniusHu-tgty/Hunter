import json
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import requests

from core.stealth.stealth_http_client import StealthHTTPClient
from core.stealth.waf_detector import STRATEGIES


class Cookies(dict):
    def get_dict(self):
        return dict(self)


class Response:
    def __init__(self, status=200, text="", headers=None, url="https://fixture/"):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()
        self.cookies = Cookies()
        self.history = []


class RecordingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.http_version = "HTTP/1.1"

    def request(self, method, url, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "kwargs": kwargs,
                "http_version": self.http_version,
            }
        )
        return self.responses.pop(0)


def make_client(tmp_path):
    return StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: SimpleNamespace(http_version="HTTP/1.1"),
        sleep=lambda _: None,
    )


def apply(client, strategy_id, data, headers=None, context=None):
    return client._apply_strategy(
        {"id": strategy_id},
        headers or {},
        data,
        request_context=context,
    )


def test_double_percent_encoding_only_reencodes_percent_signs(tmp_path):
    client = make_client(tmp_path)

    headers, data, status = apply(
        client,
        "double-percent-encoding",
        {"value": "a%20b", "plain": "100"},
    )

    assert headers == {}
    assert data == {"value": "a%2520b", "plain": "100"}
    assert status == "applied"


def test_protocol_version_switch_toggles_transport_state(tmp_path):
    client = make_client(tmp_path)
    transport = SimpleNamespace(http_version="HTTP/1.1")
    context = {"session": transport}

    first = apply(client, "protocol-version-switch", {}, context=context)
    assert first[2] == "applied"
    assert transport.http_version == "HTTP/2"

    second = apply(client, "protocol-version-switch", {}, context=context)
    assert second[2] == "applied"
    assert transport.http_version == "HTTP/1.1"


def test_chunked_body_uses_256_byte_chunks_and_terminal_chunk(tmp_path):
    client = make_client(tmp_path)
    context = {"session": SimpleNamespace(http_version="HTTP/1.1")}

    headers, data, status = apply(
        client,
        "chunked-body",
        "x" * 300,
        headers={"Content-Length": "300"},
        context=context,
    )

    assert status == "applied"
    assert headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in headers
    assert data == (
        b"100\r\n"
        + (b"x" * 256)
        + b"\r\n2c\r\n"
        + (b"x" * 44)
        + b"\r\n0\r\n\r\n"
    )


def test_query_to_body_changes_get_url_and_method(tmp_path):
    client = make_client(tmp_path)
    context = {
        "method": "GET",
        "url": "https://fixture/search?q=one&q=two&blank=",
    }

    headers, data, status = apply(
        client,
        "query-to-body",
        None,
        context=context,
    )

    assert status == "applied"
    assert context["method"] == "POST"
    assert urlsplit(context["url"]).query == ""
    assert parse_qsl(data, keep_blank_values=True) == [
        ("q", "one"),
        ("q", "two"),
        ("blank", ""),
    ]
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_benign_field_padding_appends_deterministic_form_fields(tmp_path):
    client = make_client(tmp_path)

    _, data, status = apply(client, "benign-field-padding", {"user": "alice"})

    assert status == "applied"
    assert list(data.items()) == [
        ("user", "alice"),
        ("submit", "continue"),
        ("source", "web"),
        ("lang", "en"),
    ]


def test_content_type_rotation_reserializes_each_body_format(tmp_path):
    client = make_client(tmp_path)
    transport = SimpleNamespace(http_version="HTTP/1.1")
    context = {"session": transport}

    form_headers, form_data, form_status = apply(
        client,
        "content-type-rotation",
        {"a": "1"},
        context=context,
    )
    multipart_headers, multipart_data, multipart_status = apply(
        client,
        "content-type-rotation",
        {"a": "1"},
        context=context,
    )
    json_headers, json_data, json_status = apply(
        client,
        "content-type-rotation",
        {"a": "1"},
        context=context,
    )

    assert (form_status, multipart_status, json_status) == (
        "applied",
        "applied",
        "applied",
    )
    assert form_headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert form_data == "a=1"
    assert multipart_headers["Content-Type"].startswith(
        "multipart/form-data; boundary="
    )
    assert 'name="a"' in multipart_data
    assert json_headers["Content-Type"] == "application/json"
    assert json.loads(json_data) == {"a": "1"}


def test_sql_and_unicode_value_transformations(tmp_path):
    client = make_client(tmp_path)

    _, doubled, doubled_status = apply(
        client,
        "keyword-double-write",
        {"q": "UNION SELECT"},
    )
    _, unicode_data, unicode_status = apply(
        client,
        "unicode-equivalent",
        {"q": "admin account"},
    )
    _, nulled, nulled_status = apply(
        client,
        "null-byte-padding",
        {"q": "admin"},
    )
    _, commented, commented_status = apply(
        client,
        "comment-injection",
        {"q": "UNION SELECT"},
    )

    assert doubled_status == "applied"
    assert doubled["q"] == "UNUNIONION SELSELECTECT"
    assert unicode_status == "applied"
    replacements = sum(a != b for a, b in zip("admin account", unicode_data["q"]))
    assert 0 < replacements <= int(len("admin account") * 0.3)
    assert nulled_status == "applied"
    assert nulled["q"] == "a%00d%00m%00i%00n"
    assert commented_status == "applied"
    assert commented["q"] == "UN/**/ION SEL/**/ECT"


def test_every_declared_strategy_has_an_applicable_execution_path(tmp_path):
    client = make_client(tmp_path)
    declared = {strategy_id for rows in STRATEGIES.values() for strategy_id, _ in rows}
    transport = SimpleNamespace(http_version="HTTP/1.1")

    string_strategies = {"case-variation", "line-folding", "chunked-body"}
    query_strategies = {"query-to-body"}
    websocket_strategies = {"websocket-upgrade"}
    contexts = {
        strategy_id: {
            "method": "GET",
            "url": "https://fixture/path?a=1",
            "session": transport,
            "websocket_endpoint": strategy_id in websocket_strategies,
        }
        for strategy_id in declared
    }

    unsupported = []
    for strategy_id in sorted(declared):
        if strategy_id in string_strategies:
            data = "UNION SELECT ASCII(a)"
        elif strategy_id in query_strategies or strategy_id in websocket_strategies:
            data = None
        elif strategy_id == "double-percent-encoding":
            data = {"q": "a%20b"}
        else:
            data = {"q": "UNION SELECT ASCII(a) <value>"}
        _, _, status = apply(
            client,
            strategy_id,
            data,
            context=contexts[strategy_id],
        )
        if status == "unsupported":
            unsupported.append(strategy_id)

    assert unsupported == []


def test_query_to_body_reaches_transport_as_post_form_request(tmp_path):
    transport = RecordingTransport(
        [
            Response(403, "forbidden", {"X-D-WAF": "1"}),
            Response(200, "ok"),
        ]
    )
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.waf.strategies_for = lambda _: [
        {"id": "query-to-body", "description": "fixture"}
    ]

    result = client.stealth_request(
        "GET",
        "https://fixture/search?q=one&q=two",
        options={"max_retries": 1},
    )

    assert result["status_code"] == 200
    assert transport.calls[1]["method"] == "POST"
    assert transport.calls[1]["url"] == "https://fixture/search"
    assert transport.calls[1]["kwargs"]["data"] == "q=one&q=two"
    assert (
        transport.calls[1]["kwargs"]["headers"]["Content-Type"]
        == "application/x-www-form-urlencoded"
    )


def test_protocol_switch_reaches_retry_transport_session(tmp_path):
    transport = RecordingTransport(
        [
            Response(403, "forbidden", {"X-Azure-Ref": "1"}),
            Response(200, "ok"),
        ]
    )
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.waf.strategies_for = lambda _: [
        {"id": "protocol-version-switch", "description": "fixture"}
    ]

    result = client.stealth_request(
        "POST",
        "https://fixture/api",
        data={"q": "value"},
        options={"max_retries": 1},
    )

    assert result["status_code"] == 200
    assert transport.calls[0]["http_version"] == "HTTP/1.1"
    assert transport.calls[1]["http_version"] == "HTTP/2"
    assert result["timeline"][1]["strategy_status"] == "applied"


def test_percent_marker_strategies_are_serialized_once_before_transport(tmp_path):
    cases = [
        ("double-percent-encoding", "a%20b", "q=a%2520b"),
        ("null-byte-padding", "admin", "q=a%00d%00m%00i%00n"),
    ]

    for strategy_id, value, expected in cases:
        transport = RecordingTransport(
            [
                Response(403, "forbidden", {"X-Azure-Ref": "1"}),
                Response(200, "ok"),
            ]
        )
        client = StealthHTTPClient(
            state_dir=tmp_path / strategy_id,
            transport_factory=lambda transport=transport: transport,
            sleep=lambda _: None,
        )
        client.waf.strategies_for = lambda _, strategy_id=strategy_id: [
            {"id": strategy_id, "description": "fixture"}
        ]

        result = client.stealth_request(
            "POST",
            "https://fixture/api",
            data={"q": value},
            options={"max_retries": 1},
        )

        assert result["status_code"] == 200
        assert transport.calls[1]["kwargs"]["data"] == expected


def test_requests_transport_prepares_chunked_body_without_content_length(tmp_path):
    class CapturingSession(requests.Session):
        def __init__(self):
            super().__init__()
            self.prepared = []

        def send(self, request, **kwargs):
            self.prepared.append(request)
            response = requests.Response()
            response.status_code = 403 if len(self.prepared) == 1 else 200
            response._content = b"forbidden" if response.status_code == 403 else b"ok"
            response.headers = (
                {"X-Tencent-WAF": "1"} if response.status_code == 403 else {}
            )
            response.url = request.url
            response.request = request
            return response

    transport = CapturingSession()
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.waf.strategies_for = lambda _: [
        {"id": "chunked-body", "description": "fixture"}
    ]

    result = client.stealth_request(
        "POST",
        "https://fixture/api",
        data="x" * 300,
        options={"max_retries": 1},
    )

    prepared = transport.prepared[1]
    chunks = list(prepared.body)
    assert result["status_code"] == 200
    assert prepared.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in prepared.headers
    assert [len(chunk) for chunk in chunks] == [256, 44]
