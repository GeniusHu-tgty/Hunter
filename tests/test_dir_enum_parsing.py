import base64
import json

import mcp_server


def _ffuf_stdout(records):
    return "\n".join(json.dumps(record, ensure_ascii=False) for record in records)


def _run_dir_enum(monkeypatch, records):
    stdout = _ffuf_stdout(records)
    monkeypatch.setattr(
        mcp_server._hunter,
        "ffuf_fuzz",
        lambda url, wordlist=None: {
            "status": "success",
            "stdout": stdout,
            "stderr": "",
            "returncode": 0,
        },
    )
    return mcp_server._execute_agent("dir-enum", "https://target.test"), stdout


def test_dir_enum_decodes_standard_and_urlsafe_base64_paths(monkeypatch):
    standard_token = "LndlbGwta25vd24vYnJvd3Nlcmlk"
    urlsafe_text = "路径/测试"
    urlsafe_token = (
        base64.urlsafe_b64encode(urlsafe_text.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    records = [
        {
            "url": (
                f"https://target.test/{standard_token}"
                "?source=ffuf#browser"
            ),
            "status": 200,
            "input": {"FUZZ": standard_token},
        },
        {
            "url": f"https://target.test/{urlsafe_token}",
            "status": 200,
        },
    ]

    payload, stdout = _run_dir_enum(monkeypatch, records)

    assert payload["stdout_preview"] == stdout
    assert payload["200"] == [
        "/.well-known/browserid?source=ffuf",
        f"/{urlsafe_text}",
    ]
    assert payload["found"] == 2
    assert payload["scanned"] == 2


def test_dir_enum_keeps_plain_invalid_and_binary_paths(monkeypatch):
    records = [
        {"url": "https://target.test/admin/", "status": 200},
        {"url": "https://target.test/not_base64!/", "status": 403},
        {
            "url": "https://target.test/AP8B",
            "status": 200,
            "input": {"FUZZ": "AP8B"},
        },
    ]

    payload, _ = _run_dir_enum(monkeypatch, records)

    assert payload["200"] == ["/admin/", "/AP8B"]
    assert payload["403"] == ["/not_base64!/"]


def test_dir_enum_summary_groups_statuses_and_resolves_redirects(monkeypatch):
    records = [
        {"url": "https://target.test/admin/", "status": 200},
        {
            "url": "https://target.test/user/",
            "status": 302,
            "redirectlocation": "/user/login",
        },
        {"url": "https://target.test/config/", "status": 404},
    ]

    payload, _ = _run_dir_enum(monkeypatch, records)
    assert payload["200"] == ["/admin/"]
    assert payload["302"] == [{
        "path": "/user/",
        "redirect": "https://target.test/user/login",
    }]
    assert payload["found"] == 2
    assert payload["scanned"] == 3


def test_dir_enum_summary_excludes_404_when_total_is_at_least_twenty(
    monkeypatch,
):
    records = [
        {
            "url": f"https://target.test/item-{index}/",
            "status": 200,
        }
        for index in range(19)
    ]
    records.append(
        {
            "url": "https://target.test/missing/",
            "status": 404,
        }
    )

    payload, _ = _run_dir_enum(monkeypatch, records)
    assert payload["count"] == 20
    assert payload["found"] == 19
    assert payload["scanned"] == 20
    assert len(payload["200"]) == 19
    assert "404" not in payload


def test_dir_enum_returns_compact_filtered_groups(monkeypatch):
    records = [
        {"url": "https://target.test/ok", "status": 200},
        {
            "url": "https://target.test/login",
            "status": 302,
            "redirectlocation": "/cas/login",
        },
        {"url": "https://target.test/private", "status": 403},
        {"url": "https://target.test/missing", "status": 404},
    ]

    payload, _ = _run_dir_enum(monkeypatch, records)

    assert payload["200"] == ["/ok"]
    assert payload["302"] == [{
        "path": "/login",
        "redirect": "https://target.test/cas/login",
    }]
    assert payload["403"] == ["/private"]
    assert payload["found"] == 3
    assert payload["scanned"] == 4
    assert "results" not in payload
    assert "parsed_results" not in payload


def test_dir_enum_compact_groups_are_capped_at_fifty(monkeypatch):
    records = [
        {"url": f"https://target.test/path-{index}", "status": 200}
        for index in range(60)
    ]

    payload, _ = _run_dir_enum(monkeypatch, records)

    assert payload["found"] == 60
    assert len(payload["200"]) == 50
