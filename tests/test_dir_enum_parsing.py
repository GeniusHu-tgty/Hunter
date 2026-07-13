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
    assert payload["results"] == records
    assert payload["parsed_results"][0]["url"] == (
        "https://target.test/.well-known/browserid"
        "?source=ffuf#browser"
    )
    assert payload["parsed_results"][0]["raw_url"] == records[0]["url"]
    assert payload["parsed_results"][1]["url"] == (
        f"https://target.test/{urlsafe_text}"
    )
    assert payload["parsed_results"][1]["raw_url"] == records[1]["url"]


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

    assert [record["url"] for record in payload["parsed_results"]] == [
        record["url"] for record in records
    ]
    assert [record["raw_url"] for record in payload["parsed_results"]] == [
        record["url"] for record in records
    ]


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
    summary = payload["human_readable"]

    assert "HTTP 200 (1个):" in summary
    assert "  https://target.test/admin/" in summary
    assert "HTTP 302 (1个):" in summary
    assert (
        "  https://target.test/user/ -> "
        "https://target.test/user/login"
    ) in summary
    assert "HTTP 404 (1个):" in summary
    assert "  https://target.test/config/" in summary


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
    summary = payload["human_readable"]

    assert payload["count"] == 20
    assert "HTTP 200 (19个):" in summary
    assert "HTTP 404" not in summary
    assert "https://target.test/missing/" not in summary
