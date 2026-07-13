import asyncio
import json
import time
from pathlib import Path

import core.mcp_server as core_mcp_server
import mcp_server
from core.mcp_server import HunterMCPServer


def _scanner(tmp_path):
    scanner = object.__new__(HunterMCPServer)
    scanner.wordlist_dir = tmp_path
    return scanner


def test_crtsh_success_skips_dns_bruteforce(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        scanner,
        "_crtsh_enum",
        lambda domain, timeout: {
            "status": "success",
            "subdomains": [f"www.{domain}", f"mail.{domain}"],
            "error": "",
        },
    )

    def unexpected_dns(*args, **kwargs):
        raise AssertionError("DNS brute force must not run after crt.sh succeeds")

    monkeypatch.setattr(scanner, "_dns_brute_enum", unexpected_dns)

    result = scanner.subfinder_enum("example.edu.cn")

    assert result["status"] == "success"
    assert result["source"] == "crt.sh"
    assert result["stdout"].splitlines() == [
        "mail.example.edu.cn",
        "www.example.edu.cn",
    ]
    assert result["attempts"][0]["timeout_seconds"] == 10


def test_crtsh_http_query_uses_ten_second_timeout_and_filters_names(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            observed["limit"] = limit
            return json.dumps(
                [
                    {
                        "name_value": (
                            "*.example.edu.cn\n"
                            "JW.EXAMPLE.EDU.CN\n"
                            "outside.example.net"
                        ),
                        "common_name": "lib.example.edu.cn",
                    }
                ]
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        observed["url"] = request.full_url
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setattr(core_mcp_server, "urlopen", fake_urlopen)

    result = scanner._crtsh_enum("example.edu.cn", timeout=10)

    assert observed["timeout"] == 10
    assert "output=json" in observed["url"]
    assert result["status"] == "success"
    assert result["subdomains"] == [
        "jw.example.edu.cn",
        "lib.example.edu.cn",
    ]


def test_crtsh_timeout_is_a_wall_clock_deadline(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)

    class SlowResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            time.sleep(0.15)
            return b"[]"

    monkeypatch.setattr(
        core_mcp_server,
        "urlopen",
        lambda request, timeout: SlowResponse(),
    )

    started = time.monotonic()
    result = scanner._crtsh_enum("example.edu.cn", timeout=0.05)
    elapsed = time.monotonic() - started

    assert result["status"] == "timeout"
    assert elapsed < 0.12


def test_crtsh_timeout_falls_back_to_dns_bruteforce(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        scanner,
        "_crtsh_enum",
        lambda domain, timeout: {
            "status": "timeout",
            "subdomains": [],
            "error": f"crt.sh timed out after {timeout:g}s",
        },
    )
    observed = {}

    def fake_dns(domain, timeout, query_timeout):
        observed.update(
            domain=domain,
            timeout=timeout,
            query_timeout=query_timeout,
        )
        return {
            "status": "success",
            "subdomains": [f"jw.{domain}", f"lib.{domain}"],
            "error": "",
            "queries": 2,
            "timed_out": False,
            "wordlist": str(tmp_path / "subdomains_edu.txt"),
        }

    monkeypatch.setattr(scanner, "_dns_brute_enum", fake_dns)

    result = scanner.subfinder_enum("example.edu.cn")

    assert result["status"] == "success"
    assert result["source"] == "dns-brute"
    assert result["stdout"].splitlines() == [
        "jw.example.edu.cn",
        "lib.example.edu.cn",
    ]
    assert observed["domain"] == "example.edu.cn"
    assert observed["query_timeout"] == 3
    assert 0 < observed["timeout"] <= 110
    assert result["attempts"][0]["status"] == "timeout"
    assert result["attempts"][1]["status"] == "success"


def test_dns_bruteforce_uses_three_second_queries_and_wordlist(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    wordlist = tmp_path / "subdomains_edu.txt"
    wordlist.write_text("www\njw\nmissing\n", encoding="utf-8")
    observed = []

    def fake_resolve(host, timeout):
        observed.append((host, timeout))
        if host.startswith(("www.", "jw.")):
            return ["192.0.2.10"], ""
        return [], ""

    monkeypatch.setattr(scanner, "_resolve_dns_name", fake_resolve)

    result = scanner._dns_brute_enum(
        "example.edu.cn",
        timeout=120,
        query_timeout=3,
    )

    assert result["status"] == "success"
    assert result["subdomains"] == [
        "jw.example.edu.cn",
        "www.example.edu.cn",
    ]
    assert {
        ("www.example.edu.cn", 3),
        ("jw.example.edu.cn", 3),
        ("missing.example.edu.cn", 3),
    } <= set(observed)
    assert all(timeout == 3 for _, timeout in observed)
    assert len(observed) == 4
    assert result["queries"] == 3


def test_dns_bruteforce_filters_wildcard_dns_results(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    (tmp_path / "subdomains_edu.txt").write_text(
        "www\njw\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        scanner,
        "_resolve_dns_name",
        lambda host, timeout: (["192.0.2.10"], ""),
    )

    result = scanner._dns_brute_enum(
        "example.edu.cn",
        timeout=120,
        query_timeout=3,
    )

    assert result["status"] == "error"
    assert result["subdomains"] == []
    assert result["wildcard_detected"] is True
    assert result["wildcard_addresses"] == ["192.0.2.10"]
    assert result["wildcard_matches"] == 2


def test_dns_resolver_applies_three_second_timeout(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    observed = {}

    class Resolver:
        def __init__(self, configure):
            observed["configure"] = configure
            observed["instance"] = self
            self.timeout = None
            self.lifetime = None

        def resolve(
            self,
            host,
            record_type,
            lifetime,
            search,
            raise_on_no_answer,
        ):
            observed["call"] = {
                "host": host,
                "record_type": record_type,
                "lifetime": lifetime,
                "search": search,
                "raise_on_no_answer": raise_on_no_answer,
            }
            return ["192.0.2.10"]

    monkeypatch.setattr(core_mcp_server.dns_resolver, "Resolver", Resolver)

    addresses, error = scanner._resolve_dns_name(
        "jw.example.edu.cn",
        timeout=3,
    )

    assert error == ""
    assert addresses == ["192.0.2.10"]
    assert observed["configure"] is True
    assert observed["instance"].timeout == 3
    assert observed["instance"].lifetime == 3
    assert observed["call"] == {
        "host": "jw.example.edu.cn",
        "record_type": "A",
        "lifetime": 3,
        "search": False,
        "raise_on_no_answer": False,
    }


def test_dns_nxdomain_does_not_issue_redundant_aaaa_query(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    calls = []

    class Resolver:
        timeout = None
        lifetime = None

        def __init__(self, configure):
            pass

        def resolve(self, host, record_type, **kwargs):
            calls.append(record_type)
            raise core_mcp_server.dns_resolver.NXDOMAIN()

    monkeypatch.setattr(core_mcp_server.dns_resolver, "Resolver", Resolver)

    addresses, error = scanner._resolve_dns_name(
        "missing.example.edu.cn",
        timeout=3,
    )

    assert addresses == []
    assert error == ""
    assert calls == ["A"]


def test_dns_resolver_is_reused_within_a_worker_thread(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    observed = {"created": 0, "hosts": []}

    class Resolver:
        timeout = None
        lifetime = None

        def __init__(self, configure):
            observed["created"] += 1

        def resolve(self, host, record_type, **kwargs):
            observed["hosts"].append(host)
            return ["192.0.2.10"]

    monkeypatch.setattr(core_mcp_server.dns_resolver, "Resolver", Resolver)

    scanner._resolve_dns_name("jw.example.edu.cn", timeout=3)
    scanner._resolve_dns_name("lib.example.edu.cn", timeout=3)

    assert observed["created"] == 1
    assert observed["hosts"] == [
        "jw.example.edu.cn",
        "lib.example.edu.cn",
    ]


def test_both_enumeration_paths_return_clear_error(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        scanner,
        "_crtsh_enum",
        lambda domain, timeout: {
            "status": "timeout",
            "subdomains": [],
            "error": "crt.sh timed out after 10s",
        },
    )
    monkeypatch.setattr(
        scanner,
        "_dns_brute_enum",
        lambda domain, timeout, query_timeout: {
            "status": "error",
            "subdomains": [],
            "error": "DNS brute force completed but no names resolved",
            "queries": 240,
            "timed_out": False,
            "wordlist": str(tmp_path / "subdomains_edu.txt"),
        },
    )

    result = scanner.subfinder_enum("example.edu.cn")

    assert result["status"] == "error"
    assert result["stdout"] == ""
    assert "crt.sh timed out after 10s" in result["error"]
    assert "DNS brute force completed but no names resolved" in result["error"]
    assert result["returncode"] == 1


def test_dns_budget_expiry_with_results_is_explicitly_partial(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        scanner,
        "_crtsh_enum",
        lambda domain, timeout: {
            "status": "timeout",
            "subdomains": [],
            "error": "crt.sh timed out after 10s",
        },
    )
    monkeypatch.setattr(
        scanner,
        "_dns_brute_enum",
        lambda domain, timeout, query_timeout: {
            "status": "success",
            "subdomains": [f"jw.{domain}"],
            "error": "",
            "queries": 256,
            "timed_out": True,
            "wordlist": str(tmp_path / "subdomains_edu.txt"),
        },
    )

    result = scanner.subfinder_enum("example.edu.cn")

    assert result["status"] == "success"
    assert result["partial"] is True
    assert result["timed_out"] is True
    assert "partial" in result["warning"].lower()


def test_mcp_subdomain_payload_preserves_results_and_diagnostics(monkeypatch):
    monkeypatch.setattr(
        mcp_server._hunter,
        "subfinder_enum",
        lambda domain: {
            "status": "success",
            "stdout": f"jw.{domain}\nlib.{domain}\n",
            "stderr": "crt.sh timed out after 10s; used DNS fallback",
            "returncode": 0,
            "source": "dns-brute",
            "attempts": [
                {"source": "crt.sh", "status": "timeout"},
                {"source": "dns-brute", "status": "success"},
            ],
            "wordlist": "wordlists/subdomains_edu.txt",
            "error": "",
            "partial": True,
            "timed_out": True,
            "warning": "DNS fallback returned partial results",
        },
    )

    result = mcp_server._execute_agent("subdomain", "example.edu.cn")

    assert result["tool"] == "subfinder"
    assert result["status"] == "success"
    assert result["source"] == "dns-brute"
    assert result["subdomains"] == [
        "jw.example.edu.cn",
        "lib.example.edu.cn",
    ]
    assert result["count"] == 2
    assert result["attempts"][0]["status"] == "timeout"
    assert result["wordlist"].endswith("subdomains_edu.txt")
    assert result["partial"] is True
    assert result["timed_out"] is True
    assert "partial" in result["warning"].lower()


def test_hunter_subdomain_outer_timeout_exceeds_internal_budget(monkeypatch):
    observed = {}
    monkeypatch.setattr(
        mcp_server,
        "_execute_agent",
        lambda agent_name, target, **kwargs: {"status": "success"},
    )

    async def fake_wait_for(awaitable, timeout):
        observed["timeout"] = timeout
        await awaitable
        return {"status": "success"}

    monkeypatch.setattr(mcp_server.asyncio, "wait_for", fake_wait_for)

    result = asyncio.run(
        mcp_server._execute_agent_async("subdomain", "example.edu.cn")
    )

    assert result["status"] == "success"
    assert observed["timeout"] == 120


def test_education_wordlist_contains_required_prefixes_and_two_hundred_entries():
    path = (
        Path(__file__).resolve().parents[1]
        / "wordlists"
        / "subdomains_edu.txt"
    )
    entries = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required = {
        "www",
        "mail",
        "vpn",
        "ftp",
        "api",
        "dev",
        "test",
        "staging",
        "admin",
        "portal",
        "sso",
        "jw",
        "jwc",
        "jwgl",
        "lib",
        "cas",
        "authserver",
        "my",
        "yjs",
        "xsc",
        "xg",
        "zsb",
        "jy",
        "hq",
        "wxy",
        "szxy",
        "hcxy",
        "lcyxy",
        "jxjy",
        "gqn",
        "sztz",
        "xsgz",
        "sms",
        "wiki",
        "gitlab",
        "jenkins",
    }

    assert len(entries) >= 200
    assert required <= entries


def test_education_prefixes_are_prioritized_before_bulk_generic_entries():
    path = (
        Path(__file__).resolve().parents[1]
        / "wordlists"
        / "subdomains_edu.txt"
    )
    ordered = [
        line.split("#", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    priority = {
        "jw",
        "jwc",
        "jwgl",
        "lib",
        "cas",
        "authserver",
        "my",
        "portal",
        "yjs",
        "xsc",
        "xg",
        "zsb",
        "jy",
        "hq",
        "wxy",
        "szxy",
        "hcxy",
        "lcyxy",
        "jxjy",
        "gqn",
        "sztz",
        "xsgz",
        "vpn",
        "mail",
    }

    assert priority <= set(ordered[:48])


def test_runtime_dns_wordlist_keeps_at_least_two_hundred_bounded_prefixes():
    scanner = HunterMCPServer()
    path, words = scanner._subdomain_words()

    assert path.name == "subdomains_edu.txt"
    assert 200 <= len(words) <= 256
    assert {
        "jw",
        "jwc",
        "jwgl",
        "lib",
        "cas",
        "authserver",
        "my",
        "portal",
        "yjs",
        "xsc",
        "xg",
        "zsb",
        "jy",
        "hq",
        "wxy",
        "szxy",
        "hcxy",
        "lcyxy",
        "jxjy",
        "gqn",
        "sztz",
        "xsgz",
    } <= set(words)
