import asyncio
import base64
import hashlib
import json
from pathlib import Path

import pytest
import yaml

import mcp_server
from core.session.attack_chain import AttackChain
from core.session.attack_session import AttackSession, AttackSessionStore
from core.session.post_exploitation import PostExploitation


def _jwt(payload):
    def encode(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode({'alg': 'none', 'typ': 'JWT'})}.{encode(payload)}."


def test_attack_session_persists_cookie_jar_and_discards_expired_cookies(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path, session_id="attack-cookie")
    session.update_cookies(
        {
            "session": {"value": "abc123", "domain": "example.test", "path": "/"},
            "expired": {"value": "gone", "domain": "example.test", "path": "/", "expires": 1},
        }
    )
    session.save()

    restored = AttackSession.load("attack-cookie", storage_dir=tmp_path)

    assert restored.cookies.__class__.__name__ == "CookieJar"
    assert restored.cookie_dict() == {"session": "abc123"}
    assert restored.cookie_header("https://example.test/admin") == "session=abc123"


def test_auto_extract_collects_csrf_auth_forms_redirects_and_messages(tmp_path):
    token = _jwt({"sub": "admin", "role": "administrator"})
    html = f"""
    <html>
      <head>
        <meta name="csrf-token" content="meta-csrf">
        <meta http-equiv="refresh" content="0; url=/dashboard">
      </head>
      <body>
        <form action="/login">
          <input name="csrf_token" value="form-csrf">
          <input type="hidden" name="return_to" value="/admin">
          <input name="username" value="guest">
          <select name="role"><option value="user" selected>User</option></select>
          <textarea name="note">hello</textarea>
        </form>
        <div class="alert error">Invalid password</div>
        <script>window.location.href = "/next"; const token = "{token}";</script>
      </body>
    </html>
    """
    response = {
        "url": "https://example.test/login",
        "status_code": 200,
        "headers": {
            "Authorization": f"Bearer {token}",
            "Location": "/header-redirect",
            "Set-Cookie": "sid=from-response; Path=/; HttpOnly",
        },
        "body": html,
        "json": {"api_key": "key-123", "nested": {"token": token}},
    }
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "scope-login",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )

    extracted = session.auto_extract(response)

    assert session.csrf_tokens["https://example.test/login"]["csrf_token"] == "form-csrf"
    assert session.csrf_tokens["https://example.test/login"]["csrf-token"] == "meta-csrf"
    assert session.auth_tokens["bearer"] == token
    assert session.auth_tokens["jwt"] == token
    assert session.auth_tokens["api_key"] == "key-123"
    assert extracted["forms"]["csrf_token"] == "form-csrf"
    assert extracted["hidden"]["return_to"] == "/admin"
    assert extracted["forms"]["role"] == "user"
    assert extracted["forms"]["note"] == "hello"
    assert set(extracted["redirects"]) == {
        "https://example.test/header-redirect",
        "https://example.test/dashboard",
        "https://example.test/next",
    }
    assert "Invalid password" in extracted["messages"]
    assert session.cookie_dict()["sid"] == "from-response"


def test_extract_from_response_supports_regex_css_xpath_jsonpath_and_jwt(tmp_path):
    token = _jwt({"sub": "42", "scope": "admin"})
    response = {
        "body": '<div id="result" data-id="42">Welcome admin</div>',
        "json": {"data": {"items": [{"name": "first"}]}, "token": token},
    }
    session = AttackSession("https://example.test", storage_dir=tmp_path)

    assert session.extract_from_response(r"regex:data-id=\"(\d+)\"", response) == "42"
    assert session.extract_from_response("css:#result::text", response) == "Welcome admin"
    assert session.extract_from_response("xpath://div[@id='result']/@data-id", response) == "42"
    assert session.extract_from_response("jsonpath:$.data.items[0].name", response) == "first"
    assert session.extract_from_response(f"jwt:{token}", response)["scope"] == "admin"


def test_attack_chain_executes_get_extract_post_and_transfers_state(tmp_path):
    calls = []

    def request_executor(session, request):
        calls.append(request)
        if request["method"] == "GET":
            return {
                "status": "ok",
                "status_code": 200,
                "url": "https://example.test/login",
                "headers": {"Set-Cookie": "preauth=one; Path=/"},
                "body": '<form><input name="csrf_token" value="csrf-123"></form>',
            }
        return {
            "status": "ok",
            "status_code": 200,
            "url": "https://example.test/admin",
            "headers": {},
            "body": "Welcome administrator",
        }

    definition = {
        "name": "three-step",
        "start": "get-login",
        "steps": [
            {
                "step_id": "get-login",
                "name": "Get login",
                "action": "request",
                "request": {"method": "GET", "path": "/login"},
                "on_success": "extract-csrf",
            },
            {
                "step_id": "extract-csrf",
                "name": "Extract CSRF",
                "action": "extract",
                "extract_rules": [
                    {
                        "name": "csrf",
                        "pattern": 'regex:name="csrf_token" value="([^"]+)"',
                        "store_as": "csrf",
                    }
                ],
                "on_success": "post-login",
            },
            {
                "step_id": "post-login",
                "name": "Post login",
                "action": "request",
                "request": {
                    "method": "POST",
                    "path": "/login",
                    "data": {"username": "admin", "csrf_token": "${csrf}"},
                },
                "critical": True,
            },
        ],
    }
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={"allowed_methods": ["GET", "POST"]},
    )
    chain = AttackChain(definition, request_executor=request_executor)

    result = chain.execute(session)

    assert result["status"] == "complete"
    assert calls[1]["data"]["csrf_token"] == "csrf-123"
    assert "preauth=one" in calls[1]["headers"]["Cookie"]
    assert session.extracted_data["csrf"] == "csrf-123"
    assert [item["step_id"] for item in result["steps"]] == [
        "get-login",
        "extract-csrf",
        "post-login",
    ]


def test_attack_chain_loads_yaml_and_critical_failure_creates_blocker_checkpoint(tmp_path):
    chain_path = tmp_path / "chain.yml"
    chain_path.write_text(
        yaml.safe_dump(
            {
                "name": "critical-chain",
                "steps": [
                    {
                        "step_id": "must-work",
                        "name": "Must work",
                        "action": "request",
                        "request": {"method": "GET", "path": "/blocked"},
                        "max_retries": 1,
                        "critical": True,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    attempts = []

    def request_executor(session, request):
        attempts.append(request)
        return {"status": "error", "status_code": 503, "headers": {}, "body": "blocked"}

    session = AttackSession("https://example.test", storage_dir=tmp_path, session_id="critical")
    result = AttackChain.load(chain_path, request_executor=request_executor).execute(session)

    assert result["status"] == "blocked"
    assert len(attempts) == 2
    assert result["blocker"]["step_id"] == "must-work"
    assert Path(result["blocker"]["checkpoint"]).exists()


def test_checkpoint_restores_cookie_tokens_state_and_extracted_data(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path, session_id="checkpoint")
    session.update_cookies({"sid": "before"})
    session.auth_tokens["bearer"] = "token-before"
    session.state = "scan"
    session.extracted_data["database"] = "app"
    checkpoint = session.save_checkpoint("known-good")

    session.update_cookies({"sid": "after"})
    session.auth_tokens["bearer"] = "token-after"
    session.state = "post_exploit"
    session.extracted_data["database"] = "wrong"
    session.restore_checkpoint("known-good")

    assert Path(checkpoint["path"]).exists()
    assert session.cookie_dict()["sid"] == "before"
    assert session.auth_tokens["bearer"] == "token-before"
    assert session.state == "scan"
    assert session.extracted_data["database"] == "app"
    assert "known-good" in session.checkpoints


def test_post_exploitation_requires_confirmed_evidence_and_approval_for_high_impact_actions(tmp_path):
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "approval-1",
            "approved_by": "operator",
            "evidence_ids": ["ev-1"],
            "capabilities": ["read", "file_write"],
            "post_exploit_actions": [
                "enumerate_databases",
                "enumerate_tables",
                "export_user_rows",
            ],
        },
    )
    planner = PostExploitation(
        approval_verifier=lambda session, vuln_type, details, actions: {
            "trusted": True,
            "source": "test-approval-registry",
        }
    )

    unconfirmed = planner.run(session, "sqli", {"confirmed": False})
    planned = planner.run(
        session,
        "sqli",
        {
            "confirmed": True,
            "evidence_ids": ["ev-1"],
            "dbms": "mysql",
            "capabilities": ["read", "file_write"],
        },
    )
    approved = planner.run(
        session,
        "sqli",
        {
            "confirmed": True,
            "evidence_ids": ["ev-1"],
            "dbms": "mysql",
            "capabilities": ["read"],
            "approved_actions": ["enumerate_databases", "enumerate_tables", "export_user_rows"],
        },
        approved=True,
    )

    assert unconfirmed["status"] == "rejected"
    assert planned["status"] == "approval-required"
    assert any(item["action"] == "write_webshell" for item in planned["actions"])
    assert approved["status"] == "ready"
    assert {item["action"] for item in approved["approved_actions"]} == {
        "enumerate_databases",
        "enumerate_tables",
        "export_user_rows",
    }
    assert not approved["executed"]


def test_post_exploitation_cannot_self_approve_without_session_scope_and_evidence(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    result = PostExploitation().run(
        session,
        "ssrf",
        {
            "confirmed": True,
            "capabilities": ["persistent_write"],
            "approved_actions": ["write_redis_crontab_or_ssh_key"],
        },
        approved=True,
    )
    assert result["status"] == "rejected"
    assert result["approved_actions"] == []


def test_self_declared_session_scope_cannot_create_trusted_ready_state(tmp_path):
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "self-declared",
            "approved_by": "caller",
            "evidence_ids": ["ev-self"],
            "capabilities": ["persistent_write"],
            "post_exploit_actions": ["write_redis_crontab_or_ssh_key"],
        },
    )
    result = PostExploitation().run(
        session,
        "ssrf",
        {
            "confirmed": True,
            "evidence_ids": ["ev-self"],
            "capabilities": ["persistent_write"],
            "approved_actions": ["write_redis_crontab_or_ssh_key"],
        },
        approved=True,
    )
    assert result["status"] == "approval-required"
    assert result["approved_actions"] == []
    assert result["requested_actions"][0]["action"] == "write_redis_crontab_or_ssh_key"


def test_attack_session_mcp_tools_registered_contracted_and_smoke(tmp_path):
    tools = {
        "hunter_session_start",
        "hunter_session_execute_chain",
        "hunter_session_checkpoint",
        "hunter_post_exploit",
        "hunter_session_state",
    }
    registered = {
        name
        for name, value in vars(mcp_server).items()
        if name.startswith("hunter_") and callable(value)
    }
    assert tools <= registered

    contract = json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert tools <= set(contract["data"]["required_tools"])

    mcp_server._reset_attack_session_store(tmp_path)
    created = json.loads(
        asyncio.run(mcp_server.hunter_session_start("https://example.test"))
    )
    assert created["status"] == "ok"
    session_id = created["data"]["session_id"]

    state = json.loads(asyncio.run(mcp_server.hunter_session_state(session_id=session_id)))
    assert state["data"]["target"] == "https://example.test"

    saved = json.loads(
        asyncio.run(
            mcp_server.hunter_session_checkpoint(
                session_id=session_id,
                action="save",
                name="mcp-checkpoint",
            )
        )
    )
    assert saved["status"] == "ok"
    listed = json.loads(
        asyncio.run(
            mcp_server.hunter_session_checkpoint(
                session_id=session_id,
                action="list",
            )
        )
    )
    assert "mcp-checkpoint" in listed["data"]["checkpoints"]

    post = json.loads(
        asyncio.run(
            mcp_server.hunter_post_exploit(
                session_id=session_id,
                vuln_type="sqli",
                vuln_details={"confirmed": True, "capabilities": ["read"]},
            )
        )
    )
    assert post["data"]["status"] == "rejected"


def test_attack_session_store_rejects_unknown_session(tmp_path):
    store = AttackSessionStore(tmp_path)
    with pytest.raises(KeyError):
        store.get("missing")


def test_chain_does_not_persist_secret_parameters_or_history_values(tmp_path):
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "login-proof",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    chain = AttackChain(
        {
            "name": "secret",
            "parameters": {"username": "", "password": ""},
            "steps": [
                {
                    "step_id": "submit",
                    "name": "Submit",
                    "action": "request",
                    "request": {
                        "method": "POST",
                        "path": "/login",
                        "data": {
                            "username": "${username}",
                            "password": "${password}",
                        },
                    },
                }
            ],
        },
        request_executor=lambda session, request: {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "ok",
        },
    )

    result = chain.execute(
        session,
        params={"username": "admin", "password": "secret-value"},
    )

    serialized = json.dumps(session.snapshot(), ensure_ascii=False)
    public_result = json.dumps(result, ensure_ascii=False)
    history = json.dumps(session.history, ensure_ascii=False)
    assert "secret-value" not in serialized
    assert "secret-value" not in public_result
    assert "secret-value" not in history
    assert "password" not in session.extracted_data


def test_sensitive_state_is_encrypted_at_rest_and_redacted_from_snapshot(tmp_path):
    sentinel = "SENTINEL-SECRET-123"
    session = AttackSession("https://example.test", storage_dir=tmp_path, session_id="sealed")
    session.update_cookies({"sid": sentinel})
    session.csrf_tokens["https://example.test/form"] = {"csrf_token": sentinel}
    session.auth_tokens["bearer"] = sentinel
    session.extracted_data["password"] = sentinel
    session.save()
    checkpoint = session.save_checkpoint("sealed-state")

    assert sentinel not in session.state_path.read_text(encoding="utf-8")
    assert sentinel not in Path(checkpoint["path"]).read_text(encoding="utf-8")
    assert sentinel not in json.dumps(session.public_snapshot(), ensure_ascii=False)

    restored = AttackSession.load("sealed", storage_dir=tmp_path)
    assert restored.cookie_dict()["sid"] == sentinel
    assert restored.auth_tokens["bearer"] == sentinel
    assert restored.csrf_tokens["https://example.test/form"]["csrf_token"] == sentinel
    assert restored.extracted_data["password"] == sentinel


def test_authenticated_requires_verified_response_proof_not_arbitrary_cookie(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    session.update_cookies({"tracking": "1"})
    chain = AttackChain(
        {
            "name": "auth-proof",
            "steps": [
                {
                    "step_id": "check",
                    "name": "Check",
                    "action": "condition",
                    "condition": {"field": "authenticated", "operator": "truthy"},
                }
            ],
        },
        sleep=lambda _: None,
    )
    result = chain.execute(session)
    assert result["status"] == "failed"

    session.mark_authenticated(
        {
            "type": "protected-page",
            "url": "https://example.test/admin",
            "evidence": "dashboard marker",
        }
    )
    assert AttackChain(
        {
            "name": "auth-proof-ok",
            "steps": [
                {
                    "step_id": "check",
                    "name": "Check",
                    "action": "condition",
                    "condition": {"field": "authenticated", "operator": "truthy"},
                }
            ],
        },
        sleep=lambda _: None,
    ).execute(session)["status"] == "complete"


def test_approval_required_pauses_chain_instead_of_reporting_complete(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    chain = AttackChain(
        {
            "name": "approval",
            "steps": [
                {
                    "step_id": "exploit",
                    "name": "Exploit",
                    "action": "exploit",
                    "critical": True,
                }
            ],
        }
    )
    result = chain.execute(session)
    assert result["status"] == "approval-required"
    assert result["pending"]["step_id"] == "exploit"


def test_request_scope_blocks_cross_origin_and_unapproved_methods(tmp_path):
    calls = []
    session = AttackSession("https://authorized.example", storage_dir=tmp_path)
    executor = lambda session, request: calls.append(request) or {
        "status": "ok",
        "status_code": 200,
        "url": request["url"],
        "headers": {},
        "body": "ok",
    }
    external = AttackChain(
        {
            "name": "external",
            "steps": [
                {
                    "step_id": "one",
                    "name": "One",
                    "action": "request",
                    "request": {"method": "GET", "url": "https://outside.example/"},
                    "critical": True,
                }
            ],
        },
        request_executor=executor,
    ).execute(session)
    unsafe_method = AttackChain(
        {
            "name": "delete",
            "steps": [
                {
                    "step_id": "one",
                    "name": "One",
                    "action": "request",
                    "request": {"method": "DELETE", "path": "/account"},
                    "critical": True,
                }
            ],
        },
        request_executor=executor,
    ).execute(session)

    assert external["status"] == "blocked"
    assert unsafe_method["status"] == "blocked"
    assert calls == []


def test_cookie_restore_preserves_duplicate_paths_and_host_only_scope(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path, session_id="cookies")
    session.update_cookie_records(
        [
            {
                "name": "sid",
                "value": "root",
                "domain": "example.test",
                "path": "/",
                "host_only": True,
            },
            {
                "name": "sid",
                "value": "admin",
                "domain": "example.test",
                "path": "/admin",
                "host_only": True,
            },
        ]
    )
    session.save()
    restored = AttackSession.load("cookies", storage_dir=tmp_path)

    assert len(list(restored.cookies)) == 2
    assert "sid=root" in restored.cookie_header("https://example.test/admin")
    assert "sid=admin" in restored.cookie_header("https://example.test/admin")
    assert restored.cookie_header("https://sub.example.test/admin") == ""


def test_critical_checkpoint_contains_blocker_metadata(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    result = AttackChain(
        {
            "name": "blocker",
            "steps": [
                {
                    "step_id": "fail",
                    "name": "Fail",
                    "action": "request",
                    "request": {"method": "GET", "path": "/"},
                    "critical": True,
                }
            ],
        },
        request_executor=lambda session, request: {
            "status": "error",
            "status_code": 500,
            "url": request["url"],
            "headers": {},
            "body": "",
        },
    ).execute(session)
    body = json.loads(Path(result["blocker"]["checkpoint"]).read_text(encoding="utf-8"))
    restored = session.decrypt_persisted_state(body["state"])
    assert restored["blockers"][-1]["step_id"] == "fail"


def test_attack_http_clients_are_isolated_per_attack_session(tmp_path):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    first = store.create("https://example.test", session_id="attack-one")
    second = store.create("https://example.test", session_id="attack-two")
    one_client = mcp_server._get_attack_http_client(first)
    two_client = mcp_server._get_attack_http_client(second)
    assert one_client is not two_client
    assert one_client.state_dir != two_client.state_dir


def test_chain_results_redact_sensitive_variables(tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    result = AttackChain(
        {
            "name": "redact",
            "parameters": {"password": "", "token": ""},
            "steps": [
                {
                    "step_id": "wait",
                    "name": "Wait",
                    "action": "wait",
                }
            ],
        },
        sleep=lambda _: None,
    ).execute(session, {"password": "pw-secret", "token": "token-secret"})
    assert "pw-secret" not in json.dumps(result)
    assert "token-secret" not in json.dumps(result)


def test_preset_templates_declare_all_placeholders():
    for path in (Path(mcp_server.HUNTER_DIR) / "chains").glob("*.yml"):
        chain = AttackChain.load(path)
        assert chain.undefined_variables == set(), path.name


def test_retry_switches_payload_variant_and_exposes_strategy_metadata(tmp_path):
    seen = []

    def request_executor(session, request):
        seen.append(request)
        if len(seen) == 1:
            return {
                "status": "error",
                "status_code": 403,
                "url": request["url"],
                "headers": {},
                "body": "blocked",
            }
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "ok",
        }

    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "retry",
            "approved_by": "operator",
            "allowed_methods": ["POST"],
        },
    )
    result = AttackChain(
        {
            "name": "retry-variants",
            "steps": [
                {
                    "step_id": "probe",
                    "name": "Probe",
                    "action": "request",
                    "request": {
                        "method": "POST",
                        "path": "/probe",
                        "data": {"value": "${payload}"},
                    },
                    "max_retries": 1,
                    "options": {
                        "payload_variable": "payload",
                        "payload_variants": ["variant-one", "variant-two"],
                        "retry_strategies": ["baseline", "waf-rotate"],
                    },
                }
            ],
        },
        request_executor=request_executor,
    ).execute(session)

    assert result["status"] == "complete"
    assert [item["data"]["value"] for item in seen] == [
        "variant-one",
        "variant-two",
    ]
    assert seen[1]["options"]["retry_strategy"] == "waf-rotate"


@pytest.mark.parametrize(
    "status",
    [
        "approval-required",
        "ready",
        "deferred",
        "rejected",
        "blocked",
    ],
)
def test_exploit_planning_statuses_do_not_continue_success_path(tmp_path, status):
    side_effects = []
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    chain = AttackChain(
        {
            "name": f"approval-{status}",
            "steps": [
                {
                    "step_id": "exploit",
                    "name": "Exploit",
                    "action": "exploit",
                    "on_success": "side-effect",
                },
                {
                    "step_id": "side-effect",
                    "name": "Side effect",
                    "action": "request",
                    "request": {"method": "POST", "path": "/side-effect"},
                },
            ],
        },
        request_executor=lambda session, request: side_effects.append(request)
        or {"status": "ok", "status_code": 200},
        exploit_executor=lambda session, details: {"status": status},
    )

    result = chain.execute(session)

    assert result["status"] == status
    assert result["steps"][0]["success"] is False
    assert result["pending"]["step_id"] == "exploit"
    assert side_effects == []


def test_checkpoint_restore_resumes_failed_chain_step_without_replaying_success(tmp_path):
    calls = []
    fail_second = True

    def request_executor(session, request):
        nonlocal fail_second
        step = request["url"].rsplit("/", 1)[-1]
        calls.append(step)
        if step == "second" and fail_second:
            fail_second = False
            return {"status": "error", "status_code": 503, "body": "retry"}
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "ok",
        }

    definition = {
        "name": "resume-chain",
        "steps": [
            {
                "step_id": "first",
                "name": "First",
                "action": "request",
                "request": {"method": "POST", "path": "/first"},
                "on_success": "second",
            },
            {
                "step_id": "second",
                "name": "Second",
                "action": "request",
                "request": {"method": "POST", "path": "/second"},
                "critical": True,
            },
        ],
    }
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        session_id="resume",
        authorization={"allowed_methods": ["POST"]},
    )
    chain = AttackChain(definition, request_executor=request_executor)

    blocked = chain.execute(session)
    checkpoint_name = Path(blocked["blocker"]["checkpoint"]).stem
    session.restore_checkpoint(checkpoint_name)
    resumed = chain.execute(session)

    assert blocked["status"] == "blocked"
    assert resumed["status"] == "complete"
    assert [item["step_id"] for item in resumed["steps"]] == ["second"]
    assert calls == ["first", "second", "second"]
    assert session.chain_cursors["resume-chain"]["status"] == "complete"


def test_mutating_request_persists_in_flight_and_requires_manual_recovery(tmp_path):
    observed = []
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        session_id="in-flight-post",
        authorization={"allowed_methods": ["POST"]},
    )

    def crash_after_dispatch(current_session, request):
        persisted = AttackSession.load("in-flight-post", storage_dir=tmp_path)
        marker = persisted.chain_cursors["mutation"]["in_flight"]
        observed.append((marker["step_id"], marker["method"], marker["url"]))
        raise KeyboardInterrupt("simulated process crash")

    definition = {
        "name": "mutation",
        "steps": [
            {
                "step_id": "change",
                "name": "Change",
                "action": "request",
                "request": {"method": "POST", "path": "/change"},
            }
        ],
    }
    with pytest.raises(KeyboardInterrupt, match="simulated process crash"):
        AttackChain(definition, request_executor=crash_after_dispatch).execute(session)

    restored = AttackSession.load("in-flight-post", storage_dir=tmp_path)
    replayed = []
    result = AttackChain(
        definition,
        request_executor=lambda current_session, request: replayed.append(request)
        or {"status": "ok", "status_code": 200},
    ).execute(restored)

    assert observed == [("change", "POST", "https://example.test/change")]
    assert result["status"] == "recovery-required"
    assert result["pending"]["step_id"] == "change"
    assert result["pending"]["method"] == "POST"
    assert replayed == []
    assert restored.chain_cursors["mutation"]["status"] == "recovery-required"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_safe_request_recovers_after_in_flight_crash(tmp_path, method):
    calls = []
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        session_id=f"in-flight-{method.lower()}",
        authorization={"allowed_methods": [method]},
    )
    definition = {
        "name": f"safe-{method.lower()}",
        "steps": [
            {
                "step_id": "read",
                "name": "Read",
                "action": "request",
                "request": {"method": method, "path": "/status"},
            }
        ],
    }

    def crash_once(current_session, request):
        calls.append(request["method"])
        raise KeyboardInterrupt("simulated process crash")

    with pytest.raises(KeyboardInterrupt, match="simulated process crash"):
        AttackChain(definition, request_executor=crash_once).execute(session)

    restored = AttackSession.load(
        f"in-flight-{method.lower()}", storage_dir=tmp_path
    )
    result = AttackChain(
        definition,
        request_executor=lambda current_session, request: calls.append(request["method"])
        or {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "safe",
        },
    ).execute(restored)

    assert result["status"] == "complete"
    assert calls == [method, method]


def test_chain_public_results_summarize_response_but_internal_extract_keeps_body(
    tmp_path,
):
    body = "token=internal-secret"
    authorization = "Bearer response-secret"
    cookie = "sid=cookie-secret; Path=/"
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={"allowed_methods": ["GET"]},
    )
    chain = AttackChain(
        {
            "name": "response-summary",
            "steps": [
                {
                    "step_id": "fetch",
                    "name": "Fetch",
                    "action": "request",
                    "request": {"method": "GET", "path": "/source"},
                    "on_success": "extract",
                },
                {
                    "step_id": "extract",
                    "name": "Extract",
                    "action": "extract",
                    "extract_rules": [
                        {
                            "store_as": "internal_token",
                            "pattern": r"regex:token=(.+)",
                        }
                    ],
                },
            ],
        },
        request_executor=lambda current_session, request: {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {
                "Authorization": authorization,
                "Set-Cookie": cookie,
                "Location": "/next",
            },
            "body": body,
        },
    )

    result = chain.execute(session)
    public_response = result["steps"][0]["results"][0]
    public_text = json.dumps(result, ensure_ascii=False)

    assert result["status"] == "complete"
    assert session.extracted_data["internal_token"] == "internal-secret"
    assert session.chain_cursors["response-summary"]["last_response"]["body"] == body
    assert body not in public_text
    assert authorization not in public_text
    assert cookie not in public_text
    assert "body" not in public_response
    assert "headers" not in public_response
    assert public_response["body_hash"] == hashlib.sha256(body.encode()).hexdigest()
    assert public_response["body_size"] == len(body.encode())
    assert public_response["status"] == "ok"
    assert public_response["status_code"] == 200
    assert public_response["location"] == "/next"


def test_execute_and_history_redact_all_sensitive_input_parameter_values(tmp_path):
    secrets = {
        "password": "password-value",
        "token": "token-value",
        "client_secret": "secret-value",
        "cookie": "cookie-value",
        "auth": "auth-value",
    }

    def request_executor(session, request):
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": json.dumps(request["data"]),
            "echo": request["data"],
        }

    session = AttackSession("https://example.test", storage_dir=tmp_path)
    chain = AttackChain(
        {
            "name": "redacted-execute",
            "steps": [
                {
                    "step_id": "send",
                    "name": "Send",
                    "action": "request",
                    "request": {
                        "method": "POST",
                        "path": "/login",
                        "data": {
                            key: "${" + key + "}"
                            for key in secrets
                        },
                    },
                }
            ],
        },
        request_executor=request_executor,
    )

    result = chain.execute(session, params=secrets)
    public_result = json.dumps(result, ensure_ascii=False)
    history = json.dumps(session.history, ensure_ascii=False)

    for secret in secrets.values():
        assert secret not in public_result
        assert secret not in history


def test_public_snapshot_redacts_credentials_but_snapshot_keeps_internal_state(tmp_path):
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        headers={
            "Authorization": "Bearer header-secret",
            "X-Trace": "trace-secret",
        },
    )
    session.update_cookies({"sid": "cookie-secret"})
    session.csrf_tokens["https://example.test/form"] = {
        "csrf_token": "csrf-secret"
    }
    session.auth_tokens["bearer"] = "auth-secret"
    session.record_history(
        "request",
        {
            "password": "history-secret",
            "headers": {"Cookie": "sid=history-cookie"},
        },
    )

    internal = session.snapshot()
    public = session.public_snapshot()
    public_text = json.dumps(public, ensure_ascii=False)

    assert internal["cookies"][0]["value"] == "cookie-secret"
    assert internal["headers"]["Authorization"] == "Bearer header-secret"
    assert internal["csrf_tokens"]["https://example.test/form"]["csrf_token"] == "csrf-secret"
    assert internal["auth_tokens"]["bearer"] == "auth-secret"
    for secret in (
        "cookie-secret",
        "header-secret",
        "trace-secret",
        "csrf-secret",
        "auth-secret",
        "history-secret",
        "history-cookie",
    ):
        assert secret not in public_text
    assert public["cookies"][0]["value"] == "[REDACTED]"
    assert public["headers"]["Authorization"] == "[REDACTED]"
    assert public["csrf_tokens"]["https://example.test/form"]["csrf_token"] == "[REDACTED]"
    assert public["auth_tokens"]["bearer"] == "[REDACTED]"


def test_attack_chain_rejects_dangling_branch_reference():
    with pytest.raises(ValueError, match="unknown step"):
        AttackChain(
            {
                "name": "dangling",
                "steps": [
                    {
                        "step_id": "one",
                        "name": "One",
                        "action": "wait",
                        "on_success": "missing",
                    }
                ],
            },
            sleep=lambda _: None,
        )


@pytest.mark.parametrize(
    "name",
    [
        "login_to_admin.yml",
        "sqli_to_data_dump.yml",
        "file_upload_to_shell.yml",
        "ssrf_to_internal_access.yml",
        "jwt_to_account_takeover.yml",
        "card_shop_attack.yml",
    ],
)
def test_preset_attack_chains_load_with_valid_references(name):
    chain = AttackChain.load(Path(mcp_server.HUNTER_DIR) / "chains" / name)
    assert chain.steps
    assert chain.start in chain.by_id


def test_attack_session_tools_are_in_fastmcp_registry():
    registered = {
        tool.name for tool in asyncio.run(mcp_server.mcp.list_tools())
    }
    assert {
        "hunter_session_start",
        "hunter_session_execute_chain",
        "hunter_session_checkpoint",
        "hunter_post_exploit",
        "hunter_session_state",
    } <= registered


def test_session_state_rejects_ambiguous_target_and_session_id(tmp_path):
    mcp_server._reset_attack_session_store(tmp_path)
    result = json.loads(
        asyncio.run(
            mcp_server.hunter_session_state(
                target="https://example.test",
                session_id="attack-one",
            )
        )
    )
    assert result["status"] == "error"
    assert "either target or session_id" in result["error"]


def test_unknown_attack_session_returns_mcp_error_envelope(tmp_path):
    mcp_server._reset_attack_session_store(tmp_path)
    state = json.loads(
        asyncio.run(mcp_server.hunter_session_state(session_id="attack-missing"))
    )
    post = json.loads(
        asyncio.run(
            mcp_server.hunter_post_exploit(
                session_id="attack-missing",
                vuln_type="sqli",
                vuln_details={"confirmed": True},
            )
        )
    )
    assert state["status"] == "error"
    assert post["status"] == "error"
    assert state["error_type"] == post["error_type"] == "KeyError"


def test_facade_capabilities_advertise_attack_session_surface():
    result = mcp_server._hunter_tools.capabilities()
    tools = result["data"]["tools"]
    assert {
        "hunter_session_start",
        "hunter_session_execute_chain",
        "hunter_session_checkpoint",
        "hunter_post_exploit",
        "hunter_session_state",
    } <= set(tools)
    assert result["data"]["attack_session"]["schema_version"] == "1.0"
    assert result["data"]["attack_session"]["templates"] == 6


def test_redact_sensitive_masks_all_hidden_and_extra_field_values():
    from core.session.attack_session import redact_sensitive

    value = {
        "extra_fields": {
            "execution": "flow-secret",
            "RelayState": "relay-secret",
            "ordinary_hidden": "hidden-secret",
        },
        "hidden": {"lt": "lt-secret"},
    }

    assert redact_sensitive(value) == {
        "extra_fields": {
            "execution": "[REDACTED]",
            "RelayState": "[REDACTED]",
            "ordinary_hidden": "[REDACTED]",
        },
        "hidden": {"lt": "[REDACTED]"},
    }
