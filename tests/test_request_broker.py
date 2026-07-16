from __future__ import annotations

from pathlib import Path

from core.request_broker import (
    ArtifactStore,
    Classification,
    DependentProcess,
    IdentityPool,
    RequestBroker,
    RequestSpec,
    ResponseProjection,
    block_cluster_similarity,
    build_response_projection,
)
from core.request_broker.projection import block_cluster_similarity, build_response_projection


class FakeResponse:
    def __init__(self, status_code=200, text="ok", headers=None, url="https://lab.test/"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = url
        self.history = []
        self.cookies = {}


class SequenceTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_classifier_rejects_waf_variant_even_when_status_is_200(tmp_path):
    broker = RequestBroker(tmp_path, transport=SequenceTransport())
    outcome = broker.classify_response(
        RequestSpec("GET", "https://lab.test/search?q=x", mode="probe"),
        FakeResponse(200, "<title>Access denied</title><p>Request blocked by security policy</p>"),
    )

    assert outcome.classification is Classification.WAF_BLOCK
    assert outcome.confidence >= 0.9


def test_broker_persists_a_compact_discover_artifact(tmp_path):
    broker = RequestBroker(
        tmp_path,
        transport=SequenceTransport(FakeResponse(200, "<title>Portal</title><main>Welcome</main>")),
    )

    outcome = broker.request(RequestSpec("GET", "https://lab.test/", mode="discover"))

    assert outcome.evidence_ids[0].startswith("artifact:")


def test_rate_limit_enters_persistent_cooldown(tmp_path):
    transport = SequenceTransport(FakeResponse(429, "too many requests"))
    broker = RequestBroker(tmp_path, transport=transport, now=lambda: 1000.0)
    result = broker.request(RequestSpec("GET", "https://lab.test/"))

    assert result.classification is Classification.RATE_LIMITED
    assert broker.state_for("https://lab.test/")["cooldown_until"] == 1030.0

    restarted = RequestBroker(tmp_path, transport=SequenceTransport(), now=lambda: 1001.0)
    assert restarted.state_for("https://lab.test/")["state"] == "COOLING_DOWN"


def test_broker_persists_proxy_and_work_cursor_across_restart(tmp_path):
    broker = RequestBroker(tmp_path, transport=SequenceTransport())
    broker.set_current_proxy("https://lab.test/", "http://127.0.0.1:8080", identity="owner")
    broker.save_work_cursor("https://lab.test/", {"tool": "nuclei", "position": 7}, identity="owner")

    restarted = RequestBroker(tmp_path, transport=SequenceTransport())
    state = restarted.state_for("https://lab.test/", identity="owner")

    assert state["current_proxy"] == "http://127.0.0.1:8080"
    assert state["work_cursor"] == {"position": 7, "tool": "nuclei"}


def test_repeated_blocks_enter_hard_blocked_and_stop_active_requests(tmp_path):
    now = [1000.0]
    broker = RequestBroker(
        tmp_path,
        transport=SequenceTransport(
            FakeResponse(429, "too many requests"),
            FakeResponse(429, "too many requests"),
        ),
        now=lambda: now[0],
        hard_block_threshold=2,
    )

    broker.request(RequestSpec("GET", "https://lab.test/"))
    now[0] = 1031.0
    broker.request(RequestSpec("GET", "https://lab.test/"))
    rejected = broker.request(RequestSpec("GET", "https://lab.test/"))

    assert broker.state_for("https://lab.test/")["state"] == "HARD_BLOCKED"
    assert rejected.missing_inputs == ["hard_blocked"]


def test_probe_requires_clean_baselines_before_it_can_be_allowed(tmp_path):
    transport = SequenceTransport(
        FakeResponse(200, "<title>Portal</title><main>Welcome</main>"),
        FakeResponse(200, "<title>Access denied</title><main>blocked by WAF</main>"),
        FakeResponse(200, "<title>Portal</title><main>Welcome</main>"),
    )
    broker = RequestBroker(tmp_path, transport=transport)
    result = broker.run_probe(
        RequestSpec("GET", "https://lab.test/search?q=PAYLOAD", mode="probe"),
        clean_url="https://lab.test/search?q=normal",
    )

    assert result.classification is Classification.WAF_BLOCK
    assert len(result.controls) == 3
    assert result.next_actions == ["cool_down_target"]


def test_recovery_probe_uses_a_clean_origin_request(tmp_path):
    transport = SequenceTransport(FakeResponse(200, "<title>Portal</title><main>Welcome</main>"))
    broker = RequestBroker(tmp_path, transport=transport, now=lambda: 2000.0)
    broker.set_cooldown("https://lab.test/path?q=x", "RATE_LIMITED", 1999.0)

    result = broker.recovery_probe("https://lab.test/path?q=x")

    assert result.classification is Classification.ALLOWED_APP
    assert transport.calls[0][1] == "https://lab.test/"
    assert transport.calls[0][2]["params"] is None


def test_recovery_probe_requires_a_matching_healthy_baseline(tmp_path):
    now = [1000.0]
    broker = RequestBroker(
        tmp_path,
        transport=SequenceTransport(
            FakeResponse(200, "<title>Portal</title><main>Welcome</main>"),
            FakeResponse(200, "<title>Interstitial</title><main>Please wait</main>"),
        ),
        now=lambda: now[0],
    )
    broker.request(RequestSpec("GET", "https://lab.test/"))
    broker.set_cooldown("https://lab.test/path", "RATE_LIMITED", 999.0)

    result = broker.recovery_probe("https://lab.test/path")

    assert result.classification is Classification.SOFT_BAN
    assert result.next_actions == ["cool_down_target"]


def test_empty_shell_200_that_deviates_from_healthy_baseline_is_soft_ban(tmp_path):
    broker = RequestBroker(
        tmp_path,
        transport=SequenceTransport(
            FakeResponse(200, "<title>Portal</title><main><h1>Account overview</h1><a href='/settings'>Settings</a></main>"),
            FakeResponse(200, "<title>Please wait</title><main><p>Checking your browser before accessing the application.</p></main>"),
        ),
    )
    broker.request(RequestSpec("GET", "https://lab.test/"))

    outcome = broker.request(RequestSpec("GET", "https://lab.test/settings"))

    assert outcome.classification is Classification.SOFT_BAN
    assert outcome.next_actions == ["cool_down_target"]


def test_discover_artifacts_are_compact_and_quota_blocks_low_priority_writes(tmp_path):
    store = ArtifactStore(tmp_path, quota_bytes=100)

    first = store.write({"body": "x" * 500}, mode="discover")
    second = store.write({"body": "y" * 500}, mode="discover")

    assert first.stored is True
    assert first.sample_bytes <= 1024
    assert second.stored is False
    assert second.reason == "quota_exhausted"


def test_projection_captures_redirect_cookies_and_html_structure(tmp_path):
    response = FakeResponse(
        200,
        "<title>Portal</title><form action='/login'><input name='user'></form>"
        "<script src='/app.js'></script><a href='/admin'>Admin</a><p>Welcome home</p>",
        headers={"Set-Cookie": "sid=abc; HttpOnly", "X-Test": "one"},
        url="https://lab.test/login",
    )
    response.history = [object()]
    response.cookies = {"sid": "abc"}
    projection = RequestBroker(tmp_path, transport=SequenceTransport()).classify_response(
        RequestSpec("GET", "https://lab.test/"), response
    ).projection

    assert projection["redirect_count"] == 1
    assert projection["cookies"] == ["sid"]
    assert projection["html"]["title"] == "Portal"
    assert projection["html"]["forms"] == ["/login"]
    assert projection["html"]["script_count"] == 1
    assert projection["html"]["links"] == ["/admin"]


def test_block_cluster_similarity_scores_structurally_equivalent_interstitials():
    first = build_response_projection(FakeResponse(200, "<title>Please wait</title><main><p>Checking your browser</p></main>"))
    second = build_response_projection(FakeResponse(200, "<title>Please wait</title><main><p>Verifying your request</p></main>"))

    assert block_cluster_similarity(first, second) >= 0.7


def test_projection_captures_json_shape_and_sensitive_fields(tmp_path):
    projection = RequestBroker(tmp_path, transport=SequenceTransport()).classify_response(
        RequestSpec("GET", "https://lab.test/api/me"),
        FakeResponse(200, '{"code":0,"user":{"id":1,"token":"secret"}}', headers={"Content-Type": "application/json"}),
    ).projection

    assert projection["json"]["top_level_type"] == "object"
    assert projection["json"]["business_code"] == 0
    assert projection["json"]["key_paths"] == ["code", "user", "user.id", "user.token"]
    assert projection["json"]["sensitive_fields"] == ["user.token"]


def test_artifact_gc_removes_only_expired_unreferenced_telemetry(tmp_path):
    store = ArtifactStore(tmp_path, telemetry_retention_seconds=1, now=lambda: 100.0)
    stale = store.write({"body": "stale"}, mode="discover", target_id="lab")
    referenced = store.write({"body": "referenced"}, mode="discover", target_id="lab")
    protected = store.write({"body": "protected"}, mode="verify", target_id="lab", protected=True)
    store.add_reference(referenced.digest, "workflow", "wf-1")
    store.db.execute("UPDATE artifacts SET created_at=0")
    store.db.commit()

    removed = store.collect_garbage()

    assert stale.digest in removed
    assert referenced.digest not in removed
    assert protected.digest not in removed


def test_event_kernel_manifest_reference_protects_artifact_from_gc(tmp_path):
    store = ArtifactStore(tmp_path, telemetry_retention_seconds=1, now=lambda: 100.0)
    artifact = store.write({"body": "manifest-bound"}, mode="discover")
    store.register_event_kernel_manifest(artifact.digest, "attempt-manifest-1")
    store.db.execute("UPDATE artifacts SET created_at=0")
    store.db.commit()

    assert artifact.digest not in store.collect_garbage()


def test_discover_respects_per_target_quota(tmp_path):
    store = ArtifactStore(tmp_path, quota_bytes=10_000, target_quota_bytes=1)

    write = store.write({"body": "small"}, mode="discover", target_id="lab")

    assert write.stored is False
    assert write.reason == "target_quota_exhausted"


def test_broker_applies_selected_identity_to_transport_request(tmp_path):
    identities = IdentityPool()
    identities.register("owner", cookies={"sid": "cookie"}, bearer_token="token", csrf_token="csrf", user_agent="Owner UA")
    transport = SequenceTransport(FakeResponse(200, "<main>healthy application response</main>"))
    broker = RequestBroker(tmp_path, transport=transport, identity_pool=identities)

    broker.request(RequestSpec("GET", "https://lab.test/api", headers={"X-Request": "one"}, identity="owner"))

    headers = transport.calls[0][2]["headers"]
    assert headers["Authorization"] == "Bearer token"
    assert headers["X-CSRF-Token"] == "csrf"
    assert headers["User-Agent"] == "Owner UA"
    assert headers["Cookie"] == "sid=cookie"
    assert headers["X-Request"] == "one"


def test_broker_reads_repository_config_by_default(tmp_path):
    broker = RequestBroker(tmp_path, transport=SequenceTransport())

    assert broker.initial_cooldown_seconds == 30
    assert broker.max_cooldown_seconds == 600
    assert broker.hard_block_threshold == 5
    assert broker.artifacts.quota_bytes == 500 * 1024 * 1024
    assert broker.artifacts.target_quota_bytes == 100 * 1024 * 1024


def test_request_broker_public_api_exposes_projection_and_mitm_protocol_types():
    assert ResponseProjection.__name__ == "ResponseProjection"
    assert callable(build_response_projection)
    assert callable(block_cluster_similarity)
    assert DependentProcess.__name__ == "DependentProcess"
