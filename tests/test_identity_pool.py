from core.request_broker.identity import IdentityPool


def test_identity_pool_switches_namespaces_and_imports_browser_context():
    pool = IdentityPool()
    pool.register("owner", cookies={"sid": "abc"}, bearer_token="token", csrf_token="csrf")
    pool.import_browser_context("owner", {"cookies": {"browser": "yes"}, "user_agent": "Browser UA", "final_url": "https://lab.test/app"})

    identity = pool.switch("owner")

    assert identity.namespace == "owner"
    assert identity.headers()["Authorization"] == "Bearer token"
    assert identity.headers()["X-CSRF-Token"] == "csrf"
    assert identity.cookies == {"sid": "abc", "browser": "yes"}
    assert identity.final_url == "https://lab.test/app"


def test_identity_pool_keeps_refresh_token_inside_its_namespace():
    pool = IdentityPool()
    pool.register("owner", refresh_token="refresh-owner")
    pool.register("viewer", refresh_token="refresh-viewer")

    assert pool.switch("owner").refresh_token == "refresh-owner"
    assert pool.switch("viewer").refresh_token == "refresh-viewer"


def test_identity_pool_always_exposes_anonymous_namespace():
    assert IdentityPool().switch("anonymous").namespace == "anonymous"
