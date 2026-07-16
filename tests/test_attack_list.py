from core.request_broker.attack_list import build_attack_list


def test_attack_list_deduplicates_and_prioritizes_risky_endpoints():
    entries = build_attack_list([
        {"url": "https://lab.test/api/users/42", "method": "GET", "source": "openapi", "parameters": ["id"], "auth": "Bearer"},
        {"url": "https://lab.test/admin/export", "method": "POST", "source": "browser", "parameters": []},
        {"url": "https://lab.test/api/users/42", "method": "GET", "source": "burp", "parameters": ["id"]},
    ])

    assert len(entries) == 2
    assert entries[0]["url"].endswith("/admin/export")
    assert "admin" in entries[0]["risk_categories"]
    assert entries[1]["sources"] == ["burp", "openapi"]
