from core.recon.asset_priority import AssetPriority, PriorityAsset


def test_priority_asset_exposes_classification_details():
    asset = AssetPriority().classify_asset(
        "https://example.test/app",
        "192.0.2.10",
        [443],
        ["nginx"],
        200,
    )

    assert isinstance(asset, PriorityAsset)
    assert asset.url == "https://example.test/app"
    assert asset.ip == "192.0.2.10"
    assert asset.priority == "P2"
    assert asset.status == 200
    assert asset.ports == (443,)
    assert asset.technologies == ("nginx",)
    assert asset.attack_clues
    assert asset.reasons


def test_p0_sensitive_paths_are_case_insensitive_and_variant_tolerant():
    scanner = AssetPriority()

    for url in (
        "https://example.test/.ENV",
        "https://example.test/.git/config",
        "https://example.test/phpMyAdmin/",
        "https://example.test/swagger-ui/index.html",
        "https://example.test/actuator/health",
    ):
        asset = scanner.classify_asset(url, "192.0.2.20", [], [], 200)
        assert asset.priority == "P0", url


def test_p0_dangerous_ports_accept_common_recon_shapes():
    scanner = AssetPriority()
    port_inputs = (
        [6379],
        ["9200/tcp"],
        {27017: "mongodb"},
        [{"port": 11211, "state": "open"}],
        [{"portid": "2375", "protocol": "tcp"}],
        {"ports": [{"number": 6379}]},
    )

    for ports in port_inputs:
        asset = scanner.classify_asset("http://example.test", "192.0.2.30", ports, [], 200)
        assert asset.priority == "P0", ports


def test_closed_dangerous_port_does_not_trigger_p0():
    asset = AssetPriority().classify_asset(
        "http://example.test",
        "192.0.2.31",
        [{"port": 6379, "state": "closed"}],
        [],
        200,
    )

    assert asset.priority == "P2"


def test_p1_paths_frameworks_and_403_status():
    scanner = AssetPriority()

    assert scanner.classify_asset("https://x.test/ADMIN/", "", [], [], 200).priority == "P1"
    assert scanner.classify_asset("https://x.test/user-login", "", [], [], 200).priority == "P1"
    assert scanner.classify_asset("https://x.test/file_upload", "", [], [], 200).priority == "P1"
    assert scanner.classify_asset("https://x.test/api/v2/users", "", [], [], 200).priority == "P1"
    assert scanner.classify_asset("https://x.test/", "", [], ["Spring Boot"], 200).priority == "P1"
    assert scanner.classify_asset("https://x.test/", "", [], [], "HTTP/1.1 403 Forbidden").priority == "P1"


def test_lowest_priority_number_wins_over_other_signals():
    asset = AssetPriority().classify_asset(
        "https://example.test/.git/config",
        "192.0.2.40",
        [443],
        ["WordPress"],
        503,
    )

    assert asset.priority == "P0"


def test_p2_and_p3_fallback_rules():
    scanner = AssetPriority()

    live = scanner.classify_asset("https://example.test/app", "", [8080], ["nginx"], 200)
    static = scanner.classify_asset("https://example.test/index.html", "", [443], ["Static HTML"], 200)
    missing = scanner.classify_asset("https://example.test/missing", "", [443], [], 404)
    unavailable = scanner.classify_asset("https://example.test/", "", [443], [], 503)

    assert live.priority == "P2"
    assert static.priority == "P3"
    assert missing.priority == "P3"
    assert unavailable.priority == "P3"


def test_attack_clue_mapping_has_broad_technology_coverage():
    scanner = AssetPriority()

    assert len(scanner.TECHNOLOGY_ATTACK_CLUES) >= 15
    expectations = {
        "PHP": ("SQLi", "LFI"),
        "ASP.NET": ("MSSQL SQLi", "ViewState"),
        "Spring Boot": ("Actuator", "Spring4Shell"),
        "Laravel": ("APP_KEY",),
        "Django": ("debug",),
        "WordPress": ("plugin",),
    }

    for technology, clues in expectations.items():
        asset = scanner.classify_asset("https://example.test/", "", [], [technology], 200)
        joined = " ".join(asset.attack_clues).lower()
        for clue in clues:
            assert clue.lower() in joined, (technology, clue, asset.attack_clues)


def test_attack_surface_summary_is_printable_and_sorted_by_priority():
    scanner = AssetPriority()
    assets = [
        scanner.classify_asset("https://p3.test/missing", "192.0.2.3", [], [], 404),
        scanner.classify_asset("https://p1.test/admin", "192.0.2.1", [443], ["Django"], 200),
        scanner.classify_asset("http://p0.test", "192.0.2.0", [6379], ["Redis"], 200),
        scanner.classify_asset("https://p2.test/app", "192.0.2.2", [443], ["nginx"], 200),
    ]

    summary = scanner.attack_surface_summary(assets)

    assert isinstance(summary, str)
    assert summary.index("P0") < summary.index("P1") < summary.index("P2") < summary.index("P3")
    assert summary.index("http://p0.test") < summary.index("https://p1.test/admin")
    assert "Attack Surface Summary" in summary
    assert "192.0.2.0" in summary
    assert "Redis" in summary
