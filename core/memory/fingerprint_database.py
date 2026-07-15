"""Passive WAF, CDN, CMS, framework, and API fingerprint catalog."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Fingerprint:
    kind: str
    name: str
    version: str = ""
    header_rules: tuple[tuple[str, str], ...] = ()
    header_features: tuple[str, ...] = ()
    absent_header_rules: tuple[str, ...] = ()
    cookie_rules: tuple[str, ...] = ()
    meta_rules: tuple[str, ...] = ()
    body_rules: tuple[str, ...] = ()
    path_rules: tuple[str, ...] = ()
    host_rules: tuple[str, ...] = ()
    favicon_hashes: tuple[str, ...] = ()
    screenshot_rules: tuple[str, ...] = ()
    login_features: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    auth: str = ""
    endpoints: tuple[str, ...] = ()
    minimum_evidence: int = 1
    allow_weak_cookies: bool = False
    detection: str = ""


def _fp(
    kind: str,
    name: str,
    *,
    version: str = "",
    headers: Mapping[str, str] | None = None,
    header_features: Iterable[str] = (),
    absent_headers: Iterable[str] = (),
    cookies: Iterable[str] = (),
    meta: Iterable[str] = (),
    body: Iterable[str] = (),
    paths: Iterable[str] = (),
    hosts: Iterable[str] = (),
    favicon: Iterable[str] = (),
    screenshots: Iterable[str] = (),
    login_features: Iterable[str] = (),
    cves: Iterable[str] = (),
    auth: str = "",
    endpoints: Iterable[str] = (),
    minimum_evidence: int = 1,
    allow_weak_cookies: bool = False,
) -> Fingerprint:
    return Fingerprint(
        kind=kind,
        name=name,
        version=version,
        header_rules=tuple((str(key).casefold(), str(value).casefold()) for key, value in (headers or {}).items()),
        header_features=tuple(str(item).casefold() for item in header_features),
        absent_header_rules=tuple(
            str(item).casefold() for item in absent_headers
        ),
        cookie_rules=tuple(str(item).casefold() for item in cookies),
        meta_rules=tuple(str(item).casefold() for item in meta),
        body_rules=tuple(str(item).casefold() for item in body),
        path_rules=tuple(str(item).casefold() for item in paths),
        host_rules=tuple(str(item).casefold() for item in hosts),
        favicon_hashes=tuple(str(item).casefold() for item in favicon),
        screenshot_rules=tuple(str(item).casefold() for item in screenshots),
        login_features=tuple(str(item) for item in login_features),
        cves=tuple(str(item) for item in cves),
        auth=auth,
        endpoints=tuple(str(item) for item in endpoints),
        minimum_evidence=max(1, int(minimum_evidence)),
        allow_weak_cookies=bool(allow_weak_cookies),
        detection=f"Matched passive {kind} signature for {name}.",
    )


WAF_NAMES = (
    "Cloudflare", "Akamai Kona", "AWS WAF", "Imperva", "F5 BIG-IP ASM",
    "Barracuda WAF", "Fortinet FortiWeb", "Sucuri", "Radware AppWall",
    "Citrix NetScaler WAF", "ModSecurity", "NAXSI", "Wallarm",
    "Wordfence", "Comodo WAF", "Palo Alto Prisma WAF", "Azure WAF",
    "Google Cloud Armor", "Alibaba Cloud WAF", "Tencent Cloud WAF",
    "Huawei Cloud WAF", "Fastly Next-Gen WAF", "Reblaze", "Signal Sciences",
    "StackPath WAF", "DenyAll", "Positive Technologies PT AF",
    "Qualys WAF", "Ergon WAF", "AppTrana", "Defender for Cloud",
    "Sucuri CloudProxy",
)

CDN_SPECS = (
    ("Cloudflare", {"server": "cloudflare"}, ("/cdn-cgi/",)),
    ("Akamai", {"x-akamai-transformed": ""}, ()),
    ("Fastly", {"x-served-by": ""}, ()),
    ("Amazon CloudFront", {"via": "cloudfront"}, ()),
    ("Azure Front Door", {"x-azure-ref": ""}, ()),
    ("Google Cloud CDN", {"via": "google"}, ()),
    ("Bunny CDN", {"server": "bunnycdn"}, ()),
    ("KeyCDN", {"x-edge-location": ""}, ()),
    ("StackPath", {"x-sp-cdn": ""}, ()),
    ("Alibaba CDN", {"ali-swift-global-savetime": ""}, ()),
    ("Tencent EdgeOne", {"x-nws-log-uuid": ""}, ()),
    ("QUIC.cloud", {"x-qc-cache": ""}, ()),
)

CMS_NAMES = (
    "WordPress", "Joomla", "Drupal", "Magento", "PrestaShop", "TYPO3",
    "Ghost", "Strapi", "Umbraco", "Kentico", "Sitecore", "DNN",
    "Concrete CMS", "Craft CMS", "OctoberCMS", "SilverStripe", "Moodle",
    "Shopify", "Wix", "Squarespace", "Webflow", "WooCommerce", "OpenCart",
    "osCommerce", "Zen Cart", "Shopware", "BigCommerce", "Mautic",
    "Chamilo", "MediaWiki", "phpBB", "vBulletin", "MyBB", "Discourse",
    "Flarum", "Grav", "Kirby", "Pimcore", "Contao", "Bolt CMS", "MODX",
    "ExpressionEngine", "Plone", "Orchard Core", "Textpattern", "Pico CMS",
    "ProcessWire", "Backdrop CMS", "Microweber", "Liferay", "Jekyll",
    "Hugo", "Contentful", "Sanity", "Directus", "Payload CMS",
)

FRAMEWORK_NAMES = (
    "Django", "Flask", "FastAPI", "Ruby on Rails", "Laravel", "Symfony",
    "CodeIgniter", "Yii", "CakePHP", "Express", "NestJS", "Koa", "Hapi",
    "Next.js", "Nuxt", "SvelteKit", "ASP.NET Core", "ASP.NET MVC",
    "Spring Boot", "Spring MVC", "Struts", "JSF", "Jakarta EE", "Tomcat",
    "Play Framework", "Phoenix", "Gin", "Echo", "Fiber", "Actix Web",
    "Rocket", "Axum", "Fiber Go", "Fastify", "AdonisJS", "Remix",
    "Angular", "React", "Vue", "Grails",
)

_WEAK_COOKIE_NAMES = {
    "session",
    "sessionid",
    "jsessionid",
    "phpsessid",
    "sid",
    "_session",
}

_WEAK_PATH_EVIDENCE = {
    "/admin",
    "/api",
    "/docs",
    "/login",
    "/static",
    "/system",
    "/user/login",
}


def _seed_header_rules(
    values: Iterable[Any],
) -> tuple[dict[str, str], tuple[str, ...]]:
    rules: dict[str, str] = {}
    features: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        if ":" in text:
            key, expected = text.split(":", 1)
            key = key.strip()
            if key:
                rules[key] = expected.strip()
                continue
        features.append(text)
    return rules, tuple(features)


def _merge_signature(first: Fingerprint, second: Fingerprint) -> Fingerprint:
    def merged(*values: Iterable[Any]) -> tuple[Any, ...]:
        return tuple(dict.fromkeys(item for group in values for item in group))

    body_rules = merged(first.body_rules, second.body_rules)
    if first.kind == "cms" and second.meta_rules:
        # The legacy catalog used the product name as a broad body substring.
        # Seeded CMS entries have HTML-meta evidence, which is less noisy.
        body_rules = tuple(second.body_rules)
    return Fingerprint(
        kind=first.kind,
        name=first.name,
        version=second.version or first.version,
        header_rules=merged(first.header_rules, second.header_rules),
        header_features=merged(first.header_features, second.header_features),
        absent_header_rules=merged(
            first.absent_header_rules,
            second.absent_header_rules,
        ),
        cookie_rules=merged(first.cookie_rules, second.cookie_rules),
        meta_rules=merged(first.meta_rules, second.meta_rules),
        body_rules=body_rules,
        path_rules=merged(first.path_rules, second.path_rules),
        host_rules=merged(first.host_rules, second.host_rules),
        favicon_hashes=merged(first.favicon_hashes, second.favicon_hashes),
        screenshot_rules=merged(first.screenshot_rules, second.screenshot_rules),
        login_features=merged(first.login_features, second.login_features),
        cves=merged(first.cves, second.cves),
        auth=second.auth or first.auth,
        endpoints=merged(first.endpoints, second.endpoints),
        minimum_evidence=max(
            first.minimum_evidence,
            second.minimum_evidence,
        ),
        allow_weak_cookies=(
            first.allow_weak_cookies or second.allow_weak_cookies
        ),
        detection=second.detection or first.detection,
    )


def _load_memory_seed_catalog(
    signatures: Iterable[Fingerprint],
) -> list[Fingerprint]:
    catalog = list(signatures)
    try:
        from scripts.seed_memory import (
            CMS_SEEDS,
            EDU_SYSTEM_SEEDS,
            FRAMEWORK_SEEDS,
        )
    except (ImportError, ModuleNotFoundError):
        return catalog

    indexes = {
        (item.kind.casefold(), item.name.casefold()): index
        for index, item in enumerate(catalog)
    }
    for kind, records in (("cms", CMS_SEEDS), ("framework", FRAMEWORK_SEEDS)):
        for record in records:
            headers, header_features = _seed_header_rules(record.get("headers", ()))
            signature = _fp(
                kind,
                str(record["name"]),
                headers=headers,
                header_features=header_features,
                cookies=record.get("cookies", ()),
                meta=record.get("meta", ()),
                paths=record.get("paths", ()),
            )
            key = (kind, signature.name.casefold())
            if key in indexes:
                index = indexes[key]
                catalog[index] = _merge_signature(catalog[index], signature)
            else:
                indexes[key] = len(catalog)
                catalog.append(signature)
    for record in EDU_SYSTEM_SEEDS:
        headers, header_features = _seed_header_rules(
            record.get("headers", ())
        )
        signature = _fp(
            "edu",
            str(record["name"]),
            headers=headers,
            header_features=header_features,
            absent_headers=record.get("absent_headers", ()),
            cookies=record.get("cookies", ()),
            body=record.get("body", ()),
            paths=record.get("paths", ()),
            hosts=record.get("hosts", ()),
            login_features=record.get("login_features", ()),
            auth=str(record.get("auth") or ""),
            endpoints=record.get("endpoints", ()),
            minimum_evidence=int(record.get("minimum_evidence") or 1),
            allow_weak_cookies=bool(
                record.get("allow_weak_cookies", False)
            ),
        )
        key = ("edu", signature.name.casefold())
        if key in indexes:
            index = indexes[key]
            catalog[index] = _merge_signature(catalog[index], signature)
        else:
            indexes[key] = len(catalog)
            catalog.append(signature)
    return catalog


def _seed_catalog() -> list[Fingerprint]:
    signatures: list[Fingerprint] = []
    for name in WAF_NAMES:
        rules: dict[str, str] = {}
        body = [name]
        if name == "Cloudflare":
            rules = {"server": "cloudflare"}
            body = ["attention required", "cloudflare ray id"]
        elif name == "AWS WAF":
            rules = {"x-amzn-waf-action": ""}
        elif name == "Imperva":
            rules = {"x-iinfo": ""}
        elif name == "ModSecurity":
            rules = {"server": "mod_security"}
        signatures.append(
            _fp(
                "waf",
                name,
                headers=rules,
                body=body,
                screenshots=body,
            )
        )

    for name, headers, paths in CDN_SPECS:
        signatures.append(_fp("cdn", name, headers=headers, paths=paths))

    cms_paths = {
        "WordPress": ("/wp-admin", "/wp-content", "/wp-includes"),
        "Joomla": ("/administrator", "/components/com_"),
        "Drupal": ("/core/misc/drupal.js", "/sites/default"),
        "Magento": ("/static/version", "/customer/account"),
        "PrestaShop": ("/modules/", "/themes/"),
        "TYPO3": ("/typo3/", "/typo3conf/"),
        "Ghost": ("/ghost/", "/assets/ghost"),
        "Strapi": ("/admin/", "/api/"),
        "Moodle": ("/login/index.php", "/lib/javascript.php"),
        "MediaWiki": ("/w/load.php", "/wiki/"),
        "Shopify": ("/cdn/shop/", "/cart.js"),
        "WooCommerce": ("/wp-content/plugins/woocommerce",),
        "phpBB": ("/styles/", "/ucp.php"),
        "Discourse": ("/assets/discourse", "/session/csrf"),
    }
    cms_logins = {
        "WordPress": ("/wp-login.php", "user_login"),
        "Joomla": ("/administrator/index.php", "mod-login-username"),
        "Drupal": ("/user/login", "edit-name"),
        "Magento": ("/admin/", "login-form"),
        "Moodle": ("/login/index.php", "username"),
        "Ghost": ("/ghost/#/signin",),
        "Strapi": ("/admin/auth/login",),
        "MediaWiki": ("/wiki/Special:UserLogin",),
    }
    cms_cves = {
        "WordPress": ("CVE-2022-21661",),
        "Joomla": ("CVE-2023-23752",),
        "Drupal": ("CVE-2018-7600",),
        "Magento": ("CVE-2022-24086",),
    }
    for name in CMS_NAMES:
        paths = cms_paths.get(name, (f"/{name.lower().replace(' ', '').replace('.', '')}",))
        body = [name]
        if name == "WordPress":
            body = ['name="generator" content="wordpress']
        signatures.append(
            _fp(
                "cms",
                name,
                paths=paths,
                body=body,
                login_features=cms_logins.get(name, ()),
                cves=cms_cves.get(name, ()),
            )
        )

    framework_paths = {
        "Django": ("/static/admin/",),
        "Laravel": ("/_ignition/",),
        "Express": ("/socket.io/",),
        "Next.js": ("/_next/static/",),
        "ASP.NET Core": ("/_framework/",),
        "Spring Boot": ("/actuator/",),
        "Tomcat": ("/manager/html",),
        "FastAPI": ("/docs", "/openapi.json"),
        "Flask": ("/static/",),
    }
    for name in FRAMEWORK_NAMES:
        paths = framework_paths.get(name, ())
        signatures.append(_fp("framework", name, paths=paths, body=[name]))

    api_specs = (
        ("Kong", ("/services", "/routes"), "API key or OAuth2"),
        ("Apigee", ("/v1/", "/oauth/token"), "OAuth2"),
        ("AWS API Gateway", ("/restapis", "/execute-api"), "IAM/API key"),
        ("Azure API Management", ("/swagger", "/status-0123456789abcdef"), "subscription key/OAuth2"),
        ("Tyk", ("/tyk/", "/hello"), "API key/OAuth2"),
        ("KrakenD", ("/__health",), "API key/JWT"),
        ("WSO2 API Manager", ("/publisher", "/store"), "OAuth2"),
        ("MuleSoft Anypoint", ("/cloudhub",), "OAuth2"),
        ("GraphQL", ("/graphql",), "Bearer/session"),
        ("Hasura", ("/v1/graphql", "/v1/metadata"), "admin secret/JWT"),
        ("Swagger/OpenAPI", ("/swagger.json", "/openapi.json"), "endpoint-defined"),
        ("gRPC Gateway", ("/grpc.health.v1.Health",), "mTLS/JWT"),
    )
    for name, paths, auth in api_specs:
        signatures.append(_fp("api", name, paths=paths, auth=auth, endpoints=paths))
    return _load_memory_seed_catalog(signatures)


class FingerprintDatabase:
    """In-memory seeded catalog with passive, confidence-scored matching."""

    def __init__(self, signatures: Iterable[Fingerprint] | None = None) -> None:
        self.signatures = list(signatures or _seed_catalog())

    def counts(self) -> dict[str, int]:
        return {
            kind: sum(1 for item in self.signatures if item.kind == kind)
            for kind in ("waf", "cdn", "cms", "edu", "framework", "api")
        }

    def list(self, kind: str = "") -> list[dict[str, Any]]:
        selected = [item for item in self.signatures if not kind or item.kind == kind.casefold()]
        return [self._public(item) for item in selected]

    def detect(self, observations: Mapping[str, Any] | None) -> dict[str, Any]:
        data = dict(observations or {})
        raw_headers = data.get("headers")
        headers_observed = isinstance(raw_headers, Mapping)
        headers = {
            str(key).casefold(): str(value).casefold()
            for key, value in (raw_headers or {}).items()
        }
        rendered_headers = " ".join(
            f"{key}: {value}" for key, value in headers.items()
        )
        cookies = self._normalise_cookies(
            data.get("cookies"),
            "; ".join(
                value
                for value in (
                    headers.get("cookie", ""),
                    headers.get("set-cookie", ""),
                )
                if value
            ),
        )
        body = str(data.get("body") or "").casefold()
        paths = [str(path).casefold() for path in (data.get("paths") or [])]
        raw_url = str(
            data.get("url")
            or data.get("target_url")
            or ""
        ).strip()
        parsed_url = urlsplit(raw_url)
        if raw_url and not parsed_url.hostname:
            parsed_url = urlsplit(f"//{raw_url}")
        if parsed_url.path and parsed_url.path != "/":
            paths.append(parsed_url.path.casefold())
        hosts = [
            str(value).casefold().strip()
            for value in (
                data.get("host"),
                data.get("hostname"),
                data.get("domain"),
                parsed_url.hostname,
            )
            if value
        ]
        favicon = str(data.get("favicon_hash") or "").casefold()
        matches: dict[str, list[dict[str, Any]]] = {}

        for signature in self.signatures:
            evidence: list[dict[str, Any]] = []
            for key, expected in signature.header_rules:
                actual = headers.get(key, "")
                if key in headers and (not expected or expected in actual):
                    evidence.append({"source": "header", "key": key, "value": actual[:256]})
            for expected in signature.header_features:
                if expected and (
                    expected in headers or expected in rendered_headers
                ):
                    evidence.append({"source": "header", "match": expected[:160]})
            if headers_observed:
                for expected in signature.absent_header_rules:
                    if expected and expected not in headers:
                        evidence.append(
                            {
                                "source": "header-absence",
                                "match": expected[:160],
                            }
                        )
            for expected in signature.cookie_rules:
                if expected and self._cookie_matches(
                    expected,
                    cookies,
                    allow_weak=signature.allow_weak_cookies,
                ):
                    evidence.append({"source": "cookie", "match": expected[:160]})
            for expected in signature.meta_rules:
                if expected and self._meta_matches(expected, body):
                    evidence.append({"source": "meta", "match": expected[:160]})
            for expected in signature.body_rules:
                if expected and self._body_matches(expected, body):
                    evidence.append({"source": "body", "match": expected[:160]})
            for expected in signature.path_rules:
                if any(expected in path for path in paths):
                    evidence.append({"source": "path", "match": expected[:160]})
            for expected in signature.host_rules:
                if any(fnmatch.fnmatch(host, expected) for host in hosts):
                    evidence.append({"source": "host", "match": expected[:160]})
            if favicon and favicon in signature.favicon_hashes:
                evidence.append({"source": "favicon_hash", "match": favicon})
            screenshot_text = str(data.get("screenshot_text") or "").casefold()
            for expected in signature.screenshot_rules:
                if expected and expected in screenshot_text:
                    evidence.append({"source": "screenshot_text", "match": expected[:160]})
            if len(evidence) < signature.minimum_evidence:
                continue
            if signature.kind in {"cms", "framework", "api"} and evidence:
                only_paths = all(item.get("source") == "path" for item in evidence)
                weak_paths = all(
                    str(item.get("match") or "").rstrip("/")
                    in _WEAK_PATH_EVIDENCE
                    for item in evidence
                )
                if only_paths and weak_paths:
                    continue
            score = min(0.99, 0.5 + 0.15 * len(evidence))
            public = self._public(signature)
            detected_version = self._detect_version(
                signature,
                body,
                rendered_headers,
            )
            if detected_version:
                public["version"] = detected_version
            matches.setdefault(signature.kind, []).append(
                {
                    **public,
                    "confidence": round(score, 2),
                    "evidence": evidence,
                }
            )

        selected: dict[str, Any] = {}
        for kind, candidates in matches.items():
            candidates.sort(key=lambda item: (-item["confidence"], item["name"]))
            selected[kind] = candidates[0]
        confidence = 0.0
        if selected:
            confidence = round(
                sum(item["confidence"] for item in selected.values()) / len(selected),
                2,
            )
        return {
            "waf": selected.get("waf"),
            "cdn": selected.get("cdn"),
            "cms": selected.get("cms"),
            "edu": selected.get("edu"),
            "framework": selected.get("framework"),
            "api": selected.get("api"),
            "language": self._infer_language(selected),
            "database": None,
            "confidence": confidence,
            "matches": matches,
            "evidence": [
                evidence
                for item in selected.values()
                if isinstance(item, dict)
                for evidence in item.get("evidence", [])
            ],
        }

    @staticmethod
    def _normalise_cookies(value: Any, cookie_header: str = "") -> tuple[str, ...]:
        cookies: list[str] = []
        if isinstance(value, Mapping):
            for key, item in value.items():
                cookies.extend(
                    (
                        str(key).casefold(),
                        f"{key}={item}".casefold(),
                    )
                )
        elif isinstance(value, (list, tuple, set)):
            cookies.extend(str(item).casefold() for item in value)
        elif value not in (None, ""):
            cookies.append(str(value).casefold())
        if cookie_header:
            cookies.extend(
                part.strip().casefold()
                for part in str(cookie_header).split(";")
                if part.strip()
            )
        return tuple(cookies)

    @staticmethod
    def _cookie_matches(
        expected: str,
        cookies: Iterable[str],
        *,
        allow_weak: bool = False,
    ) -> bool:
        expected_name = str(expected).casefold().strip()
        if expected_name in _WEAK_COOKIE_NAMES and not allow_weak:
            return False
        allow_prefix = expected_name.endswith(("_", "-"))
        for cookie in cookies:
            cookie_name = str(cookie).split("=", 1)[0].strip().casefold()
            if cookie_name == expected_name:
                return True
            if allow_prefix and cookie_name.startswith(expected_name):
                return True
        return False

    @staticmethod
    def _body_matches(expected: str, body: str) -> bool:
        if not expected:
            return False
        if re.fullmatch(r"[a-z0-9 .+#_-]+", expected):
            return re.search(
                rf"(?<![a-z0-9_]){re.escape(expected)}(?![a-z0-9_])",
                body,
                flags=re.IGNORECASE,
            ) is not None
        return expected in body

    @staticmethod
    def _meta_matches(expected: str, body: str) -> bool:
        tags = re.findall(r"<meta\b[^>]*>", body, flags=re.IGNORECASE)
        return any(expected in tag for tag in tags)

    @staticmethod
    def _detect_version(
        signature: Fingerprint,
        body: str,
        rendered_headers: str,
    ) -> str:
        if signature.version:
            return signature.version
        name = re.escape(signature.name.casefold())
        expression = (
            rf"\b{name}\b(?:[/\s_-]+)"
            rf"(?:v(?:ersion)?[\s:=_-]*)?"
            rf"(\d+(?:\.\d+){{1,3}})"
        )
        match = re.search(expression, f"{rendered_headers} {body}")
        return match.group(1) if match else ""

    @staticmethod
    def _infer_language(selected: Mapping[str, Any]) -> str | None:
        framework = str((selected.get("framework") or {}).get("name", "")).casefold()
        if any(name in framework for name in ("django", "flask", "fastapi")):
            return "Python"
        if any(name in framework for name in ("laravel", "symfony", "php")):
            return "PHP"
        if any(name in framework for name in ("asp.net", ".net")):
            return "C#"
        if any(name in framework for name in ("spring", "java", "tomcat", "struts")):
            return "Java"
        if any(name in framework for name in ("node", "express", "next", "nuxt", "react", "vue")):
            return "JavaScript"
        return None

    @staticmethod
    def _public(item: Fingerprint) -> dict[str, Any]:
        headers = [
            f"{key}: {value}" if value else key
            for key, value in item.header_rules
        ]
        headers.extend(item.header_features)
        return {
            "kind": item.kind,
            "name": item.name,
            "version": item.version,
            "headers": headers,
            "absent_headers": list(item.absent_header_rules),
            "cookies": list(item.cookie_rules),
            "meta": list(item.meta_rules),
            "paths": list(item.path_rules),
            "hosts": list(item.host_rules),
            "cves": list(item.cves),
            "auth": item.auth,
            "default_endpoints": list(item.endpoints),
            "login_features": list(item.login_features),
            "screenshot_features": list(item.screenshot_rules),
            "minimum_evidence": item.minimum_evidence,
            "detection": item.detection,
        }


__all__ = ["Fingerprint", "FingerprintDatabase"]
