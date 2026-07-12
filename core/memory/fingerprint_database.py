"""Passive WAF, CDN, CMS, framework, and API fingerprint catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class Fingerprint:
    kind: str
    name: str
    version: str = ""
    header_rules: tuple[tuple[str, str], ...] = ()
    body_rules: tuple[str, ...] = ()
    path_rules: tuple[str, ...] = ()
    favicon_hashes: tuple[str, ...] = ()
    screenshot_rules: tuple[str, ...] = ()
    login_features: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    auth: str = ""
    endpoints: tuple[str, ...] = ()
    detection: str = ""


def _fp(
    kind: str,
    name: str,
    *,
    version: str = "",
    headers: Mapping[str, str] | None = None,
    body: Iterable[str] = (),
    paths: Iterable[str] = (),
    favicon: Iterable[str] = (),
    screenshots: Iterable[str] = (),
    login_features: Iterable[str] = (),
    cves: Iterable[str] = (),
    auth: str = "",
    endpoints: Iterable[str] = (),
) -> Fingerprint:
    return Fingerprint(
        kind=kind,
        name=name,
        version=version,
        header_rules=tuple((str(key).casefold(), str(value).casefold()) for key, value in (headers or {}).items()),
        body_rules=tuple(str(item).casefold() for item in body),
        path_rules=tuple(str(item).casefold() for item in paths),
        favicon_hashes=tuple(str(item).casefold() for item in favicon),
        screenshot_rules=tuple(str(item).casefold() for item in screenshots),
        login_features=tuple(str(item) for item in login_features),
        cves=tuple(str(item) for item in cves),
        auth=auth,
        endpoints=tuple(str(item) for item in endpoints),
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
    return signatures


class FingerprintDatabase:
    """In-memory seeded catalog with passive, confidence-scored matching."""

    def __init__(self, signatures: Iterable[Fingerprint] | None = None) -> None:
        self.signatures = list(signatures or _seed_catalog())

    def counts(self) -> dict[str, int]:
        return {
            kind: sum(1 for item in self.signatures if item.kind == kind)
            for kind in ("waf", "cdn", "cms", "framework", "api")
        }

    def list(self, kind: str = "") -> list[dict[str, Any]]:
        selected = [item for item in self.signatures if not kind or item.kind == kind.casefold()]
        return [self._public(item) for item in selected]

    def detect(self, observations: Mapping[str, Any] | None) -> dict[str, Any]:
        data = dict(observations or {})
        headers = {
            str(key).casefold(): str(value).casefold()
            for key, value in (data.get("headers") or {}).items()
        }
        body = str(data.get("body") or "").casefold()
        paths = [str(path).casefold() for path in (data.get("paths") or [])]
        favicon = str(data.get("favicon_hash") or "").casefold()
        matches: dict[str, list[dict[str, Any]]] = {}

        for signature in self.signatures:
            evidence: list[dict[str, Any]] = []
            for key, expected in signature.header_rules:
                actual = headers.get(key, "")
                if key in headers and (not expected or expected in actual):
                    evidence.append({"source": "header", "key": key, "value": actual[:256]})
            for expected in signature.body_rules:
                if expected and expected in body:
                    evidence.append({"source": "body", "match": expected[:160]})
            for expected in signature.path_rules:
                if any(expected in path for path in paths):
                    evidence.append({"source": "path", "match": expected[:160]})
            if favicon and favicon in signature.favicon_hashes:
                evidence.append({"source": "favicon_hash", "match": favicon})
            screenshot_text = str(data.get("screenshot_text") or "").casefold()
            for expected in signature.screenshot_rules:
                if expected and expected in screenshot_text:
                    evidence.append({"source": "screenshot_text", "match": expected[:160]})
            if not evidence:
                continue
            score = min(0.99, 0.5 + 0.15 * len(evidence))
            matches.setdefault(signature.kind, []).append(
                {
                    **self._public(signature),
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
        return {
            "kind": item.kind,
            "name": item.name,
            "version": item.version,
            "cves": list(item.cves),
            "auth": item.auth,
            "default_endpoints": list(item.endpoints),
            "login_features": list(item.login_features),
            "screenshot_features": list(item.screenshot_rules),
            "detection": item.detection,
        }


__all__ = ["Fingerprint", "FingerprintDatabase"]
