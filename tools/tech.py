# tools/tech.py
"""Hunter v4 — Technology Fingerprinting

Identifies web technologies from HTTP responses, headers, cookies, and HTML.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

FRAMEWORKS = {
    "ThinkPHP": {
        "headers": [r"X-Powered-By:\s*ThinkPHP"],
        "cookies": [r"thinkphp_show_page_trace"],
        "body": [r"ThinkPHP\s*[\d.]+", r"thinkphp_show_page_trace"],
    },
    "Laravel": {
        "headers": [r"X-Powered-By:\s*Laravel"],
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "body": [r"csrf-token", r"laravel"],
    },
    "Django": {
        "headers": [r"X-Frame-Options:\s*DENY"],
        "cookies": [r"csrftoken", r"sessionid"],
        "body": [r"csrfmiddlewaretoken", r"django"],
    },
    "Flask": {
        "headers": [r"Server:\s*Werkzeug"],
        "cookies": [r"session=ey"],
        "body": [r"Werkzeug", r"Flask"],
    },
    "Express": {
        "headers": [r"X-Powered-By:\s*Express"],
        "body": [r"express"],
    },
    "Spring": {
        "headers": [r"X-Application-Context"],
        "body": [r"Whitelabel Error Page", r"spring"],
    },
    "WordPress": {
        "body": [r"wp-content", r"wp-includes", r"wordpress", r"wp-json"],
        "cookies": [r"wordpress_"],
    },
    "Drupal": {
        "body": [r"Drupal", r"drupal\.js", r"sites/default/files"],
        "cookies": [r"SSESS.*"],
    },
    "React": {
        "body": [r"react", r"__NEXT_DATA__", r"_next/static"],
    },
    "Vue.js": {
        "body": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"data-v-"],
    },
    "Angular": {
        "body": [r"ng-version", r"angular", r"ng-app"],
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"_next/static", r"nextjs"],
    },
    "Nginx": {"headers": [r"Server:\s*nginx"]},
    "Apache": {"headers": [r"Server:\s*Apache"]},
    "IIS": {"headers": [r"Server:\s*Microsoft-IIS"]},
    "Tomcat": {
        "headers": [r"Server:\s*Apache-Coyote"],
        "body": [r"Apache Tomcat"],
    },
}

CMS_MAP = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"Drupal", r"drupal\.js"],
    "Joomla": [r"joomla", r"/media/jui/"],
    "Magento": [r"magento", r"skin/frontend"],
    "Shopify": [r"shopify", r"cdn\.shopify\.com"],
}

WAF_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
    "Akamai": [r"akamai", r"X-Akamai-Transformed"],
    "AWS WAF": [r"x-amzn-RequestId", r"awselb"],
    "ModSecurity": [r"mod_security", r"NOYB"],
    "Incapsula": [r"incap_ses", r"visid_incap"],
    "Sucuri": [r"sucuri", r"X-Sucuri-ID"],
}

LANGUAGE_HINTS = {
    "PHP": [r"X-Powered-By:\s*PHP", r"\.php", r"PHPSESSID"],
    "Java": [r"JSESSIONID", r"\.jsp", r"\.do", r"\.action"],
    "Python": [r"Python", r"Django", r"Flask", r"Werkzeug"],
    "Ruby": [r"Ruby", r"Rails", r"_session_id="],
    "ASP.NET": [r"X-Powered-By:\s*ASP\.NET", r"\.aspx", r"ASP\.NET"],
    "Node.js": [r"X-Powered-By:\s*Express", r"connect\.sid"],
}

KNOWN_VULNS = {
    "ThinkPHP 5.0": ["ThinkPHP 5.0.x RCE (CVE-2018-20062)"],
    "ThinkPHP 5.1": ["ThinkPHP 5.1.x RCE (CVE-2018-20062)", "ThinkPHP 5.1.x SQLi (CVE-2019-9082)"],
    "Apache 2.4.49": ["Apache 2.4.49 Path Traversal (CVE-2021-41773)"],
    "Apache 2.4.50": ["Apache 2.4.50 Path Traversal (CVE-2021-42013)"],
    "OpenSSL 1.0.1": ["Heartbleed (CVE-2014-0160)"],
    "OpenSSH 7.4": ["OpenSSH 7.4 User Enumeration (CVE-2018-15473)"],
}


def _match_patterns(text: str, patterns: dict) -> dict:
    results = {}
    for key, regexes in patterns.items():
        for regex in regexes:
            if re.search(regex, text, re.I):
                results[key] = regex
                break
    return results


def tech_impl(url: str) -> dict:
    """Identify technologies used by target."""
    session = _get_session()

    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookies_text = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())
    body = resp.text
    all_text = f"{headers_text}\n{cookies_text}\n{body}"

    frameworks = _match_patterns(all_text, FRAMEWORKS)
    cms = _match_patterns(all_text, CMS_MAP)
    wafs = _match_patterns(all_text, WAF_SIGNATURES)
    languages = _match_patterns(all_text, LANGUAGE_HINTS)

    technologies = {
        "server": resp.headers.get("Server", ""),
        "language": next(iter(languages.keys()), None),
        "framework": next(iter(frameworks.keys()), None),
        "cms": next(iter(cms.keys()), None),
        "waf": next(iter(wafs.keys()), None),
    }

    evidence = {}
    for k, v in {**frameworks, **cms, **wafs, **languages}.items():
        evidence[k] = v

    known_vulns = []
    for tech_key, vulns in KNOWN_VULNS.items():
        if tech_key.lower() in all_text.lower():
            known_vulns.extend(vulns)

    return {
        "url": url,
        "technologies": technologies,
        "evidence": evidence,
        "known_vulns": known_vulns,
        "status": resp.status_code,
        "headers": dict(resp.headers),
    }
