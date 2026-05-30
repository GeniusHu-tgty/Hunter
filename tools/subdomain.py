# tools/subdomain.py
"""Hunter v4 — Subdomain Discovery"""

import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

BRUTE_PREFIXES = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "test", "dev", "staging", "beta", "alpha", "demo", "sandbox",
    "api", "app", "web", "portal", "admin", "panel", "dashboard",
    "blog", "forum", "wiki", "docs", "help", "support", "status",
    "cdn", "static", "media", "img", "images", "assets", "files",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "svn", "ci", "cd", "jenkins", "build",
    "monitor", "grafana", "prometheus", "kibana", "elk", "log",
    "auth", "sso", "login", "oauth", "ldap", "cas", "saml",
    "oa", "crm", "erp", "hr", "finance", "pay", "billing",
    "shop", "store", "ecommerce", "cart", "order", "payment",
    "mobile", "m", "wap", "ios", "android",
    "internal", "intranet", "corp", "office", "gateway",
    "proxy", "lb", "ha", "backup", "bak", "old", "archive",
]


def subdomain_impl(domain: str, methods: list[str] = None) -> dict:
    if methods is None:
        methods = ["crtsh", "dns_brute"]
    start = time.time()
    all_subdomains = {}

    if "crtsh" in methods:
        crtsh_results = _crtsh_search(domain)
        for sub, info in crtsh_results.items():
            all_subdomains[sub] = info

    if "dns_brute" in methods:
        brute_results = _dns_brute(domain)
        for sub, info in brute_results.items():
            if sub not in all_subdomains:
                all_subdomains[sub] = info

    if "subfinder" in methods:
        subfinder_results = _subfinder(domain)
        for sub, info in subfinder_results.items():
            if sub not in all_subdomains:
                all_subdomains[sub] = info

    for sub, info in all_subdomains.items():
        if not info.get("ip"):
            try:
                ip = socket.gethostbyname(sub)
                info["ip"] = ip
            except socket.gaierror:
                info["ip"] = ""

    elapsed_ms = int((time.time() - start) * 1000)
    return {
        "domain": domain,
        "subdomains": [{"subdomain": sub, "source": info.get("source", "unknown"), "ip": info.get("ip", "")} for sub, info in sorted(all_subdomains.items())],
        "total_found": len(all_subdomains),
        "elapsed_ms": elapsed_ms,
    }


def _crtsh_search(domain: str) -> dict:
    results = {}
    try:
        session = _get_session()
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            import json
            data = json.loads(resp.text)
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        results[sub] = {"source": "crtsh"}
    except Exception:
        pass
    return results


def _dns_brute(domain: str) -> dict:
    results = {}
    for prefix in BRUTE_PREFIXES:
        subdomain = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            results[subdomain] = {"source": "dns_brute", "ip": ip}
        except socket.gaierror:
            continue
    return results


def _subfinder(domain: str) -> dict:
    results = {}
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                sub = line.strip().lower()
                if sub:
                    results[sub] = {"source": "subfinder"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results
