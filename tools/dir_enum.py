"""Hunter v4 — Directory Enumerator

HTTP directory/path brute-force with intelligent filtering.
Falls back to ffuf if available for faster scanning.
"""

import sys
import time
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

DEFAULT_PATHS = [
    "admin", "login", "api", "console", "dashboard", "manager", "panel",
    "wp-admin", "wp-login.php", "administrator", "phpmyadmin", "phpinfo.php",
    ".git/config", ".git/HEAD", ".env", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "favicon.ico",
    "backup", "backup.sql", "backup.zip", "db", "database",
    "config", "config.php", "config.json", "config.yml", "settings",
    "debug", "test", "dev", "staging", "old", "temp", "tmp",
    "uploads", "upload", "files", "static", "assets", "public",
    "api/v1", "api/v2", "api/docs", "swagger", "swagger-ui",
    "graphql", "graphiql", "wsdl",
    ".svn/entries", ".DS_Store", "WEB-INF/web.xml",
    "server-status", "server-info", "info", "status",
    "readme", "README.md", "CHANGELOG", "LICENSE",
    "install", "setup", "register", "signup", "forgot",
    "user", "users", "account", "profile", "member",
    "search", "help", "support", "contact", "about",
    "feed", "rss", "atom", "sitemap",
    "cgi-bin", "bin", "scripts", "includes", "lib",
    "vendor", "node_modules", ".npm", ".cache",
    "log", "logs", "error.log", "access.log", "debug.log",
    "phpinfo", "info.php", "test.php", "shell.php", "cmd.php",
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "administrator/index.php", "admin.php", "login.php",
    "index.html", "index.htm", "index.php", "default.aspx",
    "app", "app.php", "main", "main.php", "home",
    "data", "storage", "cache", "temp", "export", "import",
    "upload.php", "download", "download.php", "file.php",
    "img", "images", "image", "media", "video", "audio",
    "css", "js", "fonts", "font", "icons",
    "api/auth", "api/user", "api/admin", "api/config",
    "api/health", "api/status", "api/version", "api/info",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "elmah.axd", "trace.axd", "web.config",
]


def dir_enum_impl(url: str, wordlist: str = "default", extensions: list[str] = None,
                  max_results: int = 50, timeout: int = 5, threads: int = 10) -> dict:
    """Enumerate directories and files on target."""
    start = time.time()
    base_url = url.rstrip("/")

    paths = DEFAULT_PATHS if wordlist == "default" else _load_wordlist(wordlist)

    candidates = list(paths)
    if extensions:
        for path in list(paths):
            if "." not in path.split("/")[-1]:
                for ext in extensions:
                    candidates.append(f"{path}.{ext}")

    session = _get_session()
    found = []
    baseline_size = _get_baseline_size(session, base_url, timeout)

    def check_path(path: str) -> Optional[dict]:
        url = f"{base_url}/{path}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            size = len(resp.text)
            status = resp.status_code

            if status == 404:
                return None
            if status == 200 and baseline_size and abs(size - baseline_size) < 50:
                return None

            redirect = resp.headers.get("Location", "") if status in (301, 302, 303, 307, 308) else None
            interesting = _is_interesting(path, status, size)

            return {
                "path": f"/{path}",
                "status": status,
                "size": size,
                "redirect": redirect,
                "interesting": interesting,
            }
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, p): p for p in candidates[:500]}
        for future in as_completed(futures):
            if len(found) >= max_results:
                break
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: (0 if x["interesting"] else 1, x["status"]))

    elapsed_ms = int((time.time() - start) * 1000)
    interesting_count = sum(1 for f in found if f["interesting"])

    return {
        "url": base_url,
        "found": found[:max_results],
        "total_checked": len(candidates),
        "interesting_count": interesting_count,
        "scan_time_ms": elapsed_ms,
    }


def _get_baseline_size(session, base_url: str, timeout: int) -> Optional[int]:
    try:
        resp = session.get(f"{base_url}/nonexistent_path_12345", timeout=timeout, allow_redirects=False)
        if resp.status_code == 200:
            return len(resp.text)
    except Exception:
        pass
    return None


def _is_interesting(path: str, status: int, size: int) -> bool:
    sensitive_patterns = [
        ".git", ".env", ".htpasswd", "backup", "config", "admin",
        "phpinfo", "debug", "log", "database", "db", "sql",
        ".svn", "WEB-INF", "server-status", "actuator", "elmah",
        "swagger", "graphql", "wp-admin", "phpmyadmin",
    ]
    path_lower = path.lower()
    if any(p in path_lower for p in sensitive_patterns):
        return True
    if status in (200, 301, 302) and size > 0:
        return True
    return False


def _load_wordlist(wordlist: str) -> list[str]:
    path = Path(wordlist)
    if path.exists():
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    return DEFAULT_PATHS
