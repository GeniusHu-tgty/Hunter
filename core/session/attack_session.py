"""Persistent state container for an authorized multi-step assessment."""

from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .secret_store import SecretStore


_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"
)
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
_REDACTED = "[REDACTED]"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _safe_name(value: str, kind: str) -> str:
    if not _SAFE_NAME_RE.fullmatch(value or ""):
        raise ValueError(f"invalid {kind}: {value!r}")
    return value


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return (
        "password" in normalized
        or "passwd" in normalized
        or normalized == "pwd"
        or "token" in normalized
        or "secret" in normalized
        or "cookie" in normalized
        or "csrf" in normalized
        or normalized in {
            "auth",
            "authorization",
            "proxy_authorization",
            "apikey",
            "api_key",
            "extra_fields",
            "hidden",
        }
        or normalized.startswith("auth_")
        or normalized.endswith("_auth")
    )


def _mask_structure(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _mask_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_structure(item) for item in value]
    if isinstance(value, tuple):
        return [_mask_structure(item) for item in value]
    return _REDACTED


def _sensitive_values(value: Any, inherited_sensitive: bool = False) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.update(
                _sensitive_values(
                    item,
                    inherited_sensitive=inherited_sensitive or _is_sensitive_key(key),
                )
            )
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.update(_sensitive_values(item, inherited_sensitive))
    elif inherited_sensitive and value not in {None, ""}:
        found.add(str(value))
    return found


def redact_sensitive(
    value: Any,
    sensitive_values: set[str] | None = None,
) -> Any:
    replacements = sorted(
        {item for item in (sensitive_values or set()) if item},
        key=len,
        reverse=True,
    )
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if _is_sensitive_key(key):
                redacted[key] = _mask_structure(item)
            else:
                redacted[key] = redact_sensitive(item, set(replacements))
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item, set(replacements)) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item, set(replacements)) for item in value]
    if isinstance(value, str):
        result = value
        for secret in replacements:
            result = result.replace(secret, _REDACTED)
        return result
    return deepcopy(value)


def _decode_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain three segments")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode()).decode("utf-8")
        value = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JWT payload") from exc
    if not isinstance(value, dict):
        raise ValueError("JWT payload must be an object")
    return value


def _response_view(response: Any) -> dict[str, Any]:
    if isinstance(response, dict):
        headers = response.get("headers") or {}
        body = response.get("body", response.get("text", ""))
        json_value = response.get("json")
        if json_value is None and isinstance(body, str):
            try:
                json_value = json.loads(body)
            except (TypeError, json.JSONDecodeError):
                pass
        return {
            "url": str(response.get("url") or ""),
            "status_code": int(response.get("status_code") or 0),
            "headers": {str(key): str(value) for key, value in dict(headers).items()},
            "body": str(body or ""),
            "json": json_value,
        }

    headers = {
        str(key): str(value)
        for key, value in dict(getattr(response, "headers", {}) or {}).items()
    }
    body = str(getattr(response, "text", "") or "")
    json_value = None
    json_method = getattr(response, "json", None)
    if callable(json_method):
        try:
            json_value = json_method()
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return {
        "url": str(getattr(response, "url", "") or ""),
        "status_code": int(getattr(response, "status_code", 0) or 0),
        "headers": headers,
        "body": body,
        "json": json_value,
    }


class _HTMLInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[dict[str, Any]] = []
        self.forms: dict[str, str] = {}
        self.hidden: dict[str, str] = {}
        self.csrf: dict[str, str] = {}
        self.redirects: list[str] = []
        self.messages: list[str] = []
        self.scripts: list[str] = []
        self._stack: list[dict[str, Any]] = []
        self._textarea: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None
        self._message: dict[str, Any] | None = None
        self._script: list[str] | None = None

    @staticmethod
    def _attrs(attrs) -> dict[str, str]:
        return {str(key).lower(): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        values = self._attrs(attrs)
        element = {"tag": tag, "attrs": values, "text": ""}
        self.elements.append(element)
        self._stack.append(element)

        if tag == "input":
            name = values.get("name", "")
            value = values.get("value", "")
            if name:
                self.forms[name] = value
                if values.get("type", "").lower() == "hidden":
                    self.hidden[name] = value
                lowered = name.lower()
                if (
                    "csrf" in lowered
                    or "xsrf" in lowered
                    or lowered
                    in {"_token", "token", "authenticity_token", "execution", "lt"}
                ):
                    self.csrf[name] = value
        elif tag == "meta":
            name = values.get("name", "")
            if "csrf" in name.lower() and values.get("content"):
                self.csrf[name] = values["content"]
            if values.get("http-equiv", "").lower() == "refresh":
                match = re.search(r"url\s*=\s*(.+)", values.get("content", ""), re.I)
                if match:
                    self.redirects.append(match.group(1).strip(" '\""))
        elif tag == "textarea":
            self._textarea = {"name": values.get("name", ""), "parts": []}
        elif tag == "select":
            self._select = {"name": values.get("name", ""), "value": "", "fallback": ""}
        elif tag == "option" and self._select is not None:
            option_value = values.get("value", "")
            if not self._select["fallback"]:
                self._select["fallback"] = option_value
            if "selected" in values:
                self._select["value"] = option_value
        elif tag == "script":
            self._script = []

        marker = " ".join(
            [values.get("id", ""), values.get("class", ""), values.get("role", "")]
        ).lower()
        if any(word in marker for word in ("alert", "error", "message", "notice")):
            self._message = {"tag": tag, "parts": []}

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._stack:
            self._stack[-1]["text"] += data
        if self._textarea is not None:
            self._textarea["parts"].append(data)
        if self._message is not None:
            self._message["parts"].append(data)
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea" and self._textarea is not None:
            name = self._textarea["name"]
            if name:
                self.forms[name] = "".join(self._textarea["parts"]).strip()
            self._textarea = None
        elif tag == "select" and self._select is not None:
            name = self._select["name"]
            if name:
                self.forms[name] = self._select["value"] or self._select["fallback"]
            self._select = None
        elif tag == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None

        if self._message is not None and tag == self._message["tag"]:
            value = " ".join("".join(self._message["parts"]).split())
            if value:
                self.messages.append(value)
            self._message = None

        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index]["tag"] == tag:
                del self._stack[index:]
                break


def _make_cookie(
    name: str,
    value: str,
    domain: str,
    path: str = "/",
    expires: int | None = None,
    secure: bool = False,
    host_only: bool = False,
) -> Cookie:
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=bool(domain) and not host_only,
        domain_initial_dot=domain.startswith("."),
        path=path or "/",
        path_specified=True,
        secure=secure,
        expires=expires,
        discard=expires is None,
        comment=None,
        comment_url=None,
        rest={},
        rfc2109=False,
    )


class AttackSession:
    VALID_STATES = {"discovery", "auth", "scan", "exploit", "post_exploit"}

    def __init__(
        self,
        target: str,
        storage_dir: str | Path,
        session_id: str | None = None,
        headers: dict[str, str] | None = None,
        fingerprint_headers: dict[str, str] | None = None,
        authorization: dict[str, Any] | None = None,
    ) -> None:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if not parsed.hostname:
            raise ValueError("target must be a URL or domain")
        self.session_id = _safe_name(
            session_id or f"attack-{uuid.uuid4().hex[:12]}", "session id"
        )
        self.target = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.hostname}"
        self.storage_dir = Path(storage_dir).resolve()
        self.secret_store = SecretStore(self.storage_dir)
        self.cookies = CookieJar()
        self.headers = dict(headers or {})
        self.fingerprint_headers = dict(fingerprint_headers or {})
        self.csrf_tokens: dict[str, dict[str, str]] = {}
        self.auth_tokens: dict[str, str] = {}
        self.state = "discovery"
        self.history: list[dict[str, Any]] = []
        self.extracted_data: dict[str, Any] = {}
        self.checkpoints: dict[str, dict[str, Any]] = {}
        self.blockers: list[dict[str, Any]] = []
        self.chain_cursors: dict[str, dict[str, Any]] = {}
        supplied_authorization = deepcopy(authorization or {})
        allowed_origins = supplied_authorization.get("allowed_origins") or [
            self.origin(self.target)
        ]
        allowed_methods = supplied_authorization.get("allowed_methods") or [
            "GET",
            "HEAD",
            "OPTIONS",
        ]
        self.authorization = {
            "approval_id": str(supplied_authorization.get("approval_id") or ""),
            "approved_by": str(supplied_authorization.get("approved_by") or ""),
            "allowed_origins": sorted(
                {self.origin(value) for value in allowed_origins}
            ),
            "allowed_methods": sorted(
                {str(value).upper() for value in allowed_methods}
            ),
            "evidence_ids": sorted(
                {
                    str(value)
                    for value in supplied_authorization.get("evidence_ids", [])
                }
            ),
            "capabilities": sorted(
                {
                    str(value)
                    for value in supplied_authorization.get("capabilities", [])
                }
            ),
            "post_exploit_actions": sorted(
                {
                    str(value)
                    for value in supplied_authorization.get(
                        "post_exploit_actions", []
                    )
                }
            ),
        }
        self.authentication = {
            "verified": False,
            "evidence": {},
            "verified_at": "",
        }
        self.created_at = _now()
        self.updated_at = self.created_at

    @staticmethod
    def origin(value: str) -> str:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        scheme = parsed.scheme or "https"
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{(parsed.hostname or '').lower()}:{port}"

    def authorize_request(self, method: str, url: str) -> None:
        origin = self.origin(url)
        if origin not in set(self.authorization.get("allowed_origins", [])):
            raise PermissionError(f"request origin is outside authorized scope: {origin}")
        method = method.upper()
        if method not in set(self.authorization.get("allowed_methods", [])):
            raise PermissionError(f"request method is not authorized: {method}")

    def mark_authenticated(self, evidence: dict[str, Any]) -> None:
        if not evidence.get("url") or not evidence.get("evidence"):
            raise ValueError("authentication proof requires url and evidence")
        if self.origin(str(evidence["url"])) not in set(
            self.authorization.get("allowed_origins", [])
        ):
            raise ValueError("authentication proof is outside authorized scope")
        self.authentication = {
            "verified": True,
            "evidence": deepcopy(evidence),
            "verified_at": _now(),
        }

    @property
    def directory(self) -> Path:
        return self.storage_dir / self.session_id

    @property
    def state_path(self) -> Path:
        return self.directory / "session.json"

    def merge_headers(self, custom: dict[str, str] | None = None) -> dict[str, str]:
        merged = dict(self.fingerprint_headers)
        merged.update(self.headers)
        merged.update(custom or {})
        return merged

    def update_cookies(self, values: dict[str, Any], default_url: str = "") -> None:
        parsed = urlparse(default_url or self.target)
        default_domain = parsed.hostname or urlparse(self.target).hostname or ""
        records = []
        for name, raw in values.items():
            spec = raw if isinstance(raw, dict) else {"value": raw}
            records.append(
                {
                    "name": str(name),
                    "value": str(spec.get("value", "")),
                    "domain": str(spec.get("domain") or default_domain),
                    "path": str(spec.get("path") or "/"),
                    "expires": spec.get("expires"),
                    "secure": bool(spec.get("secure", False)),
                    "host_only": bool(
                        spec.get("host_only", "domain" not in spec)
                    ),
                }
            )
        self.update_cookie_records(records)

    def update_cookie_records(self, records: list[dict[str, Any]]) -> None:
        for spec in records:
            expires = spec.get("expires")
            if isinstance(expires, str):
                try:
                    expires = int(parsedate_to_datetime(expires).timestamp())
                except (TypeError, ValueError, OverflowError):
                    expires = None
            cookie = _make_cookie(
                str(spec.get("name", "")),
                str(spec.get("value", "")),
                str(spec.get("domain") or urlparse(self.target).hostname or ""),
                str(spec.get("path") or "/"),
                int(expires) if expires is not None else None,
                bool(spec.get("secure", False)),
                bool(spec.get("host_only", False)),
            )
            self.cookies.set_cookie(cookie)
        self.cookies.clear_expired_cookies()

    def _capture_set_cookie(self, header: str, url: str) -> None:
        if not header:
            return
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            return
        values: dict[str, Any] = {}
        for name, morsel in parsed.items():
            domain = morsel["domain"] or urlparse(url or self.target).hostname
            path = morsel["path"] or "/"
            if morsel["max-age"]:
                try:
                    if int(morsel["max-age"]) <= 0:
                        try:
                            self.cookies.clear(domain, path, name)
                        except KeyError:
                            pass
                        continue
                except ValueError:
                    pass
            expires = None
            if morsel["expires"]:
                try:
                    expires = int(parsedate_to_datetime(morsel["expires"]).timestamp())
                except (TypeError, ValueError, OverflowError):
                    pass
            values[name] = {
                "value": morsel.value,
                "domain": domain,
                "path": path,
                "expires": expires,
                "secure": bool(morsel["secure"]),
                "host_only": not bool(morsel["domain"]),
            }
        self.update_cookies(values, default_url=url)

    def cookie_dict(self) -> dict[str, str]:
        self.cookies.clear_expired_cookies()
        return {cookie.name: cookie.value for cookie in self.cookies}

    def cookie_header(self, url: str = "") -> str:
        parsed = urlparse(url or self.target)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"
        pairs = []
        self.cookies.clear_expired_cookies()
        for cookie in self.cookies:
            domain = cookie.domain.lstrip(".")
            if not cookie.domain_specified and hostname != domain:
                continue
            if (
                cookie.domain_specified
                and domain
                and hostname != domain
                and not hostname.endswith(f".{domain}")
            ):
                continue
            if cookie.path and not path.startswith(cookie.path):
                continue
            if cookie.secure and parsed.scheme != "https":
                continue
            pairs.append(f"{cookie.name}={cookie.value}")
        return "; ".join(pairs)

    def _cookie_records(self) -> list[dict[str, Any]]:
        self.cookies.clear_expired_cookies()
        return [
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "expires": cookie.expires,
                "secure": cookie.secure,
                "host_only": not cookie.domain_specified,
            }
            for cookie in self.cookies
        ]

    def _runtime_snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "session_id": self.session_id,
            "target": self.target,
            "cookies": self._cookie_records(),
            "headers": deepcopy(self.headers),
            "fingerprint_headers": deepcopy(self.fingerprint_headers),
            "csrf_tokens": deepcopy(self.csrf_tokens),
            "auth_tokens": deepcopy(self.auth_tokens),
            "state": self.state,
            "history": deepcopy(self.history),
            "extracted_data": deepcopy(self.extracted_data),
            "checkpoints": deepcopy(self.checkpoints),
            "blockers": deepcopy(self.blockers),
            "chain_cursors": deepcopy(self.chain_cursors),
            "authorization": deepcopy(self.authorization),
            "authentication": deepcopy(self.authentication),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state_path": str(self.state_path),
        }

    def snapshot(self) -> dict[str, Any]:
        return self._runtime_snapshot()

    def public_snapshot(self) -> dict[str, Any]:
        value = self._runtime_snapshot()
        for cookie in value["cookies"]:
            cookie["value"] = _REDACTED
        value["headers"] = {
            key: _REDACTED for key in value["headers"]
        }
        value["fingerprint_headers"] = {
            key: _REDACTED for key in value["fingerprint_headers"]
        }
        value["csrf_tokens"] = _mask_structure(value["csrf_tokens"])
        value["auth_tokens"] = _mask_structure(value["auth_tokens"])
        value["history"] = redact_sensitive(value["history"])
        value["extracted_data"] = redact_sensitive(value["extracted_data"])
        value["blockers"] = redact_sensitive(value["blockers"])
        value["chain_cursors"] = {
            name: redact_sensitive(
                {
                    key: item
                    for key, item in cursor.items()
                    if key != "last_response"
                }
            )
            for name, cursor in value["chain_cursors"].items()
        }
        value["authentication"] = redact_sensitive(value["authentication"])
        return value

    def persisted_state(self) -> dict[str, Any]:
        value = self._runtime_snapshot()
        secret_fields = (
            "cookies",
            "headers",
            "csrf_tokens",
            "auth_tokens",
            "extracted_data",
            "chain_cursors",
            "authorization",
            "authentication",
        )
        secrets = {field: value.pop(field) for field in secret_fields}
        value["sealed_secrets"] = self.secret_store.seal(secrets)
        value["secret_fields"] = list(secret_fields)
        return value

    def decrypt_persisted_state(self, value: dict[str, Any]) -> dict[str, Any]:
        result = deepcopy(value)
        token = result.pop("sealed_secrets", "")
        result.pop("secret_fields", None)
        if token:
            secrets = self.secret_store.open(token)
            if not isinstance(secrets, dict):
                raise ValueError("attack-session secret payload must be an object")
            result.update(secrets)
        return result

    def save(self) -> dict[str, Any]:
        self.updated_at = _now()
        value = self.persisted_state()
        _atomic_json_write(self.state_path, value)
        return self.public_snapshot()

    @classmethod
    def load(cls, session_id: str, storage_dir: str | Path) -> "AttackSession":
        session_id = _safe_name(session_id, "session id")
        path = Path(storage_dir).resolve() / session_id / "session.json"
        if not path.is_file():
            raise KeyError(f"attack session not found: {session_id}")
        stored = json.loads(path.read_text(encoding="utf-8-sig"))
        session = cls(
            stored["target"],
            storage_dir=storage_dir,
            session_id=stored["session_id"],
            fingerprint_headers=stored.get("fingerprint_headers"),
        )
        value = session.decrypt_persisted_state(stored)
        session.headers = deepcopy(value.get("headers", {}))
        session.update_cookie_records(
            [
                item
                for item in value.get("cookies", [])
                if isinstance(item, dict) and item.get("name")
            ]
        )
        session.csrf_tokens = deepcopy(value.get("csrf_tokens", {}))
        session.auth_tokens = deepcopy(value.get("auth_tokens", {}))
        session.state = value.get("state", "discovery")
        session.history = deepcopy(value.get("history", []))
        session.extracted_data = deepcopy(value.get("extracted_data", {}))
        session.checkpoints = deepcopy(value.get("checkpoints", {}))
        session.blockers = deepcopy(value.get("blockers", []))
        session.chain_cursors = deepcopy(value.get("chain_cursors", {}))
        session.authorization = deepcopy(
            value.get("authorization", session.authorization)
        )
        session.authentication = deepcopy(
            value.get("authentication", session.authentication)
        )
        session.created_at = value.get("created_at", _now())
        session.updated_at = value.get("updated_at", session.created_at)
        return session

    def save_checkpoint(self, name: str) -> dict[str, Any]:
        name = _safe_name(name, "checkpoint name")
        created_at = _now()
        path = self.directory / "checkpoints" / f"{name}.json"
        body = {
            "checkpoint_name": name,
            "session_id": self.session_id,
            "created_at": created_at,
            "state": self.persisted_state(),
        }
        _atomic_json_write(path, body)
        self.checkpoints[name] = {"path": str(path), "created_at": created_at}
        self.save()
        return {"name": name, "path": str(path), "created_at": created_at}

    def restore_checkpoint(self, name: str) -> dict[str, Any]:
        name = _safe_name(name, "checkpoint name")
        metadata = self.checkpoints.get(name)
        path = (
            Path(metadata["path"])
            if metadata
            else self.directory / "checkpoints" / f"{name}.json"
        )
        if not path.is_file():
            raise KeyError(f"checkpoint not found: {name}")
        body = json.loads(path.read_text(encoding="utf-8-sig"))
        state = self.decrypt_persisted_state(body["state"])
        if state.get("session_id") != self.session_id:
            raise ValueError("checkpoint session mismatch")
        known_checkpoints = deepcopy(self.checkpoints)
        restored = AttackSession.load_from_snapshot(state, self.storage_dir)
        self.__dict__.update(restored.__dict__)
        self.checkpoints.update(known_checkpoints)
        self.checkpoints.setdefault(
            name,
            {"path": str(path), "created_at": body.get("created_at", _now())},
        )
        self.record_history(
            "checkpoint.restore",
            {"checkpoint": name, "path": str(path)},
        )
        self.save()
        return {"name": name, "path": str(path), "state": self.public_snapshot()}

    @classmethod
    def load_from_snapshot(
        cls, value: dict[str, Any], storage_dir: str | Path
    ) -> "AttackSession":
        session = cls(
            value["target"],
            storage_dir=storage_dir,
            session_id=value["session_id"],
            headers=value.get("headers"),
            fingerprint_headers=value.get("fingerprint_headers"),
            authorization=value.get("authorization"),
        )
        session.update_cookie_records(
            [
                item
                for item in value.get("cookies", [])
                if isinstance(item, dict) and item.get("name")
            ]
        )
        for field in (
            "csrf_tokens",
            "auth_tokens",
            "history",
            "extracted_data",
            "checkpoints",
            "blockers",
            "chain_cursors",
        ):
            setattr(session, field, deepcopy(value.get(field, getattr(session, field))))
        session.authentication = deepcopy(
            value.get("authentication", session.authentication)
        )
        session.state = value.get("state", "discovery")
        session.created_at = value.get("created_at", _now())
        session.updated_at = value.get("updated_at", session.created_at)
        return session

    def record_history(
        self,
        operation: str,
        details: dict[str, Any] | None = None,
        elapsed: float | None = None,
    ) -> dict[str, Any]:
        item = {
            "timestamp": _now(),
            "operation": operation,
            "details": redact_sensitive(details or {}),
        }
        if elapsed is not None:
            item["elapsed"] = round(float(elapsed), 6)
        self.history.append(item)
        self.history = self.history[-1000:]
        return item

    def set_state(self, state: str) -> None:
        if state not in self.VALID_STATES:
            raise ValueError(f"invalid attack state: {state}")
        self.state = state

    def csrf_for_url(self, url: str) -> dict[str, str]:
        if url in self.csrf_tokens:
            return deepcopy(self.csrf_tokens[url])
        parsed = urlparse(url)
        best: dict[str, str] = {}
        for page, values in self.csrf_tokens.items():
            page_url = urlparse(page)
            if page_url.netloc == parsed.netloc:
                best.update(values)
        return best

    def extract_from_response(self, pattern: str, response: Any) -> Any:
        view = _response_view(response)
        if pattern.startswith("regex:"):
            match = re.search(pattern[6:], view["body"], re.I | re.S)
            if not match:
                raise ValueError("regex did not match")
            return match.group(1) if match.lastindex else match.group(0)
        if pattern.startswith("jsonpath:"):
            return self._jsonpath(pattern[9:], view["json"])
        if pattern.startswith("jwt:"):
            token = pattern[4:].strip()
            if not token:
                token = next(iter(_JWT_RE.findall(view["body"])), "")
            return _decode_jwt(token)
        if pattern.startswith("css:"):
            return self._css(pattern[4:], view["body"])
        if pattern.startswith("xpath:"):
            return self._xpath(pattern[6:], view["body"])

        match = re.search(pattern, view["body"], re.I | re.S)
        if not match:
            raise ValueError("pattern did not match")
        return match.group(1) if match.lastindex else match.group(0)

    @staticmethod
    def _jsonpath(path: str, value: Any) -> Any:
        if value is None:
            raise ValueError("response has no JSON body")
        path = path.strip()
        if path == "$":
            return value
        if not path.startswith("$."):
            raise ValueError("JSONPath must start with $.")
        tokens = re.findall(r"([A-Za-z_][\w-]*)|\[(\d+)\]", path[2:])
        current = value
        for key, index in tokens:
            current = current[int(index)] if index else current[key]
        return current

    @staticmethod
    def _inventory(body: str) -> _HTMLInventory:
        inventory = _HTMLInventory()
        inventory.feed(body or "")
        return inventory

    @classmethod
    def _css(cls, selector: str, body: str) -> Any:
        text_mode = selector.endswith("::text")
        attribute_match = re.search(r"::attr\(([^)]+)\)$", selector)
        selector = re.sub(r"::(?:text|attr\([^)]+\))$", "", selector).strip()
        inventory = cls._inventory(body)
        for element in inventory.elements:
            attrs = element["attrs"]
            matched = False
            if selector.startswith("#"):
                matched = attrs.get("id") == selector[1:]
            elif selector.startswith("."):
                matched = selector[1:] in attrs.get("class", "").split()
            elif re.fullmatch(r"[A-Za-z][\w-]*", selector):
                matched = element["tag"] == selector.lower()
            if matched:
                if attribute_match:
                    return attrs.get(attribute_match.group(1).lower())
                if text_mode:
                    return " ".join(element["text"].split())
                return {"tag": element["tag"], "attrs": attrs, "text": element["text"]}
        raise ValueError("CSS selector did not match")

    @classmethod
    def _xpath(cls, expression: str, body: str) -> Any:
        match = re.fullmatch(
            r"//([A-Za-z][\w-]*)(?:\[@([\w-]+)=['\"]([^'\"]+)['\"]\])?(?:/@([\w-]+)|/text\(\))?",
            expression.strip(),
        )
        if not match:
            raise ValueError("unsupported XPath expression")
        tag, filter_attr, filter_value, output_attr = match.groups()
        inventory = cls._inventory(body)
        for element in inventory.elements:
            attrs = element["attrs"]
            if element["tag"] != tag.lower():
                continue
            if filter_attr and attrs.get(filter_attr.lower()) != filter_value:
                continue
            if output_attr:
                return attrs.get(output_attr.lower())
            return " ".join(element["text"].split())
        raise ValueError("XPath did not match")

    def auto_extract(self, response: Any) -> dict[str, Any]:
        view = _response_view(response)
        page_url = view["url"] or self.target
        inventory = self._inventory(view["body"])
        set_cookie = next(
            (
                value
                for key, value in view["headers"].items()
                if key.lower() == "set-cookie"
            ),
            "",
        )
        self._capture_set_cookie(set_cookie, page_url)

        csrf = dict(inventory.csrf)
        if csrf:
            self.csrf_tokens.setdefault(page_url, {}).update(csrf)

        authorization = next(
            (
                value
                for key, value in view["headers"].items()
                if key.lower() == "authorization"
            ),
            "",
        )
        if authorization.lower().startswith("bearer "):
            bearer = authorization.split(None, 1)[1].strip()
            self.auth_tokens["bearer"] = bearer
            if _JWT_RE.fullmatch(bearer):
                self.auth_tokens["jwt"] = bearer

        jwt_values = _JWT_RE.findall(view["body"])
        api_values: dict[str, str] = {}

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    lowered = str(key).lower()
                    if lowered in {
                        "key",
                        "api_key",
                        "apikey",
                        "token",
                        "access_token",
                        "bearer",
                    } and isinstance(child, (str, int, float)):
                        api_values[lowered] = str(child)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
            elif isinstance(value, str) and _JWT_RE.fullmatch(value):
                jwt_values.append(value)

        walk(view["json"])
        for key, value in api_values.items():
            token_type = "api_key" if "key" in key else key
            self.auth_tokens[token_type] = value
        if jwt_values:
            self.auth_tokens["jwt"] = jwt_values[0]

        redirects = []
        location = next(
            (
                value
                for key, value in view["headers"].items()
                if key.lower() == "location"
            ),
            "",
        )
        if location:
            redirects.append(urljoin(page_url, location))
        redirects.extend(urljoin(page_url, value) for value in inventory.redirects)
        for script in inventory.scripts:
            for match in re.finditer(
                r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
                script,
                re.I,
            ):
                redirects.append(urljoin(page_url, match.group(1)))
        redirects = list(dict.fromkeys(redirects))

        result = {
            "page_url": page_url,
            "csrf_tokens": csrf,
            "forms": inventory.forms,
            "hidden": inventory.hidden,
            "auth_tokens": deepcopy(self.auth_tokens),
            "redirects": redirects,
            "messages": list(dict.fromkeys(inventory.messages)),
        }
        self.extracted_data.setdefault("forms", {}).update(inventory.forms)
        self.extracted_data.setdefault("hidden", {}).update(inventory.hidden)
        self.extracted_data["redirects"] = redirects
        self.extracted_data["messages"] = result["messages"]
        self.record_history(
            "response.extract",
            {
                "url": page_url,
                "status_code": view["status_code"],
                "csrf": sorted(csrf),
                "auth": sorted(self.auth_tokens),
                "redirects": redirects,
            },
        )
        return result


class AttackSessionStore:
    def __init__(self, storage_dir: str | Path) -> None:
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, AttackSession] = {}

    def create(
        self,
        target_url: str,
        session_id: str | None = None,
        headers: dict[str, str] | None = None,
        fingerprint_headers: dict[str, str] | None = None,
        authorization: dict[str, Any] | None = None,
    ) -> AttackSession:
        session = AttackSession(
            target_url,
            storage_dir=self.storage_dir,
            session_id=session_id,
            headers=headers,
            fingerprint_headers=fingerprint_headers,
            authorization=authorization,
        )
        session.record_history("session.start", {"target": session.target})
        session.save()
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> AttackSession:
        session_id = _safe_name(session_id, "session id")
        if session_id not in self._sessions:
            self._sessions[session_id] = AttackSession.load(
                session_id, storage_dir=self.storage_dir
            )
        return self._sessions[session_id]

    def list(self) -> list[dict[str, Any]]:
        result = []
        for path in sorted(self.storage_dir.glob("*/session.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            result.append(
                {
                    "session_id": value.get("session_id"),
                    "target": value.get("target"),
                    "state": value.get("state"),
                    "updated_at": value.get("updated_at"),
                }
            )
        return result
