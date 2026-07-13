"""Extract login form structure and prepare attack-chain parameters."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse


_ACTION_KEYWORDS = ("login", "signin", "auth", "logon", "sso", "cas")
_IDENTITY_KEYWORDS = ("user", "account", "email", "phone")
_TOKEN_NAMES = (
    "csrf",
    "xsrf",
    "token",
    "_token",
    "authenticity_token",
    "execution",
    "lt",
)


def _attrs(values) -> dict[str, str]:
    return {
        str(name).lower(): "" if value is None else str(value)
        for name, value in values
    }


def _token_field(name: str) -> bool:
    lowered = name.strip().lower()
    return (
        "csrf" in lowered
        or "xsrf" in lowered
        or "token" in lowered
        or lowered in {"execution", "lt", "authenticity_token", "_token"}
    )


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None
        self._textarea: dict[str, Any] | None = None
        self._button: dict[str, Any] | None = None

    @staticmethod
    def _field(
        values: dict[str, str],
        field_type: str,
        default_value: str = "",
    ) -> dict[str, str]:
        return {
            "name": values.get("name", ""),
            "type": field_type,
            "default_value": default_value,
            "placeholder": values.get("placeholder", ""),
        }

    def _finish_form(self) -> None:
        if self._form is not None:
            self.forms.append(self._form)
        self._form = None
        self._select = None
        self._textarea = None
        self._button = None

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        values = _attrs(attrs)
        if tag == "form":
            if self._form is not None:
                self._finish_form()
            self._form = {
                "raw_action": values.get("action", ""),
                "raw_method": values.get("method", ""),
                "fields": [],
                "has_csrf": False,
                "submit_button": {},
            }
            return
        if self._form is None:
            return

        if tag == "input":
            field_type = (values.get("type") or "text").lower()
            name = values.get("name", "")
            if name:
                self._form["fields"].append(
                    self._field(values, field_type, values.get("value", ""))
                )
                if _token_field(name):
                    self._form["has_csrf"] = True
            if (
                field_type in {"submit", "image"}
                and not self._form["submit_button"]
            ):
                self._form["submit_button"] = {
                    "name": name,
                    "value": values.get("value", ""),
                }
        elif tag == "select":
            self._select = {
                "attrs": values,
                "options": [],
            }
        elif tag == "option" and self._select is not None:
            self._select["options"].append(
                {
                    "value": values.get("value"),
                    "selected": "selected" in values,
                    "parts": [],
                }
            )
        elif tag == "textarea":
            self._textarea = {"attrs": values, "parts": []}
        elif tag == "button":
            button_type = (values.get("type") or "submit").lower()
            if button_type == "submit":
                self._button = {"attrs": values, "parts": []}

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._select is not None and self._select["options"]:
            self._select["options"][-1]["parts"].append(data)
        if self._textarea is not None:
            self._textarea["parts"].append(data)
        if self._button is not None:
            self._button["parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form":
            self._finish_form()
            return
        if self._form is None:
            return

        if tag == "select" and self._select is not None:
            values = self._select["attrs"]
            name = values.get("name", "")
            if name:
                options = self._select["options"]
                selected = next(
                    (option for option in options if option["selected"]),
                    options[0] if options else None,
                )
                default_value = ""
                if selected is not None:
                    text = "".join(selected["parts"]).strip()
                    default_value = (
                        text if selected["value"] is None else selected["value"]
                    )
                self._form["fields"].append(
                    self._field(values, "select", default_value)
                )
                if _token_field(name):
                    self._form["has_csrf"] = True
            self._select = None
        elif tag == "textarea" and self._textarea is not None:
            values = self._textarea["attrs"]
            name = values.get("name", "")
            if name:
                self._form["fields"].append(
                    self._field(
                        values,
                        "textarea",
                        "".join(self._textarea["parts"]).strip(),
                    )
                )
                if _token_field(name):
                    self._form["has_csrf"] = True
            self._textarea = None
        elif tag == "button" and self._button is not None:
            if not self._form["submit_button"]:
                values = self._button["attrs"]
                self._form["submit_button"] = {
                    "name": values.get("name", ""),
                    "value": values.get("value")
                    or "".join(self._button["parts"]).strip(),
                }
            self._button = None

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self._finish_form()


class FormExtractor:
    """Extract forms and identify the best login-form candidate."""

    @staticmethod
    def _score(form: dict[str, Any]) -> tuple[int, int, int]:
        action = str(form.get("raw_action") or "").lower()
        fields = list(form.get("fields") or [])
        action_match = int(any(word in action for word in _ACTION_KEYWORDS))
        password_match = int(
            any(str(field.get("type") or "").lower() == "password" for field in fields)
        )
        identity_match = int(
            any(
                any(
                    word in str(field.get("name") or "").lower()
                    for word in _IDENTITY_KEYWORDS
                )
                for field in fields
            )
        )
        return action_match, password_match, identity_match

    def extract_login_forms(
        self,
        html: str,
        base_url: str,
    ) -> list[dict[str, Any]]:
        parsed = urlparse(str(base_url or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")

        parser = _FormParser()
        parser.feed(str(html or ""))
        parser.close()
        forms = deepcopy(parser.forms)
        selected_index: int | None = None
        selected_score = (0, 0, 0)
        for index, form in enumerate(forms):
            score = self._score(form)
            if score > selected_score:
                selected_index = index
                selected_score = score

        result = []
        for index, form in enumerate(forms):
            raw_action = str(form.pop("raw_action", "") or "")
            raw_method = str(form.pop("raw_method", "") or "").upper()
            form["action"] = urljoin(base_url, raw_action or base_url)
            form["method"] = raw_method if raw_method in {"GET", "POST"} else "GET"
            form["is_login"] = selected_index == index and selected_score > (0, 0, 0)
            result.append(form)
        return result


class CredentialGenerator:
    """Generate deterministic, bounded credential candidates for a form."""

    BASE_CREDENTIALS = (
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("test", "test"),
        ("root", "root"),
        ("guest", "guest"),
        ("user", "user"),
        ("admin", "password123"),
        ("admin", "letmein"),
        ("admin", "welcome1"),
        ("root", "toor"),
        ("root", "123456"),
        ("test", "123456"),
        ("guest", "123456"),
        ("user", "123456"),
        ("wiener", "peter"),
        ("admin", "qwerty"),
        ("admin", "qwerty123"),
        ("admin", "2024!"),
        ("admin", "admin2024"),
    )
    _USERNAME_TYPES = {"text", "email", "tel", "phone"}
    _CAPTCHA_MARKERS = ("captcha", "verifycode", "verification", "vcode")
    _IGNORED_DOMAIN_LABELS = {
        "www",
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "ac",
        "cn",
        "uk",
        "io",
        "co",
    }

    @staticmethod
    def _fields(login_form: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            field
            for field in list(login_form.get("fields") or [])
            if isinstance(field, dict) and str(field.get("name") or "").strip()
        ]

    @classmethod
    def _username_field(cls, fields: list[dict[str, Any]]) -> str:
        for field in fields:
            name = str(field.get("name") or "")
            lowered = name.lower()
            if any(marker in lowered for marker in _IDENTITY_KEYWORDS):
                return name
        for field in fields:
            name = str(field.get("name") or "")
            field_type = str(field.get("type") or "text").lower()
            if field_type in cls._USERNAME_TYPES:
                return name
        return ""

    @staticmethod
    def _password_field(fields: list[dict[str, Any]]) -> str:
        for field in fields:
            name = str(field.get("name") or "")
            field_type = str(field.get("type") or "").lower()
            if field_type == "password":
                return name
        for field in fields:
            name = str(field.get("name") or "")
            lowered = name.lower()
            if "password" in lowered or "passwd" in lowered or lowered == "pwd":
                return name
        return ""

    @classmethod
    def _captcha_field(cls, fields: list[dict[str, Any]]) -> str:
        for field in fields:
            name = str(field.get("name") or "")
            marker = " ".join(
                (
                    name,
                    str(field.get("type") or ""),
                    str(field.get("placeholder") or ""),
                )
            ).lower().replace("_", "").replace("-", "")
            if any(item in marker for item in cls._CAPTCHA_MARKERS):
                return name
        return ""

    @classmethod
    def _organization_token(cls, action: str) -> str:
        hostname = (urlparse(str(action or "")).hostname or "").lower()
        labels = [
            label
            for label in hostname.split(".")
            if label and label not in cls._IGNORED_DOMAIN_LABELS
        ]
        return labels[-1] if labels else ""

    @staticmethod
    def _hidden_defaults(fields: list[dict[str, Any]]) -> dict[str, str]:
        return {
            str(field["name"]): str(field.get("default_value") or "")
            for field in fields
            if str(field.get("type") or "").lower() == "hidden"
        }

    def generate_credentials(
        self,
        login_form: dict[str, Any],
        role_hint: str = "",
    ) -> list[dict[str, Any]]:
        fields = self._fields(login_form)
        username_field = self._username_field(fields)
        password_field = self._password_field(fields)
        if not username_field or not password_field:
            return []

        pairs = list(self.BASE_CREDENTIALS)
        organization = self._organization_token(str(login_form.get("action") or ""))
        candidate_user = str(role_hint or "admin").strip() or "admin"
        if organization:
            current_year = datetime.now(timezone.utc).year
            domain_passwords = [
                f"{organization}@123",
                f"{organization}2024",
                f"{organization}123",
                f"{organization}!",
                f"{organization}{current_year}",
            ]
            pairs.extend((candidate_user, password) for password in domain_passwords)

        unique_pairs = []
        seen = set()
        for username, password in pairs:
            pair = (str(username), str(password))
            if pair not in seen:
                seen.add(pair)
                unique_pairs.append(pair)

        extra_fields = self._hidden_defaults(fields)
        captcha_field = self._captcha_field(fields)
        return [
            {
                "username": username,
                "password": password,
                "username_field": username_field,
                "password_field": password_field,
                "extra_fields": deepcopy(extra_fields),
                "requires_captcha": bool(captcha_field),
                "captcha_field": captcha_field,
            }
            for username, password in unique_pairs
        ]


class AttackChainFeeder:
    """Translate a discovered login form into attack-chain parameters."""

    @staticmethod
    def _missing(value: Any) -> bool:
        return value is None or (
            isinstance(value, str) and not value.strip()
        ) or value == {} or value == []

    @staticmethod
    def _template_values(chain_template: dict[str, Any]) -> dict[str, Any]:
        raw = chain_template.get("parameters")
        source = raw if isinstance(raw, dict) else chain_template
        values = {}
        for name, definition in source.items():
            if isinstance(definition, dict) and "default" in definition:
                values[str(name)] = deepcopy(definition.get("default"))
            else:
                values[str(name)] = deepcopy(definition)
        return values

    @staticmethod
    def _fill(values: dict[str, Any], name: str, value: Any) -> None:
        if name not in values or AttackChainFeeder._missing(values[name]):
            values[name] = deepcopy(value)

    def feed_chain(
        self,
        login_form: dict[str, Any],
        credentials: list[dict[str, Any]],
        chain_template: dict[str, Any],
    ) -> dict[str, Any]:
        action = str(login_form.get("action") or "").strip()
        parsed = urlparse(action)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("login form action must be an absolute HTTP(S) URL")

        fields = CredentialGenerator._fields(login_form)
        username_field = CredentialGenerator._username_field(fields)
        password_field = CredentialGenerator._password_field(fields)
        hidden_fields = CredentialGenerator._hidden_defaults(fields)
        submit_button = login_form.get("submit_button") or {}
        submit_name = str(submit_button.get("name") or "").strip()
        if submit_name:
            hidden_fields[submit_name] = str(submit_button.get("value") or "")
        token_field = next(
            (name for name in hidden_fields if _token_field(name)),
            "",
        )
        login_path = parsed.path or "/"
        if parsed.query:
            login_path += f"?{parsed.query}"

        template = dict(chain_template or {})
        structured_template = isinstance(template.get("parameters"), dict)
        values = self._template_values(template)

        discovered = {
            "target_url": f"{parsed.scheme}://{parsed.netloc}",
            "login_path": login_path,
            "request_method": str(login_form.get("method") or "GET").upper(),
            "username_field": username_field,
            "password_field": password_field,
            "csrf_field": token_field,
            "csrf_token": hidden_fields.get(token_field, ""),
            "extra_fields": hidden_fields,
            "credentials": credentials,
        }
        for name, value in discovered.items():
            if name == "extra_fields":
                existing = values.get(name)
                if isinstance(existing, dict):
                    if structured_template:
                        merged = deepcopy(existing)
                        merged.update(value)
                    else:
                        merged = deepcopy(value)
                        merged.update(existing)
                    values[name] = merged
                else:
                    values[name] = deepcopy(value)
            elif structured_template:
                values[name] = deepcopy(value)
            else:
                self._fill(values, name, value)

        if credentials:
            first = credentials[0]
            for name in ("username", "password"):
                value = first.get(name, "")
                if structured_template:
                    values[name] = deepcopy(value)
                else:
                    self._fill(values, name, value)
        return values


def prepare_auto_login(
    session: Any,
    chain: Any,
    params: dict[str, Any] | None,
    request_executor: Any,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    """Prepare one login attempt and return params, summary, and terminal result."""
    runtime_params = dict(params or {})
    chain_parameters = getattr(chain, "parameters", {}) or {}
    login_capable = {"username_field", "password_field"} <= set(
        chain_parameters
    )
    target_url = str(runtime_params.get("target_url") or "").strip()
    if not login_capable or not target_url:
        return runtime_params, None, None

    parsed_target = urlparse(target_url)
    if parsed_target.path and parsed_target.path != "/":
        discovery_url = target_url
    else:
        login_path = str(
            runtime_params.get("login_path")
            or chain_parameters.get("login_path")
            or "/login"
        )
        discovery_url = urljoin(
            target_url.rstrip("/") + "/",
            login_path.lstrip("/"),
        )

    try:
        session.authorize_request("GET", discovery_url)
        response = request_executor(
            session,
            {
                "method": "GET",
                "url": discovery_url,
                "headers": session.merge_headers(),
                "data": None,
                "options": {"auto_form_discovery": True},
            },
        )
        session.auto_extract(response)
        response_url = str(response.get("url") or discovery_url)
        forms = FormExtractor().extract_login_forms(
            str(response.get("body") or ""),
            response_url,
        )
        login_form = next(
            (form for form in forms if form.get("is_login")),
            None,
        )
        if login_form is None:
            return runtime_params, {
                "status": "no-login-form",
                "discovery_url": discovery_url,
                "form_count": len(forms),
                "candidate_count": 0,
            }, None

        action = str(login_form.get("action") or "")
        parsed_action = urlparse(action)
        public_action = (
            f"{parsed_action.scheme}://{parsed_action.netloc}"
            f"{parsed_action.path or '/'}"
        )
        base_summary = {
            "discovery_url": discovery_url,
            "action": public_action,
            "method": login_form.get("method", "GET"),
            "field_names": [
                field.get("name", "")
                for field in login_form.get("fields", [])
            ],
            "has_csrf": bool(login_form.get("has_csrf")),
        }
        if session.origin(action) != session.origin(response_url):
            summary = {
                **base_summary,
                "status": "cross-origin-action-required",
                "candidate_count": 0,
            }
            return runtime_params, summary, {
                "status": "blocked",
                "reason": "cross-origin login action requires explicit operator handling",
                "auto_extract": summary,
            }

        credentials = CredentialGenerator().generate_credentials(
            login_form,
            role_hint=str(runtime_params.get("role_hint") or ""),
        )
        if not credentials:
            return runtime_params, {
                **base_summary,
                "status": "missing-credential-fields",
                "candidate_count": 0,
            }, None

        first = credentials[0]
        if first.get("requires_captcha"):
            summary = {
                **base_summary,
                "status": "captcha-required",
                "requires_captcha": True,
                "captcha_field": first.get("captcha_field", ""),
                "candidate_count": len(credentials),
            }
            return runtime_params, summary, {
                "status": "blocked",
                "reason": "captcha requires operator or solver input",
                "auto_extract": summary,
            }

        prepared = AttackChainFeeder().feed_chain(
            login_form,
            credentials,
            runtime_params,
        )
        return prepared, {
            **base_summary,
            "status": "prepared",
            "requires_captcha": False,
            "captcha_field": "",
            "candidate_count": len(credentials),
        }, None
    except Exception as exc:
        return runtime_params, {
            "status": "discovery-failed",
            "discovery_url": discovery_url,
            "error_type": type(exc).__name__,
        }, None
