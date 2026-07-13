"""Bounded YAML/JSON attack-chain state machine."""

from __future__ import annotations

import hashlib
import json
import re
import time
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urljoin, urlparse

import yaml

from .attack_session import AttackSession, _sensitive_values, redact_sensitive


_EXPLOIT_PAUSE_STATUSES = {
    "approval-required",
    "blocked",
    "deferred",
    "ready",
    "rejected",
}
_SAFE_REPLAY_METHODS = {"GET", "HEAD"}
_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")
_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def _append_query(url: str, values: dict[str, Any]) -> str:
    parsed = urlparse(url)
    encoded = urlencode(values, doseq=True)
    query = f"{parsed.query}&{encoded}" if parsed.query else encoded
    return parsed._replace(query=query).geturl()


@dataclass
class AttackStep:
    step_id: str
    name: str
    action: str
    request: dict[str, Any] = field(default_factory=dict)
    extract_rules: list[dict[str, Any]] = field(default_factory=list)
    condition: dict[str, Any] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    on_success: str = ""
    on_failure: str = ""
    max_retries: int = 0
    critical: bool = False
    wait_seconds: float = 0.0
    state: str = ""
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.step_id:
            raise ValueError("step_id is required")
        if self.action not in {"request", "extract", "condition", "exploit", "wait"}:
            raise ValueError(f"unsupported attack action: {self.action}")
        self.max_retries = max(0, min(10, int(self.max_retries)))
        self.wait_seconds = max(0.0, min(60.0, float(self.wait_seconds or 0)))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AttackStep":
        allowed = set(cls.__dataclass_fields__)
        return cls(**{key: deepcopy(item) for key, item in value.items() if key in allowed})


class AttackChain:
    def __init__(
        self,
        definition: dict[str, Any],
        request_executor: Callable[[AttackSession, dict[str, Any]], dict[str, Any]]
        | None = None,
        exploit_executor: Callable[[AttackSession, dict[str, Any]], dict[str, Any]]
        | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.name = str(definition.get("name") or "attack-chain")
        self.description = str(definition.get("description") or "")
        raw_parameters = definition.get("parameters") or {}
        if not isinstance(raw_parameters, dict):
            raise ValueError("attack chain parameters must be an object")
        self.parameters: dict[str, Any] = {}
        self.parameter_definitions: dict[str, dict[str, Any]] = {}
        for raw_name, raw_definition in raw_parameters.items():
            name = str(raw_name)
            if not _PARAMETER_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid attack chain parameter name: {name}")
            descriptor_keys = {"description", "required", "default"}
            if (
                isinstance(raw_definition, dict)
                and descriptor_keys <= set(raw_definition)
            ):
                description = str(raw_definition.get("description") or "")
                required = bool(raw_definition.get("required", False))
                default = deepcopy(raw_definition.get("default", ""))
            else:
                description = ""
                required = False
                default = deepcopy(raw_definition)
            self.parameters[name] = default
            self.parameter_definitions[name] = {
                "description": description,
                "required": required,
                "default": deepcopy(default),
            }
        self.steps = [
            AttackStep.from_dict(item) for item in (definition.get("steps") or [])
        ]
        if not self.steps:
            raise ValueError("attack chain must contain at least one step")
        self.by_id = {step.step_id: step for step in self.steps}
        if len(self.by_id) != len(self.steps):
            raise ValueError("attack chain step ids must be unique")
        self.start = str(definition.get("start") or self.steps[0].step_id)
        if self.start not in self.by_id:
            raise ValueError(f"unknown start step: {self.start}")
        for step in self.steps:
            references = [step.on_success, step.on_failure]
            if step.action == "condition":
                references.extend(
                    [
                        str(step.condition.get("true_branch") or ""),
                        str(step.condition.get("false_branch") or ""),
                    ]
                )
            for reference in references:
                if reference and reference not in self.by_id:
                    raise ValueError(
                        f"unknown step reference {reference!r} from {step.step_id!r}"
                    )
        produced = {
            str(rule.get("store_as") or rule.get("name") or "")
            for step in self.steps
            for rule in step.extract_rules
        }
        produced.update(
            str(step.options.get("payload_variable") or "payload")
            for step in self.steps
            if step.options.get("payload_variants")
        )
        referenced = set()
        for step in self.steps:
            referenced.update(self._placeholders(asdict(step)))
        self.undefined_variables = referenced - set(self.parameters) - produced
        self.request_executor = request_executor or self._missing_request_executor
        self.exploit_executor = exploit_executor or self._default_exploit_executor
        self.sleep = sleep

    @classmethod
    def load(
        cls,
        path: str | Path,
        request_executor=None,
        exploit_executor=None,
        sleep=time.sleep,
    ) -> "AttackChain":
        path = Path(path).resolve()
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            raise ValueError("attack chain must be YAML or JSON")
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("attack chain exceeds 1 MiB")
        text = path.read_text(encoding="utf-8-sig")
        value = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        if not isinstance(value, dict):
            raise ValueError("attack chain root must be an object")
        return cls(value, request_executor, exploit_executor, sleep)

    @staticmethod
    def _missing_request_executor(session, request):
        raise RuntimeError("attack chain request executor is not configured")

    @staticmethod
    def _default_exploit_executor(session, details):
        return {
            "status": "approval-required",
            "action": details.get("action") or details.get("vuln_type") or "exploit",
            "reason": "No approved exploit executor was configured.",
        }

    @staticmethod
    def _substitute(value: Any, variables: dict[str, Any]) -> Any:
        if isinstance(value, str):
            for key, replacement in variables.items():
                value = value.replace("${" + key + "}", str(replacement))
            return value
        if isinstance(value, dict):
            substituted = {}
            for key, item in value.items():
                new_key = (
                    AttackChain._substitute(key, variables)
                    if isinstance(key, str)
                    else key
                )
                if new_key in substituted:
                    raise ValueError(
                        f"duplicate mapping key after substitution: {new_key}"
                    )
                substituted[new_key] = AttackChain._substitute(item, variables)
            return substituted
        if isinstance(value, list):
            return [AttackChain._substitute(item, variables) for item in value]
        return value

    @staticmethod
    def _placeholders(value: Any) -> set[str]:
        if isinstance(value, str):
            return set(_PLACEHOLDER_RE.findall(value))
        if isinstance(value, dict):
            found = set()
            for key, item in value.items():
                found.update(AttackChain._placeholders(key))
                found.update(AttackChain._placeholders(item))
            return found
        if isinstance(value, (list, tuple)):
            found = set()
            for item in value:
                found.update(AttackChain._placeholders(item))
            return found
        return set()

    @staticmethod
    def _successful(result: dict[str, Any]) -> bool:
        status = str(result.get("status") or "").strip().lower()
        status_code = int(result.get("status_code") or 0)
        if status_code:
            return status in {"", "ok", "success", "complete"} and status_code < 400
        return status in {"ok", "success", "complete"}

    @staticmethod
    def _response_summary(result: dict[str, Any]) -> dict[str, Any]:
        body = result.get("body")
        if isinstance(body, bytes):
            body_bytes = body
        elif body is None:
            body_bytes = b""
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8", errors="replace")
        else:
            body_bytes = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8", errors="replace")
        headers = result.get("headers")
        location = ""
        if isinstance(headers, dict):
            for name, value in headers.items():
                if str(name).lower() == "location":
                    location = str(value)
                    break
        summary = {
            "status": str(result.get("status") or ""),
            "status_code": int(result.get("status_code") or 0),
            "body_hash": hashlib.sha256(body_bytes).hexdigest(),
            "body_size": len(body_bytes),
        }
        if result.get("url"):
            parsed = urlparse(str(result["url"]))
            summary["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if location:
            parsed = urlparse(location)
            summary["location"] = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.scheme and parsed.netloc
                else parsed.path
            )
        if result.get("error"):
            value = str(result["error"]).encode("utf-8", errors="replace")
            summary["error"] = "request-error"
            summary["error_hash"] = hashlib.sha256(value).hexdigest()
        if result.get("reason"):
            value = str(result["reason"]).encode("utf-8", errors="replace")
            summary["reason"] = "request-reason"
            summary["reason_hash"] = hashlib.sha256(value).hexdigest()
        return summary

    def _persist_in_flight(
        self,
        session: AttackSession,
        step: AttackStep,
        method: str,
        url: str,
        attempt: int,
    ) -> None:
        cursor = deepcopy(session.chain_cursors.get(self.name) or {})
        parsed_url = urlparse(url)
        persisted_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        cursor.update(
            {
                "current_step": step.step_id,
                "status": "running",
                "in_flight": {
                    "step_id": step.step_id,
                    "method": method,
                    "url": persisted_url,
                    "attempt": attempt,
                    "started_at": time.time(),
                },
                "updated_at": time.time(),
            }
        )
        session.chain_cursors[self.name] = cursor
        session.save()

    @staticmethod
    def _resolve_field(session: AttackSession, field_name: str) -> Any:
        if field_name == "state":
            return session.state
        if field_name.startswith("auth."):
            return session.auth_tokens.get(field_name[5:])
        if field_name.startswith("extracted."):
            current: Any = session.extracted_data
            for token in field_name[10:].split("."):
                current = current.get(token) if isinstance(current, dict) else None
            return current
        if field_name == "authenticated":
            return bool(session.authentication.get("verified"))
        if field_name == "has_csrf":
            return any(session.csrf_tokens.values())
        return session.extracted_data.get(field_name)

    def _check_preconditions(
        self, session: AttackSession, preconditions: list[str]
    ) -> tuple[bool, str]:
        for condition in preconditions:
            if condition in {"authenticated", "has_csrf"}:
                if not self._resolve_field(session, condition):
                    return False, condition
            elif condition.startswith("state:"):
                if session.state != condition.split(":", 1)[1]:
                    return False, condition
            elif condition.startswith("extracted:"):
                if self._resolve_field(
                    session, f"extracted.{condition.split(':', 1)[1]}"
                ) is None:
                    return False, condition
            elif condition.startswith("auth:"):
                if condition.split(":", 1)[1] not in session.auth_tokens:
                    return False, condition
            else:
                return False, condition
        return True, ""

    @staticmethod
    def _missing_required_value(value: Any) -> bool:
        return value is None or (
            isinstance(value, str) and not value.strip()
        )

    def _resolve_parameters(
        self,
        session: AttackSession,
        params: dict[str, Any] | None,
    ) -> dict[str, Any]:
        variables = deepcopy(self.parameters)
        variables.update(session.extracted_data)
        variables.update(params or {})
        return variables

    def _validate_step_parameters(
        self,
        step: AttackStep,
        variables: dict[str, Any],
    ) -> None:
        referenced = self._placeholders(asdict(step))
        missing = []
        for name, definition in self.parameter_definitions.items():
            if not definition["required"] or name not in referenced:
                continue
            if self._missing_required_value(variables.get(name)):
                description = definition["description"]
                missing.append(
                    f"{name} ({description})" if description else name
                )
        if missing:
            raise ValueError("缺少必要参数: " + "; ".join(missing))

    def _execute_request(
        self,
        step: AttackStep,
        session: AttackSession,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        raw_extra_fields = step.request.get("extra_fields")
        request = self._substitute(step.request, variables)
        extra_fields = request.pop("extra_fields", None)
        if isinstance(raw_extra_fields, str):
            match = _PLACEHOLDER_RE.fullmatch(raw_extra_fields.strip())
            if match:
                extra_fields = deepcopy(variables.get(match.group(1), {}))
        if extra_fields is not None and not isinstance(extra_fields, dict):
            raise TypeError("request extra_fields must be an object")
        path = str(request.pop("path", request.pop("url", "")) or "")
        url = urljoin(session.target.rstrip("/") + "/", path)
        params = request.pop("params", None)
        if params:
            url = _append_query(url, params)
        method = str(request.pop("method", "GET")).upper()
        headers = session.merge_headers(request.pop("headers", None))
        headers = {
            name: value
            for name, value in headers.items()
            if value is not None and str(value) != ""
        }
        cookie_header = session.cookie_header(url)
        if cookie_header and not headers.get("Cookie"):
            headers["Cookie"] = cookie_header
        data = request.pop("data", None)
        if isinstance(data, dict):
            data = {
                key: value
                for key, value in data.items()
                if str(key).strip()
            }
        if extra_fields:
            if data is None:
                data = {}
            if not isinstance(data, dict):
                raise TypeError("request data must be an object when extra_fields are used")
            merged_data = deepcopy(extra_fields)
            merged_data.update(data)
            data = merged_data
        if isinstance(data, dict):
            has_explicit_csrf = any(
                "csrf" in str(name).lower()
                or str(name).lower()
                in {
                    "_token",
                    "authenticity_token",
                    "execution",
                    "lt",
                    "token",
                    "xsrf",
                }
                for name in data
            )
            if not has_explicit_csrf:
                for name, value in session.csrf_for_url(url).items():
                    data.setdefault(name, value)
        if method in _SAFE_REPLAY_METHODS and isinstance(data, dict) and data:
            url = _append_query(url, data)
            data = None
        session.authorize_request(method, url)
        request_options = self._substitute(
            deepcopy(request.pop("options", step.options)),
            variables,
        )
        if variables.get("_retry_strategy"):
            request_options["retry_strategy"] = variables["_retry_strategy"]
        request_options["chain_attempt"] = int(variables.get("_retry_attempt", 0))
        if variables.get("_retry_strategy") == "waf-rotate":
            request_options.setdefault("max_retries", 1)
        payload = {
            "method": method,
            "url": url,
            "headers": headers,
            "data": data,
            "options": request_options,
        }
        payload.update(request)
        self._persist_in_flight(
            session,
            step,
            method,
            url,
            int(variables.get("_retry_attempt", 0)),
        )
        result = self.request_executor(session, payload)
        if not isinstance(result, dict):
            raise TypeError("request executor must return a dict")
        session.auto_extract(result)
        proof = request_options.get("authentication_proof") or {}
        if proof and self._successful(result):
            body = str(result.get("body") or "")
            final_url = str(result.get("url") or url)
            body_pattern = str(proof.get("body_regex") or "")
            reject_pattern = str(proof.get("reject_url_regex") or "")
            required_token = str(proof.get("required_token") or "")
            body_matches = not body_pattern or bool(re.search(body_pattern, body, re.I))
            url_allowed = not reject_pattern or not re.search(
                reject_pattern, final_url, re.I
            )
            token_present = not required_token or required_token in session.auth_tokens
            if body_matches and url_allowed and token_present:
                session.mark_authenticated(
                    {
                        "type": "response-proof",
                        "url": final_url,
                        "evidence": {
                            "step_id": step.step_id,
                            "body_regex": body_pattern,
                            "required_token": required_token,
                        },
                    }
                )
        return result

    def _execute_extract(
        self,
        step: AttackStep,
        session: AttackSession,
        variables: dict[str, Any],
        last_response: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if last_response is None:
            raise ValueError("extract step has no previous response")
        extracted = {}
        for rule in step.extract_rules:
            name = str(rule.get("store_as") or rule.get("name") or "")
            if not name:
                raise ValueError("extract rule requires store_as or name")
            pattern = self._substitute(str(rule.get("pattern") or ""), variables)
            value = session.extract_from_response(pattern, last_response)
            current = variables.get(name)
            if (
                name not in self.parameter_definitions
                or self._missing_required_value(current)
            ):
                variables[name] = value
            session.extracted_data[name] = deepcopy(value)
            extracted[name] = value
        return {"status": "ok", "extracted": extracted}

    def _execute_condition(
        self,
        step: AttackStep,
        session: AttackSession,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        condition = self._substitute(step.condition, variables)
        actual = self._resolve_field(session, str(condition.get("field") or ""))
        expected = condition.get("value")
        operator = str(condition.get("operator") or "eq")
        operations = {
            "eq": lambda: actual == expected,
            "ne": lambda: actual != expected,
            "contains": lambda: expected in actual if actual is not None else False,
            "exists": lambda: actual is not None,
            "truthy": lambda: bool(actual),
            "in": lambda: actual in expected if expected is not None else False,
        }
        if operator not in operations:
            raise ValueError(f"unsupported condition operator: {operator}")
        matched = bool(operations[operator]())
        return {
            "status": "ok" if matched else "failed",
            "matched": matched,
            "actual": actual,
            "expected": expected,
        }

    def _execute_step(
        self,
        step: AttackStep,
        session: AttackSession,
        variables: dict[str, Any],
        last_response: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if step.action == "request":
            return self._execute_request(step, session, variables)
        if step.action == "extract":
            return self._execute_extract(
                step, session, variables, last_response
            )
        if step.action == "condition":
            return self._execute_condition(step, session, variables)
        if step.action == "wait":
            seconds = step.wait_seconds or float(step.options.get("seconds", 0))
            seconds = max(0.0, min(60.0, seconds))
            self.sleep(seconds)
            return {"status": "ok", "waited": seconds}
        details = self._substitute(step.options, variables)
        details.setdefault("action", step.name)
        return self.exploit_executor(session, details)

    def execute(
        self,
        session: AttackSession,
        params: dict[str, Any] | None = None,
        max_steps: int = 200,
    ) -> dict[str, Any]:
        sensitive_values = _sensitive_values(params or {})
        variables = self._resolve_parameters(session, params)
        saved_cursor = deepcopy(session.chain_cursors.get(self.name) or {})
        in_flight = deepcopy(saved_cursor.get("in_flight") or {})
        in_flight_method = str(in_flight.get("method") or "").upper()
        if in_flight and in_flight_method not in _SAFE_REPLAY_METHODS:
            pending = {
                "step_id": str(
                    in_flight.get("step_id")
                    or saved_cursor.get("current_step")
                    or self.start
                ),
                "status": "recovery-required",
                "reason": "A mutating request was in flight without a confirmed outcome.",
                "method": in_flight_method or "UNKNOWN",
            }
            if in_flight.get("url"):
                pending["url"] = str(in_flight["url"])
            saved_cursor["status"] = "recovery-required"
            saved_cursor["current_step"] = pending["step_id"]
            saved_cursor["updated_at"] = time.time()
            session.chain_cursors[self.name] = saved_cursor
            session.save()
            return redact_sensitive(
                {
                    "status": "recovery-required",
                    "chain": self.name,
                    "steps": [],
                    "variables": variables,
                    "pending": pending,
                },
                sensitive_values,
            )
        if in_flight:
            saved_cursor.pop("in_flight", None)
            saved_cursor["status"] = "running"
            saved_cursor["updated_at"] = time.time()
            session.chain_cursors[self.name] = saved_cursor
            session.save()
        resumable = (
            saved_cursor.get("status")
            in {"blocked", "failed", "paused", "running", "recovery-required"}
            and saved_cursor.get("current_step") in self.by_id
        )
        current = (
            str(saved_cursor["current_step"])
            if resumable
            else self.start
        )
        last_response = (
            deepcopy(saved_cursor.get("last_response"))
            if resumable
            else None
        )
        completed_steps = (
            list(saved_cursor.get("completed_steps") or [])
            if resumable
            else []
        )
        results = []
        visited = 0
        session.chain_cursors[self.name] = {
            "current_step": current,
            "status": "running",
            "completed_steps": completed_steps,
            "last_response": deepcopy(last_response),
            "updated_at": time.time(),
        }
        session.save()

        while current:
            visited += 1
            if visited > max_steps:
                raise RuntimeError("attack chain exceeded maximum step budget")
            if current not in self.by_id:
                raise ValueError(f"attack chain references unknown step: {current}")
            step = self.by_id[current]
            self._validate_step_parameters(step, variables)
            preconditions_ok, failed_precondition = self._check_preconditions(
                session, step.preconditions
            )
            started = time.monotonic()
            attempt_results = []
            error = ""
            success = False
            if not preconditions_ok:
                error = f"precondition failed: {failed_precondition}"
            else:
                for attempt in range(step.max_retries + 1):
                    try:
                        attempt_variables = deepcopy(variables)
                        variants = list(step.options.get("payload_variants") or [])
                        if variants:
                            variable_name = str(
                                step.options.get("payload_variable") or "payload"
                            )
                            attempt_variables[variable_name] = variants[
                                min(attempt, len(variants) - 1)
                            ]
                        strategies = list(
                            step.options.get("retry_strategies") or []
                        )
                        attempt_variables["_retry_attempt"] = attempt
                        if strategies:
                            attempt_variables["_retry_strategy"] = strategies[
                                min(attempt, len(strategies) - 1)
                            ]
                        result = self._execute_step(
                            step, session, attempt_variables, last_response
                        )
                        attempt_results.append(result)
                        success = self._successful(result)
                        if success:
                            if step.action == "extract":
                                variables.update(
                                    {
                                        key: value
                                        for key, value in attempt_variables.items()
                                        if not key.startswith("_retry_")
                                    }
                                )
                            if step.action == "request":
                                last_response = result
                            break
                        error = str(
                            result.get("error")
                            or result.get("reason")
                            or result.get("status")
                            or "step failed"
                        )
                    except Exception as exc:
                        error = str(exc)
                        attempt_results.append(
                            {"status": "error", "error": str(exc)}
                        )
                    if attempt < step.max_retries:
                        delay = min(8.0, float(step.options.get("retry_wait", 0)))
                        if delay:
                            self.sleep(delay)

            elapsed = time.monotonic() - started
            public_attempt_results = (
                [self._response_summary(item) for item in attempt_results]
                if step.action == "request"
                else attempt_results
            )
            record = {
                "step_id": step.step_id,
                "name": step.name,
                "action": step.action,
                "success": success,
                "attempts": len(attempt_results),
                "results": public_attempt_results,
                "error": error,
                "elapsed": round(elapsed, 6),
            }
            results.append(record)
            result_status = (
                str(attempt_results[-1].get("status") or "").strip().lower()
                if attempt_results
                else ""
            )
            pause_status = (
                result_status
                if step.action == "exploit"
                and result_status in _EXPLOIT_PAUSE_STATUSES
                else ""
            )
            if step.action == "condition":
                branch = (
                    step.condition.get("true_branch")
                    if success
                    else step.condition.get("false_branch")
                )
                fallback = step.on_success if success else step.on_failure
                next_step = str(branch or fallback)
            else:
                next_step = step.on_success if success else step.on_failure
            if success and step.step_id not in completed_steps:
                completed_steps.append(step.step_id)
            if pause_status:
                cursor_status = (
                    "blocked"
                    if pause_status == "blocked"
                    else "failed"
                    if pause_status == "rejected"
                    else "paused"
                )
                cursor_step = step.step_id
            elif not success and step.critical:
                cursor_status = "blocked"
                cursor_step = step.step_id
            elif next_step:
                cursor_status = "running"
                cursor_step = next_step
            elif success:
                cursor_status = "complete"
                cursor_step = ""
            else:
                cursor_status = "failed"
                cursor_step = step.step_id
            session.chain_cursors[self.name] = {
                "current_step": cursor_step,
                "status": cursor_status,
                "completed_steps": completed_steps,
                "last_response": deepcopy(last_response),
                "updated_at": time.time(),
            }
            session.record_history(
                "chain.step",
                redact_sensitive(
                    {
                        "chain": self.name,
                        "step": asdict(step),
                        "success": success,
                        "attempts": len(attempt_results),
                        "error": error,
                    },
                    sensitive_values,
                ),
                elapsed,
            )
            if step.state and success:
                session.set_state(step.state)
            session.save()

            if pause_status:
                return redact_sensitive(
                    {
                        "status": pause_status,
                        "chain": self.name,
                        "steps": results,
                        "variables": variables,
                        "pending": {
                            "step_id": step.step_id,
                            "status": pause_status,
                            "reason": error or pause_status,
                        },
                    },
                    sensitive_values,
                )

            if not success and step.critical:
                checkpoint_name = f"blocker-{step.step_id}-{int(time.time())}"
                checkpoint_path = str(
                    session.directory / "checkpoints" / f"{checkpoint_name}.json"
                )
                blocker = {
                    "chain": self.name,
                    "step_id": step.step_id,
                    "reason": redact_sensitive(
                        error
                        or (
                            attempt_results[-1].get("error")
                            if attempt_results
                            else "critical step failed"
                        )
                        or "critical step failed",
                        sensitive_values,
                    ),
                    "checkpoint": checkpoint_path,
                    "created_at": time.time(),
                }
                session.blockers.append(blocker)
                checkpoint = session.save_checkpoint(checkpoint_name)
                blocker["created_at"] = checkpoint["created_at"]
                session.save()
                return redact_sensitive(
                    {
                        "status": "blocked",
                        "chain": self.name,
                        "steps": results,
                        "variables": variables,
                        "blocker": blocker,
                    },
                    sensitive_values,
                )
            current = next_step
            if not current and not success:
                return redact_sensitive(
                    {
                        "status": "failed",
                        "chain": self.name,
                        "steps": results,
                        "variables": variables,
                    },
                    sensitive_values,
                )

        session.record_history(
            "chain.complete",
            {"chain": self.name, "steps": len(results)},
        )
        session.save()
        return redact_sensitive(
            {
                "status": "complete",
                "chain": self.name,
                "steps": results,
                "variables": variables,
            },
            sensitive_values,
        )
