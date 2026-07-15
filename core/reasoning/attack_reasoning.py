"""Evidence-driven attack strategy generation for Hunter orchestration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any
from urllib.parse import urljoin, urlparse


_PRIORITY = {"P0": 0, "P1": 1, "P2": 2}
_CREDENTIAL_USER = "$" + "{credentials.username}"
_CREDENTIAL_PASSWORD = "$" + "{credentials.password}"
_PREVIOUS_CAPTCHA = "$" + "{captcha.previous_token}"


class AttackReasoner:
    """Map observed facts and evidence to deterministic next-step strategies."""

    def __init__(self) -> None:
        self.rules = (
            self._cas_default_credentials,
            self._slider_captcha_bypass,
            self._session_login_followup,
            self._system_session_followup,
            self._cas_service_redirect,
            self._cas_status_probe,
            self._jwt_assessment,
            self._basic_auth_credentials,
            self._vsb_admin_and_search,
            self._chaoxing_access_control,
            self._spring_management_surfaces,
            self._nginx_path_normalization,
            self._authenticated_upload_chain,
            self._redirect_parameter_probe,
            self._object_access_control,
            self._memory_waf_bypass,
            self._image_captcha_bypass,
            self._recaptcha_operator_flow,
            self._authenticated_evidence_followup,
            self._csrf_form_assessment,
        )

    def reason(self, facts: dict, evidence: list, technique_memory: dict) -> list[dict]:
        current = self._normalize_facts(facts)
        observations = [dict(item) for item in evidence or [] if isinstance(item, Mapping)]
        memory = dict(technique_memory or {})
        strategies = []
        seen = set()
        for rule in self.rules:
            strategy = rule(current, observations, memory)
            if not strategy:
                continue
            strategy_id = str(strategy.get("strategy_id") or "")
            if not strategy_id or strategy_id in seen:
                continue
            seen.add(strategy_id)
            strategies.append(strategy)
        return sorted(strategies, key=lambda item: (self._priority(item), item["strategy_id"]))

    @staticmethod
    def _normalize_facts(facts: dict) -> dict:
        result = deepcopy(dict(facts or {}))
        for key, default in (
            ("target_url", ""), ("target_type", "general_web"),
            ("authentication", "none"), ("endpoints", []), ("params", []),
            ("forms", []), ("cookies", {}), ("technologies", []),
        ):
            result.setdefault(key, default)
        return result

    @staticmethod
    def _priority(strategy: Mapping[str, Any]) -> int:
        return min((_PRIORITY.get(str(item.get("priority") or "P2"), 2) for item in strategy.get("actions", []) if isinstance(item, Mapping)), default=2)

    @staticmethod
    def _strategy(strategy_id: str, title: str, condition: str, actions: Sequence[dict]) -> dict:
        return {"strategy_id": strategy_id, "title": title, "actions": [dict(item) for item in actions], "condition": condition}

    @staticmethod
    def _fields(facts: Mapping[str, Any]) -> set[str]:
        output = set()
        for form in facts.get("forms", []):
            if not isinstance(form, Mapping):
                continue
            for field in form.get("fields") or form.get("inputs") or []:
                value = (field.get("name") or field.get("id") or field.get("type")) if isinstance(field, Mapping) else field
                if str(value or "").strip():
                    output.add(str(value).casefold().strip())
        return output

    @classmethod
    def _has_password(cls, facts: Mapping[str, Any]) -> bool:
        return any(any(token in name for token in ("password", "passwd", "pwd")) for name in cls._fields(facts))

    @staticmethod
    def _login_evidence(evidence: Sequence[Mapping[str, Any]]) -> bool:
        return any(item.get("type") == "login_page" or any(marker in str(item.get("summary") or "").casefold() for marker in ("login", "登录", "需要认证", "需要登录", "cas")) for item in evidence)

    @staticmethod
    def _paths(facts: Mapping[str, Any]) -> list[str]:
        output = []
        for item in facts.get("endpoints", []):
            value = item.get("url") if isinstance(item, Mapping) else item
            if str(value or "").strip():
                output.append(urlparse(str(value)).path or str(value))
        return output

    @staticmethod
    def _tech(facts: Mapping[str, Any]) -> str:
        return " | ".join(str(item) for item in facts.get("technologies", [])).casefold()

    @staticmethod
    def _cookie(facts: Mapping[str, Any]) -> str:
        cookies = facts.get("cookies", {})
        if not isinstance(cookies, Mapping):
            return ""
        return "; ".join(f"{name}={value}" for name, value in cookies.items() if str(name or "").strip() and str(value or "").strip())

    @staticmethod
    def _target(facts: Mapping[str, Any], path: str = "") -> str:
        base = str(facts.get("target_url") or "")
        return urljoin(base.rstrip("/") + "/", path.lstrip("/")) if path else base

    @classmethod
    def _login_path(cls, facts: Mapping[str, Any]) -> str:
        for form in facts.get("forms", []):
            if isinstance(form, Mapping) and form.get("action"):
                return str(form["action"])
        return next((path for path in cls._paths(facts) if any(marker in path.casefold() for marker in ("login", "signin", "/cas/"))), "/login")

    @staticmethod
    def _param(facts: Mapping[str, Any], candidates: Sequence[str], default: str = "") -> str:
        values = {str(item).casefold(): str(item) for item in facts.get("params", [])}
        return next((values[name] for name in candidates if name in values), default)

    @staticmethod
    def _chain(action: str, priority: str, params: dict, chain: str = "login_to_admin") -> dict:
        payload = dict(params)
        if chain == "login_to_admin":
            payload.setdefault("username", _CREDENTIAL_USER)
            payload.setdefault("password", _CREDENTIAL_PASSWORD)
        return {"action": action, "tool": "hunter_session_execute_chain", "chain": chain, "priority": priority, "params": payload}

    def _cas_default_credentials(self, facts, evidence, memory):
        if facts["target_type"] != "cas_authentication" or not facts["forms"] or not self._has_password(facts):
            return None
        login_path = self._login_path(facts)
        return self._strategy("cas_default_creds", "尝试 CAS 默认管理员凭证", "CAS 登录页 + 含 password 字段", [
            {"tool": "hunter_session_execute_chain", "chain": "login_to_admin", "priority": "P0", "params": {"target_url": facts["target_url"], "username": "admin", "password": "admin@123", "login_path": login_path}},
            {"tool": "hunter_auto_sqli", "param": "username", "priority": "P0", "params": {"target_url": self._target(facts, login_path)}},
        ])

    def _slider_captcha_bypass(self, facts, evidence, memory):
        captcha = facts.get("captcha") or {}
        if captcha.get("type") != "slider" or captcha.get("bypassable") is not False:
            return None
        common = {"target_url": facts["target_url"], "login_path": self._login_path(facts)}
        return self._strategy("slider_captcha_bypass", "按成本递增尝试滑块验证码绕过", "滑块验证码已确认且当前不可直接绕过", [
            self._chain("try_remove_captcha_param", "P0", {**common, "extra_fields": {"captcha": None}}),
            self._chain("try_fixed_captcha_value", "P1", {**common, "extra_fields": {"captcha": "0000"}}),
            self._chain("try_reuse_session_captcha", "P1", {**common, "extra_fields": {"captcha": _PREVIOUS_CAPTCHA}}),
            {"action": "log_operator_required", "tool": "hunter_scan_plan", "priority": "P2", "params": {"target": facts["target_url"], "mode": "standard", "phases": ["vulnerability-analysis"]}},
        ])

    def _session_login_followup(self, facts, evidence, memory):
        if facts["authentication"] != "session_cookie" or not self._login_evidence(evidence):
            return None
        common = {"target_url": facts["target_url"], "login_path": self._login_path(facts)}
        return self._strategy("session_login_assessment", "验证会话登录弱口令与固定风险", "Session Cookie 认证 + 已观察到登录页", [
            self._chain("bruteforce_credentials", "P0", common),
            self._chain("test_session_fixation", "P0", {**common, "session_cookie": self._cookie(facts)}),
        ])

    def _system_session_followup(self, facts, evidence, memory):
        cookies = facts.get("cookies", {})
        if "/system/" not in self._paths(facts) or not isinstance(cookies, Mapping) or not cookies.get("JSESSIONID"):
            return None
        cookie = self._cookie(facts)
        target = self._target(facts, "/system/")
        return self._strategy("system_session_followup", "携带 JSESSIONID 继续验证后台路径", "/system/ 已发现 + JSESSIONID 可用", [
            {"action": "access_with_session", "tool": "hunter_auto_access_control", "priority": "P0", "params": {"target": target, "cookie": cookie, "session_cookie": cookie, "probe_path": "/system/"}},
            {"action": "scan_dir_behind_auth", "tool": "hunter_scan_plan", "priority": "P1", "params": {"target": target, "mode": "standard", "phases": ["recon", "vulnerability-analysis"]}},
        ])

    def _cas_service_redirect(self, facts, evidence, memory):
        if facts["target_type"] != "cas_authentication" and "service" not in {str(item).casefold() for item in facts["params"]}:
            return None
        return self._strategy("cas_service_redirect", "测试 CAS service 参数开放重定向", "CAS 认证或发现 service 参数", [{"tool": "hunter_auto_ssrf", "param": "service", "priority": "P0", "params": {"target_url": facts["target_url"]}}])

    def _cas_status_probe(self, facts, evidence, memory):
        if facts["target_type"] != "cas_authentication":
            return None
        return self._strategy("cas_status_endpoint", "检查 CAS 状态与票据端点暴露", "目标识别为 CAS 认证", [{"action": "check_cas_status_endpoint", "tool": "hunter_auto_access_control", "priority": "P1", "params": {"target": self._target(facts, "/cas/status")}}])

    def _jwt_assessment(self, facts, evidence, memory):
        if facts["authentication"] != "jwt":
            return None
        return self._strategy("jwt_claim_assessment", "验证 JWT 签名与声明边界", "认证方式为 JWT", [{"tool": "hunter_auto_jwt", "priority": "P0", "params": {"target": facts["target_url"], "token": facts.get("jwt_token", "")}}])

    def _basic_auth_credentials(self, facts, evidence, memory):
        if facts["authentication"] != "basic":
            return None
        return self._strategy("basic_default_creds", "尝试 Basic Auth 默认凭证", "认证方式为 Basic Auth", [self._chain("try_default_credentials", "P0", {"target_url": facts["target_url"], "login_path": self._login_path(facts), "username": "admin", "password": "admin"})])

    def _vsb_admin_and_search(self, facts, evidence, memory):
        if facts["target_type"] != "vsb_cms" and "vsb" not in self._tech(facts):
            return None
        return self._strategy("vsb_admin_search", "验证 VSB 后台认证与搜索注入", "识别到 VSB Portal / 博达 CMS", [
            self._chain("try_default_credentials", "P0", {"target_url": facts["target_url"], "login_path": "/system/login.jsp", "username": "admin", "password": "admin"}),
            {"tool": "hunter_auto_sqli", "param": self._param(facts, ("search", "q", "keyword"), "search"), "priority": "P0", "params": {"target_url": self._target(facts, "/search.jsp")}},
        ])

    def _chaoxing_access_control(self, facts, evidence, memory):
        if facts["target_type"] != "chaoxing_portal" and "chaoxing" not in self._tech(facts):
            return None
        return self._strategy("chaoxing_portal_access", "验证超星入口与 API 越权", "识别到超星智慧门户", [
            {"tool": "hunter_auto_access_control", "priority": "P0", "params": {"target": self._target(facts, "/entry/")}},
            {"tool": "hunter_auto_access_control", "priority": "P1", "params": {"target": self._target(facts, "/api/")}},
        ])

    def _spring_management_surfaces(self, facts, evidence, memory):
        if "spring" not in self._tech(facts):
            return None
        return self._strategy("spring_management_surfaces", "检查 Spring 管理端点暴露", "技术栈包含 Spring", [
            {"tool": "hunter_auto_access_control", "priority": "P0", "params": {"target": self._target(facts, "/actuator")}},
            {"tool": "hunter_auto_access_control", "priority": "P1", "params": {"target": self._target(facts, "/actuator/env")}},
        ])

    def _nginx_path_normalization(self, facts, evidence, memory):
        if "nginx" not in self._tech(facts):
            return None
        return self._strategy("nginx_path_normalization", "验证 Nginx 路径规范化边界", "技术栈包含 Nginx", [{"tool": "hunter_scan_plan", "priority": "P1", "params": {"target": facts["target_url"], "mode": "standard", "phases": ["vulnerability-analysis"]}}])

    def _authenticated_upload_chain(self, facts, evidence, memory):
        upload_path = next((path for path in self._paths(facts) if any(marker in path.casefold() for marker in ("upload", "avatar", "import"))), "")
        if not upload_path:
            return None
        return self._strategy("authenticated_upload_chain", "验证上传限制并跟踪可访问文件", "发现上传类端点", [{"tool": "hunter_scan_plan", "priority": "P1", "params": {"target": self._target(facts, upload_path), "mode": "standard", "phases": ["vulnerability-analysis"]}}])

    def _redirect_parameter_probe(self, facts, evidence, memory):
        param = self._param(facts, ("url", "redirect", "return", "callback", "next", "service"))
        if not param:
            return None
        return self._strategy("redirect_parameter_probe", "验证 URL 参数的重定向与服务端请求边界", "发现 URL/redirect/callback 类参数", [{"tool": "hunter_auto_ssrf", "param": param, "priority": "P1", "params": {"target_url": facts["target_url"]}}])

    def _object_access_control(self, facts, evidence, memory):
        param = self._param(facts, ("id", "uid", "user_id", "course_id", "object_id"))
        if not param:
            return None
        endpoint = self._paths(facts)[0] if self._paths(facts) else ""
        return self._strategy("object_access_control", "验证对象标识参数的越权访问", "发现对象 ID 类参数", [{"tool": "hunter_auto_idor", "priority": "P1", "params": {"target": self._target(facts, endpoint), "endpoint": endpoint, "cookie": self._cookie(facts)}, "param": param}])

    def _memory_waf_bypass(self, facts, evidence, memory):
        recommendations = memory.get("recommendations") or memory.get("best_techniques") or []
        if not facts.get("waf") or not recommendations:
            return None
        names = []
        for item in recommendations:
            name = item.get("name") if isinstance(item, Mapping) else item
            if str(name or "").strip() and str(name) not in names:
                names.append(str(name))
        if not names:
            return None
        return self._strategy("memory_waf_bypass", "按历史成功率选择 WAF 绕过策略", "检测到 WAF + TechniqueMemory 有成功记录", [{"tool": "hunter_scan_plan", "priority": "P1", "techniques": names, "params": {"target": facts["target_url"], "mode": "standard", "phases": ["vulnerability-analysis"]}}])

    def _image_captcha_bypass(self, facts, evidence, memory):
        if (facts.get("captcha") or {}).get("type") != "image":
            return None
        common = {"target_url": facts["target_url"], "login_path": self._login_path(facts)}
        return self._strategy("image_captcha_reuse", "测试图形验证码固定值与会话重用", "检测到图形验证码", [
            self._chain("try_fixed_captcha_value", "P1", {**common, "extra_fields": {"captcha": "0000"}}),
            self._chain("try_reuse_session_captcha", "P1", {**common, "extra_fields": {"captcha": _PREVIOUS_CAPTCHA}}),
        ])

    def _recaptcha_operator_flow(self, facts, evidence, memory):
        if (facts.get("captcha") or {}).get("type") != "recaptcha":
            return None
        return self._strategy("recaptcha_browser_flow", "转交浏览器完成 reCAPTCHA 后复用会话", "检测到 reCAPTCHA", [{"action": "log_operator_required", "tool": "hunter_browser_navigate", "priority": "P2", "params": {"target_url": facts["target_url"]}}])

    def _authenticated_evidence_followup(self, facts, evidence, memory):
        if not self._cookie(facts) or not any(any(marker in str(item.get("summary") or "").casefold() for marker in ("需要登录", "需要认证", "login required", "authentication required")) for item in evidence):
            return None
        path = next((value for value in self._paths(facts) if value not in {"/login", "/signin"}), "/")
        return self._strategy("authenticated_evidence_followup", "携带已观察会话重试受保护资源", "证据提示需要登录 + 已获得 Cookie", [{"tool": "hunter_auto_access_control", "priority": "P0", "params": {"target": self._target(facts, path), "cookie": self._cookie(facts)}}])

    def _csrf_form_assessment(self, facts, evidence, memory):
        if not facts["forms"] or not self._fields(facts).intersection({"csrf", "csrf_token", "_token", "authenticity_token"}):
            return None
        return self._strategy("csrf_token_assessment", "验证表单 CSRF Token 绑定与重用", "表单包含 CSRF Token 字段", [{"tool": "hunter_auto_csrf", "priority": "P1", "params": {"target": self._target(facts, self._login_path(facts)), "cookie": self._cookie(facts)}}])
