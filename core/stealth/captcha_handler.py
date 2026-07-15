"""Captcha classification, OCR solving, bypass detection, and operator handoff."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import io
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping


CAPTCHA_FIELD_RE = re.compile(r"captcha|kaptcha|verify(?:code)?|checkcode|vcode", re.I)
CAPTCHA_FAILURE_RE = re.compile(
    r"invalid\s*(?:captcha|code)|captcha\s*(?:failed|incorrect)|"
    r"verification\s*code\s*(?:failed|incorrect)|\u9a8c\u8bc1\u7801(?:\u9519\u8bef|\u5931\u8d25|\u65e0\u6548)",
    re.I,
)
CLIENT_CAPTCHA_RE = re.compile(
    r"captchaVerified\s*=\s*true|validateCaptcha\s*\(|checkCaptcha\s*\(|verifyCaptcha\s*\(|"
    r"localStorage\.setItem\([^)]*(?:captcha|verify)[^)]*(?:true|verified|bypass)",
    re.I,
)
CAPTCHA_CHALLENGE_RE = re.compile(
    r"name=[\"'](?:captcha|verifycode|checkcode|vcode)|(?:captcha|verify)[^\n]{0,100}\.(?:png|jpg|jpeg|gif)|"
    r"recaptcha|h-captcha|turnstile|slider|"
    r"captcha\s*(?:required|challenge)",
    re.I,
)


_DISPLAY_NONE_RE = re.compile(r"display\s*:\s*none\b", re.I)
_CAPTCHA_ATTRIBUTE_RE = re.compile(r"captcha|kaptcha|verify(?:code)?|checkcode|vcode|turnstile|slider", re.I)
_VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class _CaptchaVisibilityParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._hidden_stack: list[bool] = []
        self.image_candidates = 0
        self.visible_images = 0
        self.field_candidates = 0
        self.visible_fields = 0
        self.visible_challenges = 0

    @property
    def hidden_only(self) -> bool:
        if self.image_candidates:
            return not self.visible_images and not self.visible_challenges
        if self.field_candidates:
            return not self.visible_fields and not self.visible_challenges
        return False

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]], *, push: bool) -> None:
        tag_name = tag.lower()
        attributes = {str(name).lower(): str(value or "") for name, value in attrs}
        parent_hidden = self._hidden_stack[-1] if self._hidden_stack else False
        element_hidden = (
            parent_hidden
            or "hidden" in attributes
            or bool(_DISPLAY_NONE_RE.search(attributes.get("style", "")))
            or (tag_name == "input" and attributes.get("type", "").strip().lower() == "hidden")
        )
        signal = " ".join(
            attributes.get(name, "")
            for name in ("id", "name", "class", "src", "data-src", "alt", "title")
        )
        if tag_name == "img" and _CAPTCHA_ATTRIBUTE_RE.search(signal):
            self.image_candidates += 1
            if not element_hidden:
                self.visible_images += 1
        elif tag_name == "input" and CAPTCHA_FIELD_RE.search(signal):
            self.field_candidates += 1
            if not element_hidden:
                self.visible_fields += 1
        elif re.search(r"recaptcha|h-captcha|turnstile|slider|click captcha|select captcha", signal, re.I):
            if not element_hidden:
                self.visible_challenges += 1
        if push and tag_name not in _VOID_ELEMENTS:
            self._hidden_stack.append(element_hidden)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs, push=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() not in _VOID_ELEMENTS and self._hidden_stack:
            self._hidden_stack.pop()


class CaptchaSolver:
    """Resolve image captchas with optional local OCR engines."""

    _install_attempted = False

    def __init__(
        self,
        ocr_engines: Mapping[str, Any] | None = None,
        *,
        auto_install: bool = True,
        install_timeout: int = 30,
        printer=print,
    ):
        self.ocr_engines = dict(ocr_engines or {})
        self.install_timeout = max(1, int(install_timeout))
        self.printer = printer
        self._cache: dict[str, dict[str, Any]] = {}
        self._stats: dict[str, dict[str, int]] = {}
        self._available = {
            "ddddocr": importlib.util.find_spec("ddddocr") is not None,
            "pytesseract": importlib.util.find_spec("pytesseract") is not None,
            "PIL": importlib.util.find_spec("PIL") is not None,
        }
        if not self._available["ddddocr"] and not self._available["pytesseract"] and auto_install:
            self._install_ddddocr()
        if not self._available["ddddocr"] or not self._available["PIL"]:
            self.printer(
                "Optional captcha OCR dependencies are missing. Install with: "
                f"{sys.executable} -m pip install ddddocr pillow"
            )

    @property
    def available(self) -> bool:
        return bool(self.ocr_engines or self._available["ddddocr"] or self._available["pytesseract"])

    def _install_ddddocr(self) -> None:
        if CaptchaSolver._install_attempted:
            return
        CaptchaSolver._install_attempted = True
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "ddddocr"],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.install_timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return
        importlib.invalidate_caches()
        self._available["ddddocr"] = importlib.util.find_spec("ddddocr") is not None
        self._available["PIL"] = importlib.util.find_spec("PIL") is not None

    def _preprocess(self, data: bytes) -> Any:
        if not self._available["PIL"]:
            return data
        try:
            from PIL import Image, ImageFilter, ImageOps

            image = Image.open(io.BytesIO(data)).convert("L")
            image = ImageOps.autocontrast(image)
            image = image.point(lambda value: 255 if value > 145 else 0)
            return image.filter(ImageFilter.MedianFilter(3))
        except Exception:
            return data

    @staticmethod
    def _to_png(image: Any) -> bytes:
        if isinstance(image, bytes):
            return image
        output = io.BytesIO()
        image.save(output, format="PNG")
        return output.getvalue()

    def _engine(self, name: str | None):
        selected = name or "auto"
        if selected in self.ocr_engines:
            return selected, self.ocr_engines[selected]
        if selected == "auto":
            selected = "ddddocr" if self._available["ddddocr"] else "pytesseract"
        if selected == "ddddocr" and self._available["ddddocr"]:
            module = importlib.import_module("ddddocr")
            engine = module.DdddOcr(show_ad=False)
            return selected, lambda image: engine.classification(self._to_png(image))
        if selected == "pytesseract" and self._available["pytesseract"]:
            module = importlib.import_module("pytesseract")
            return selected, lambda image: module.image_to_string(image, config="--psm 7")
        raise RuntimeError(f"OCR engine unavailable: {selected}")

    def solve(self, data: bytes, target: str, engine: str | None = None, *, use_cache: bool = True, candidate_offset: int = 0) -> dict[str, Any]:
        requested_engine = engine or "auto"
        digest = hashlib.sha256(bytes(data or b"")).hexdigest()
        cache_key = f"{requested_engine}:{digest}"
        stat = self._stats.setdefault(str(target), {"attempts": 0, "successes": 0})
        stat["attempts"] += 1
        if use_cache and cache_key in self._cache:
            cached = dict(self._cache[cache_key])
            cached["attempt"] = stat["attempts"]
            cached["cached"] = True
            stat["successes"] += int(cached["solved"])
            return cached
        candidates = [requested_engine]
        if requested_engine in {"auto", "pytesseract", "ddddocr"}:
            candidates = ["ddddocr", "pytesseract"]
        if candidates:
            offset = int(candidate_offset) % len(candidates)
            candidates = candidates[offset:] + candidates[:offset]
        selected = requested_engine
        text = ""
        errors = []
        for candidate in candidates:
            try:
                selected, recognizer = self._engine(candidate)
                text = re.sub(r"\s+", "", str(recognizer(self._preprocess(data)) or ""))
                if text:
                    break
                errors.append(f"{candidate}: empty OCR result")
            except Exception as exc:
                errors.append(f"{candidate}: {exc}")
        solved = bool(text)
        error = "; ".join(errors) or "empty OCR result"
        confidence = 0.9 if solved and selected == "ddddocr" else 0.75 if solved else 0.0
        result = {
            "solved": solved,
            "text": text,
            "engine": selected,
            "attempt": stat["attempts"],
            "confidence": confidence,
            "cached": False,
        }
        if not solved:
            result["error"] = error
        if solved:
            self._cache[cache_key] = dict(result)
        stat["successes"] += int(solved)
        return result

    def solve_with_refresh(
        self,
        fetch_image,
        target: str,
        engine: str | None = None,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        attempts = []
        for _ in range(min(3, max(1, int(max_attempts)))):
            result = self.solve(fetch_image(), target, engine, use_cache=False)
            attempts.append(result)
            if result["solved"]:
                return {"solved": True, "text": result["text"], "attempts": attempts}
        return {"solved": False, "text": "", "attempts": attempts}

    def invalidate(self, data: bytes, engine: str | None = None) -> None:
        requested_engine = engine or "auto"
        digest = hashlib.sha256(bytes(data or b"")).hexdigest()
        self._cache.pop(f"{requested_engine}:{digest}", None)
    def stats(self, target: str) -> dict[str, Any]:
        stat = dict(self._stats.get(str(target), {"attempts": 0, "successes": 0}))
        stat["success_rate"] = stat["successes"] / stat["attempts"] if stat["attempts"] else 0.0
        return stat


class CaptchaBypassDetector:
    """Probe common server-side captcha enforcement mistakes."""

    fixed_values = ("0000", "1234")

    @staticmethod
    def _accepted(result: Any) -> bool:
        if isinstance(result, bool):
            return result
        if isinstance(result, Mapping):
            if "accepted" in result:
                return bool(result["accepted"])
            if "success" in result:
                return bool(result["success"])
            status = str(result.get("status", "")).lower()
            code = int(result.get("status_code", 0) or 0)
            body = str(result.get("body", result.get("text", "")))
            if CAPTCHA_FAILURE_RE.search(body) or CAPTCHA_CHALLENGE_RE.search(body):
                return False
            if status in {"ok", "solved", "bypassed", "success"}:
                return True
            return 200 <= code < 300 and bool(body.strip())
        code = int(getattr(result, "status_code", 0) or 0)
        body = str(getattr(result, "text", ""))
        return (
            200 <= code < 300
            and bool(body.strip())
            and not CAPTCHA_FAILURE_RE.search(body)
            and not CAPTCHA_CHALLENGE_RE.search(body)
        )

    @staticmethod
    def _submit(submitter: Any, params: dict[str, Any], session_token: Any = None) -> Any:
        if submitter is None:
            return None
        function = getattr(submitter, "submit_captcha", None) or (submitter if callable(submitter) else None)
        if function is None:
            return None
        calls = []
        if session_token is not None:
            calls.extend((lambda: function(params, session=session_token), lambda: function(session_token, params)))
        calls.append(lambda: function(params))
        last_error = None
        for call in calls:
            try:
                return call()
            except TypeError as exc:
                last_error = exc
        if last_error:
            raise last_error
        return None

    def detect_bypass(self, response: Any, session: Any, previous_attempts: Any) -> dict[str, Any]:
        context = dict(previous_attempts) if isinstance(previous_attempts, Mapping) else {}
        params = dict(context.get("params") or {})
        fields = [name for name in params if CAPTCHA_FIELD_RE.search(str(name))]
        submitter = context.get("submitter") or session
        current_session = context.get("session_id")
        result = {
            "bypassed": False,
            "method": None,
            "remove_param": False,
            "fixed_value": False,
            "fixed_captcha_value": "",
            "cross_session_reuse": False,
            "client_side_only": bool(CLIENT_CAPTCHA_RE.search(str(getattr(response, "text", "")))),
            "reusable": False,
            "confidence": 0.0,
            "probes": [],
        }
        if not fields or submitter is None:
            return result

        without_captcha = {name: value for name, value in params.items() if name not in fields}
        removed = self._submit(submitter, without_captcha, current_session)
        result["remove_param"] = self._accepted(removed)
        result["probes"].append({"method": "remove_param", "accepted": result["remove_param"]})

        for value in tuple(context.get("fixed_values") or self.fixed_values):
            candidate = dict(params)
            for field in fields:
                candidate[field] = value
            accepted = self._accepted(self._submit(submitter, candidate, current_session))
            result["probes"].append({"method": "fixed_value", "value": value, "accepted": accepted})
            if accepted:
                result["fixed_value"] = True
                result["fixed_captcha_value"] = str(value)
                break

        captcha_value = context.get("captcha_value")
        if captcha_value is None:
            captcha_value = params.get(fields[0])
        reusable_params = dict(params)
        for field in fields:
            reusable_params[field] = captcha_value
        first_reuse = self._accepted(self._submit(submitter, reusable_params, current_session))
        second_reuse = self._accepted(self._submit(submitter, reusable_params, current_session))
        result["reusable"] = bool(first_reuse and second_reuse)
        result["probes"].append({"method": "reuse", "accepted": result["reusable"]})

        other_session = context.get("other_session")
        if other_session is not None:
            result["cross_session_reuse"] = bool(
                first_reuse and self._accepted(self._submit(submitter, reusable_params, other_session))
            )
            result["probes"].append({"method": "cross_session_reuse", "accepted": result["cross_session_reuse"]})

        if result["remove_param"]:
            result.update(bypassed=True, method="remove_param", confidence=0.95)
        elif result["fixed_value"]:
            result.update(bypassed=True, method="fixed_value", confidence=0.9)
        elif result["reusable"] or result["cross_session_reuse"]:
            result.update(bypassed=True, method="reuse", confidence=0.85)
        return result


class CaptchaHandler:
    def __init__(
        self,
        ocr_engines: Mapping[str, Any] | None = None,
        artifact_dir: str | Path | None = None,
        *,
        technique_memory: Any = None,
        solver: CaptchaSolver | None = None,
        bypass_detector: CaptchaBypassDetector | None = None,
        auto_install: bool = True,
    ):
        self.artifact_dir = Path(artifact_dir or "evidence/captcha").resolve()
        self.solver = solver or CaptchaSolver(ocr_engines, auto_install=auto_install)
        self.ocr_engines = self.solver.ocr_engines
        self.bypass_detector = bypass_detector or CaptchaBypassDetector()
        self.technique_memory = technique_memory
        self._image_attempts: dict[str, int] = {}

    def detect(self, response: Any) -> dict[str, Any]:
        raw_text = str(getattr(response, "text", ""))
        text = raw_text.lower()
        headers = {str(key).lower(): str(value).lower() for key, value in getattr(response, "headers", {}).items()}
        content_type = headers.get("content-type", "")
        visibility = _CaptchaVisibilityParser()
        try:
            visibility.feed(raw_text)
            visibility.close()
        except Exception:
            visibility = _CaptchaVisibilityParser()
        if visibility.hidden_only:
            return {"type": None, "automatic": True, "detected": False, "content_type": content_type}
        if any(value in text for value in ("recaptcha", "h-captcha", "cf-turnstile", "turnstile")):
            captcha_type, automatic = "behavior", False
        elif any(value in text for value in ("slider", "slide captcha", "unlock captcha", "\u6ed1\u5757")):
            captcha_type, automatic = "slider", False
        elif any(value in text for value in ("click captcha", "select captcha", "\u70b9\u9009\u9a8c\u8bc1\u7801")):
            captcha_type, automatic = "click", False
        elif any(value in text for value in ("sms_code", "短信验证码", "phone code")):
            captcha_type, automatic = "sms", False
        elif re.search(r"(captcha|kaptcha|verify)[^\n]{0,100}\.(png|jpg|jpeg|gif)|name=[\"'](?:captcha|verifycode)", text):
            captcha_type, automatic = "image", True
        elif re.search(r"name=[\"'](?:csrf|_token|authenticity_token)", text):
            captcha_type, automatic = "csrf", True
        else:
            captcha_type, automatic = None, True
        return {"type": captcha_type, "automatic": automatic, "detected": captcha_type is not None, "content_type": content_type}

    def solve_image(self, data: bytes, target: str, engine: str | None = None) -> dict[str, Any]:
        digest = hashlib.sha256(bytes(data or b"")).hexdigest()
        attempt_key = f"{target}:{engine or 'auto'}:{digest}"
        candidate_offset = self._image_attempts.get(attempt_key, 0)
        result = self.solver.solve(
            data,
            target,
            engine,
            use_cache=candidate_offset == 0,
            candidate_offset=candidate_offset,
        )
        self._image_attempts[attempt_key] = candidate_offset + 1
        return result

    def solve_image_with_refresh(self, fetch_image, target: str, engine: str | None = None, max_attempts: int = 3) -> dict[str, Any]:
        return self.solver.solve_with_refresh(fetch_image, target, engine, max_attempts)


    def stats(self, target: str) -> dict[str, Any]:
        return self.solver.stats(target)

    @staticmethod
    def _result(status: str, *, captcha_value: str = "", bypass_method: str | None = None, confidence: float = 0.0, artifact: str | None = None) -> dict[str, Any]:
        return {"status": status, "captcha_value": captcha_value, "bypass_method": bypass_method, "confidence": max(0.0, min(1.0, float(confidence))), "artifact": artifact}

    @staticmethod
    def _captcha_field(response: Any, params: Mapping[str, Any]) -> str:
        for name in params:
            if CAPTCHA_FIELD_RE.search(str(name)):
                return str(name)
        match = re.search(r"name=[\"'](?P<name>[^\"']*(?:captcha|verify(?:code)?|checkcode|vcode)[^\"']*)[\"']", str(getattr(response, "text", "")), re.I)
        return match.group("name") if match else "captcha"

    def _record_bypass(self, target: str, bypass: Mapping[str, Any]) -> None:
        if self.technique_memory is None or not bypass.get("method"):
            return
        try:
            self.technique_memory.record_attempt(target_url=str(target), technique_name=f"captcha_{bypass['method']}", waf_type="captcha", success=True, metadata={key: value for key, value in bypass.items() if key != "probes"}, notes="Captcha bypass detected automatically.")
        except Exception:
            return

    @staticmethod
    def _write_png(path: Path, data: bytes, fallback_text: str = "Captcha challenge requires operator action.") -> None:
        try:
            from PIL import Image, ImageDraw

            try:
                image = Image.open(io.BytesIO(data)).convert("RGB")
            except Exception:
                image = Image.new("RGB", (1280, 720), "white")
                ImageDraw.Draw(image).multiline_text((24, 24), fallback_text[:4000], fill="black", spacing=4)
            image.save(path, format="PNG")
        except Exception:
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDAT\x08\xd7c\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\x89\x89\xf1\x00\x00\x00\x00IEND\xaeB`\x82")
    def _save_screenshot(self, response: Any, target: str, captcha_type: str, session: Any, context: Mapping[str, Any]) -> str:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(target))
        path = self.artifact_dir / f"{safe_target}-{captcha_type}.png"
        screenshot = context.get("screenshot") or getattr(session, "screenshot", None) or getattr(response, "screenshot", None)
        fallback_text = str(getattr(response, "text", "")) or "Captcha challenge requires operator action."
        if callable(screenshot):
            try:
                captured = screenshot(path=str(path))
            except TypeError:
                captured = screenshot(str(path))
            if isinstance(captured, (bytes, bytearray)):
                screenshot_data = bytes(captured)
            elif captured and Path(str(captured)).exists():
                screenshot_data = Path(str(captured)).read_bytes()
            elif path.exists():
                screenshot_data = path.read_bytes()
            else:
                screenshot_data = b""
            self._write_png(path, screenshot_data, fallback_text)
            return str(path)
        content = bytes(getattr(response, "content", b"") or b"")
        self._write_png(path, content, fallback_text)
        return str(path)

    def handle(self, response: Any, target: str, engine: str | None = None, *, session: Any = None, previous_attempts: Any = None) -> dict[str, Any]:
        captcha_type = self.detect(response)["type"]
        if captcha_type is None or captcha_type == "csrf":
            return self._result("not-required")
        context = dict(previous_attempts) if isinstance(previous_attempts, Mapping) else {}
        params = dict(context.get("params") or {})
        if captcha_type == "image" and self.solver.available:
            fetch_image = context.get("fetch_image")
            for _ in range(3):
                data = fetch_image() if callable(fetch_image) else bytes(getattr(response, "content", b"") or b"")
                solved = self.solve_image(data, target, engine)
                if not solved["solved"]:
                    continue
                captcha_value = solved["text"]
                retry_params = dict(params)
                retry_params[self._captcha_field(response, params)] = captcha_value
                retry = context.get("retry") or context.get("submitter") or session
                can_retry = callable(retry) or callable(getattr(retry, "submit_captcha", None))
                if can_retry and not CaptchaBypassDetector._accepted(CaptchaBypassDetector._submit(retry, retry_params)):
                    self.solver.invalidate(data, engine)
                    continue
                result = self._result("solved", captcha_value=captcha_value, bypass_method="ocr", confidence=solved.get("confidence", 0.75))
                result.update(solved=True, text=captcha_value)
                return result
        bypass = self.bypass_detector.detect_bypass(response, session, context)
        if bypass.get("bypassed"):
            self._record_bypass(target, bypass)
            public_method = "remove_param" if bypass.get("method") == "client_side" else bypass.get("method")
            result = self._result("bypassed", captcha_value=str(bypass.get("fixed_captcha_value", "")), bypass_method=public_method, confidence=bypass.get("confidence", 0.0))
            result["bypass"] = bypass
            return result
        return self._result("operator-required", artifact=self._save_screenshot(response, target, str(captcha_type), session, context))

    def test_bypass(self, target: str, submitter: Any, params: Mapping[str, Any], session_ids=None) -> dict[str, Any]:
        sessions = list(session_ids or ["default"])
        response = type("CaptchaResponse", (), {"text": ""})()
        result = self.bypass_detector.detect_bypass(response, submitter, {"params": dict(params), "captcha_value": next((value for name, value in params.items() if CAPTCHA_FIELD_RE.search(str(name))), ""), "session_id": sessions[0], "other_session": sessions[-1]})
        return {"target": target, "reusable": result["reusable"], "parameter_optional": result["remove_param"], "cross_session_reuse": result["cross_session_reuse"], "client_side_candidate": result["client_side_only"]}
