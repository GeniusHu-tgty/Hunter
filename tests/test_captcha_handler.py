from pathlib import Path

from core.stealth.captcha_handler import CaptchaBypassDetector, CaptchaHandler


class Response:
    def __init__(self, text="", content=b"", headers=None, status_code=200, url="https://fixture/login"):
        self.text = text
        self.content = content
        self.headers = headers or {}
        self.status_code = status_code
        self.url = url


class RecordingMemory:
    def __init__(self):
        self.calls = []

    def record_attempt(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs


def test_ocr_failure_three_times_falls_back_to_remove_parameter_bypass(tmp_path):
    ocr_calls = []
    submissions = []

    def failing_ocr(_image):
        ocr_calls.append(1)
        raise RuntimeError("ocr unavailable")

    def submit(params):
        submissions.append(dict(params))
        return {"accepted": "captcha" not in params}

    memory = RecordingMemory()
    handler = CaptchaHandler(
        ocr_engines={"broken": failing_ocr},
        artifact_dir=tmp_path,
        technique_memory=memory,
        auto_install=False,
    )
    result = handler.handle(
        Response(
            text='<img src="/captcha.png"><input name="captcha">',
            content=b"same-image",
            headers={"Content-Type": "image/png"},
        ),
        target="https://fixture/login",
        engine="broken",
        session=submit,
        previous_attempts={"params": {"username": "alice", "captcha": "stale"}},
    )

    assert result["status"] == "bypassed"
    assert result["bypass_method"] == "remove_param"
    assert len(ocr_calls) == 3
    assert submissions
    assert memory.calls[0]["technique_name"] == "captcha_remove_param"


def test_bypass_detector_finds_fixed_cross_session_client_and_reuse_paths():
    calls = []

    def submit(params, session=None):
        calls.append((dict(params), session))
        value = params.get("verifyCode")
        return {
            "accepted": value in {"0000", "known-good"},
            "client_validated": value == "client-only",
        }

    detector = CaptchaBypassDetector()
    result = detector.detect_bypass(
        Response(text="captchaVerified = true; validateCaptcha();"),
        submit,
        {
            "params": {"username": "alice", "verifyCode": "known-good"},
            "captcha_value": "known-good",
            "other_session": "fresh-session",
            "fixed_values": ["0000", "1234"],
        },
    )

    assert result["fixed_value"] is True
    assert result["cross_session_reuse"] is True
    assert result["reusable"] is True
    assert result["client_side_only"] is True
    assert result["method"] == "fixed_value"
    assert calls


def test_operator_required_saves_png_screenshot(tmp_path):
    class BrowserSession:
        def screenshot(self, path):
            Path(path).write_bytes(b"PNG screenshot evidence")
            return path

    handler = CaptchaHandler(artifact_dir=tmp_path, auto_install=False)
    result = handler.handle(
        Response(text='<div class="slider unlock captcha"></div>', content=b"html"),
        target="https://fixture/login",
        session=BrowserSession(),
        previous_attempts={"params": {"captcha": ""}},
    )

    assert result == {
        "status": "operator-required",
        "captcha_value": "",
        "bypass_method": None,
        "confidence": 0.0,
        "artifact": result["artifact"],
    }
    assert result["artifact"].endswith(".png")
    assert Path(result["artifact"]).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")

def test_http_200_captcha_page_is_not_treated_as_bypass_success():
    detector = CaptchaBypassDetector()

    def submit(_params, session=None):
        return Response(
            text='<input name="captcha">',
            status_code=200,
        )

    result = detector.detect_bypass(
        Response(text='<input name="captcha">'),
        submit,
        {"params": {"captcha": "known"}, "other_session": "fresh"},
    )

    assert result["bypassed"] is False
    assert result["remove_param"] is False
    assert result["fixed_value"] is False
    assert result["reusable"] is False


def test_client_side_signal_is_candidate_not_unproven_bypass():
    detector = CaptchaBypassDetector()
    false_result = detector.detect_bypass(
        Response(text="window.captchaVerified = false;"),
        None,
        {},
    )
    true_result = detector.detect_bypass(
        Response(text="window.captchaVerified = true; validateCaptcha();"),
        None,
        {},
    )

    assert false_result["client_side_only"] is False
    assert false_result["bypassed"] is False
    assert true_result["client_side_only"] is True
    assert true_result["bypassed"] is False


def test_legacy_pytesseract_selection_still_prefers_ddddocr(tmp_path):
    calls = []
    handler = CaptchaHandler(
        ocr_engines={
            "ddddocr": lambda _image: calls.append("ddddocr") or "2468",
            "pytesseract": lambda _image: calls.append("pytesseract") or "1357",
        },
        artifact_dir=tmp_path,
        auto_install=False,
    )

    result = handler.solve_image(b"image", "fixture", engine="pytesseract")

    assert result["text"] == "2468"
    assert result["engine"] == "ddddocr"
    assert calls == ["ddddocr"]


def test_operator_screenshot_supports_keyword_only_browser_and_writes_png(tmp_path):
    class BrowserSession:
        def screenshot(self, *, path):
            Path(path).write_bytes(b"not actually a png")
            return path

    handler = CaptchaHandler(artifact_dir=tmp_path, auto_install=False)
    result = handler.handle(
        Response(text='<div class="slider unlock captcha"></div>'),
        target="https://fixture/login",
        session=BrowserSession(),
    )

    assert Path(result["artifact"]).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")

def test_status_ok_or_vcode_image_challenge_is_not_accepted():
    detector = CaptchaBypassDetector()

    assert detector._accepted({"status": "ok", "body": '<input name="captcha">'}) is False
    assert detector._accepted(Response(text='<input name="vcode"><img src="/captcha.png">')) is False


def test_rejected_nonempty_ocr_rotates_engine_instead_of_reusing_cache(tmp_path):
    calls = []
    submissions = []

    def ddddocr_engine(_image):
        calls.append("ddddocr")
        return "wrong"

    def pytesseract_engine(_image):
        calls.append("pytesseract")
        return "8642"

    def submit(params):
        submissions.append(dict(params))
        return {"accepted": params.get("captcha") == "8642"}

    handler = CaptchaHandler(
        ocr_engines={"ddddocr": ddddocr_engine, "pytesseract": pytesseract_engine},
        artifact_dir=tmp_path,
        auto_install=False,
    )
    result = handler.handle(
        Response(
            text='<img src="/captcha.png"><input name="captcha">',
            content=b"same-image",
            headers={"Content-Type": "image/png"},
        ),
        target="https://fixture/login",
        engine="pytesseract",
        session=submit,
        previous_attempts={"params": {"username": "alice", "captcha": ""}},
    )

    assert result["status"] == "solved"
    assert result["captcha_value"] == "8642"
    assert calls[:2] == ["ddddocr", "pytesseract"]
    assert [item["captcha"] for item in submissions[:2]] == ["wrong", "8642"]

def test_reappearing_same_image_rotates_engine_for_legacy_client_contract(tmp_path):
    calls = []
    handler = CaptchaHandler(
        ocr_engines={
            "ddddocr": lambda _image: calls.append("ddddocr") or "wrong",
            "pytesseract": lambda _image: calls.append("pytesseract") or "9753",
        },
        artifact_dir=tmp_path,
        auto_install=False,
    )

    first = handler.solve_image(b"same-image", "https://fixture/login", "pytesseract")
    second = handler.solve_image(b"same-image", "https://fixture/login", "pytesseract")

    assert first["text"] == "wrong"
    assert second["text"] == "9753"
    assert calls == ["ddddocr", "pytesseract"]
