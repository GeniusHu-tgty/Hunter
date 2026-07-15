from core.stealth.captcha_handler import CaptchaHandler


class Response:
    def __init__(self, text):
        self.text = text
        self.headers = {"Content-Type": "text/html"}


def test_hidden_cas_kaptcha_is_not_detected():
    html = """
    <script>
      const errorTimes = 0;
      const captchaRequired = false;
    </script>
    <div id="captcha-container" style="display:none">
      <img id="captchaImg" src="@{${#themes.code('cas.standard.css.file')}}" alt="kaptcha">
      <input type="text" name="captcha">
    </div>
    """

    result = CaptchaHandler(auto_install=False).detect(Response(html))

    assert result["type"] is None
    assert result["automatic"] is True
    assert result["detected"] is False


def test_visible_captcha_image_is_detected():
    html = '<div><img src="/captcha.png"><input name="captcha"></div>'

    result = CaptchaHandler(auto_install=False).detect(Response(html))

    assert result["type"] == "image"
    assert result["automatic"] is True
    assert result["detected"] is True


def test_kaptcha_jpg_with_dynamic_query_is_detected():
    html = '<img src="/kaptcha.jpg?id=1712345678901"><input name="captcha">'

    result = CaptchaHandler(auto_install=False).detect(Response(html))

    assert result["type"] == "image"
    assert result["automatic"] is True
    assert result["detected"] is True


def test_template_captcha_url_is_not_required_and_is_not_fetched():
    from core.stealth.stealth_http_client import StealthHTTPClient

    class PageResponse(Response):
        url = "https://fixture/login"

    class RejectingTransport:
        def request(self, *_args, **_kwargs):
            raise AssertionError("template captcha URL must not be fetched")

    client = object.__new__(StealthHTTPClient)
    result = client._solve_page_captcha(
        PageResponse('<img src="@{${#themes.code(\'cas.standard.css.file\')}}" alt="captcha">'),
        RejectingTransport(),
        {"target": "https://fixture"},
        {},
        {},
        None,
        [],
    )

    assert result["status"] == "not-required"
    assert result["type"] is None
    assert result["solved"] is False


def test_hidden_captcha_image_does_not_block_visible_field():
    html = '<img src="/captcha.png" style="display: none"><input name="captcha">'

    result = CaptchaHandler(auto_install=False).detect(Response(html))

    assert result["type"] is None
    assert result["detected"] is False


def test_hidden_captcha_input_is_not_detected():
    html = '<input type="hidden" name="captcha" value="">'

    result = CaptchaHandler(auto_install=False).detect(Response(html))

    assert result["type"] is None
    assert result["detected"] is False
