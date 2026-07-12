import base64
import io
import json
from pathlib import Path

import pytest

from core.stealth.waf_detector import WAFDetector
from core.stealth.captcha_handler import CaptchaHandler


class Response:
    def __init__(self, status=200, headers=None, text='', content=b'', url='https://fixture/'):
        self.status_code=status; self.headers=headers or {}; self.text=text; self.content=content; self.url=url


def test_waf_passive_detection_cloudflare_and_chinese_block_page():
    detector=WAFDetector()
    result=detector.detect_response(Response(403, {'Server':'cloudflare','CF-Ray':'abc'}, '您的请求已被拦截 安全检测'))
    assert result['blocked'] is True
    assert result['waf_type']=='Cloudflare'
    assert result['confidence'] >= 0.8


def test_waf_modsecurity_detection_and_ranked_strategy_learning(tmp_path):
    detector=WAFDetector(history_path=tmp_path/'history.json')
    result=detector.detect_response(Response(403, {'Server':'nginx'}, 'ModSecurity Action: Access denied with code 403'))
    assert result['waf_type']=='ModSecurity'
    strategies=detector.strategies_for('ModSecurity')
    assert any('case' in s['id'] or 'comment' in s['id'] for s in strategies)
    detector.record_outcome('ModSecurity', strategies[-1]['id'], True)
    assert detector.strategies_for('ModSecurity')[0]['id']==strategies[-1]['id']


def test_active_probe_uses_injected_sender_and_classifies_blocked_payloads():
    seen=[]
    def sender(method,url,**kwargs):
        params=kwargs.get('params') or {}
        seen.append(params)
        return Response(403, {'Server':'cloudflare','CF-Ray':'x'}, 'forbidden') if params else Response()
    result=WAFDetector().active_probe('https://fixture/',sender)
    assert len(seen)==4
    assert result['blocked_probes']>=3
    assert result['waf_type']=='Cloudflare'


def simple_png_bytes():
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return b'not-a-real-image'
    image=Image.new('RGB',(120,40),'white'); ImageDraw.Draw(image).text((10,8),'1234',fill='black')
    out=io.BytesIO(); image.save(out,format='PNG'); return out.getvalue()


def test_captcha_classification_and_csrf_detection():
    handler=CaptchaHandler()
    assert handler.detect(Response(text='<img src="/captcha.png"><input name="captcha">'))['type']=='image'
    assert handler.detect(Response(text='<div class="slider unlock captcha"></div>'))['type']=='slider'
    assert handler.detect(Response(text='<div class="h-captcha"></div>'))['type']=='behavior'
    assert handler.detect(Response(text='<input type="hidden" name="csrf_token" value="abc">'))['type']=='csrf'


def test_image_captcha_ocr_preprocessing_and_stats_with_injected_engine(tmp_path):
    calls=[]
    handler=CaptchaHandler(ocr_engines={'custom':lambda image: calls.append(image) or ' 12A4 '}, artifact_dir=tmp_path)
    result=handler.solve_image(simple_png_bytes(),target='fixture',engine='custom')
    assert result['solved'] is True and result['text']=='12A4'
    assert handler.stats('fixture')['success_rate']==1.0
    assert calls


def test_unhandled_behavior_captcha_saves_artifact_and_requests_operator(tmp_path):
    handler=CaptchaHandler(artifact_dir=tmp_path)
    result=handler.handle(Response(text='<div class="cf-turnstile"></div>',content=b'page'),target='fixture')
    assert result['status']=='operator-required'
    assert Path(result['artifact']).exists()


def test_captcha_bypass_checks_use_injected_submitter():
    handler=CaptchaHandler()
    def submit(session_id,params):
        if 'captcha' not in params: return {'accepted':True}
        return {'accepted': params['captcha']=='fixed'}
    result=handler.test_bypass('fixture',submit,{'captcha':'fixed'},session_ids=['a','b'])
    assert result['parameter_optional'] is True
    assert result['reusable'] is True
    assert result['cross_session_reuse'] is True


def test_image_captcha_refresh_is_bounded_to_three_attempts(tmp_path):
    calls=[]
    values=iter(['','', '7788'])
    handler=CaptchaHandler(ocr_engines={'custom':lambda image:next(values)},artifact_dir=tmp_path)
    result=handler.solve_image_with_refresh(lambda:calls.append(1) or simple_png_bytes(),'fixture','custom',max_attempts=9)
    assert result['solved'] is True and result['text']=='7788'
    assert len(calls)==3


def test_chinese_vendor_signatures_are_utf8_and_detectable():
    result=WAFDetector().detect_response(Response(403,{'X-SafeDog':'1'},'??? ????????'))
    assert result['waf_type']=='SafeDog' and result['blocked']
