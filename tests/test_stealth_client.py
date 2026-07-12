import json
from pathlib import Path

from core.stealth.stealth_http_client import StealthHTTPClient


class Cookies(dict):
    def get_dict(self): return dict(self)

class Response:
    def __init__(self,status=200,text='',headers=None,url='https://fixture/',content=b''):
        self.status_code=status;self.text=text;self.headers=headers or {};self.url=url;self.content=content;self.cookies=Cookies();self.history=[]

class Transport:
    def __init__(self,responses): self.responses=list(responses);self.calls=[]
    def request(self,method,url,**kwargs): self.calls.append((method,url,kwargs)); return self.responses.pop(0)


def test_session_create_persists_fingerprint_cookie_and_csrf(tmp_path):
    transport=Transport([Response(text='<input name="csrf_token" value="abc">',headers={'Set-Cookie':'sid=1'})])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    created=client.session_create('https://fixture')
    result=client.stealth_request('GET','https://fixture/form')
    state=client.session_state('https://fixture')
    assert created['fingerprint_id']==state['fingerprint_id']
    assert state['csrf_tokens']['csrf_token']=='abc'
    assert transport.calls[0][2]['headers']['User-Agent']
    assert transport.calls[0][2]['verify'] is True
    assert Path(state['state_path']).exists()


def test_waf_block_switches_strategy_and_retries(tmp_path):
    transport=Transport([Response(403,'forbidden',{'Server':'cloudflare','CF-Ray':'x'}),Response(200,'ok')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/path',options={'max_retries':2})
    assert result['status_code']==200
    assert result['attempts']==2
    assert result['timeline'][0]['waf']['blocked'] is True
    assert result['timeline'][1]['strategy']


def test_rate_limit_waits_and_retries(tmp_path):
    slept=[]; transport=Transport([Response(429,'rate limited',{'Retry-After':'1'}),Response(200,'ok')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=slept.append)
    result=client.stealth_request('GET','https://fixture/',options={'max_retries':2,'jitter':False})
    assert result['status_code']==200 and slept
    assert client.session_state('https://fixture')['rate_limit']['last_backoff_seconds']>=1


def test_operator_captcha_interrupts_without_blind_retry(tmp_path):
    transport=Transport([Response(200,'<div class="cf-turnstile"></div>',content=b'page')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/login')
    assert result['status']=='operator-required'
    assert Path(result['captcha']['artifact']).exists()


def test_multi_step_chain_extracts_value_for_next_request(tmp_path):
    transport=Transport([Response(200,'{"token":"abc"}',headers={'Content-Type':'application/json'}),Response(200,'done')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.execute_chain('https://fixture',[{'method':'GET','url':'/a','extract':{'token':'json:token'}},{'method':'POST','url':'/b','data':{'auth':'${token}'}}])
    assert result['variables']['token']=='abc'
    assert transport.calls[1][2]['data']['auth']=='abc'


def test_stealth_scan_uses_bounded_injected_probes(tmp_path):
    transport=Transport([Response(200,'ok') for _ in range(20)])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_scan('https://fixture',options={'active_waf':True,'rate_probe_rates':[1,2]})
    assert result['waf']['blocked_probes']==0
    assert result['rate_limit']['tested_rates']==[1,2]
    assert 'captcha' in result


def test_cookie_is_restored_into_transport(tmp_path):
    first=Transport([Response(200,'ok',{'Set-Cookie':'sid=abc'})])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:first,sleep=lambda _:None)
    client.stealth_request('GET','https://fixture/')
    class CookieTransport(Transport):
        def __init__(self): super().__init__([Response(200,'ok')]); self.cookies=Cookies()
    restored=CookieTransport(); client2=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:restored,sleep=lambda _:None)
    client2.session_create('https://fixture',resume=True)
    assert restored.cookies['sid']=='abc'


def test_session_key_isolates_scheme_and_port(tmp_path):
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:Transport([Response()]),sleep=lambda _:None)
    a=client.session_create('http://fixture:80',resume=False); b=client.session_create('https://fixture:8443',resume=False)
    assert a['target']!=b['target'] and a['fingerprint_id']!=b['fingerprint_id']


def test_unsupported_strategy_is_not_sent_or_scored(tmp_path):
    transport=Transport([Response(403,'forbidden',{'Server':'cloudflare','CF-Ray':'x'}),Response(403,'forbidden',{'Server':'cloudflare','CF-Ray':'x'})])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/',options={'max_retries':1})
    assert result['timeline'][1]['strategy_status']=='unsupported'
    assert 'X-Hunter-Strategy' not in transport.calls[1][2]['headers']


def test_large_response_body_is_bounded_and_artifact_saved(tmp_path):
    transport=Transport([Response(200,'X'*5000)])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/',options={'max_body_chars':100})
    assert len(result['body'])<=101 and result['body_truncated'] is True
    assert Path(result['body_artifact']).exists()


def test_proxy_failure_rotates_to_next_proxy(tmp_path):
    class FailingTransport(Transport):
        def request(self,method,url,**kwargs):
            self.calls.append((method,url,kwargs))
            proxy=kwargs.get('proxies',{}).get('https','')
            if proxy.endswith(':1'): raise RuntimeError('proxy failed')
            return Response(200,'ok')
    transport=FailingTransport([]); client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    client.set_proxy_pool(['http://one:1','http://two:2'])
    result=client.stealth_request('GET','https://fixture/',options={'max_retries':2})
    assert result['status_code']==200
    assert transport.calls[0][2]['proxies']['https']!=transport.calls[1][2]['proxies']['https']


def test_image_captcha_can_refresh_ocr_and_resubmit(tmp_path):
    html='<img src="/captcha.png"><input name="captcha">'
    transport=Transport([Response(200,html),Response(200,'',content=simple_png_bytes() if 'simple_png_bytes' in globals() else b'image'),Response(200,'accepted')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    client.captcha.ocr_engines['custom']=lambda image:'1234'
    result=client.stealth_request('POST','https://fixture/login',data={'user':'a'},options={'captcha_engine':'custom','captcha_field':'captcha','max_retries':2})
    assert result['status_code']==200
    assert any(call[2].get('data',{}).get('captcha')=='1234' for call in transport.calls if isinstance(call[2].get('data'),dict))


def test_applied_waf_failure_is_scored_before_retry(tmp_path):
    transport=Transport([Response(403,'forbidden',{'X-Mod-Security':'1'}),Response(403,'forbidden',{'X-Mod-Security':'1'}),Response(200,'ok')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('POST','https://fixture/',data='select',options={'max_retries':2})
    history=client.waf.history['ModSecurity']
    assert history['case-variation']['attempts']==1
    assert history['case-variation']['successes']==0
    assert result['status_code']==200


def test_plain_503_does_not_change_rate_state(tmp_path):
    transport=Transport([Response(503,'maintenance',{})])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/',options={'max_retries':0,'jitter':False})
    assert result['timeline'][0]['rate_limited'] is False
    assert client.session_state('https://fixture')['rate_limit']['failures']==0


def test_proxy_failure_is_attributed_to_request_proxy(tmp_path):
    class FailingTransport(Transport):
        def request(self,method,url,**kwargs):
            self.calls.append((method,url,kwargs)); raise RuntimeError('proxy failed')
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:FailingTransport([]),sleep=lambda _:None)
    client.set_proxy_pool(['http://one:1'])
    client.stealth_request('GET','https://fixture/',options={'max_retries':0})
    assert client.rate.state('https://fixture:443','http://one:1')['failures']==1
    assert client.rate.state('https://fixture:443',None)['failures']==0


def test_waf_block_timeline_preserves_proxy_without_marking_ip_ban(tmp_path):
    transport=Transport([Response(403,'forbidden',{'X-Mod-Security':'1'})])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    client.set_proxy_pool(['http://one:1'])
    result=client.stealth_request('GET','https://fixture/',options={'max_retries':0})
    assert result['timeline'][0]['proxy']=='http://one:1'
    assert client.proxy_pool.proxies['http://one:1']['target_bans'].get('https://fixture:443') is not True


def test_rate_limit_failure_is_counted_once(tmp_path):
    transport=Transport([Response(429,'rate limited',{'Retry-After':'1'}),Response(200,'ok')])
    slept=[]; client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=slept.append)
    client.stealth_request('GET','https://fixture/',options={'max_retries':1,'jitter':False})
    assert slept[0]==1


def test_captcha_fetches_real_image_and_resubmits_same_session(tmp_path):
    png=b'\x89PNG\r\n\x1a\nfixture'
    transport=Transport([Response(200,'<img src="/captcha.png"><input name="captcha">',url='https://fixture/login'),Response(200,'',{'Content-Type':'image/png'},url='https://fixture/captcha.png',content=png),Response(200,'accepted')])
    seen=[]; client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    client.captcha.ocr_engines['custom']=lambda image: seen.append(image) or '1234'
    result=client.stealth_request('POST','https://fixture/login',data={'user':'a'},options={'captcha_engine':'custom','max_retries':2})
    assert transport.calls[1][1]=='https://fixture/captcha.png'
    assert bytes(seen[0]).startswith(b'\x89PNG')
    assert transport.calls[2][2]['data']['captcha']=='1234'
    assert result['status_code']==200


def test_captcha_refreshes_image_at_most_three_times(tmp_path):
    page='<img src="/captcha.png"><input name="captcha">'; png=b'\x89PNG\r\n\x1a\nfixture'
    transport=Transport([Response(200,page,url='https://fixture/login')]+[Response(200,'',{'Content-Type':'image/png'},url='https://fixture/captcha.png',content=png) for _ in range(3)]+[Response(200,'accepted')])
    values=iter(['','','7788']); client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    client.captcha.ocr_engines['custom']=lambda image:next(values)
    result=client.stealth_request('POST','https://fixture/login',data={'user':'a'},options={'captcha_engine':'custom','max_retries':1})
    assert sum(call[1].endswith('/captcha.png') for call in transport.calls)==3
    assert transport.calls[-1][2]['data']['captcha']=='7788'
    assert result['status_code']==200
