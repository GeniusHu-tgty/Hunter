import json
from pathlib import Path

import pytest

from core.stealth.stealth_http_client import StealthHTTPClient


class Cookies(dict):
    def get_dict(self): return dict(self)

class Response:
    def __init__(self,status=200,text='',headers=None,url='https://fixture/',content=b''):
        self.status_code=status;self.text=text;self.headers=headers or {};self.url=url;self.content=content;self.cookies=Cookies();self.history=[]

class Transport:
    def __init__(self,responses): self.responses=list(responses);self.calls=[]
    def request(self,method,url,**kwargs): self.calls.append((method,url,kwargs)); return self.responses.pop(0)


class ExceptionTransport(Transport):
    def request(self,method,url,**kwargs):
        self.calls.append((method,url,kwargs))
        item=self.responses.pop(0)
        if isinstance(item,BaseException):
            raise item
        return item


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


def test_repeated_requests_and_restore_keep_one_fingerprint(tmp_path):
    first_transport=Transport([Response(),Response()])
    first=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:first_transport,
        sleep=lambda _:None,
    )
    created=first.session_create('https://fixture',resume=False)
    first.stealth_request(
        'GET',
        'https://fixture/a',
        options={'max_retries':0},
    )
    first.stealth_request(
        'GET',
        'https://fixture/b',
        options={'max_retries':0},
    )

    restored=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:Transport([]),
        sleep=lambda _:None,
    )
    state=restored.session_create('https://fixture',resume=True)

    assert state['fingerprint_id']==created['fingerprint_id']
    assert (
        first_transport.calls[0][2]['headers']['User-Agent']
        ==first_transport.calls[1][2]['headers']['User-Agent']
    )


def test_manual_rotation_changes_family_and_records_state(tmp_path):
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:Transport([]),
        sleep=lambda _:None,
    )
    before=client.session_create('https://fixture',resume=False)

    event=client.rotate_fingerprint(
        'https://fixture',
        reason='manual-test',
    )
    after=client.session_state('https://fixture')

    assert event['previous_browser']!=event['new_browser']
    assert before['fingerprint_id']!=after['fingerprint_id']
    assert after['fingerprint_rotation_count']==1
    assert after['fingerprint_rotations'][-1]['reason']=='manual-test'


def test_detection_session_can_explicitly_rotate_fingerprint(tmp_path):
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:Transport([]),
        sleep=lambda _:None,
    )
    session=client.session_create('https://fixture',resume=False)
    detection=client.detection_session(session['session_id'])

    event=detection.rotate_fingerprint('detection-manual')

    assert event['reason']=='detection-manual'
    assert event['previous_browser']!=event['new_browser']
    assert client.session_state('https://fixture')[
        'fingerprint_rotation_count'
    ]==1


def test_waf_block_switches_strategy_and_retries(tmp_path):
    transport=Transport([Response(403,'forbidden',{'Server':'cloudflare','CF-Ray':'x'}),Response(200,'ok')])
    client=StealthHTTPClient(state_dir=tmp_path,transport_factory=lambda:transport,sleep=lambda _:None)
    result=client.stealth_request('GET','https://fixture/path',options={'max_retries':2})
    assert result['status_code']==200
    assert result['attempts']==2
    assert result['timeline'][0]['waf']['blocked'] is True
    assert result['timeline'][1]['strategy']


@pytest.mark.parametrize(
    'body',
    [
        'forbidden',
        'Access Denied',
        '\u8bf7\u6c42\u88ab\u62e6\u622a',
        '\u5b89\u5168\u68c0\u6d4b',
    ],
)
def test_403_block_keyword_rotates_family_and_retries(tmp_path,body):
    transport=Transport([Response(403,body),Response(200,'ok')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/private',
        options={'max_retries':2},
    )
    state=client.session_state('https://fixture')

    assert result['status_code']==200
    assert result['timeline'][0]['fingerprint_id']!=(
        result['timeline'][-1]['fingerprint_id']
    )
    assert state['fingerprint_rotations'][-1]['reason']==(
        '403-block-keyword'
    )
    assert state['fingerprint_rotations'][-1]['previous_browser']!=(
        state['fingerprint_rotations'][-1]['new_browser']
    )


def test_automatic_fingerprint_rotation_retries_are_capped_at_two(
    tmp_path,
):
    transport=Transport([
        Response(403,'forbidden',{'X-Mod-Security':'1'})
        for _ in range(4)
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/private',
        options={'max_retries':3},
    )
    state=client.session_state('https://fixture')

    assert result['attempts']==4
    assert state['fingerprint_rotation_count']==2
    assert len(state['fingerprint_rotations'])==2
    assert all(
        event['automatic'] is True
        for event in state['fingerprint_rotations']
    )


def test_plain_authorization_403_does_not_rotate(tmp_path):
    transport=Transport([Response(403,'permission required')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/private',
        options={'max_retries':2},
    )

    assert result['attempts']==1
    assert client.session_state('https://fixture')[
        'fingerprint_rotation_count'
    ]==0


def test_second_plain_gateway_error_rotates_then_retries(tmp_path):
    transport=Transport([
        Response(502,'gateway'),
        Response(503,'maintenance'),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':2,'jitter':False},
    )
    state=client.session_state('https://fixture')

    assert result['status_code']==200
    assert result['attempts']==3
    assert state['fingerprint_rotations'][-1]['reason']==(
        'gateway-502-503-streak'
    )
    assert result['timeline'][0]['fingerprint_id']!=(
        result['timeline'][-1]['fingerprint_id']
    )


def test_non_gateway_response_resets_gateway_streak(tmp_path):
    transport=Transport([
        Response(502,'gateway'),
        Response(200,'ok'),
        Response(502,'gateway'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    first=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':1,'jitter':False},
    )
    second=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':0,'jitter':False},
    )
    state=client.session_state('https://fixture')

    assert first['status_code']==200
    assert second['status_code']==502
    assert state['fingerprint_failures']['gateway']==1
    assert state['fingerprint_rotation_count']==0


def test_rate_limited_503_does_not_rotate_fingerprint(tmp_path):
    transport=Transport([
        Response(503,'rate limited',{'Retry-After':'1'}),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':1,'jitter':False},
    )
    state=client.session_state('https://fixture')

    assert result['status_code']==200
    assert state['fingerprint_rotation_count']==0
    assert state['fingerprint_failures']['gateway']==0


def test_second_consecutive_timeout_rotates_then_retries(tmp_path):
    transport=ExceptionTransport([
        TimeoutError('one'),
        TimeoutError('two'),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':2,'jitter':False},
    )
    state=client.session_state('https://fixture')

    assert result['status_code']==200
    assert result['attempts']==3
    assert state['fingerprint_rotations'][-1]['reason']==(
        'consecutive-timeouts'
    )
    assert state['fingerprint_rotations'][-1]['previous_browser']!=(
        state['fingerprint_rotations'][-1]['new_browser']
    )
    assert state['fingerprint_rotations'][-1]['effective'] is True
    assert state['fingerprint_rotations'][-1]['outcome_status_code']==200


def test_timeout_retries_use_exponential_backoff(tmp_path):
    transport=ExceptionTransport([
        TimeoutError('one'),
        TimeoutError('two'),
        Response(200,'ok'),
    ])
    slept=[]
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=slept.append,
    )
    client.rate.before_request=lambda *args,**kwargs:0

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':2,'jitter':False},
    )

    assert slept==[1,2]
    assert [row['retry_delay'] for row in result['timeline'][:2]]==[1,2]


def test_timeout_rotation_is_session_scoped_across_requests(tmp_path):
    transport=ExceptionTransport([
        TimeoutError('first request'),
        TimeoutError('second request'),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    first=client.stealth_request(
        'GET',
        'https://fixture/one',
        options={'max_retries':0,'jitter':False},
    )
    second=client.stealth_request(
        'GET',
        'https://fixture/two',
        options={'max_retries':1,'jitter':False},
    )

    assert first['status']=='error'
    assert second['status_code']==200
    assert second['timeline'][0]['retry_reason']=='consecutive-timeouts'
    assert client.session_state('https://fixture')[
        'fingerprint_rotation_count'
    ]==1


def test_gateway_switches_transport_and_records_effect(tmp_path):
    primary=Transport([Response(502,'gateway')])
    fallback=Transport([Response(200,'ok')])

    class Memory:
        def __init__(self): self.attempts=[]
        def record_attempt(self,**kwargs): self.attempts.append(kwargs)

    memory=Memory()
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:primary,
        fallback_transport_factory=lambda:fallback,
        technique_memory=memory,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)
    runtime=client._runtime('https://fixture')
    runtime['transport_backend']='curl_cffi'
    runtime['is_curl_transport']=True

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':1,'jitter':False},
    )

    assert result['status_code']==200
    assert result['timeline'][0]['transport_switch'][
        'new_backend'
    ]=='requests-fallback'
    assert memory.attempts[-1]['technique_name']==(
        'transport_backend_switch'
    )
    assert memory.attempts[-1]['success'] is True


def test_http_response_resets_timeout_streak(tmp_path):
    transport=ExceptionTransport([
        TimeoutError('one'),
        TimeoutError('two'),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    first=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':1,'jitter':False},
    )
    assert first['status']=='error'
    assert client.session_state('https://fixture')[
        'fingerprint_failures'
    ]['timeout']==2

    second=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':0,'jitter':False},
    )

    assert second['status_code']==200
    assert client.session_state('https://fixture')[
        'fingerprint_failures'
    ]['timeout']==0


def test_non_timeout_exception_resets_timeout_streak(tmp_path):
    transport=ExceptionTransport([
        TimeoutError('one'),
        RuntimeError('connection failed'),
        Response(200,'ok'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )

    result=client.stealth_request(
        'GET',
        'https://fixture/',
        options={'max_retries':2,'jitter':False},
    )
    state=client.session_state('https://fixture')

    assert result['status_code']==200
    assert state['fingerprint_failures']['timeout']==0
    assert state['fingerprint_rotation_count']==0


def test_health_probe_200_with_target_403_means_fingerprint_blocked(
    tmp_path,
):
    transport=Transport([Response(200,'icon')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )

    assert result['classification']=='fingerprint_blocked'
    assert result['probe_status_code']==200
    assert transport.calls[0][1].endswith('/favicon.ico')


@pytest.mark.parametrize('probe_status',[403,502,503])
def test_blocked_health_probe_means_ip_or_target_problem(
    tmp_path,
    probe_status,
):
    transport=Transport([Response(probe_status,'blocked')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )

    assert result['classification']==(
        'ip_blocked_or_target_unavailable'
    )
    assert result['probe_status_code']==probe_status


def test_health_probe_falls_back_from_missing_favicon_to_root(tmp_path):
    transport=Transport([
        Response(404,'missing'),
        Response(200,'home'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )

    assert result['classification']=='fingerprint_blocked'
    assert len(transport.calls)==2
    assert transport.calls[0][1].endswith('/favicon.ico')
    assert transport.calls[1][1].endswith(':443/')


def test_health_probe_falls_back_to_root_when_favicon_errors(tmp_path):
    transport=ExceptionTransport([
        RuntimeError('favicon failed'),
        Response(200,'home'),
    ])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )

    assert result['classification']=='fingerprint_blocked'
    assert len(transport.calls)==2
    assert transport.calls[0][1].endswith('/favicon.ico')
    assert transport.calls[1][1].endswith(':443/')


def test_health_probe_timeout_means_target_unreachable(tmp_path):
    transport=ExceptionTransport([TimeoutError('favicon timeout'),TimeoutError('root timeout')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )

    assert result['classification']=='target_unreachable'
    assert result['error_type']=='TimeoutError'


def test_health_probe_does_not_enter_stealth_request_or_change_counters(
    tmp_path,
    monkeypatch,
):
    transport=Transport([Response(200,'icon')])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    client.session_create('https://fixture',resume=False)
    before=client.session_state('https://fixture')
    monkeypatch.setattr(
        client,
        'stealth_request',
        lambda *args,**kwargs:pytest.fail('recursive request'),
    )

    result=client.check_fingerprint_health(
        'https://fixture',
        target_status_code=403,
    )
    after=client.session_state('https://fixture')

    assert result['classification']=='fingerprint_blocked'
    assert after['rate_limit']==before['rate_limit']
    assert after['timeline']==before['timeline']
    assert after['fingerprint_failures']==before['fingerprint_failures']
    assert after['fingerprint_health']['classification']==(
        'fingerprint_blocked'
    )


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
    client.waf.strategies_for=lambda _: [{'id':'not-implemented','description':'fixture'}]
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


def test_send_detection_request_restores_session_state_by_id(tmp_path):
    seed_transport=Transport([])
    seed_transport.cookies=Cookies()
    seed=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:seed_transport,
        sleep=lambda _:None,
    )
    session=seed.session_create('https://fixture',resume=False)
    state=seed._runtime('https://fixture')['state']
    state['cookies']={'JSESSIONID':'authenticated'}
    state['csrf_tokens']={'csrf_token':'known-token'}
    state['timeline']=[{'waf':{'waf_type':'Cloudflare','blocked':True}}]
    seed._save(state)

    restored_transport=Transport([Response(200,'{"ok":true}',{'Content-Type':'application/json'})])
    restored_transport.cookies=Cookies()
    restored=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:restored_transport,
        sleep=lambda _:None,
    )
    restored.waf.strategies_for=lambda _: [
        {'id':'header-consistency','description':'fixture'}
    ]

    result=restored.send_detection_request(
        session['session_id'],
        'POST',
        'https://fixture/admin',
        {'view':'all'},
        {'action':'list'},
        {'X-Detection':'yes'},
    )

    method,url,kwargs=restored_transport.calls[0]
    assert method=='POST'
    assert url=='https://fixture/admin?view=all'
    assert kwargs['data']['action']=='list'
    assert kwargs['data']['csrf_token']=='known-token'
    assert kwargs['headers']['X-Detection']=='yes'
    assert kwargs['headers']['User-Agent']
    assert kwargs['headers']['Cache-Control']=='max-age=0'
    assert restored_transport.cookies['JSESSIONID']=='authenticated'
    assert result['status_code']==200
    assert result['session_id']==session['session_id']
    assert result['timeline'][0]['strategy']=='header-consistency'


def test_send_detection_request_returns_clear_error_for_unknown_session(tmp_path):
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:Transport([]),
        sleep=lambda _:None,
    )
    result=client.send_detection_request(
        'stealth-missing',
        'GET',
        'https://fixture/',
        None,
        None,
        None,
    )
    assert result['status']=='error'
    assert result['session_id']=='stealth-missing'
    assert 'not found' in result['error'].lower()


def test_send_detection_request_rejects_cross_origin_reuse(tmp_path):
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:Transport([]),
        sleep=lambda _:None,
    )
    session=client.session_create('https://fixture',resume=False)
    result=client.send_detection_request(
        session['session_id'],
        'GET',
        'https://other.example/',
        None,
        None,
        None,
    )
    assert result['status']=='error'
    assert 'origin' in result['error'].lower()


def test_stealth_scan_exposes_reusable_session_id(tmp_path):
    transport=Transport([Response(200,'ok') for _ in range(4)])
    client=StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda:transport,
        sleep=lambda _:None,
    )
    result=client.stealth_scan(
        'https://fixture',
        options={
            'active_waf':False,
            'rate_probe_rates':[1],
            'requests_per_rate':1,
        },
    )
    assert result['session']['session_id'].startswith('stealth-')
