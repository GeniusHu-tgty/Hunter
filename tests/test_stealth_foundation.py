from pathlib import Path

import pytest

from core.stealth.fingerprint_manager import FingerprintManager
from core.stealth.proxy_pool import ProxyPool
from core.stealth.rate_limiter import AdaptiveRateLimiter


def test_fingerprint_pool_session_consistency_rotation_and_uniqueness():
    manager=FingerprintManager(seed=1)
    pool=manager.fingerprints()
    assert len(pool)>=50
    assert len({x['id'] for x in pool})==len(pool)
    assert manager.for_session('a')['id']==manager.for_session('a')['id']
    first=manager.choose('round-robin')['id']; second=manager.choose('round-robin')['id']; assert first!=second


def test_for_session_never_silently_replaces_existing_fingerprint():
    manager=FingerprintManager(seed=5)
    firefox=next(
        item for item in manager.fingerprints()
        if item['browser']=='Firefox'
    )
    manager.bind_session('stealth-fixed',firefox['id'])

    assert manager.for_session('stealth-fixed')['id']==firefox['id']
    with pytest.raises(RuntimeError,match='rotate_fingerprint'):
        manager.for_session('stealth-fixed',require_impersonate=True)
    assert manager.for_session('stealth-fixed')['id']==firefox['id']


def test_rotate_fingerprint_changes_browser_family_and_binding():
    manager=FingerprintManager(seed=7)
    first=manager.for_session('stealth-rotate')

    second=manager.rotate_fingerprint(
        'stealth-rotate',
        current_fingerprint_id=first['id'],
    )

    assert second['id']!=first['id']
    assert second['browser']!=first['browser']
    assert manager.for_session('stealth-rotate')['id']==second['id']


def test_import_browser_and_freshness_pruning():
    manager=FingerprintManager()
    imported=manager.import_browser({'userAgent':'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36','languages':['en-US','en'],'platform':'Win32','screen':{'width':1920,'height':1080},'timezone':'America/New_York','userAgentData':{'platform':'Windows','mobile':False,'brands':[{'brand':'Chromium','version':'130'}]}})
    assert imported['source']=='browser' and imported['headers']['Sec-CH-UA']
    result=manager.prune_stale({'Chrome':125,'Edge':124,'Firefox':120,'Safari':18})
    assert result['removed']>0
    assert manager.get(imported['id'])


def test_proxy_loading_health_target_bans_scoring_and_pruning(tmp_path):
    f=tmp_path/'p.txt'; f.write_text('http://one:1,CN,elite\nsocks5://two:2,US,transparent\n')
    pool=ProxyPool(); pool.load_file(f)
    pool.health_check(lambda p,t:{'ok':p['url'].startswith('http'),'latency_ms':20,'banned':False},target='x')
    assert pool.select('x')['url']=='http://one:1'
    pool.check('http://one:1',lambda p,t:{'ok':True,'latency_ms':20,'banned':True},target='blocked')
    assert pool.select('blocked') is None
    for _ in range(3): pool.check('socks5://two:2',lambda p,t:{'ok':False},target='x')
    assert 'socks5://two:2' in pool.prune()


def test_rate_probe_backoff_per_proxy_and_jitter():
    class R:
        def __init__(self,s): self.status_code=s
    values=iter([200,200,200,200,429,429])
    limiter=AdaptiveRateLimiter(sleep=lambda _:None,seed=2)
    result=limiter.probe_threshold('x',lambda:R(next(values)),rates=[1,2,5],requests_per_rate=2,proxy='p')
    assert result['threshold_rps']==5 and result['safe_rps']==4.5
    assert limiter.backoff('x','p')==1 and limiter.backoff('x','p')==2
    assert limiter.state('x','other')['failures']==0
    delays=[limiter.before_request('human',jitter=True) for _ in range(5)]
    assert len(set(round(x,4) for x in delays))>1


def test_browser_import_from_playwright_like_page():
    class Page:
        def evaluate(self,script): return {'userAgent':'Mozilla/5.0 Firefox/122.0','languages':['en-US'],'platform':'Linux','screen':{'width':1366,'height':768},'timezone':'Europe/London'}
    result=FingerprintManager().import_browser(page=Page())
    assert result['browser']=='Firefox' and result['screen']=='1366x768'


def test_rate_probe_reports_observed_timing_and_inconclusive_sample():
    class R: status_code=200; headers={}
    clock=[0.0]
    def sleep(value): clock[0]+=value
    limiter=AdaptiveRateLimiter(sleep=sleep,clock=lambda:clock[0])
    one=limiter.probe_threshold('x',lambda:R(),rates=[2],requests_per_rate=1)
    assert one['status']=='inconclusive'
    measured=limiter.probe_threshold('x',lambda:R(),rates=[2],requests_per_rate=3)
    assert measured['samples'][0]['observed_rps']>0


def test_version_source_refreshes_and_prunes_on_startup():
    manager=FingerprintManager(version_source=lambda:{'Chrome':128,'Edge':125,'Firefox':121,'Safari':18})
    assert manager.last_refreshed_at
    assert all(manager.freshness_status(item)['fresh'] for item in manager.fingerprints())


def test_rate_probe_uses_each_response_rate_limit_signals():
    class R:
        def __init__(self,status,headers=None,text=''): self.status_code=status; self.headers=headers or {}; self.text=text
    values=iter([R(503,{'Retry-After':'2'}),R(200),R(200)])
    limiter=AdaptiveRateLimiter(sleep=lambda _:None)
    result=limiter.probe_threshold('x',lambda:next(values),rates=[2],requests_per_rate=3)
    assert result['threshold_rps']==2


def test_plain_503_is_not_rate_limited():
    limiter=AdaptiveRateLimiter(sleep=lambda _:None)
    limiter.record_response('x',503,headers={},body='maintenance')
    assert limiter.state('x')['failures']==0
