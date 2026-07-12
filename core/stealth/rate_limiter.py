"""Adaptive per-target/per-proxy rate state with bounded probes and jitter."""
from __future__ import annotations
import random,time

class AdaptiveRateLimiter:
 def __init__(self,sleep=time.sleep,seed=None,clock=time.monotonic): self.sleep=sleep; self.random=random.Random(seed); self.clock=clock; self.states={}
 def _key(self,target,proxy=None): return f'{target}|{proxy or "direct"}'
 def _state(self,target,proxy=None): return self.states.setdefault(self._key(target,proxy),{'threshold_rps':None,'safe_rps':1.0,'backoff_seconds':0,'last_backoff_seconds':0,'failures':0,'success_streak':0,'last_request':0.0,'window_seconds':None})
 def state(self,target,proxy=None): return dict(self._state(target,proxy))
 @staticmethod
 def is_rate_limited(status,headers=None,body=''):
  status=int(status); headers={str(k).lower():str(v) for k,v in (headers or {}).items()}; text=str(body or '').lower()
  return status==429 or (status==503 and (bool(headers.get('retry-after')) or 'rate limit' in text or 'too many requests' in text))
 def before_request(self,target,proxy=None,jitter=True,human=False):
  state=self._state(target,proxy); interval=1/max(0.05,state['safe_rps']); elapsed=self.clock()-state['last_request']; base=max(0,interval-elapsed)
  factor=min(5,max(0.2,self.random.lognormvariate(-0.15,0.65))) if human else self.random.uniform(0.7,1.3) if jitter else 1
  state['last_request']=self.clock()+base*factor; return base*factor
 def backoff(self,target,proxy=None,headers=None,failure_recorded=False):
  state=self._state(target,proxy)
  if not failure_recorded: self.record_failure(target,proxy)
  retry=float((headers or {}).get('Retry-After',0) or 0); sequence=[1,2,4,8,30,60]; delay=max(retry,sequence[min(max(0,state['failures']-1),len(sequence)-1)]); state['backoff_seconds']=delay; state['last_backoff_seconds']=delay; return delay
 def record_response(self,target,status,proxy=None,headers=None,body='',limited=None):
  state=self._state(target,proxy); limited=self.is_rate_limited(status,headers,body) if limited is None else bool(limited)
  if limited: return self.record_failure(target,proxy)
  state['success_streak']+=1; state['failures']=max(0,state['failures']-1); state['backoff_seconds']=0; ceiling=(state['threshold_rps'] or max(1,state['safe_rps']))*0.9; state['safe_rps']=min(ceiling,max(0.1,state['safe_rps']*1.08)); return dict(state)
 def record_failure(self,target,proxy=None):
  state=self._state(target,proxy); state['success_streak']=0; state['failures']+=1; state['safe_rps']=max(0.05,state['safe_rps']/2); return dict(state)
 def probe_threshold(self,target,sender,rates=None,requests_per_rate=5,proxy=None):
  rates=rates or [1,2,5,10,20]; tested=[]; samples=[]; threshold=None
  if requests_per_rate < 2: return {'status':'inconclusive','threshold_rps':None,'safe_rps':self._state(target,proxy)['safe_rps'],'tested_rates':[],'samples':[],'reason':'at least two requests per rate are required'}
  for rate in rates:
   observations=[]; timestamps=[]; started=self.clock()
   for index in range(requests_per_rate):
    timestamps.append(self.clock()); response=sender(); observations.append({'status_code':int(response.status_code),'headers':dict(getattr(response,'headers',{})),'body':str(getattr(response,'text',''))})
    if index+1<requests_per_rate: self.sleep(1/max(0.1,rate))
   duration=max(0.000001,self.clock()-started); observed=(requests_per_rate-1)/max(0.000001,timestamps[-1]-timestamps[0]); limited=any(self.is_rate_limited(x['status_code'],x['headers'],x['body']) for x in observations); statuses=[x['status_code'] for x in observations]
   samples.append({'target_rps':rate,'observed_rps':round(observed,3),'duration_seconds':round(duration,3),'statuses':statuses,'limited':limited}); tested.append(rate)
   if limited: threshold=rate; break
  state=self._state(target,proxy); state['threshold_rps']=threshold; state['safe_rps']=(threshold*0.9 if threshold else rates[-1]*0.9); state['window_seconds']=samples[-1]['duration_seconds'] if samples else None
  return {'status':'limited' if threshold else 'not-observed','threshold_rps':threshold,'safe_rps':state['safe_rps'],'tested_rates':tested,'requests_per_rate':requests_per_rate,'samples':samples}
