"""Unified stateful HTTP client with bounded adaptive controls and audit timeline."""
from __future__ import annotations
import json,os,re,time,uuid
from copy import deepcopy
from pathlib import Path
from urllib.parse import urljoin,urlparse

try: import requests
except ImportError: requests=None
from .fingerprint_manager import FingerprintManager
from .proxy_pool import ProxyPool
from .rate_limiter import AdaptiveRateLimiter
from .waf_detector import WAFDetector
from .captcha_handler import CaptchaHandler

CSRF_RE=re.compile(r'(?:name=["\'](?P<name>csrf(?:_token)?|_token|authenticity_token)["\'][^>]*value=["\'](?P<value>[^"\']+)|value=["\'](?P<value2>[^"\']+)["\'][^>]*name=["\'](?P<name2>csrf(?:_token)?|_token|authenticity_token)["\'])',re.I)

class StealthHTTPClient:
 def __init__(self,state_dir=None,transport_factory=None,sleep=time.sleep,fingerprint_manager=None,proxy_pool=None,persist_secrets=True):
  self.state_dir=Path(state_dir or 'sessions/stealth').resolve(); self.state_dir.mkdir(parents=True,exist_ok=True); self.transport_factory=transport_factory or self._default_transport; self.sleep=sleep; self.fingerprints=fingerprint_manager or FingerprintManager(); self.proxy_pool=proxy_pool or ProxyPool(); self.waf=WAFDetector(self.state_dir/'waf_history.json'); self.rate=AdaptiveRateLimiter(sleep=sleep); self.captcha=CaptchaHandler(artifact_dir=self.state_dir/'captcha'); self.persist_secrets=bool(persist_secrets); self._sessions={}
 def _default_transport(self):
  if requests is None: raise RuntimeError('requests is required for live HTTP transport')
  s=requests.Session(); return s
 def _key(self,target):
  parsed=urlparse(target if '://' in target else 'https://'+target); scheme=parsed.scheme or 'https'; port=parsed.port or (443 if scheme=='https' else 80); return f'{scheme}://{(parsed.hostname or target).lower()}:{port}'
 def _path(self,key): return self.state_dir/f'{re.sub(r"[^a-zA-Z0-9_.-]","_",key)}.json'
 def session_create(self,target,resume=True,fingerprint_strategy='random'):
  key=self._key(target); path=self._path(key)
  if resume and path.exists(): state=json.loads(path.read_text(encoding='utf-8-sig'))
  else:
   fp=self.fingerprints.for_session(key,strategy=fingerprint_strategy); state={'session_id':f'stealth-{uuid.uuid4().hex[:12]}','target':key,'fingerprint_id':fp['id'],'cookies':{},'csrf_tokens':{},'oauth_chain':[],'steps':[],'timeline':[],'rate_limit':{},'proxy':None,'created_at':time.time()}; self._save(state)
  transport=self.transport_factory()
  if state.get('cookies') and hasattr(transport,'cookies'):
   try: transport.cookies.update(state['cookies'])
   except Exception as exc: state.setdefault('restore_warnings',[]).append(str(exc))
  runtime={'state':state,'transport':transport}; self._sessions[key]=runtime; return self.session_state(target)
 def _runtime(self,target):
  key=self._key(target)
  if key not in self._sessions: self.session_create(target)
  return self._sessions[key]
 def _save(self,state):
  persisted=deepcopy(state)
  if not self.persist_secrets:
   persisted['cookies']={}; persisted['csrf_tokens']={}
  path=self._path(state['target']); temporary=path.with_suffix(path.suffix+f'.{uuid.uuid4().hex}.tmp'); temporary.write_text(json.dumps(persisted,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); os.replace(temporary,path)
 def session_state(self,target):
  runtime=self._runtime(target); state=deepcopy(runtime['state']); state['state_path']=str(self._path(state['target'])); return state
 def set_proxy_pool(self,proxies=None,file_path=None,checker=None,target=None):
  if file_path: self.proxy_pool.load_file(file_path)
  for value in proxies or []: self.proxy_pool.add(value)
  if checker: self.proxy_pool.health_check(checker,target)
  return self.proxy_pool.summary()
 def _csrf(self,text,state):
  for match in CSRF_RE.finditer(text or ''):
   name=match.group('name') or match.group('name2'); value=match.group('value') or match.group('value2'); state['csrf_tokens'][name]=value
 def _headers(self,state,headers):
  fp=self.fingerprints.get(state['fingerprint_id']); merged=dict(fp['headers']); merged.update(headers or {}); return merged
 def _proxy_args(self,state,url):
  proxy=self.proxy_pool.select(target=self._key(url))
  if not proxy: return {}
  state['proxy']=proxy['url']; return {'proxies':{'http':proxy['url'],'https':proxy['url']}}
 def _apply_strategy(self,strategy,headers,data):
  headers=dict(headers); data=deepcopy(data)
  if not strategy: return headers,data,'none'
  sid=strategy['id']
  if sid=='content-type-json': headers['Content-Type']='application/json'; return headers,data,'applied'
  if sid=='header-consistency': headers.setdefault('Cache-Control','max-age=0'); return headers,data,'applied'
  if sid=='parameter-order' and isinstance(data,dict): return headers,dict(reversed(list(data.items()))),'applied'
  if sid=='percent-encoding' and isinstance(data,dict):
   from urllib.parse import quote
   return headers,{k:quote(str(v),safe='') for k,v in data.items()},'applied'
  if sid=='parameter-pollution' and isinstance(data,dict): return headers,[(k,v) for k,v in data.items() for _ in (0,1)],'applied'
  if sid=='case-variation' and isinstance(data,str): return headers,''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(data)),'applied'
  if sid=='line-folding' and isinstance(data,str): return headers,data.replace(' ','\n'),'applied'
  return headers,data,'unsupported'
 def _captcha_image_url(self,response):
  text=str(getattr(response,'text','')); matches=re.findall(r'<img[^>]+(?:src|data-src)=["\']([^"\']+)["\'][^>]*>',text,re.I)
  candidate=next((x for x in matches if 'captcha' in x.lower() or 'verify' in x.lower()),matches[0] if matches and ('captcha' in text.lower() or 'verify' in text.lower()) else '')
  return urljoin(getattr(response,'url',''),candidate) if candidate else ''
 def _solve_page_captcha(self,response,transport,state,request_headers,options,request_proxy,timeline):
  image_url=self._captcha_image_url(response)
  if not image_url: return self.captcha.handle(response,state['target'],options.get('captcha_engine','pytesseract'))
  attempts=[]
  for number in range(1,4):
   kwargs={'headers':request_headers,'allow_redirects':True,'timeout':options.get('timeout',15),'verify':options.get('verify_tls',True)}
   if request_proxy: kwargs['proxies']={'http':request_proxy,'https':request_proxy}
   image_response=transport.request('GET',image_url,**kwargs); result=self.captcha.solve_image(getattr(image_response,'content',b''),state['target'],options.get('captcha_engine','pytesseract')); attempts.append(result); timeline.append({'event':'captcha-image-fetch','attempt':number,'url':image_url,'status_code':image_response.status_code,'proxy':request_proxy,'ocr':result})
   if result['solved']: return {'solved':True,'text':result['text'],'type':'image','attempts':attempts}
  return {'solved':False,'text':'','type':'image','attempts':attempts}
 def stealth_request(self,method,url,headers=None,data=None,options=None):
  options=options or {}; runtime=self._runtime(url); state=runtime['state']; transport=runtime['transport']; max_retries=min(3,max(0,int(options.get('max_retries',3)))); strategy=None; timeline=[]; response=None
  for attempt in range(max_retries+1):
   request_headers=self._headers(state,headers); request_data=deepcopy(data)
   for name,value in state['csrf_tokens'].items():
    if isinstance(request_data,dict): request_data.setdefault(name,value)
   request_headers,request_data,strategy_status=self._apply_strategy(strategy,request_headers,request_data); delay=self.rate.before_request(state['target'],proxy=state.get('proxy'),jitter=options.get('jitter',True))
   if delay: self.sleep(delay)
   proxy_args=self._proxy_args(state,url); request_proxy=state.get('proxy'); kwargs={'headers':request_headers,'data':request_data,'allow_redirects':options.get('follow_redirects',True),'timeout':options.get('timeout',15),'verify':options.get('verify_tls',True)}
   if isinstance(request_data,dict) and str(request_headers.get('Content-Type','')).startswith('application/json'): kwargs.pop('data',None); kwargs['json']=request_data
   kwargs.update(proxy_args); start=time.monotonic()
   try: response=transport.request(method,url,**kwargs); elapsed=round(time.monotonic()-start,4)
   except Exception as exc:
    elapsed=round(time.monotonic()-start,4); timeline.append({'attempt':attempt+1,'error':str(exc),'elapsed':elapsed,'strategy':strategy and strategy['id'],'strategy_status':strategy_status,'proxy':request_proxy})
    if request_proxy: self.proxy_pool.record_request(request_proxy,False,state['target']); state['proxy']=None
    self.rate.record_failure(state['target'],request_proxy)
    if attempt<max_retries: self.sleep(self.rate.backoff(state['target'],request_proxy,failure_recorded=True)); continue
    self._finalize(state,timeline); return {'status':'error','error':str(exc),'attempts':attempt+1,'timeline':timeline}
   waf=self.waf.detect_response(response); response_headers=dict(getattr(response,'headers',{})); response_text=str(getattr(response,'text','')); limited=self.rate.is_rate_limited(response.status_code,response_headers,response_text)
   if request_proxy: self.proxy_pool.record_request(request_proxy,not waf['blocked'],state['target'],banned=False,latency_ms=elapsed*1000)
   self.rate.record_response(state['target'],response.status_code,request_proxy,response_headers,response_text,limited=limited); self._csrf(response_text,state)
   captcha_info=self.captcha.detect(response); captcha=self._solve_page_captcha(response,transport,state,request_headers,options,request_proxy,timeline) if captcha_info['type']=='image' else self.captcha.handle(response,state['target'],options.get('captcha_engine','pytesseract'))
   if strategy and waf['waf_type'] and strategy_status=='applied' and not limited and captcha_info['type'] is None: self.waf.record_outcome(waf['waf_type'],strategy['id'],not waf['blocked'])
   if getattr(response,'history',None): state['oauth_chain'].extend([getattr(x,'url','') for x in response.history if getattr(x,'url','')]); state['oauth_chain']=state['oauth_chain'][-200:]
   row={'attempt':attempt+1,'status_code':response.status_code,'elapsed':elapsed,'strategy':strategy and strategy['id'],'strategy_status':strategy_status,'fingerprint_id':state['fingerprint_id'],'proxy':request_proxy,'waf':waf,'rate_limited':limited,'captcha':captcha}; timeline.append(row)
   if captcha.get('solved') and isinstance(request_data,dict) and attempt<max_retries: request_data[options.get('captcha_field','captcha')]=captcha['text']; data=request_data; continue
   if captcha.get('status')=='operator-required': self._finalize(state,timeline); return {'status':'operator-required','captcha':captcha,'status_code':response.status_code,'attempts':attempt+1,'timeline':timeline}
   if limited and attempt<max_retries: self.sleep(self.rate.backoff(state['target'],request_proxy,response_headers,failure_recorded=True)); continue
   if waf['blocked'] and attempt<max_retries:
    choices=self.waf.strategies_for(waf['waf_type']); strategy=choices[min(attempt,len(choices)-1)]; continue
   break
  self._capture_cookies(response,state); self._finalize(state,timeline); body=str(getattr(response,'text','')); limit=max(100,int(options.get('max_body_chars',16000))); truncated=len(body)>limit; artifact=''
  if truncated:
   directory=self.state_dir/'responses'; directory.mkdir(parents=True,exist_ok=True); path=directory/f'{uuid.uuid4().hex}.body'; path.write_text(body,encoding='utf-8'); artifact=str(path); body=body[:max(0,limit-1)]+'?'
  return {'status':'ok' if response and response.status_code<400 else 'blocked','status_code':response.status_code if response else 0,'url':getattr(response,'url',url),'headers':dict(getattr(response,'headers',{})),'body':body,'body_truncated':truncated,'body_artifact':artifact,'attempts':sum(1 for x in timeline if 'attempt' in x and x.get('event')!='captcha-image-fetch'),'timeline':timeline}
 def _capture_cookies(self,response,state):
  cookies=getattr(response,'cookies',None)
  if cookies and hasattr(cookies,'get_dict'): state['cookies'].update(cookies.get_dict())
  header=dict(getattr(response,'headers',{})).get('Set-Cookie','') if response else ''
  if header and '=' in header: name,value=header.split(';',1)[0].split('=',1); state['cookies'][name]=value
 def _finalize(self,state,timeline): state['timeline'].extend(timeline); state['timeline']=state['timeline'][-500:]; state['steps'].append({'at':time.time(),'attempts':len(timeline)}); state['steps']=state['steps'][-500:]; state['oauth_chain']=state['oauth_chain'][-200:]; state['rate_limit']=self.rate.state(state['target'],state.get('proxy')); self._save(state)
 def execute_chain(self,target,steps):
  variables={}; results=[]
  for step in steps:
   def sub(value):
    if isinstance(value,str):
     for k,v in variables.items(): value=value.replace('${'+k+'}',str(v))
    return value
   url=urljoin(target+'/' if not target.endswith('/') else target,sub(step['url'])); data={k:sub(v) for k,v in (step.get('data') or {}).items()}; result=self.stealth_request(step.get('method','GET'),url,headers=step.get('headers'),data=data,options=step.get('options')); results.append(result)
   for name,rule in (step.get('extract') or {}).items():
    if rule.startswith('json:'): variables[name]=json.loads(result['body'])[rule[5:]]
    elif rule.startswith('regex:'): variables[name]=re.search(rule[6:],result['body']).group(1)
  return {'results':results,'variables':variables}
 def stealth_scan(self,target,options=None):
  options=options or {}; baseline=self.stealth_request('GET',target,options={'max_retries':0}); captcha=self.captcha.detect(type('R',(),{'text':baseline.get('body',''),'headers':baseline.get('headers',{}),'status_code':baseline.get('status_code',0)})())
  def sender(method,url,**kwargs): return self._runtime(target)['transport'].request(method,url,allow_redirects=True,timeout=options.get('timeout',10),**kwargs)
  waf=self.waf.active_probe(target,sender) if options.get('active_waf',True) else {'passive':baseline['timeline'][-1].get('waf') if baseline.get('timeline') else {}}
  rates=options.get('rate_probe_rates',[1,2,5,10,20]); rate_result=self.rate.probe_threshold(target,lambda:sender('GET',target),rates=rates,requests_per_rate=options.get('requests_per_rate',5))
  return {'target':target,'baseline':baseline,'waf':waf,'rate_limit':rate_result,'captcha':captcha,'session':self.session_state(target)}

