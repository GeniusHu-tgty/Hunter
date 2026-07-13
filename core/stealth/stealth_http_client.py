"""Unified stateful HTTP client with bounded adaptive controls and audit timeline."""
from __future__ import annotations
import json,logging,os,re,time,uuid
from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qsl,quote,quote_plus,urlencode,urljoin,urlparse,urlsplit,urlunsplit

try: import requests as native_requests
except ImportError: native_requests=None
try:
 from curl_cffi import requests
 CURL_CFFI_AVAILABLE=True
except ImportError:
 requests=native_requests
 CURL_CFFI_AVAILABLE=False
from .fingerprint_manager import FingerprintManager
from .proxy_pool import ProxyPool
from .rate_limiter import AdaptiveRateLimiter
from .waf_detector import WAFDetector
from .captcha_handler import CaptchaHandler

LOGGER=logging.getLogger(__name__)
FALLBACK_WARNING='curl_cffi not installed, falling back to requests (TLS fingerprint WILL be detected)'
_FALLBACK_WARNING_EMITTED=False
CSRF_RE=re.compile(r'(?:name=["\'](?P<name>csrf(?:_token)?|_token|authenticity_token)["\'][^>]*value=["\'](?P<value>[^"\']+)|value=["\'](?P<value2>[^"\']+)["\'][^>]*name=["\'](?P<name2>csrf(?:_token)?|_token|authenticity_token)["\'])',re.I)
FINGERPRINT_BLOCK_WORDS=('forbidden','access denied','\u62e6\u622a','\u5b89\u5168\u68c0\u6d4b')

class _DetectionElapsed:
 def __init__(self,seconds): self._seconds=float(seconds)
 def total_seconds(self): return self._seconds

class DetectionResponse:
 def __init__(self,result,elapsed=0.0,cookie_jar=None):
  self.status_code=int(result.get('status_code',0) or 0); self.text=str(result.get('body','')); self.headers=dict(result.get('headers',{})); self.url=str(result.get('url','')); self.content=self.text.encode('utf-8'); self.history=[]; self.elapsed=_DetectionElapsed(elapsed); self.reason=''; self.ok=self.status_code<400; self.cookies=cookie_jar if cookie_jar is not None else self._cookie_jar(result.get('cookies',{}))
 def _cookie_jar(self,cookies):
  if CURL_CFFI_AVAILABLE and requests is not None: return requests.Cookies(dict(cookies or {}))
  if native_requests is not None: return native_requests.cookies.cookiejar_from_dict(dict(cookies or {}))
  return _FallbackCookieJar(cookies or {})
 def json(self): return json.loads(self.text)

class _FallbackCookie:
 def __init__(self,name,value): self.name=name; self.value=value
 def get_nonstandard_attr(self,name,default=None): return default
 def get_non_standard_attr(self,name,default=None): return default

class _FallbackCookieJar:
 def __init__(self,cookies=None): self._cookies=dict(cookies or {})
 def __iter__(self): return iter([_FallbackCookie(name,value) for name,value in self._cookies.items()])
 def get_dict(self): return dict(self._cookies)
 def update(self,cookies):
  if hasattr(cookies,'get_dict'): cookies=cookies.get_dict()
  self._cookies.update(dict(cookies or {}))
 def clear(self): self._cookies.clear()

class _CookieJarAdapter:
 def __init__(self,backend): self.backend=backend
 def get_dict(self):
  if hasattr(self.backend,'get_dict'): return dict(self.backend.get_dict())
  return dict(self.backend or {})
 def update(self,cookies):
  if hasattr(cookies,'get_dict'): cookies=cookies.get_dict()
  if hasattr(self.backend,'update'): self.backend.update(dict(cookies or {}))
  else:
   for name,value in dict(cookies or {}).items(): self.backend[name]=value
 def clear(self):
  if hasattr(self.backend,'clear'): self.backend.clear()
 def __iter__(self): return iter([_FallbackCookie(name,value) for name,value in self.get_dict().items()])
 def __getitem__(self,name): return self.get_dict()[name]
 def __setitem__(self,name,value): self.update({name:value})
 def get(self,name,default=None): return self.get_dict().get(name,default)
 def items(self): return self.get_dict().items()

class DetectionSession:
 def __init__(self,client,session_id):
  self.client=client; self.session_id=session_id; self.headers={}; self.verify=True
  runtime=self.client._runtime_for_session_id(session_id)
  if runtime is None: raise LookupError(f"Stealth session '{session_id}' not found")
  transport=runtime['transport']; self._cookie_backend=getattr(transport,'cookies',_FallbackCookieJar(runtime['state'].get('cookies',{}))); self.cookies=_CookieJarAdapter(self._cookie_backend)
 def _multipart(self,data,files):
  boundary=f'hunter-detection-{uuid.uuid4().hex}'
  chunks=[]
  pairs=list(data.items()) if isinstance(data,dict) else list(data or []) if isinstance(data,(list,tuple)) else []
  for name,value in pairs:
   chunks.extend([f'--{boundary}\r\n'.encode(),f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),str(value).encode(),b'\r\n'])
  for name,item in (files or {}).items():
   filename=name; content_type='application/octet-stream'; content=item
   if isinstance(item,(list,tuple)):
    if len(item)>0: filename=item[0]
    if len(item)>1: content=item[1]
    if len(item)>2: content_type=item[2]
   if hasattr(content,'read'): content=content.read()
   if isinstance(content,str): content=content.encode()
   chunks.extend([f'--{boundary}\r\n'.encode(),f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode(),f'Content-Type: {content_type}\r\n\r\n'.encode(),bytes(content),b'\r\n'])
  chunks.append(f'--{boundary}--\r\n'.encode())
  return b''.join(chunks),f'multipart/form-data; boundary={boundary}'
 def request(self,method,url,**kwargs):
  request_headers=dict(self.headers); request_headers.update(kwargs.pop('headers',{}) or {})
  params=kwargs.pop('params',None); data=kwargs.pop('data',None); json_body=kwargs.pop('json',None); files=kwargs.pop('files',None); request_cookies=kwargs.pop('cookies',None)
  if json_body is not None:
   data=json_body; request_headers.setdefault('Content-Type','application/json')
  if files:
   data,content_type=self._multipart(data,files); request_headers['Content-Type']=content_type
  if request_cookies:
   if hasattr(request_cookies,'get_dict'): request_cookies=request_cookies.get_dict()
   if isinstance(request_cookies,dict): cookie_value='; '.join(f'{name}={value}' for name,value in request_cookies.items())
   else: cookie_value=str(request_cookies)
   existing=request_headers.get('Cookie',''); request_headers['Cookie']='; '.join(value for value in (existing,cookie_value) if value)
  options={'timeout':kwargs.pop('timeout',15),'follow_redirects':kwargs.pop('allow_redirects',kwargs.pop('follow_redirects',True)),'verify_tls':kwargs.pop('verify',self.verify)}
  started=time.monotonic(); result=self.client.send_detection_request(self.session_id,method,url,params,data,request_headers,options=options); elapsed=time.monotonic()-started
  if result.get('status')=='error': raise RuntimeError(result.get('error','detection request failed'))
  self.cookies.update(result.get('cookies',{})); return DetectionResponse(result,elapsed=elapsed,cookie_jar=self.cookies)
 def get(self,url,**kwargs): return self.request('GET',url,**kwargs)
 def post(self,url,**kwargs): return self.request('POST',url,**kwargs)
 def rotate_fingerprint(self,reason='manual'):
  return self.client.rotate_fingerprint(session_id=self.session_id,reason=reason)

class StealthHTTPClient:
 def __init__(self,state_dir=None,transport_factory=None,sleep=time.sleep,fingerprint_manager=None,proxy_pool=None,persist_secrets=True,impersonate=None):
  self.state_dir=Path(state_dir or 'sessions/stealth').resolve(); self.state_dir.mkdir(parents=True,exist_ok=True); self._uses_default_transport=transport_factory is None; self.transport_factory=transport_factory or self._default_transport; self.impersonate=impersonate; self.sleep=sleep; self.fingerprints=fingerprint_manager or FingerprintManager(); self.proxy_pool=proxy_pool or ProxyPool(); self.waf=WAFDetector(self.state_dir/'waf_history.json'); self.rate=AdaptiveRateLimiter(sleep=sleep); self.captcha=CaptchaHandler(artifact_dir=self.state_dir/'captcha'); self.persist_secrets=bool(persist_secrets); self._sessions={}
 def _default_transport(self,state=None):
  global _FALLBACK_WARNING_EMITTED
  if requests is None: raise RuntimeError('requests is required for live HTTP transport')
  if not CURL_CFFI_AVAILABLE:
   if not _FALLBACK_WARNING_EMITTED:
    LOGGER.warning(FALLBACK_WARNING); _FALLBACK_WARNING_EMITTED=True
   return requests.Session()
  kwargs={}
  if state and state.get('impersonate'): kwargs['impersonate']=state['impersonate']
  return requests.Session(**kwargs)
 def _key(self,target):
  parsed=urlparse(target if '://' in target else 'https://'+target); scheme=parsed.scheme or 'https'; port=parsed.port or (443 if scheme=='https' else 80); return f'{scheme}://{(parsed.hostname or target).lower()}:{port}'
 def _path(self,key): return self.state_dir/f'{re.sub(r"[^a-zA-Z0-9_.-]","_",key)}.json'
 def _ensure_fingerprint_state(self,state):
  original=deepcopy(state); state.setdefault('session_id',f'stealth-{uuid.uuid4().hex[:12]}'); state.setdefault('cookies',{}); state.setdefault('csrf_tokens',{}); state.setdefault('oauth_chain',[]); state.setdefault('steps',[]); state.setdefault('timeline',[]); state.setdefault('rate_limit',{}); state.setdefault('proxy',None); state.setdefault('fingerprint_rotation_count',0); state.setdefault('fingerprint_rotations',[])
  failures=state.setdefault('fingerprint_failures',{}); failures.setdefault('gateway',0); failures.setdefault('timeout',0)
  self.fingerprints.bind_session(state['session_id'],state['fingerprint_id']); return original!=state
 def _prepare_transport_state(self,state,fingerprint_strategy='random',impersonate=None):
  original=(state.get('fingerprint_id'),state.get('impersonate'))
  fp=self.fingerprints.get(state['fingerprint_id'])
  effective=impersonate if impersonate is not None else self.impersonate
  if effective is None: effective=state.get('impersonate',fp.get('impersonate'))
  state['impersonate']=effective
  return original!=(state.get('fingerprint_id'),state.get('impersonate'))
 def _restore_runtime(self,state,prepare=True):
  changed=self._ensure_fingerprint_state(state)
  if prepare and self._prepare_transport_state(state): changed=True
  if changed: self._save(state)
  transport=self._default_transport(state) if self._uses_default_transport else self.transport_factory()
  if state.get('cookies') and hasattr(transport,'cookies'):
   try: transport.cookies.update(state['cookies'])
   except Exception as exc: state.setdefault('restore_warnings',[]).append(str(exc))
  module=type(transport).__module__
  is_curl=bool(CURL_CFFI_AVAILABLE and (self._uses_default_transport or module.startswith('curl_cffi.')))
  backend='curl_cffi' if self._uses_default_transport and is_curl else 'requests-fallback' if self._uses_default_transport else 'curl_cffi-custom' if is_curl else 'custom'
  runtime={'state':state,'transport':transport,'transport_backend':backend,'is_curl_transport':is_curl,'applied_impersonate':getattr(transport,'impersonate',None) if is_curl else None}; self._sessions[state['target']]=runtime; return runtime
 def _runtime_for_session_id(self,session_id):
  for runtime in self._sessions.values():
   if runtime['state'].get('session_id')==session_id: return runtime
  for path in self.state_dir.glob('*.json'):
   try: state=json.loads(path.read_text(encoding='utf-8-sig'))
   except (OSError,ValueError,TypeError,json.JSONDecodeError): continue
   if isinstance(state,dict) and state.get('session_id')==session_id and state.get('target'): return self._restore_runtime(state)
  return None
 def detection_session(self,session_id):
  if self._runtime_for_session_id(session_id) is None: raise LookupError(f"Stealth session '{session_id}' not found")
  return DetectionSession(self,session_id)
 def session_create(self,target,resume=True,fingerprint_strategy='random',impersonate=None):
  key=self._key(target); path=self._path(key)
  if resume and path.exists():
    state=json.loads(path.read_text(encoding='utf-8-sig'))
    self._ensure_fingerprint_state(state)
    self._prepare_transport_state(state,fingerprint_strategy=fingerprint_strategy,impersonate=impersonate)
    self._save(state)
  else:
   require_impersonate=self._uses_default_transport and impersonate is None and self.impersonate is None
   session_id=f'stealth-{uuid.uuid4().hex[:12]}'; fp=self.fingerprints.for_session(session_id,strategy=fingerprint_strategy,require_impersonate=require_impersonate); state={'session_id':session_id,'target':key,'fingerprint_id':fp['id'],'cookies':{},'csrf_tokens':{},'oauth_chain':[],'steps':[],'timeline':[],'rate_limit':{},'proxy':None,'fingerprint_rotation_count':0,'fingerprint_rotations':[],'fingerprint_failures':{'gateway':0,'timeout':0},'created_at':time.time()}; self._prepare_transport_state(state,fingerprint_strategy=fingerprint_strategy,impersonate=impersonate); self._save(state)
  self._restore_runtime(state,prepare=False); return self.session_state(target)
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
 def _runtime_by_identity(self,target=None,session_id=None):
  if bool(target)==bool(session_id): raise ValueError('provide exactly one of target or session_id')
  runtime=self._runtime_for_session_id(session_id) if session_id else self._runtime(target)
  if runtime is None: raise LookupError(f"Stealth session '{session_id}' not found")
  return runtime
 def _rotate_runtime_fingerprint(self,runtime,reason,automatic=False):
  state=runtime['state']; self._ensure_fingerprint_state(state); previous=self.fingerprints.get(state['fingerprint_id'])
  require_impersonate=self._uses_default_transport and self.impersonate is None
  selected=self.fingerprints.rotate_fingerprint(state['session_id'],current_fingerprint_id=previous['id'],require_impersonate=require_impersonate)
  old_transport=runtime['transport']; old_cookies=getattr(old_transport,'cookies',None)
  if old_cookies and hasattr(old_cookies,'get_dict'): state['cookies'].update(old_cookies.get_dict())
  state['fingerprint_id']=selected['id']; state['impersonate']=self.impersonate if self.impersonate is not None else selected.get('impersonate'); state['fingerprint_rotation_count']+=1
  event={'at':time.time(),'reason':str(reason),'automatic':bool(automatic),'previous_fingerprint_id':previous['id'],'new_fingerprint_id':selected['id'],'previous_browser':previous['browser'],'new_browser':selected['browser'],'count':state['fingerprint_rotation_count']}
  state['fingerprint_rotations'].append(event); state['fingerprint_rotations']=state['fingerprint_rotations'][-100:]
  if self._uses_default_transport:
   transport=self._default_transport(state)
   if state.get('cookies') and hasattr(transport,'cookies'): transport.cookies.update(state['cookies'])
   module=type(transport).__module__; is_curl=bool(CURL_CFFI_AVAILABLE and module.startswith('curl_cffi.')); runtime.update({'transport':transport,'transport_backend':'curl_cffi' if is_curl else 'requests-fallback','is_curl_transport':is_curl,'applied_impersonate':getattr(transport,'impersonate',None) if is_curl else None})
  self._save(state); return deepcopy(event)
 def rotate_fingerprint(self,target=None,session_id=None,reason='manual',automatic=False):
  runtime=self._runtime_by_identity(target,session_id); return self._rotate_runtime_fingerprint(runtime,reason,automatic)
 def check_fingerprint_health(self,target=None,session_id=None,target_status_code=None,probe_url=None,timeout=5):
  runtime=self._runtime_by_identity(target,session_id); state=runtime['state']; transport=runtime['transport']; fingerprint=self.fingerprints.get(state['fingerprint_id'])
  if target_status_code is None:
   target_status_code=next((row.get('status_code') for row in reversed(state.get('timeline',[])) if isinstance(row,dict) and row.get('status_code') is not None),None)
  target_status=int(target_status_code) if target_status_code is not None else None; origin=state['target']
  if probe_url:
   candidate=urljoin(origin+'/',str(probe_url))
   if self._key(candidate)!=origin: raise ValueError('probe_url must match the stealth session origin')
   candidates=[candidate]
  else: candidates=[urljoin(origin+'/','favicon.ico'),origin+'/']
  headers=self._headers(state,None); request_proxy=state.get('proxy'); kwargs={'headers':headers,'allow_redirects':False,'timeout':max(0.1,float(timeout)),'verify':True}
  if request_proxy: kwargs['proxies']={'http':request_proxy,'https':request_proxy}
  if runtime.get('is_curl_transport'):
   version=str(getattr(transport,'http_version','') or '').upper()
   if version in {'HTTP/2','HTTP/2.0','2','H2'}: kwargs['http_version']='v2'
   elif version in {'HTTP/1.1','1.1','HTTP/1','1'}: kwargs['http_version']='v1'
  response=None; used_url=candidates[0]; elapsed=0.0; error_type=None; error=None
  for index,candidate in enumerate(candidates):
   used_url=candidate; started=time.monotonic()
   try: response=transport.request('GET',candidate,**kwargs); elapsed+=round(time.monotonic()-started,4); error_type=None; error=None
   except Exception as exc:
    elapsed+=round(time.monotonic()-started,4); error_type=exc.__class__.__name__; error=f'{error_type}: probe request failed'; response=None
    if index==len(candidates)-1: break
    continue
   if response.status_code not in {404,405} or index==len(candidates)-1: break
  probe_status=int(getattr(response,'status_code',0)) if response is not None else None
  if error_type: classification='target_unreachable'
  elif probe_status==200 and target_status==403: classification='fingerprint_blocked'
  elif probe_status in {403,502,503}: classification='ip_blocked_or_target_unavailable'
  elif probe_status==200: classification='healthy'
  else: classification='inconclusive'
  result={'classification':classification,'fingerprint_id':fingerprint['id'],'fingerprint_browser':fingerprint['browser'],'target_status_code':target_status,'probe_url':used_url,'probe_status_code':probe_status,'elapsed':round(elapsed,4),'transport_backend':runtime.get('transport_backend','custom'),'proxy':request_proxy,'error_type':error_type,'error':error,'checked_at':time.time()}
  state['fingerprint_health']=deepcopy(result); self._save(state); return result
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
 def _fingerprint_blocked_403(self,status_code,body):
  text=str(body or '').lower(); return int(status_code)==403 and any(marker in text for marker in FINGERPRINT_BLOCK_WORDS)
 def _record_http_fingerprint_signal(self,state,status_code,limited):
  failures=state['fingerprint_failures']; failures['timeout']=0
  if int(status_code) in {502,503} and not limited: failures['gateway']+=1
  else: failures['gateway']=0
  return failures['gateway']
 def _is_timeout_exception(self,exc):
  if isinstance(exc,TimeoutError) or exc.__class__.__name__.lower().endswith('timeout'): return True
  for module in (native_requests,requests):
   timeout_type=getattr(getattr(module,'exceptions',None),'Timeout',None)
   if isinstance(timeout_type,type) and isinstance(exc,timeout_type): return True
  return False
 def _proxy_args(self,state,url):
  proxy=self.proxy_pool.select(target=self._key(url))
  if not proxy: return {}
  state['proxy']=proxy['url']; return {'proxies':{'http':proxy['url'],'https':proxy['url']}}
 def _apply_strategy(self,strategy,headers,data,request_context=None):
  headers=dict(headers); data=deepcopy(data); context=request_context if isinstance(request_context,dict) else {}
  if not strategy: return headers,data,'none'
  sid=strategy['id']

  def drop_header(name):
   for key in list(headers):
    if key.lower()==name.lower(): headers.pop(key,None)

  def transform_values(value,transform):
   if isinstance(value,dict): return True,{key:transform(str(item)) for key,item in value.items()}
   if isinstance(value,(list,tuple)) and all(isinstance(item,(list,tuple)) and len(item)==2 for item in value):
    return True,[(key,transform(str(item))) for key,item in value]
   if isinstance(value,str): return True,transform(value)
   return False,value

  def as_pairs(value):
   if isinstance(value,dict): return list(value.items())
   if isinstance(value,(list,tuple)) and all(isinstance(item,(list,tuple)) and len(item)==2 for item in value): return list(value)
   if isinstance(value,bytes):
    try: value=value.decode('utf-8')
    except UnicodeDecodeError: return None
   if isinstance(value,str):
    try:
     parsed=json.loads(value)
     if isinstance(parsed,dict): return list(parsed.items())
    except (TypeError,ValueError,json.JSONDecodeError): pass
    if '=' in value or '&' in value: return parse_qsl(value,keep_blank_values=True)
   return None

  def serialize_body(value,content_type):
   pairs=as_pairs(value)
   if pairs is None: return None
   if content_type=='application/x-www-form-urlencoded': return urlencode(pairs,doseq=True)
   if content_type=='application/json': return json.dumps(dict(pairs),ensure_ascii=False,separators=(',',':'))
   boundary='hunter-boundary'
   parts=[]
   for key,item in pairs:
    safe_key=str(key).replace('"','%22')
    parts.extend([f'--{boundary}',f'Content-Disposition: form-data; name="{safe_key}"','',str(item)])
   parts.extend([f'--{boundary}--',''])
   return '\r\n'.join(parts)

  def rotate_content_type(value):
   types=('application/x-www-form-urlencoded','multipart/form-data','application/json')
   session=context.get('session')
   if session is not None:
    index=int(getattr(session,'_hunter_content_type_rotation',0))%len(types)
    setattr(session,'_hunter_content_type_rotation',index+1)
   else:
    current=str(headers.get('Content-Type','')).split(';',1)[0].strip().lower()
    index=(types.index(current)+1)%len(types) if current in types else 0
   content_type=types[index]; serialized=serialize_body(value,content_type)
   if serialized is None: return None
   headers['Content-Type']=f'{content_type}; boundary=hunter-boundary' if content_type=='multipart/form-data' else content_type
   drop_header('Content-Length')
   return serialized

  def sql_keyword_transform(value,marker=None,double_write=False):
   keyword_re=re.compile(r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|WHERE|FROM|JOIN|HAVING|ORDER|GROUP)\b',re.I)
   def replace(match):
    word=match.group(0); midpoint=max(1,len(word)//2)
    return word[:midpoint]+(word if double_write else marker)+word[midpoint:]
   return transform_values(value,lambda text:keyword_re.sub(replace,text))

  if sid=='content-type-json':
   headers['Content-Type']='application/json'; return headers,data,'applied'
  elif sid=='header-consistency':
   headers.setdefault('Cache-Control','max-age=0'); return headers,data,'applied'
  elif sid=='parameter-order' and isinstance(data,dict):
   return headers,dict(reversed(list(data.items()))),'applied'
  elif sid=='percent-encoding' and isinstance(data,dict):
   return headers,{k:quote(str(v),safe='') for k,v in data.items()},'applied'
  elif sid=='parameter-pollution' and isinstance(data,dict):
   return headers,[(k,v) for k,v in data.items() for _ in (0,1)],'applied'
  elif sid=='case-variation' and isinstance(data,str):
   return headers,''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(data)),'applied'
  elif sid=='line-folding' and isinstance(data,str):
   return headers,data.replace(' ','\n'),'applied'
  elif sid=='double-percent-encoding':
   applicable,transformed=transform_values(data,lambda value:value.replace('%','%25'))
   changed=applicable and transformed!=data
   if changed and isinstance(transformed,(dict,list,tuple)) and not str(headers.get('Content-Type','')).lower().startswith('application/json'): context['_preserve_percent_values']=True
   return (headers,transformed,'applied') if changed else (headers,data,'unsupported')
  elif sid=='protocol-version-switch':
   session=context.get('session')
   if session is None: return headers,data,'unsupported'
   current=str(getattr(session,'http_version','HTTP/1.1')).upper()
   session.http_version='HTTP/1.1' if current in {'HTTP/2','HTTP/2.0','2','H2'} else 'HTTP/2'
   return headers,data,'applied'
  elif sid=='chunked-body':
   session=context.get('session'); version=str(getattr(session,'http_version','HTTP/1.1')).upper() if session is not None else 'HTTP/1.1'
   if version in {'HTTP/2','HTTP/2.0','2','H2'} or data is None: return headers,data,'unsupported'
   if isinstance(data,(dict,list,tuple)):
    try:
     content_type=str(headers.get('Content-Type','')).split(';',1)[0].strip().lower()
     body=(json.dumps(data,ensure_ascii=False,separators=(',',':')) if content_type=='application/json' else urlencode(data,doseq=True)).encode('utf-8')
    except (TypeError,ValueError): return headers,data,'unsupported'
   elif isinstance(data,str): body=data.encode('utf-8')
   elif isinstance(data,(bytes,bytearray)): body=bytes(data)
   else: return headers,data,'unsupported'
   framed=b''.join(f'{len(chunk):x}\r\n'.encode('ascii')+chunk+b'\r\n' for start in range(0,len(body),256) for chunk in (body[start:start+256],))+b'0\r\n\r\n'
   context['_chunk_source']=body
   headers['Transfer-Encoding']='chunked'; drop_header('Content-Length')
   return headers,framed,'applied'
  elif sid=='query-to-body':
   method=str(context.get('method','')).upper(); raw_url=context.get('url')
   if method!='GET' or not raw_url: return headers,data,'unsupported'
   parsed=urlsplit(raw_url); query_pairs=parse_qsl(parsed.query,keep_blank_values=True)
   if not query_pairs: return headers,data,'unsupported'
   existing=[] if data is None else as_pairs(data)
   if existing is None: return headers,data,'unsupported'
   context['method']='POST'; context['url']=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',parsed.fragment))
   headers['Content-Type']='application/x-www-form-urlencoded'; drop_header('Content-Length')
   return headers,urlencode(query_pairs+existing,doseq=True),'applied'
  elif sid=='benign-field-padding':
   padding=[('submit','continue'),('source','web'),('lang','en')]
   if isinstance(data,dict):
    padded=dict(data)
    for key,value in padding: padded.setdefault(key,value)
   elif isinstance(data,(list,tuple)) and all(isinstance(item,(list,tuple)) and len(item)==2 for item in data):
    padded=list(data); existing={str(key) for key,_ in padded}; padded.extend((key,value) for key,value in padding if key not in existing)
   elif isinstance(data,str):
    content_type=str(headers.get('Content-Type','')).lower()
    if content_type.startswith('application/json'):
     try: padded=json.loads(data)
     except (TypeError,ValueError,json.JSONDecodeError): return headers,data,'unsupported'
     if not isinstance(padded,dict): return headers,data,'unsupported'
     for key,value in padding: padded.setdefault(key,value)
     padded=json.dumps(padded,ensure_ascii=False,separators=(',',':'))
    else: padded=data+('&' if data else '')+urlencode(padding)
   else: return headers,data,'unsupported'
   drop_header('Content-Length')
   return headers,padded,'applied'
  elif sid=='content-type-rotation':
   rotated=rotate_content_type(data)
   return (headers,rotated,'applied') if rotated is not None else (headers,data,'unsupported')
  elif sid=='keyword-double-write':
   applicable,transformed=sql_keyword_transform(data,double_write=True)
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='unicode-equivalent':
   equivalents={'a':'а','c':'с','e':'е','i':'і','j':'ј','o':'о','p':'р','s':'ѕ','x':'х','y':'у','A':'А','C':'С','E':'Е','I':'І','J':'Ј','O':'О','P':'Р','S':'Ѕ','X':'Х','Y':'У'}
   def replace_unicode(value):
    budget=int(len(value)*0.3); replaced=0; output=[]
    for char in value:
     if replaced<budget and char in equivalents: output.append(equivalents[char]); replaced+=1
     else: output.append(char)
    return ''.join(output)
   applicable,transformed=transform_values(data,replace_unicode)
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='null-byte-padding':
   applicable,transformed=transform_values(data,lambda value:'%00'.join(value))
   if applicable and isinstance(transformed,(dict,list,tuple)) and not str(headers.get('Content-Type','')).lower().startswith('application/json'): context['_preserve_percent_values']=True
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='comment-injection':
   applicable,transformed=sql_keyword_transform(data,marker='/**/')
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='http2-multiplex':
   session=context.get('session')
   if session is None: return headers,data,'unsupported'
   session.http_version='HTTP/2'; return headers,data,'applied'
  elif sid=='websocket-upgrade':
   method=str(context.get('method','')).upper(); raw_url=str(context.get('url',''))
   if method!='GET' or not (context.get('websocket_endpoint') or urlsplit(raw_url).scheme in {'ws','wss'}): return headers,data,'unsupported'
   headers.update({'Connection':'Upgrade','Upgrade':'websocket','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':'dGhlIHNhbXBsZSBub25jZQ=='})
   return headers,data,'applied'
  elif sid=='versioned-comment-separation':
   applicable,transformed=sql_keyword_transform(data,marker='/*!50000*/')
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='comment-separation':
   applicable,transformed=sql_keyword_transform(data,marker='/**/')
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='utf16-body':
   content_type=str(headers.get('Content-Type','application/x-www-form-urlencoded')).split(';',1)[0].strip() or 'application/x-www-form-urlencoded'
   if isinstance(data,dict):
    raw=json.dumps(data,ensure_ascii=False,separators=(',',':')) if content_type=='application/json' else urlencode(data,doseq=True)
   elif isinstance(data,str): raw=data
   elif isinstance(data,(bytes,bytearray)):
    try: raw=bytes(data).decode('utf-8')
    except UnicodeDecodeError: return headers,data,'unsupported'
   else: return headers,data,'unsupported'
   headers['Content-Type']=f'{content_type}; charset=utf-16'; drop_header('Content-Length')
   return headers,raw.encode('utf-16'),'applied'
  elif sid=='equivalent-function':
   replacements=(('SUBSTRING','MID'),('ASCII','ORD'),('LCASE','LOWER'),('UCASE','UPPER'))
   def replace_functions(value):
    for source,target in replacements: value=re.sub(rf'\b{source}(?=\s*\()',target,value,flags=re.I)
    return value
   applicable,transformed=transform_values(data,replace_functions)
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='html-numeric-entities':
   special=set('<>&"\'')
   applicable,transformed=transform_values(data,lambda value:''.join(f'&#{ord(char)};' if char in special else char for char in value))
   return (headers,transformed,'applied') if applicable else (headers,data,'unsupported')
  elif sid=='content-type-alternate':
   rotated=rotate_content_type(data)
   return (headers,rotated,'applied') if rotated is not None else (headers,data,'unsupported')
  return headers,data,'unsupported'
 def _captcha_image_url(self,response):
  text=str(getattr(response,'text','')); matches=re.findall(r'<img[^>]+(?:src|data-src)=["\']([^"\']+)["\'][^>]*>',text,re.I)
  candidate=next((x for x in matches if 'captcha' in x.lower() or 'verify' in x.lower()),matches[0] if matches and ('captcha' in text.lower() or 'verify' in text.lower()) else '')
  return urljoin(getattr(response,'url',''),candidate) if candidate else ''
 def _solve_page_captcha(self,response,transport,state,request_headers,options,request_proxy,timeline):
  image_url=self._captcha_image_url(response)
  if not image_url: return self.captcha.handle(response,state['target'],options.get('captcha_engine','pytesseract'))
  image_origin=self._key(image_url); allowed_origins=set(options.get('allowed_origins') or [state['target']])
  if image_origin not in allowed_origins: return {'solved':False,'text':'','type':'image','status':'blocked','reason':'captcha image origin is outside authorized scope','url':image_url}
  image_headers=dict(request_headers)
  if image_origin!=self._key(state['target']):
   safe_headers={'accept','accept-encoding','accept-language','cache-control','pragma','user-agent'}
   image_headers={name:value for name,value in image_headers.items() if name.lower() in safe_headers}
  attempts=[]
  for number in range(1,4):
   kwargs={'headers':image_headers,'allow_redirects':False,'timeout':options.get('timeout',15),'verify':options.get('verify_tls',True)}
   if request_proxy: kwargs['proxies']={'http':request_proxy,'https':request_proxy}
   image_response=transport.request('GET',image_url,**kwargs); result=self.captcha.solve_image(getattr(image_response,'content',b''),state['target'],options.get('captcha_engine','pytesseract')); attempts.append(result); timeline.append({'event':'captcha-image-fetch','attempt':number,'url':image_url,'status_code':image_response.status_code,'proxy':request_proxy,'ocr':result})
   if result['solved']: return {'solved':True,'text':result['text'],'type':'image','attempts':attempts}
  return {'solved':False,'text':'','type':'image','attempts':attempts}
 def stealth_request(self,method,url,headers=None,data=None,options=None):
  options=options or {}; runtime=self._runtime(url); state=runtime['state']; transport=runtime['transport']; transport_backend=runtime.get('transport_backend','custom'); applied_impersonate=runtime.get('applied_impersonate'); is_curl_transport=bool(runtime.get('is_curl_transport')); max_retries=min(3,max(0,int(options.get('max_retries',3)))); strategy=deepcopy(options.get('initial_strategy')) if isinstance(options.get('initial_strategy'),dict) else None; timeline=[]; response=None; automatic_rotation_retries=0
  for attempt in range(max_retries+1):
   request_headers=self._headers(state,headers); request_data=deepcopy(data)
   for name,value in state['csrf_tokens'].items():
    if isinstance(request_data,dict): request_data.setdefault(name,value)
   request_context={'method':method,'url':url,'session':transport,'websocket_endpoint':bool(options.get('websocket_endpoint'))}
   request_headers,request_data,strategy_status=self._apply_strategy(strategy,request_headers,request_data,request_context=request_context); request_method=request_context['method']; request_url=request_context['url']; delay=self.rate.before_request(state['target'],proxy=state.get('proxy'),jitter=options.get('jitter',True))
   if delay: self.sleep(delay)
   if request_context.get('_preserve_percent_values') and isinstance(request_data,(dict,list,tuple)):
    pairs=list(request_data.items()) if isinstance(request_data,dict) else list(request_data)
    request_data='&'.join(f'{quote_plus(str(key),safe="")}={quote_plus(str(value),safe="%")}' for key,value in pairs)
    request_headers['Content-Type']='application/x-www-form-urlencoded'
   if '_chunk_source' in request_context:
    chunk_source=request_context['_chunk_source']
    if native_requests is not None and isinstance(transport,native_requests.Session): request_data=(chunk_source[start:start+256] for start in range(0,len(chunk_source),256))
    elif is_curl_transport: request_data=chunk_source
   proxy_args=self._proxy_args(state,request_url); request_proxy=state.get('proxy'); kwargs={'headers':request_headers,'data':request_data,'allow_redirects':options.get('follow_redirects',True),'timeout':options.get('timeout',15),'verify':options.get('verify_tls',True)}
   if is_curl_transport:
    version=str(getattr(transport,'http_version','') or '').upper()
    if version in {'HTTP/2','HTTP/2.0','2','H2'}: kwargs['http_version']='v2'
    elif version in {'HTTP/1.1','1.1','HTTP/1','1'}: kwargs['http_version']='v1'
   if isinstance(request_data,dict) and str(request_headers.get('Content-Type','')).startswith('application/json'): kwargs.pop('data',None); kwargs['json']=request_data
   kwargs.update(proxy_args); start=time.monotonic()
   try: response=transport.request(request_method,request_url,**kwargs); elapsed=round(time.monotonic()-start,4)
   except Exception as exc:
    elapsed=round(time.monotonic()-start,4); timeout_failure=self._is_timeout_exception(exc); failures=state['fingerprint_failures']; failures['gateway']=0; failures['timeout']=failures['timeout']+1 if timeout_failure else 0
    row={'attempt':attempt+1,'error':str(exc),'elapsed':elapsed,'strategy':strategy and strategy['id'],'strategy_status':strategy_status,'fingerprint_id':state['fingerprint_id'],'impersonate':applied_impersonate,'requested_impersonate':state.get('impersonate'),'transport_backend':transport_backend,'proxy':request_proxy,'failure_class':'timeout' if timeout_failure else 'exception','gateway_streak':failures['gateway'],'timeout_streak':failures['timeout']}; timeline.append(row)
    if request_proxy: self.proxy_pool.record_request(request_proxy,False,state['target']); state['proxy']=None
    self.rate.record_failure(state['target'],request_proxy)
    if attempt<max_retries:
     if timeout_failure and failures['timeout']>=3 and automatic_rotation_retries<2:
      event=self._rotate_runtime_fingerprint(runtime,'consecutive-timeouts',automatic=True); automatic_rotation_retries+=1; row['fingerprint_rotation']=event; row['retry_reason']='consecutive-timeouts'
      transport=runtime['transport']; transport_backend=runtime.get('transport_backend','custom'); applied_impersonate=runtime.get('applied_impersonate'); is_curl_transport=bool(runtime.get('is_curl_transport'))
     self.sleep(self.rate.backoff(state['target'],request_proxy,failure_recorded=True)); continue
    self._finalize(state,timeline); return {'status':'error','error':str(exc),'attempts':attempt+1,'timeline':timeline}
   self._capture_cookies(response,state,transport); waf=self.waf.detect_response(response); response_headers=dict(getattr(response,'headers',{})); response_text=str(getattr(response,'text','')); limited=self.rate.is_rate_limited(response.status_code,response_headers,response_text); gateway_streak=self._record_http_fingerprint_signal(state,response.status_code,limited)
   if request_proxy: self.proxy_pool.record_request(request_proxy,not waf['blocked'],state['target'],banned=False,latency_ms=elapsed*1000)
   self.rate.record_response(state['target'],response.status_code,request_proxy,response_headers,response_text,limited=limited); self._csrf(response_text,state)
   captcha_info=self.captcha.detect(response); captcha=self._solve_page_captcha(response,transport,state,request_headers,options,request_proxy,timeline) if captcha_info['type']=='image' else self.captcha.handle(response,state['target'],options.get('captcha_engine','pytesseract'))
   if strategy and waf['waf_type'] and strategy_status=='applied' and not limited and captcha_info['type'] is None: self.waf.record_outcome(waf['waf_type'],strategy['id'],not waf['blocked'])
   if getattr(response,'history',None): state['oauth_chain'].extend([getattr(x,'url','') for x in response.history if getattr(x,'url','')]); state['oauth_chain']=state['oauth_chain'][-200:]
   row={'attempt':attempt+1,'status_code':response.status_code,'elapsed':elapsed,'strategy':strategy and strategy['id'],'strategy_status':strategy_status,'fingerprint_id':state['fingerprint_id'],'impersonate':applied_impersonate,'requested_impersonate':state.get('impersonate'),'transport_backend':transport_backend,'proxy':request_proxy,'waf':waf,'rate_limited':limited,'captcha':captcha,'gateway_streak':gateway_streak,'timeout_streak':state['fingerprint_failures']['timeout']}; timeline.append(row)
   if captcha.get('solved') and isinstance(request_data,dict) and attempt<max_retries: request_data[options.get('captcha_field','captcha')]=captcha['text']; data=request_data; continue
   if captcha.get('status')=='operator-required': self._finalize(state,timeline); return {'status':'operator-required','captcha':captcha,'status_code':response.status_code,'attempts':attempt+1,'timeline':timeline}
   if limited and attempt<max_retries: self.sleep(self.rate.backoff(state['target'],request_proxy,response_headers,failure_recorded=True)); continue
   if self._fingerprint_blocked_403(response.status_code,response_text) and attempt<max_retries and automatic_rotation_retries<2:
    if waf['blocked']:
     choices=self.waf.strategies_for(waf['waf_type'])
     if choices: strategy=choices[min(attempt,len(choices)-1)]
    event=self._rotate_runtime_fingerprint(runtime,'403-block-keyword',automatic=True); automatic_rotation_retries+=1; row['fingerprint_rotation']=event; row['retry_reason']='403-block-keyword'
    transport=runtime['transport']; transport_backend=runtime.get('transport_backend','custom'); applied_impersonate=runtime.get('applied_impersonate'); is_curl_transport=bool(runtime.get('is_curl_transport')); continue
   if response.status_code in {502,503} and not limited:
    if gateway_streak>=2 and attempt<max_retries and automatic_rotation_retries<2:
     event=self._rotate_runtime_fingerprint(runtime,'gateway-502-503-streak',automatic=True); automatic_rotation_retries+=1; row['fingerprint_rotation']=event; row['retry_reason']='gateway-502-503-streak'
     transport=runtime['transport']; transport_backend=runtime.get('transport_backend','custom'); applied_impersonate=runtime.get('applied_impersonate'); is_curl_transport=bool(runtime.get('is_curl_transport')); continue
    if attempt<max_retries: row['retry_reason']='gateway-streak-observation'; continue
   if waf['blocked'] and attempt<max_retries:
    choices=self.waf.strategies_for(waf['waf_type']); strategy=choices[min(attempt,len(choices)-1)]; continue
   break
  self._capture_cookies(response,state,transport); self._finalize(state,timeline); body=str(getattr(response,'text','')); limit=max(100,int(options.get('max_body_chars',16000))); truncated=len(body)>limit; artifact=''
  if truncated:
   directory=self.state_dir/'responses'; directory.mkdir(parents=True,exist_ok=True); path=directory/f'{uuid.uuid4().hex}.body'; path.write_text(body,encoding='utf-8'); artifact=str(path); body=body[:max(0,limit-1)]+'?'
  return {'status':'ok' if response and response.status_code<400 else 'blocked','status_code':response.status_code if response else 0,'url':getattr(response,'url',url),'headers':dict(getattr(response,'headers',{})),'body':body,'body_truncated':truncated,'body_artifact':artifact,'attempts':sum(1 for x in timeline if 'attempt' in x and x.get('event')!='captcha-image-fetch'),'timeline':timeline}
 def send_detection_request(self,session_id,method,url,params=None,data=None,headers=None,options=None):
  runtime=self._runtime_for_session_id(session_id)
  if runtime is None: return {'status':'error','error':f"Stealth session '{session_id}' not found",'session_id':session_id}
  state=runtime['state']
  if not urlsplit(str(url)).scheme: url=urljoin(state['target']+'/',str(url).lstrip('/'))
  if self._key(url)!=state['target']: return {'status':'error','error':f"Request origin {self._key(url)} does not match session origin {state['target']}",'session_id':session_id}
  if params:
   parsed=urlsplit(url)
   if isinstance(params,str): extra=parse_qsl(params,keep_blank_values=True)
   elif isinstance(params,dict): extra=list(params.items())
   elif isinstance(params,(list,tuple)): extra=list(params)
   else: return {'status':'error','error':'params must be a mapping, query string, or sequence of pairs','session_id':session_id}
   url=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(parse_qsl(parsed.query,keep_blank_values=True)+extra,doseq=True),parsed.fragment))
  request_options=dict(options or {})
  if not request_options.get('initial_strategy'):
   waf_type=''
   for row in reversed(state.get('timeline',[])):
    waf=row.get('waf',{}) if isinstance(row,dict) else {}
    if isinstance(waf,dict) and waf.get('waf_type'): waf_type=waf['waf_type']; break
   if waf_type:
    choices=self.waf.strategies_for(waf_type)
    if choices: request_options['initial_strategy']=choices[0]
  try: result=self.stealth_request(method,url,headers=headers,data=data,options=request_options)
  except Exception as exc: return {'status':'error','error':str(exc),'session_id':session_id}
  result['session_id']=session_id; result['cookies']=deepcopy(runtime['state'].get('cookies',{})); result['csrf_tokens']=deepcopy(runtime['state'].get('csrf_tokens',{})); return result
 def _capture_cookies(self,response,state,transport=None):
  for cookies in (getattr(transport,'cookies',None),getattr(response,'cookies',None)):
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

