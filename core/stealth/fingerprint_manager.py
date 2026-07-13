"""Coherent browser fingerprint pool with per-session persistence."""
from __future__ import annotations
import random,re,time,uuid
from copy import deepcopy

PLATFORMS=[('Windows','Windows NT 10.0; Win64; x64','"Windows"'),('macOS','Macintosh; Intel Mac OS X 10_15_7','"macOS"'),('Linux','X11; Linux x86_64','"Linux"')]
RESOLUTIONS=['1920x1080','1366x768','1536x864','2560x1440','1440x900','1600x900','1280x720','3840x2160','1920x1200','1280x800']
TIMEZONES=['Asia/Shanghai','America/New_York','Europe/London','Europe/Berlin','Asia/Tokyo','Asia/Singapore','Australia/Sydney','America/Los_Angeles']
LANGUAGES=['zh-CN,zh;q=0.9,en;q=0.8','en-US,en;q=0.9','en-GB,en;q=0.9','ja-JP,ja;q=0.9,en;q=0.7','de-DE,de;q=0.9,en;q=0.7']

CURL_IMPERSONATE_MAPPINGS={
 ('Chrome',110):'chrome110',
 ('Chrome',120):'chrome120',
 ('Edge',99):'edge99',
 ('Edge',101):'edge101',
 ('Safari',15):'safari15_3',
 ('Safari',17):'safari17_0',
}

def curl_impersonate_for(browser,version):
 candidates=[
  (mapped_version,value)
  for (mapped_browser,mapped_version),value in CURL_IMPERSONATE_MAPPINGS.items()
  if mapped_browser==browser and mapped_version<=int(version)
 ]
 if not candidates: return None
 return max(candidates,key=lambda item:item[0])[1]

class FingerprintManager:
 def __init__(self,seed=None,min_versions=None,version_source=None,max_age_days=120):
  self.random=random.Random(seed); self.pool=[]; self.sessions={}; self.index=0; self.version_source=version_source; self.max_age_days=max_age_days; self.last_refreshed_at=None; self.min_versions=min_versions or {'Chrome':120,'Edge':120,'Firefox':115,'Safari':16}; self._build(); self.refresh_versions(); self.prune_stale()
 def _add(self,browser,version,platform,ua,sec=None):
  pid=f'{browser.lower()}-{version}-{platform[0].lower()}-{len(self.pool):02d}'; lang=LANGUAGES[len(self.pool)%len(LANGUAGES)]; headers={'User-Agent':ua,'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8','Accept-Language':lang,'Accept-Encoding':'gzip, deflate, br'}
  if sec: headers.update({'Sec-CH-UA':sec,'Sec-CH-UA-Platform':platform[2],'Sec-CH-UA-Mobile':'?0'})
  self.pool.append({'id':pid,'browser':browser,'version':int(version),'platform':platform[0],'headers':headers,'screen':RESOLUTIONS[len(self.pool)%len(RESOLUTIONS)],'timezone':TIMEZONES[len(self.pool)%len(TIMEZONES)],'languages':lang,'impersonate':curl_impersonate_for(browser,version),'source':'preset','created_at':time.time()})
 def _build(self):
  for version in range(120,130):
   for platform in PLATFORMS[:2]: self._add('Chrome',version,platform,f'Mozilla/5.0 ({platform[1]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36',f'"Chromium";v="{version}", "Google Chrome";v="{version}", "Not_A Brand";v="24"')
  for version in range(121,127):
   for platform in PLATFORMS[:2]: self._add('Edge',version,platform,f'Mozilla/5.0 ({platform[1]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0',f'"Chromium";v="{version}", "Microsoft Edge";v="{version}", "Not_A Brand";v="24"')
  for version in range(115,123):
   for platform in PLATFORMS[:2]: self._add('Firefox',version,platform,f'Mozilla/5.0 ({platform[1]}; rv:{version}.0) Gecko/20100101 Firefox/{version}.0')
  mac=PLATFORMS[1]
  for version in range(16,20):
   for minor in range(2): self._add('Safari',version,mac,f'Mozilla/5.0 ({mac[1]}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.{minor} Safari/605.1.15')
 def refresh_versions(self):
  if self.version_source:
   values=self.version_source()
   if values: self.min_versions.update({k:int(v) for k,v in values.items()})
  self.last_refreshed_at=time.time(); return dict(self.min_versions)
 def freshness_status(self,item):
  return {'fresh':item['version']>=self.min_versions.get(item['browser'],0),'minimum_version':self.min_versions.get(item['browser'],0),'last_refreshed_at':self.last_refreshed_at}
 def fingerprints(self): return deepcopy(self.pool)
 def get(self,fingerprint_id):
  item=next((x for x in self.pool if x['id']==fingerprint_id),None)
  if not item: raise KeyError(fingerprint_id)
  return deepcopy(item)
 def choose(self,strategy='random',require_impersonate=False):
  pool=[item for item in self.pool if item.get('impersonate')] if require_impersonate else self.pool
  if not pool: raise RuntimeError('fingerprint pool is empty')
  if strategy=='round-robin': item=pool[self.index%len(pool)]; self.index+=1
  else: item=self.random.choice(pool)
  return deepcopy(item)
 def bind_session(self,session_id,fingerprint_id):
  item=self.get(fingerprint_id); self.sessions[str(session_id)]=item['id']; return item
 def for_session(self,session_id,strategy='random',require_impersonate=False):
  key=str(session_id); current=self.sessions.get(key)
  if current:
   item=self.get(current)
   if require_impersonate and not item.get('impersonate'): raise RuntimeError('session fingerprint does not support impersonation; call rotate_fingerprint() explicitly')
   return item
  item=self.choose(strategy,require_impersonate=require_impersonate); self.sessions[key]=item['id']; return item
 def rotate_fingerprint(self,session_id,current_fingerprint_id=None,strategy='random',require_impersonate=False):
  key=str(session_id); current_id=current_fingerprint_id or self.sessions.get(key); current=self.get(current_id) if current_id else None
  candidates=[item for item in self.pool if (current is None or item['browser']!=current['browser']) and (not require_impersonate or item.get('impersonate'))]
  if not candidates: raise RuntimeError('no cross-family fingerprint candidate is available')
  if strategy=='round-robin': selected=candidates[self.index%len(candidates)]; self.index+=1
  else: selected=self.random.choice(candidates)
  self.sessions[key]=selected['id']; return deepcopy(selected)
 def import_browser(self,data=None,page=None):
  if page is not None: data=page.evaluate('''() => ({userAgent:navigator.userAgent,languages:navigator.languages,language:navigator.language,platform:navigator.platform,screen:{width:screen.width,height:screen.height},timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,userAgentData:navigator.userAgentData?{brands:navigator.userAgentData.brands,mobile:navigator.userAgentData.mobile,platform:navigator.userAgentData.platform}:null})''')
  data=data or {}; ua=data.get('userAgent',''); browser='Edge' if 'Edg/' in ua else 'Firefox' if 'Firefox/' in ua else 'Safari' if 'Version/' in ua and 'Safari/' in ua else 'Chrome'; match=re.search(r'(?:Edg|Firefox|Chrome|Version)/(\d+)',ua); version=int(match.group(1)) if match else 0; platform_name=(data.get('userAgentData') or {}).get('platform') or data.get('platform','Unknown'); lang=','.join(data.get('languages') or [data.get('language','en-US')]); brands=(data.get('userAgentData') or {}).get('brands') or []; sec=', '.join(f'"{x.get("brand")}";v="{x.get("version")}"' for x in brands); item={'id':f'real-{uuid.uuid4().hex[:12]}','browser':browser,'version':version,'platform':platform_name,'headers':{'User-Agent':ua,'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Accept-Language':lang,'Accept-Encoding':'gzip, deflate, br','Sec-CH-UA':sec,'Sec-CH-UA-Platform':f'"{platform_name}"','Sec-CH-UA-Mobile':'?1' if (data.get('userAgentData') or {}).get('mobile') else '?0'},'screen':f"{data.get('screen',{}).get('width',0)}x{data.get('screen',{}).get('height',0)}",'timezone':data.get('timezone','UTC'),'languages':lang,'impersonate':curl_impersonate_for(browser,version),'source':'browser','created_at':time.time()}; self.pool.append(item); return deepcopy(item)
 def prune_stale(self,min_versions=None):
  minimum=min_versions or self.min_versions; before=len(self.pool); self.pool=[x for x in self.pool if x['source']=='browser' or x['version']>=minimum.get(x['browser'],0)]; valid={x['id'] for x in self.pool}; self.sessions={k:v for k,v in self.sessions.items() if v in valid}; return {'removed':before-len(self.pool),'remaining':len(self.pool)}
