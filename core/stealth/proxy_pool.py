"""Classified proxy inventory with injectable health and target-ban checks."""
from __future__ import annotations
import time
from pathlib import Path
from urllib.parse import urlparse

class ProxyPool:
 def __init__(self): self.proxies={}
 def add(self,value,metadata=None):
  value=value.strip();
  if not value: return None
  if '://' not in value: value='http://'+value
  parsed=urlparse(value); item=self.proxies.setdefault(value,{'url':value,'scheme':parsed.scheme.lower(),'country':(metadata or {}).get('country','unknown'),'anonymity':(metadata or {}).get('anonymity','unknown'),'latency_ms':None,'attempts':0,'successes':0,'healthy':None,'target_bans':{},'last_checked':None,'score':0.5}); return dict(item)
 def load_file(self,path):
  added=[]
  for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
   raw=line.strip()
   if not raw or raw.startswith('#'): continue
   parts=[x.strip() for x in raw.split(',')]; item=self.add(parts[0],{'country':parts[1] if len(parts)>1 else 'unknown','anonymity':parts[2] if len(parts)>2 else 'unknown'}); added.append(item)
  return added
 def check(self,url,checker,target=None):
  item=self.proxies[url]; start=time.monotonic()
  try: result=checker(dict(item),target); ok=bool(result.get('ok')); latency=result.get('latency_ms',round((time.monotonic()-start)*1000,2)); banned=bool(result.get('banned'))
  except Exception: ok=False; latency=None; banned=False
  item['attempts']+=1; item['successes']+=int(ok and not banned); item['healthy']=ok; item['latency_ms']=latency; item['last_checked']=time.time();
  if target: item['target_bans'][target]=banned
  success_rate=item['successes']/item['attempts']; speed=1/(1+(latency or 500)/500); anonymity={'elite':1,'anonymous':0.8,'transparent':0.3}.get(item['anonymity'],0.5); item['score']=round(0.5*success_rate+0.3*speed+0.2*anonymity,4); return dict(item)
 def health_check(self,checker,target=None): return [self.check(url,checker,target) for url in list(self.proxies)]
 def record_request(self,url,success,target=None,banned=False,latency_ms=None):
  if not url or url not in self.proxies: return None
  item=self.proxies[url]; item['attempts']+=1; item['successes']+=int(success and not banned); item['healthy']=bool(success); item['last_checked']=time.time();
  if latency_ms is not None: item['latency_ms']=latency_ms
  if target: item['target_bans'][target]=bool(banned)
  success_rate=item['successes']/item['attempts']; speed=1/(1+(item.get('latency_ms') or 500)/500); anonymity={'elite':1,'anonymous':0.8,'transparent':0.3}.get(item['anonymity'],0.5); item['score']=round(0.5*success_rate+0.3*speed+0.2*anonymity,4); return dict(item)
 def select(self,target=None):
  candidates=[x for x in self.proxies.values() if x['healthy'] is not False and not x['target_bans'].get(target,False)]; return dict(max(candidates,key=lambda x:x['score'])) if candidates else None
 def prune(self,min_score=0.25,min_attempts=3):
  removed=[url for url,x in self.proxies.items() if x['attempts']>=min_attempts and (x['score']<min_score or x['healthy'] is False)]; [self.proxies.pop(x,None) for x in removed]; return removed
 def summary(self): return {'total':len(self.proxies),'healthy':sum(x['healthy'] is True for x in self.proxies.values()),'unknown':sum(x['healthy'] is None for x in self.proxies.values()),'proxies':[dict(x) for x in self.proxies.values()]}
