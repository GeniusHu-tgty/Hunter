"""WAF response fingerprinting and bounded strategy orchestration."""
from __future__ import annotations
import json
from pathlib import Path

WAF_SIGNATURES = {
    'Cloudflare': {'headers': ['cf-ray','cf-cache-status'], 'values':['cloudflare'], 'body':['cloudflare','attention required']},
    'Akamai': {'headers':['akamai-grn','x-akamai-transformed'], 'values':['akamai'], 'body':['akamai reference']},
    'AWS CloudFront': {'headers':['x-amz-cf-id','x-amz-cf-pop'], 'values':['cloudfront'], 'body':['request blocked']},
    'Fastly': {'headers':['x-served-by','x-fastly-request-id'], 'values':['fastly'], 'body':['fastly error']},
    'Alibaba Cloud CDN': {'headers':['eagleid','x-swift-cachetime'], 'values':['aliyun'], 'body':['aliyun']},
    'Tencent Cloud CDN': {'headers':['x-nws-log-uuid','x-cache-lookup'], 'values':['tencent'], 'body':['tencent cloud']},
    'Alibaba Cloud WAF': {'headers':['x-aliyun-waf'], 'values':['aliyun waf'], 'body':['阿里云waf','errors.aliyun.com']},
    'Tencent Cloud WAF': {'headers':['x-tencent-waf'], 'values':['tencent waf'], 'body':['腾讯云waf']},
    'Huawei Cloud WAF': {'headers':['x-hw-waf'], 'values':['huawei waf'], 'body':['华为云waf']},
    'AWS WAF': {'headers':['x-amzn-requestid'], 'values':['aws waf'], 'body':['aws waf']},
    'Azure WAF': {'headers':['x-azure-ref'], 'values':['azure'], 'body':['azure web application firewall']},
    'ModSecurity': {'headers':['x-mod-security'], 'values':['mod_security'], 'body':['modsecurity','mod_security','access denied with code 403']},
    'NAXSI': {'headers':['x-naxsi-sig'], 'values':['naxsi'], 'body':['naxsi blocked']},
    'SafeDog': {'headers':['x-safedog'], 'values':['safedog'], 'body':['安全狗','safedog']},
    'YunSuo': {'headers':['x-yunsuo'], 'values':['yunsuo'], 'body':['云锁']},
    'DShield': {'headers':['x-d-waf'], 'values':['d盾'], 'body':['d盾']},
    '360 WAF': {'headers':['x-360-waf'], 'values':['360wzws'], 'body':['360网站卫士','360wzws']},
    'Chaitin SafeLine': {'headers':['x-safeline'], 'values':['safeline'], 'body':['长亭雷池','safeline']},
    'Sucuri': {'headers':['x-sucuri-id','x-sucuri-cache'], 'values':['sucuri'], 'body':['sucuri website firewall']},
}
BLOCK_WORDS=('forbidden','access denied','request blocked','您的请求已被拦截','安全检测','非法请求','访问被拒绝','web application firewall')
STRATEGIES={
 'Cloudflare':[('http2-multiplex','HTTP/2 connection reuse'),('chunked-body','standards-compliant chunked transfer framing'),('websocket-upgrade','WebSocket upgrade only when the application exposes a legitimate endpoint')],
 'Alibaba Cloud WAF':[('percent-encoding','context-aware percent encoding'),('parameter-pollution','duplicate parameter normalization test'),('content-type-json','alternate supported Content-Type')],
 'ModSecurity':[('case-variation','keyword case normalization test'),('comment-separation','parser normalization differential test'),('line-folding','line-break normalization test')],
 'SafeDog':[('keyword-double-write','duplicate token normalization differential test'),('equivalent-function','equivalent expression normalization test')],
 'default':[('header-consistency','use a coherent browser fingerprint'),('content-type-alternate','use another application-supported Content-Type'),('parameter-order','change benign parameter order')],
}
PROBES=[('xss','<script>alert(1)</script>'),('traversal','../../../etc/passwd'),('sqli',"' OR 1=1 --"),('parameter-volume',{f'p{i}':'x' for i in range(80)})]

class WAFDetector:
 def __init__(self,history_path=None): self.history_path=Path(history_path).resolve() if history_path else None; self.history=self._load()
 def _load(self):
  if self.history_path and self.history_path.exists(): return json.loads(self.history_path.read_text(encoding='utf-8-sig'))
  return {}
 def _save(self):
  if self.history_path: self.history_path.parent.mkdir(parents=True,exist_ok=True); self.history_path.write_text(json.dumps(self.history,indent=2)+'\n',encoding='utf-8')
 def detect_response(self,response):
  headers={str(k).lower():str(v).lower() for k,v in getattr(response,'headers',{}).items()}; text=str(getattr(response,'text','')).lower(); status=int(getattr(response,'status_code',0)); scores={}
  for name,sig in WAF_SIGNATURES.items():
   score=sum(3 for h in sig['headers'] if h in headers)+sum(2 for v in sig['values'] if any(v in x for x in headers.values()))+sum(2 for b in sig['body'] if b in text)
   if score: scores[name]=score
  waf=max(scores,key=scores.get) if scores else 'custom/unknown'; block_word=any(x in text for x in BLOCK_WORDS); blocked=status in {403,406,409,418,429,503} and (block_word or bool(scores))
  confidence=min(1.0,(scores.get(waf,0)/5)+(0.2 if blocked else 0)) if scores else (0.45 if blocked else 0.0)
  return {'blocked':blocked,'waf_type':waf if scores else ('custom/unknown' if blocked else None),'confidence':round(confidence,2),'status_code':status,'signals':scores,'block_keyword':block_word}
 def active_probe(self,url,sender,method='GET'):
  detections=[]
  for name,payload in PROBES:
   params=payload if isinstance(payload,dict) else {'hunter_probe':payload}; response=sender(method,url,params=params,headers={'X-Hunter-Probe':name}); item=self.detect_response(response); item['probe']=name; detections.append(item)
  blocked=[x for x in detections if x['blocked']]; types=[x['waf_type'] for x in blocked if x['waf_type']]
  return {'waf_type':max(set(types),key=types.count) if types else None,'blocked_probes':len(blocked),'probes':detections}
 def strategies_for(self,waf_type):
  rows=[]
  for base,(sid,description) in enumerate(STRATEGIES.get(waf_type,STRATEGIES['default'])):
   stat=self.history.get(waf_type,{}).get(sid,{}); attempts=stat.get('attempts',0); successes=stat.get('successes',0); rate=(successes+1)/(attempts+2)
   rows.append({'id':sid,'description':description,'success_rate':round(rate,3),'attempts':attempts,'base_order':base})
  return sorted(rows,key=lambda x:(-x['success_rate'],x['base_order']))
 def record_outcome(self,waf_type,strategy_id,success):
  row=self.history.setdefault(waf_type,{}).setdefault(strategy_id,{'attempts':0,'successes':0}); row['attempts']+=1; row['successes']+=int(bool(success)); self._save(); return row
 def attempt_bypass(self,waf_type,attempt,max_attempts=3):
  results=[]
  for strategy in self.strategies_for(waf_type)[:max_attempts]:
   outcome=attempt(strategy); success=bool(outcome.get('success')); self.record_outcome(waf_type,strategy['id'],success); results.append({'strategy':strategy,'outcome':outcome})
   if success: break
  return {'success':bool(results and results[-1]['outcome'].get('success')),'attempts':results}
