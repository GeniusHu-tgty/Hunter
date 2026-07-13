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
STRATEGIES = {
    'Cloudflare': [
        ('http2-multiplex', '复用 HTTP/2 连接，比较边缘节点的流级规范化差异'),
        ('chunked-body', '使用符合规范的分块传输请求体'),
        ('websocket-upgrade', '仅在应用存在合法端点时切换 WebSocket 升级'),
    ],
    'Akamai': [
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('double-percent-encoding', '二次编码百分号，测试边缘节点的多层解码差异'),
        ('protocol-version-switch', '在 HTTP/1.1 与 HTTP/2 间切换请求版本'),
    ],
    'AWS CloudFront': [
        ('parameter-order', '调整参数排列顺序，测试缓存键规范化差异'),
        ('protocol-version-switch', '使用合规格式切换 HTTP/1.1 与 HTTP/2'),
        ('benign-field-padding', '在请求体末尾追加无害字段，测试字段边界解析'),
    ],
    'Fastly': [
        ('parameter-order', '改变参数顺序，比较边缘节点与源站的规范化结果'),
        ('protocol-version-switch', '在 HTTP/1.1 与 HTTP/2 间切换请求版本'),
        ('chunked-body', '使用标准分块传输，测试请求体重组差异'),
    ],
    'Alibaba Cloud CDN': [
        ('parameter-order', '调整参数排列顺序，测试边缘缓存键规范化差异'),
        ('content-type-rotation', '在表单、multipart 与 JSON 类型间轮换'),
        ('benign-field-padding', '在请求体末尾追加无害字段，测试字段边界解析'),
    ],
    'Tencent Cloud CDN': [
        ('chunked-body', '使用标准分块传输，测试 CDN 请求体重组差异'),
        ('content-type-rotation', '轮换表单、multipart 与 JSON 请求体类型'),
        ('benign-field-padding', '在请求体末尾追加无害字段，测试长度边界解析'),
    ],
    'Alibaba Cloud WAF': [
        ('percent-encoding', '按参数上下文进行百分号编码'),
        ('parameter-pollution', '插入同名异值参数，测试重复参数规范化'),
        ('content-type-json', '将受支持的表单请求切换为 JSON 请求体'),
    ],
    'Tencent Cloud WAF': [
        ('parameter-pollution', '插入同名异值参数，测试首值与末值选择差异'),
        ('chunked-body', '使用标准分块传输，测试请求体重组差异'),
        ('content-type-rotation', '轮换表单、multipart 与 JSON 请求体类型'),
    ],
    'Huawei Cloud WAF': [
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('parameter-order', '改变参数排列顺序，测试规范化差异'),
        ('content-type-rotation', '在受支持的请求体类型之间轮换'),
    ],
    'AWS WAF': [
        ('percent-encoding', '对特殊字符进行合规百分号编码'),
        ('versioned-comment-separation', '在 SQL 关键字中插入数据库版本注释'),
        ('content-type-rotation', '在受支持的表单、multipart 与 JSON 类型间轮换'),
    ],
    'Azure WAF': [
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('protocol-version-switch', '使用合规格式切换 HTTP/1.1 与 HTTP/2'),
        ('utf16-body', '使用声明了字符集的 UTF-16 请求体测试解码差异'),
    ],
    'ModSecurity': [
        ('case-variation', '随机切换关键字大小写，测试规范化规则'),
        ('comment-separation', '在关键字内部插入注释分隔符，测试标记化差异'),
        ('line-folding', '在请求体中替换空白与换行，测试规范化差异'),
    ],
    'NAXSI': [
        ('case-variation', '随机切换参数值中的关键字大小写'),
        ('versioned-comment-separation', '在 SQL 关键字中插入数据库版本注释'),
        ('unicode-equivalent', '使用 Unicode 等价字符替换 ASCII 字符'),
    ],
    'SafeDog': [
        ('keyword-double-write', '双写关键字，测试单次替换后的重组行为'),
        ('equivalent-function', '使用等价函数表达式测试规则归一化'),
        ('case-variation', '随机切换关键字大小写，测试规范化规则'),
    ],
    'YunSuo': [
        ('case-variation', '随机切换关键字大小写，测试大小写归一化'),
        ('keyword-double-write', '双写关键字，测试单次过滤后的重组行为'),
        ('double-percent-encoding', '二次编码百分号，测试多层 URL 解码差异'),
    ],
    'DShield': [
        ('parameter-pollution', '插入同名异值参数，测试重复参数取值差异'),
        ('query-to-body', '将查询字符串参数迁移到请求体中'),
        ('html-numeric-entities', '将特殊字符改写为 HTML 数字实体'),
    ],
    '360 WAF': [
        ('case-variation', '随机切换关键字大小写，测试规范化规则'),
        ('keyword-double-write', '双写关键字，测试单次过滤后的重组行为'),
        ('unicode-equivalent', '使用 Unicode 等价字符替换 ASCII 字符'),
    ],
    'Chaitin SafeLine': [
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('parameter-order', '调整参数排列顺序，测试解析顺序差异'),
        ('content-type-rotation', '在受支持的请求体类型之间轮换'),
    ],
    'Sucuri': [
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('protocol-version-switch', '在 HTTP/1.1 与 HTTP/2 间切换请求版本'),
        ('benign-field-padding', '在请求体末尾追加无害字段，测试字段边界解析'),
    ],
    'default': [
        ('header-consistency', '使用一致且完整的浏览器请求头指纹'),
        ('content-type-alternate', '切换到应用明确支持的其他请求体类型'),
        ('parameter-order', '改变无害参数的排列顺序'),
        ('percent-encoding', '对参数值中的保留字符进行百分号编码'),
        ('double-percent-encoding', '对已编码的百分号进行二次编码'),
        ('protocol-version-switch', '在 HTTP/1.1 与 HTTP/2 间切换请求版本'),
        ('chunked-body', '使用符合规范的分块传输请求体'),
        ('parameter-pollution', '插入同名异值参数测试重复参数解析'),
        ('query-to-body', '将查询字符串参数迁移到请求体中'),
        ('benign-field-padding', '在请求体末尾追加无害字段'),
    ],
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
