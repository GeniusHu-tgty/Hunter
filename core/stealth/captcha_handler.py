"""Captcha classification, OCR adapters, statistics, and operator handoff."""
from __future__ import annotations
import io,json,re
from pathlib import Path

class CaptchaHandler:
 def __init__(self,ocr_engines=None,artifact_dir=None): self.ocr_engines=ocr_engines or {}; self.artifact_dir=Path(artifact_dir or 'evidence/captcha').resolve(); self._stats={}
 def detect(self,response):
  text=str(getattr(response,'text','')).lower(); headers={str(k).lower():str(v).lower() for k,v in getattr(response,'headers',{}).items()}
  if any(x in text for x in ('recaptcha','h-captcha','cf-turnstile','turnstile')): typ='behavior'; automatic=False
  elif any(x in text for x in ('slider','slide captcha','unlock captcha','滑块')): typ='slider'; automatic=False
  elif any(x in text for x in ('click captcha','select captcha','点选验证码')): typ='click'; automatic=False
  elif any(x in text for x in ('sms_code','短信验证码','phone code')): typ='sms'; automatic=False
  elif re.search(r'(captcha|verify)[^\n]{0,100}\.(png|jpg|jpeg|gif)|name=["\']captcha',text): typ='image'; automatic=True
  elif re.search(r'name=["\'](?:csrf|_token|authenticity_token)',text): typ='csrf'; automatic=True
  else: typ=None; automatic=True
  return {'type':typ,'automatic':automatic,'detected':typ is not None,'content_type':headers.get('content-type','')}
 def _image(self,data):
  try:
   from PIL import Image,ImageFilter,ImageOps
   image=Image.open(io.BytesIO(data)).convert('L'); image=ImageOps.autocontrast(image); image=image.filter(ImageFilter.MedianFilter(3)); return image.point(lambda x:255 if x>145 else 0)
  except Exception: return data
 def _engine(self,name):
  if name in self.ocr_engines: return self.ocr_engines[name]
  if name=='pytesseract':
   import pytesseract; return lambda image:pytesseract.image_to_string(image,config='--psm 7')
  if name=='ddddocr':
   import ddddocr; engine=ddddocr.DdddOcr(show_ad=False); return lambda image:engine.classification(image if isinstance(image,bytes) else self._to_png(image))
  raise RuntimeError(f'OCR engine unavailable: {name}')
 def _to_png(self,image):
  out=io.BytesIO(); image.save(out,format='PNG'); return out.getvalue()
 def solve_image(self,data,target,engine='pytesseract'):
  stat=self._stats.setdefault(target,{'attempts':0,'successes':0}); stat['attempts']+=1
  try: text=re.sub(r'\s+','',self._engine(engine)(self._image(data)) or ''); solved=bool(text)
  except Exception as exc: text=''; solved=False; error=str(exc)
  stat['successes']+=int(solved); result={'solved':solved,'text':text,'engine':engine,'attempt':stat['attempts']}
  if not solved: result['error']=locals().get('error','empty OCR result')
  return result
 def solve_image_with_refresh(self,fetch_image,target,engine='pytesseract',max_attempts=3):
  attempts=[]
  for _ in range(min(3,max(1,max_attempts))):
   result=self.solve_image(fetch_image(),target,engine); attempts.append(result)
   if result['solved']: return {'solved':True,'text':result['text'],'attempts':attempts}
  return {'solved':False,'text':'','attempts':attempts}
 def stats(self,target):
  stat=dict(self._stats.get(target,{'attempts':0,'successes':0})); stat['success_rate']=stat['successes']/stat['attempts'] if stat['attempts'] else 0.0; return stat
 def handle(self,response,target,engine='pytesseract'):
  detected=self.detect(response); typ=detected['type']
  if typ=='image': return self.solve_image(getattr(response,'content',b''),target,engine)
  if typ in {'slider','click','behavior','sms'}:
   self.artifact_dir.mkdir(parents=True,exist_ok=True); suffix='.png' if str(getattr(response,'headers',{}).get('Content-Type','')).startswith('image/') else '.html'; path=self.artifact_dir/f'{re.sub(r"[^a-zA-Z0-9_.-]","_",target)}-{typ}{suffix}'; body=getattr(response,'content',b'') or str(getattr(response,'text','')).encode(); path.write_bytes(body); return {'status':'operator-required','type':typ,'artifact':str(path),'message':'Complete the challenge in the authorized interactive browser, then resume the session.'}
  return {'status':'not-required' if typ is None else 'automatic','type':typ}
 def test_bypass(self,target,submitter,params,session_ids=None):
  sessions=session_ids or ['default']; original=dict(params); no_param={k:v for k,v in params.items() if 'captcha' not in k.lower() and 'verify' not in k.lower()}; fixed=submitter(sessions[0],original); repeat=submitter(sessions[0],original); optional=submitter(sessions[0],no_param); cross=submitter(sessions[-1],original)
  return {'target':target,'reusable':bool(fixed.get('accepted') and repeat.get('accepted')),'parameter_optional':bool(optional.get('accepted')),'cross_session_reuse':bool(fixed.get('accepted') and cross.get('accepted')),'client_side_candidate':bool(optional.get('accepted'))}
