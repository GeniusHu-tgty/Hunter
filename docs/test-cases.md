# Hunter Test Cases

## Test 1: Unified Scanner
```python
from core.unified_scanner import UnifiedScanner

scanner = UnifiedScanner("https://example.com")
result = scanner.run_full_scan(phases=["recon"])
assert result["phases"]["recon"]["http_status"] == 200
print("Test 1 passed")
```

## Test 2: Auto SQLi
```python
from core.auto_sqli import AutoSQLi

sqli = AutoSQLi("http://test.com/filter?category=Gifts")
result = sqli.test_boolean_blind()
print(f"Test 2: {result}")
```

## Test 3: Auto XSS
```python
from core.auto_xss import AutoXSS

xss = AutoXSS("http://test.com/search?q=")
result = xss.detect_context()
print(f"Test 3: context={result}")
```

## Test 4: Auto SSTI
```python
from core.auto_ssti import AutoSSTI

ssti = AutoSSTI("http://test.com/?message=")
result = ssti.detect_math_expressions()
print(f"Test 4: {result}")
```

## Test 5: Burp Bridge
```python
from core.burp_bridge import BurpBridge

bridge = BurpBridge()
request = bridge.send_request("http://test.com", "GET")
print(f"Test 5: {request}")
```

## Test 6: JWT Tool
```python
from core.jwt_tool import JWTTool

jwt = JWTTool()
token = jwt.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
print(f"Test 6: {token}")
```

## Test 7: Payload Loader
```python
from payloads.loader import PayloadLoader

loader = PayloadLoader()
sqli_payloads = loader.get_payloads("sqli")
print(f"Test 7: {len(sqli_payloads)} SQLi payloads")
```

## Running Tests
```bash
cd /path/to/hunter
python -m pytest tests/ -v
```

## Expected Results
- Test 1: Recon returns HTTP 200
- Test 2: Boolean blind test runs without error
- Test 3: Context detection returns string
- Test 4: Math expression detection runs
- Test 5: Burp bridge creates request
- Test 6: JWT decoded successfully
- Test 7: Payloads loaded
