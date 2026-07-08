# Hunter v8.3 Optimization Plan (Based on 72 Labs)

## Critical Optimizations Needed

### 1. auto_sqli.py - XML Encoding Bypass (HIGH PRIORITY)
**Lab #56**: WAF blocks raw SQL keywords but XML parser decodes numeric char references
**Fix**: Add XML encoding mode to auto_sqli

### 2. auto_sqli.py - Oracle DB Support (HIGH PRIORITY)
**Labs #58, #69**: Oracle requires FROM dual, TO_CHAR(1/0) for errors, DBMS_PIPE.RECEIVE_MESSAGE for time delays
**Fix**: Add Oracle-specific payloads and functions

### 3. auto_xss.py - HTML Entity Encoding Bypass (MEDIUM PRIORITY)
**Lab #44**: Server escapes ' but not &apos; - browser decodes HTML entities
**Fix**: Add HTML entity encoding bypass payloads

### 4. auto_xss.py - jQuery Sink Detection (MEDIUM PRIORITY)
**Labs #15, #59, #65**: jQuery .attr(), .html(), document.write() sinks
**Fix**: Add jQuery-specific sink detection

### 5. auto_xxe.py - XInclude Support (HIGH PRIORITY)
**Lab #71**: Can't control full XML document, need XInclude in data values
**Fix**: Add XInclude payload generation

### 6. auto_graphql.py - GET Method Support (MEDIUM PRIORITY)
**Lab #60**: Some GraphQL endpoints only accept GET
**Fix**: Add GET method probing in discover_endpoint

### 7. auto_access_control.py (NEW - HIGH PRIORITY)
**Labs #25, #39, #70, #72**: Referer-based, multi-step, role parameter bypass
**Features**: Referer forgery, multi-step bypass, role parameter testing

### 8. auto_business_logic.py (NEW - MEDIUM PRIORITY)
**Labs #38, #50**: Price manipulation, type juggling, integer overflow
**Features**: Price tampering, quantity overflow, coupon reuse

### 9. auto_cache_poison.py (NEW - LOW PRIORITY)
**Lab #45**: Unkeyed headers (X-Forwarded-Host, X-Original-URL)
**Features**: Unkeyed header detection, cache key analysis
