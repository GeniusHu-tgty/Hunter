# Hunter Tool Capability Matrix - Deep Optimized (2026-07-06)

## Core Auto-Detection Tools

### auto_sqli (Deep Optimized)
| Feature | Status | Verified |
|---------|--------|----------|
| Column detection (ORDER BY) | ✅ | ✅ |
| DB type detection (5 DBs) | ✅ | ✅ |
| Boolean blind SQLi | ✅ | ✅ |
| Time-based blind SQLi | ✅ | ✅ |
| Error-based SQLi | ✅ | ✅ |
| UNION-based extraction | ✅ | ✅ |
| Cookie injection (TrackingId) | ✅ NEW | ✅ |
| CSRF token auto-extraction | ✅ NEW | ✅ |
| Conditional response detection | ✅ NEW | ✅ |
| OOB detection (Collaborator) | ✅ NEW | ✅ |
| Precise timing (time.time) | ✅ NEW | ✅ |

### auto_xss (Deep Optimized)
| Feature | Status | Verified |
|---------|--------|----------|
| HTML context detection | ✅ | ✅ |
| Attribute context detection | ✅ | ✅ |
| JS string context detection | ✅ | ✅ |
| href context detection | ✅ | ✅ |
| jQuery selector detection | ✅ | ✅ |
| DOM XSS detection | ✅ | ✅ |
| Stored XSS detection | ✅ | ✅ |
| Encoding analysis | ✅ | ✅ |
| CSRF token auto-extraction | ✅ NEW | ✅ |
| Exploit HTML generation | ✅ NEW | ✅ |
| DOM hashchange delivery | ✅ NEW | ✅ |

### auto_ssrf (Deep Optimized)
| Feature | Status | Verified |
|---------|--------|----------|
| Internal IP probing | ✅ | ✅ |
| Cloud metadata (AWS/GCP/Azure) | ✅ | ✅ |
| Internal service discovery | ✅ | ✅ |
| Protocol smuggling | ✅ | ✅ |
| IP format bypass | ✅ | ✅ |
| URL encoding bypass | ✅ NEW | ✅ |
| Short form bypass (127.1) | ✅ NEW | ✅ |
| Double URL encoding (%2561) | ✅ NEW | ✅ |
| Open redirect chain | ✅ NEW | ✅ |
| Internal port scanning | ✅ | ✅ |
| Internal path enumeration | ✅ | ✅ |

### auto_ssti (Deep Optimized)
| Feature | Status | Verified |
|---------|--------|----------|
| Multi-engine detection (7) | ✅ | ✅ |
| WAF bypass variants | ✅ | ✅ |
| Jinja2/Twig disambiguation | ✅ NEW | ✅ |
| RCE payloads (5 engines) | ✅ NEW | ✅ |

### auto_xxe
| Feature | Status | Verified |
|---------|--------|----------|
| Classic XXE file read | ✅ | ✅ |
| Blind XXE OOB | ✅ | ✅ |
| Error-based XXE | ✅ | ✅ |

### auto_cmd
| Feature | Status | Verified |
|---------|--------|----------|
| Command injection detection | ✅ | ✅ |
| Multiple separator types | ✅ | ✅ |

### auto_idor
| Feature | Status | Verified |
|---------|--------|----------|
| Numeric ID testing | ✅ | ✅ |
| UUID enumeration | ✅ | ✅ |

## Burp Integration

### BurpBridge (30+ actions)
| Action | Purpose | Status |
|--------|---------|--------|
| send | HTTP/2 request | ✅ |
| send_http1 | HTTP/1.1 request | ✅ |
| repeater | Send to Repeater | ✅ |
| intruder | Send to Intruder | ✅ |
| collaborator_generate | OOB payload | ✅ |
| collaborator_check | OOB callbacks | ✅ |
| scanner_issues | Scanner findings | ✅ |
| proxy_history | Proxy history | ✅ |
| proxy_search | Search history | ✅ |
| exploit_server | Store+deliver exploit | ✅ |
| set_intercept | Toggle intercept | ✅ |
| set_scanner | Toggle scanner | ✅ |
| plugin_jwt | JWT Editor integration | ✅ |
| plugin_js_mining | JS Miner integration | ✅ |
| turbo_race | Race condition script | ✅ |
| turbo_brute | Brute force script | ✅ |

## Payload Categories (28 total)
sqli, xss, ssti, xxe, cmd, ssrf, access-control, file-upload, auth,
business-logic, nosql, race-condition, info_leak, jwt, lfi, cors,
graphql, oauth, prototype-pollution, smuggling, waf-bypass, ctf,
websocket, dom-xss, cache-poisoning
