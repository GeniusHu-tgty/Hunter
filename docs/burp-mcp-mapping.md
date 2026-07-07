# Hunter Burp MCP Tool Mapping

## Hunter Actions → Burp MCP Tools

| Hunter Action | Burp MCP Tool | Purpose |
|---------------|---------------|---------|
| send | send_http2_request | Send HTTP/2 request |
| send_http1 | send_http1_request | Send HTTP/1.1 request |
| repeater | create_repeater_tab_http2 | Send to Repeater |
| intruder | send_to_intruder | Send to Intruder |
| collaborator_generate | generate_collaborator_payload | OOB payload |
| collaborator_check | get_collaborator_interactions | OOB callbacks |
| scanner_issues | get_scanner_issues | Scanner findings |
| proxy_history | get_proxy_http_history | Proxy history |
| proxy_search | get_proxy_http_history_regex | Search history |
| websocket_history | get_proxy_websocket_history | WebSocket history |
| set_intercept | set_proxy_intercept_state | Toggle intercept |
| set_scanner | set_task_execution_engine_state | Toggle scanner |
| get_config | output_project_options | Project config |
| set_config | set_project_options | Update config |

## Hunter Auto Tools → Burp MCP Integration

| Hunter Tool | Burp Integration |
|-------------|------------------|
| auto_sqli | Send payloads via Burp, check Scanner results |
| auto_xss | Send payloads via Burp, verify in browser |
| auto_ssti | Send payloads via Burp, verify in browser |
| auto_ssrf | Send payloads via Burp, check Collaborator |
| auto_xxe | Send XML payloads via Burp |
| auto_cmd | Send payloads via Burp, check Collaborator |
| auto_idor | Send requests via Burp, compare responses |

## Workflow Integration

### 1. Recon Phase
```
Hunter unified_scan(recon) → Burp proxy_history
```

### 2. Detection Phase
```
Hunter auto_* tools → Burp send_http2_request
```

### 3. Exploitation Phase
```
Hunter exploit → Burp Collaborator (OOB)
```

### 4. Verification Phase
```
Hunter verify → Burp Scanner issues
```
