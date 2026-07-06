# Burp Suite Configuration for Automated Testing

## Disable All Prompts

### 1. Proxy Intercept
```
Burp MCP: set_proxy_intercept_state(intercepting=False)
```

### 2. Out-of-Scope Request Prompts
```
Burp MCP: set_user_options({"user_options": {"misc": {"out_of_scope_history_logging_action": "log"}}})
```
Default is "prompt" which causes confirmation dialogs. Change to "log" to auto-accept.

### 3. Scope - Include Everything
```
Burp MCP: set_project_options({
  "project_options": {
    "target": {
      "scope": {
        "advanced_mode": false,
        "exclude": [],
        "include": [{"enabled": true, "host": "^.*$", "port": "", "protocol": "any"}]
      }
    }
  }
})
```

### 4. Startup Settings
```
"enable_proxy_interception_at_startup": "never"  # Don't enable intercept on startup
```

## Why These Matter

When running automated tools (Hunter agents, Playwright, Python scripts), Burp's confirmation prompts block execution. The prompts are:
1. **Proxy intercept** - "Forward/Drop/Intercept" for each request
2. **Out-of-scope prompt** - "Allow this out-of-scope request?" for new domains
3. **Extension prompts** - Individual extension confirmations

Setting all of these to auto-accept allows uninterrupted automated testing.

## Verification

After applying all settings, send a test request to a new domain:
```
send_http2_request(targetHostname="example.com", ...)
```
Should complete without any Burp UI prompts.
