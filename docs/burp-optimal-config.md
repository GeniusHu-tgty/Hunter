# Burp Suite Professional - Optimal Configuration for Hunter

## Required Settings for Automated Testing

### 1. Proxy Settings
```
Settings → Proxy → Intercept → Do intercept: OFF (use MCP set_intercept)
Settings → Proxy → HTTP History → Hide: js, gif, jpg, png, ico, css, woff, svg
Settings → Proxy → WebSockets → Intercept: OFF
```

### 2. Scanner Settings
```
Settings → Scanner → Scan speed: Fast
Settings → Scanner → Scan accuracy: Thorough
Settings → Scanner → Resource pool → Concurrent requests: 10
```

### 3. Target Scope
```
Settings → Target → Scope → Advanced mode: OFF
Settings → Target → Scope → Include: ^.*$ (all targets)
Settings → Target → Scope → Exclude: (empty)
```

### 4. Connections
```
Settings → Connections → Timeout → Normal: 120000ms
Settings → Connections → Timeout → Open-ended: 10000ms
Settings → Connections → DNS → Lookup policy: Use system default
```

### 5. HTTP Settings
```
Settings → HTTP → HTTP/2 → Enable HTTP/2: ON
Settings → HTTP → HTTP/1.1 → Enable keep-alive: OFF
Settings → HTTP → Redirections → Understand 3xx: ON
```

### 6. Extensions (Required)
```
1. MCP Server (Burp MCP bridge)
2. JS Miner (automatic JS analysis)
3. JWT Editor (JWT key management)
4. Turbo Intruder (high-speed attacks)
5. JWT4B (JWT auto-decode)
6. Param Miner (hidden parameter discovery)
7. Active Scan++ (enhanced scanning)
8. Hackvertor (encoding/decoding)
9. HTTP Request Smuggler (CL.TE/TE.CL)
```

### 7. REST API (Optional)
```
Settings → Suite → REST API → Enable: ON
Settings → Suite → REST API → Port: 1337
Settings → Suite → REST API → Address: 127.0.0.1
```

## MCP Configuration

### Claude Code MCP Settings
```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": ["-jar", "path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

### Hunter MCP Settings
```json
{
  "mcpServers": {
    "hunter": {
      "command": "python",
      "args": ["path/to/hunter/mcp_server.py"]
    }
  }
}
```

## Performance Tips

### For Large Scans
- Increase concurrent request limit to 20
- Use Turbo Intruder for high-speed attacks
- Enable auto-backoff on 429/503 responses

### For Stealth Scans
- Reduce concurrent requests to 3
- Enable throttle interval (500ms)
- Use proxy rotation if available

### For Lab Testing
- Disable intercept (use MCP)
- Disable out-of-scope prompts
- Enable HTTP/2 for PortSwigger labs
