# Hunter Security Checklist

## Pre-Engagement

### 1. Authorization
- [ ] Written authorization obtained
- [ ] Scope defined
- [ ] Rules of engagement agreed
- [ ] Emergency contacts identified

### 2. Environment Setup
- [ ] VPN/proxy configured
- [ ] Burp Suite running
- [ ] Hunter MCP server running
- [ ] Playwright browser ready

## During Engagement

### 3. Reconnaissance
- [ ] Subdomain enumeration
- [ ] Port scanning
- [ ] Technology detection
- [ ] Directory enumeration
- [ ] JS file analysis

### 4. Vulnerability Detection
- [ ] SQL injection testing
- [ ] XSS testing
- [ ] SSTI testing
- [ ] SSRF testing
- [ ] XXE testing
- [ ] Command injection testing
- [ ] IDOR testing

### 5. Exploitation
- [ ] PoC developed
- [ ] Impact demonstrated
- [ ] Evidence captured
- [ ] Findings documented

### 6. Post-Exploitation
- [ ] Lateral movement assessed
- [ ] Data exposure documented
- [ ] Persistence mechanisms identified
- [ ] Cleanup performed

## Post-Engagement

### 7. Reporting
- [ ] Executive summary written
- [ ] Technical findings detailed
- [ ] Remediation recommendations provided
- [ ] Evidence attached

### 8. Cleanup
- [ ] Test accounts removed
- [ ] Test data cleaned
- [ ] Backdoors removed
- [ ] Access revoked

## Hunter-Specific Checks

### 9. Tool Verification
- [ ] Hunter MCP server responding
- [ ] Burp MCP bridge working
- [ ] Auto tools functioning
- [ ] Unified scanner operational

### 10. Payload Validation
- [ ] Payloads tested on safe targets
- [ ] No destructive payloads used
- [ ] Evidence captured safely
- [ ] Findings reproducible
