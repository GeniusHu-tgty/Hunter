#!/usr/bin/env python3
"""
Hunter MCP Server - Tool Integration Layer
Provides structured access to all Hunter pentest tools
"""

import subprocess
import json
import os
import shlex
import sys
import socket
import threading
import time
import uuid
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FutureTimeoutError,
    wait,
)
from pathlib import Path
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .process_runner import ExternalProcessRunner

try:
    import dns.exception as dns_exception
    import dns.resolver as dns_resolver
except ImportError:
    dns_exception = None
    dns_resolver = None


CRT_SH_TIMEOUT_SECONDS = 10
DNS_QUERY_TIMEOUT_SECONDS = 3
SUBDOMAIN_ENUM_TIMEOUT_SECONDS = 120
DNS_BRUTE_WORKERS = 32
DNS_BRUTE_MAX_PREFIXES = 256
CRT_SH_MAX_RESPONSE_BYTES = 5 * 1024 * 1024

class HunterMCPServer:
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.tools_dir = Path(r"C:\Users\Administrator\go\bin")
        self.wordlist_dir = self.base_dir / "wordlists"
        self.output_dir = self.base_dir / "evidence" / "tool_output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.process_runner = ExternalProcessRunner()
        
        # Set environment
        os.environ["GOPROXY"] = "https://goproxy.cn,direct"
        
    def run_tool(self, tool_name, args, timeout=300):
        """Execute a tool and return structured output"""
        direct_path = Path(str(tool_name))
        tool_path = direct_path if direct_path.exists() else self.tools_dir / f"{tool_name}.exe"
        if not tool_path.exists():
            tool_path = str(tool_name)
        if isinstance(args, str):
            arguments = shlex.split(args, posix=True)
        else:
            arguments = [str(value) for value in args]
        try:
            return self.process_runner.run(
                [str(tool_path), *arguments],
                timeout=timeout,
                env=os.environ,
            )
        except Exception as e:
            return {"status": "error", "stdout": "", "stderr": str(e), "returncode": -1}
    
    def nuclei_scan(self, target, tags=None, severity=None, timeout=240):
        """Run nuclei vulnerability scanner"""
        args = ["-u", str(target), "-timeout", "10"]
        if tags:
            args.extend(["-tags", str(tags)])
        if severity:
            args.extend(["-severity", str(severity)])
        return self.run_tool("nuclei", args, timeout=timeout)

    @staticmethod
    def _valid_subdomain(name, domain):
        candidate = str(name or "").strip().lower().rstrip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if not candidate or candidate == domain:
            return ""
        if not candidate.endswith(f".{domain}"):
            return ""
        labels = candidate.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (char.isalnum() or char == "-") for char in label)
            for label in labels
        ):
            return ""
        return candidate

    def _crtsh_enum(self, domain, timeout=CRT_SH_TIMEOUT_SECONDS):
        """Query crt.sh certificate transparency logs with a strict timeout."""
        started = time.monotonic()

        def fetch():
            query = quote(f"%.{domain}", safe="")
            request = Request(
                f"https://crt.sh/?q={query}&output=json",
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Hunter/8.2 subdomain-enumerator",
                },
            )
            with urlopen(request, timeout=timeout) as response:
                body = response.read(CRT_SH_MAX_RESPONSE_BYTES + 1)
            if len(body) > CRT_SH_MAX_RESPONSE_BYTES:
                raise ValueError("crt.sh response exceeded 5 MiB")
            records = json.loads(body.decode("utf-8"))
            if not isinstance(records, list):
                raise ValueError("crt.sh returned a non-list JSON response")

            subdomains = set()
            for record in records:
                if not isinstance(record, dict):
                    continue
                for field in ("name_value", "common_name"):
                    for raw_name in str(record.get(field, "")).splitlines():
                        name = self._valid_subdomain(raw_name, domain)
                        if name:
                            subdomains.add(name)
            return sorted(subdomains)

        executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="hunter-crtsh",
        )
        future = executor.submit(fetch)
        try:
            subdomains = future.result(timeout=max(0.001, float(timeout)))
            return {
                "status": "success" if subdomains else "empty",
                "subdomains": subdomains,
                "error": "" if subdomains else "crt.sh returned no usable subdomains",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except (FutureTimeoutError, socket.timeout) as exc:
            future.cancel()
            return {
                "status": "timeout",
                "subdomains": [],
                "error": f"crt.sh timed out after {timeout:g}s: {exc}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except HTTPError as exc:
            return {
                "status": "error",
                "subdomains": [],
                "error": f"crt.sh HTTP error {exc.code}: {exc.reason}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except URLError as exc:
            reason = getattr(exc, "reason", exc)
            status = (
                "timeout"
                if isinstance(reason, (TimeoutError, socket.timeout))
                else "error"
            )
            return {
                "status": status,
                "subdomains": [],
                "error": f"crt.sh request failed: {reason}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return {
                "status": "error",
                "subdomains": [],
                "error": f"crt.sh response could not be parsed: {exc}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except Exception as exc:
            return {
                "status": "error",
                "subdomains": [],
                "error": f"crt.sh request failed: {exc}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _resolve_dns_name(self, host, timeout=DNS_QUERY_TIMEOUT_SECONDS):
        """Resolve one candidate through the system DNS configuration."""
        if dns_resolver is None:
            return [], "dnspython is required for bounded DNS queries"

        resolver_local = getattr(self, "_dns_resolver_local", None)
        if resolver_local is None:
            resolver_local = threading.local()
            self._dns_resolver_local = resolver_local
        resolver = getattr(resolver_local, "resolver", None)
        if resolver is None:
            resolver = dns_resolver.Resolver(configure=True)
            resolver_local.resolver = resolver
        resolver.timeout = timeout
        resolver.lifetime = timeout
        addresses = set()
        errors = []
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(
                    host,
                    record_type,
                    lifetime=timeout,
                    search=False,
                    raise_on_no_answer=False,
                )
                addresses.update(
                    str(item).strip()
                    for item in answer
                    if str(item).strip()
                )
                if addresses:
                    break
            except dns_resolver.NXDOMAIN:
                break
            except dns_resolver.NoAnswer:
                continue
            except dns_resolver.NoNameservers as exc:
                errors.append(str(exc))
                break
            except dns_exception.Timeout as exc:
                errors.append(f"DNS query timed out after {timeout:g}s: {exc}")
                break
            except Exception as exc:
                errors.append(str(exc))
                break
        return sorted(addresses), "; ".join(errors)

    def _subdomain_words(self):
        wordlist = self.wordlist_dir / "subdomains_edu.txt"
        if not wordlist.exists():
            return wordlist, []
        words = []
        seen = set()
        for raw_line in wordlist.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():
            word = raw_line.split("#", 1)[0].strip().lower().strip(".")
            if (
                not word
                or word in seen
                or any(
                    not (char.isalnum() or char in {"-", "."})
                    for char in word
                )
            ):
                continue
            seen.add(word)
            words.append(word)
            if len(words) >= DNS_BRUTE_MAX_PREFIXES:
                break
        return wordlist, words

    def _dns_brute_enum(
        self,
        domain,
        timeout,
        query_timeout=DNS_QUERY_TIMEOUT_SECONDS,
    ):
        """Resolve common prefixes concurrently within the remaining budget."""
        started = time.monotonic()
        wordlist, words = self._subdomain_words()
        if not words:
            return {
                "status": "error",
                "subdomains": [],
                "error": f"DNS wordlist is missing or empty: {wordlist}",
                "queries": 0,
                "timed_out": False,
                "wordlist": str(wordlist),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }

        deadline = started + max(0.0, float(timeout))
        wildcard_host = f"hunter-{uuid.uuid4().hex[:12]}.{domain}"
        wildcard_addresses, wildcard_error = self._resolve_dns_name(
            wildcard_host,
            query_timeout,
        )
        wildcard_address_set = set(wildcard_addresses)
        workers = max(1, min(DNS_BRUTE_WORKERS, len(words)))
        executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="hunter-dns",
        )
        future_hosts = {
            executor.submit(
                self._resolve_dns_name,
                f"{word}.{domain}",
                query_timeout,
            ): f"{word}.{domain}"
            for word in words
        }
        completed, pending = wait(
            future_hosts,
            timeout=max(0.0, deadline - time.monotonic()),
        )
        for future in pending:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

        subdomains = set()
        errors = []
        wildcard_matches = 0
        for future in completed:
            host = future_hosts[future]
            try:
                addresses, error = future.result()
            except Exception as exc:
                addresses, error = [], str(exc)
            if addresses:
                if (
                    wildcard_address_set
                    and set(addresses) == wildcard_address_set
                ):
                    wildcard_matches += 1
                else:
                    subdomains.add(host)
            elif error:
                errors.append(f"{host}: {error}")

        timed_out = bool(pending) or time.monotonic() >= deadline
        if subdomains:
            status = "success"
            error = ""
        elif timed_out:
            status = "timeout"
            error = (
                f"DNS brute force reached the {timeout:g}s budget "
                "without resolving a subdomain"
            )
        elif errors and len(errors) == len(completed):
            status = "error"
            error = "DNS brute force failed: " + "; ".join(errors[:3])
        elif wildcard_matches:
            status = "error"
            error = (
                "DNS wildcard detected; all resolved candidates matched "
                "the wildcard baseline"
            )
        else:
            status = "error"
            error = "DNS brute force completed but no names resolved"

        return {
            "status": status,
            "subdomains": sorted(subdomains),
            "error": error,
            "queries": len(future_hosts),
            "completed_queries": len(completed),
            "query_errors": errors[:20],
            "timed_out": timed_out,
            "wordlist": str(wordlist),
            "wildcard_detected": bool(wildcard_address_set),
            "wildcard_probe": wildcard_host,
            "wildcard_addresses": sorted(wildcard_address_set),
            "wildcard_error": wildcard_error,
            "wildcard_matches": wildcard_matches,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    def subfinder_enum(self, domain, timeout=SUBDOMAIN_ENUM_TIMEOUT_SECONDS):
        """Enumerate through crt.sh, then bounded local DNS brute force."""
        started = time.monotonic()
        normalized = str(domain or "").strip().lower().rstrip(".")
        if (
            not normalized
            or len(normalized) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(
                    not (char.isalnum() or char == "-")
                    for char in label
                )
                for label in normalized.split(".")
            )
        ):
            message = f"Invalid domain for subdomain enumeration: {domain!r}"
            return {
                "status": "error",
                "stdout": "",
                "stderr": message,
                "error": message,
                "returncode": 1,
                "source": "",
                "attempts": [],
            }

        total_budget = max(0.1, float(timeout))
        crt_timeout = min(CRT_SH_TIMEOUT_SECONDS, total_budget)
        crt_result = self._crtsh_enum(
            normalized,
            timeout=crt_timeout,
        )
        attempts = [
            {
                "source": "crt.sh",
                "status": crt_result.get("status", "error"),
                "count": len(crt_result.get("subdomains", [])),
                "timeout_seconds": crt_timeout,
                "elapsed_seconds": crt_result.get("elapsed_seconds"),
                "error": crt_result.get("error", ""),
            }
        ]
        if crt_result.get("subdomains"):
            subdomains = sorted(set(crt_result["subdomains"]))
            return {
                "status": "success",
                "stdout": "\n".join(subdomains),
                "stderr": "",
                "error": "",
                "returncode": 0,
                "source": "crt.sh",
                "attempts": attempts,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }

        elapsed = time.monotonic() - started
        remaining = max(
            0.0,
            total_budget - elapsed,
        )
        dns_budget = min(
            remaining,
            max(0.0, total_budget - crt_timeout),
        )
        if dns_budget <= 0:
            dns_result = {
                "status": "timeout",
                "subdomains": [],
                "error": "No enumeration budget remained for DNS brute force",
                "queries": 0,
                "timed_out": True,
                "wordlist": str(self.wordlist_dir / "subdomains_edu.txt"),
            }
        else:
            dns_result = self._dns_brute_enum(
                normalized,
                timeout=dns_budget,
                query_timeout=DNS_QUERY_TIMEOUT_SECONDS,
            )
        attempts.append(
            {
                "source": "dns-brute",
                "status": dns_result.get("status", "error"),
                "count": len(dns_result.get("subdomains", [])),
                "timeout_seconds": round(dns_budget, 3),
                "query_timeout_seconds": DNS_QUERY_TIMEOUT_SECONDS,
                "queries": dns_result.get("queries", 0),
                "timed_out": dns_result.get("timed_out", False),
                "elapsed_seconds": dns_result.get("elapsed_seconds"),
                "error": dns_result.get("error", ""),
            }
        )
        if dns_result.get("subdomains"):
            subdomains = sorted(set(dns_result["subdomains"]))
            fallback_reason = crt_result.get(
                "error",
                "crt.sh returned no usable subdomains",
            )
            partial = bool(dns_result.get("timed_out", False))
            warning = (
                "DNS fallback returned partial results after reaching "
                "the enumeration budget"
                if partial
                else ""
            )
            return {
                "status": "success",
                "stdout": "\n".join(subdomains),
                "stderr": f"{fallback_reason}; used local DNS fallback",
                "error": "",
                "returncode": 0,
                "source": "dns-brute",
                "attempts": attempts,
                "wordlist": dns_result.get("wordlist", ""),
                "partial": partial,
                "timed_out": partial,
                "warning": warning,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }

        errors = [
            item
            for item in (
                crt_result.get("error", ""),
                dns_result.get("error", ""),
            )
            if item
        ]
        message = "Subdomain enumeration failed"
        if errors:
            message += ": " + "; ".join(errors)
        return {
            "status": "error",
            "stdout": "",
            "stderr": message,
            "error": message,
            "returncode": 1,
            "source": "",
            "attempts": attempts,
            "wordlist": dns_result.get("wordlist", ""),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    
    def httpx_probe(self, targets, timeout=120):
        """Probe HTTP services"""
        return self.run_tool("httpx", ["-u", targets, "-silent", "-status-code", "-title", "-tech-detect"], timeout=timeout)
    
    def naabu_scan(self, host, ports="top-100", timeout=120):
        """Scan ports"""
        if ports == "top-100":
            port_args = ["-top-ports", "100"]
        elif ports == "top-1000":
            port_args = ["-top-ports", "1000"]
        elif ports == "full":
            port_args = ["-p", "1-65535"]
        else:
            port_args = ["-p", str(ports)]
        return self.run_tool("naabu", ["-host", host, *port_args, "-silent"], timeout=timeout)
    
    def ffuf_fuzz(self, url, wordlist=None, mode="dir", timeout=240):
        """Fuzz web application"""
        if not wordlist:
            wordlist = str(self.wordlist_dir / "common.txt")
        fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
        return self.run_tool("ffuf", ["-u", fuzz_url, "-w", wordlist, "-t", "50", "-mc", "all", "-json"], timeout=timeout)
    
    def dalfox_xss(self, url, timeout=120):
        """Test for XSS vulnerabilities"""
        return self.run_tool("dalfox", ["url", url, "-silent"], timeout=timeout)
    
    def sqlmap_test(self, url, level=1, risk=1, timeout=240):
        """Test for SQL injection"""
        sqlmap_path = r"C:\Program Files\Python314\Scripts\sqlmap.exe"
        if Path(sqlmap_path).exists():
            return self.run_tool(sqlmap_path, ["-u", url, "--batch", f"--level={level}", f"--risk={risk}"], timeout=timeout)
        return self.run_tool("sqlmap", ["-u", url, "--batch", f"--level={level}", f"--risk={risk}"], timeout=timeout)
    
    def gobuster_dir(self, url, wordlist=None, timeout=240):
        """Directory brute force"""
        if not wordlist:
            wordlist = str(self.wordlist_dir / "common.txt")
        return self.run_tool("gobuster", ["dir", "-u", url, "-w", wordlist, "-t", "50", "-q"], timeout=timeout)
    
    def katana_crawl(self, url, depth=2, timeout=150):
        """Crawl web application"""
        return self.run_tool("katana", ["-u", url, "-d", str(depth), "-jc", "-silent"], timeout=timeout)
    
    def gau_urls(self, domain, timeout=60):
        """Fetch URLs from Wayback Machine"""
        return self.run_tool("gau", [domain], timeout=timeout)
    
    def js_analyze(self, url, timeout=60):
        """Analyze JavaScript files"""
        return self.run_tool("getjs", ["-u", url], timeout=timeout)
    
    def waf_detect(self, url, timeout=30):
        """Detect WAF"""
        return self.run_tool("wafw00f", [url], timeout=timeout)
    
    def whatweb_identify(self, url, timeout=30):
        """Identify web technologies"""
        return self.run_tool("whatweb", [url, "-v"], timeout=timeout)
    
    def amass_enum(self, domain, timeout=240):
        """Attack surface mapping"""
        return self.run_tool("amass", ["enum", "-d", domain], timeout=timeout)


# Global instance
hunter = HunterMCPServer()

def get_hunter():
    return hunter
