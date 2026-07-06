#!/usr/bin/env python3
"""
Hunter MCP Server - Tool Integration Layer
Provides structured access to all Hunter pentest tools
"""

import subprocess
import json
import os
import sys
from pathlib import Path
from datetime import datetime

class HunterMCPServer:
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.tools_dir = Path(r"C:\Users\Administrator\go\bin")
        self.wordlist_dir = self.base_dir / "wordlists"
        self.output_dir = self.base_dir / "evidence" / "tool_output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set environment
        os.environ["GOPROXY"] = "https://goproxy.cn,direct"
        
    def run_tool(self, tool_name, args, timeout=300):
        """Execute a tool and return structured output"""
        tool_path = self.tools_dir / f"{tool_name}.exe"
        if not tool_path.exists():
            # Try system PATH
            tool_path = tool_name
            
        cmd = f'"{tool_path}" {args}'
        
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                env=os.environ
            )
            return {
                "status": "success" if result.returncode == 0 else "error",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "stdout": "", "stderr": "Command timed out", "returncode": -1}
        except Exception as e:
            return {"status": "error", "stdout": "", "stderr": str(e), "returncode": -1}
    
    def nuclei_scan(self, target, tags=None, severity=None):
        """Run nuclei vulnerability scanner"""
        args = f"-u {target} -timeout 10"
        if tags:
            args += f" -tags {tags}"
        if severity:
            args += f" -severity {severity}"
        return self.run_tool("nuclei", args, timeout=600)
    
    def subfinder_enum(self, domain):
        """Enumerate subdomains"""
        return self.run_tool("subfinder", f"-d {domain} -silent -timeout 10 -max-time 1", timeout=90)
    
    def httpx_probe(self, targets):
        """Probe HTTP services"""
        return self.run_tool("httpx", f'-u "{targets}" -silent -status-code -title -tech-detect', timeout=120)
    
    def naabu_scan(self, host, ports="top-100"):
        """Scan ports"""
        if ports == "top-100":
            port_args = "-top-ports 100"
        elif ports == "top-1000":
            port_args = "-top-ports 1000"
        elif ports == "full":
            port_args = "-p 1-65535"
        else:
            port_args = f"-p {ports}"
        return self.run_tool("naabu", f'-host "{host}" {port_args} -silent', timeout=120)
    
    def ffuf_fuzz(self, url, wordlist=None, mode="dir"):
        """Fuzz web application"""
        if not wordlist:
            wordlist = str(self.wordlist_dir / "common.txt")
        fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
        return self.run_tool("ffuf", f'-u "{fuzz_url}" -w "{wordlist}" -t 50 -mc all -json', timeout=300)
    
    def dalfox_xss(self, url):
        """Test for XSS vulnerabilities"""
        return self.run_tool("dalfox", f"url {url} -silent", timeout=120)
    
    def sqlmap_test(self, url, level=1, risk=1):
        """Test for SQL injection"""
        sqlmap_path = r"C:\Program Files\Python314\Scripts\sqlmap.exe"
        if Path(sqlmap_path).exists():
            cmd = f'"{sqlmap_path}" -u "{url}" --batch --level={level} --risk={risk}'
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=300, env=os.environ
                )
                return {
                    "status": "success" if result.returncode == 0 else "error",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "stdout": "", "stderr": "Command timed out", "returncode": -1}
            except Exception as e:
                return {"status": "error", "stdout": "", "stderr": str(e), "returncode": -1}
        return self.run_tool("sqlmap", f'-u "{url}" --batch --level={level} --risk={risk}', timeout=300)
    
    def gobuster_dir(self, url, wordlist=None):
        """Directory brute force"""
        if not wordlist:
            wordlist = str(self.wordlist_dir / "common.txt")
        return self.run_tool("gobuster", f"dir -u {url} -w {wordlist} -t 50 -q", timeout=300)
    
    def katana_crawl(self, url, depth=2):
        """Crawl web application"""
        return self.run_tool("katana", f"-u {url} -d {depth} -jc -silent", timeout=180)
    
    def gau_urls(self, domain):
        """Fetch URLs from Wayback Machine"""
        return self.run_tool("gau", f"{domain}", timeout=60)
    
    def js_analyze(self, url):
        """Analyze JavaScript files"""
        return self.run_tool("getjs", f"-u {url}", timeout=60)
    
    def waf_detect(self, url):
        """Detect WAF"""
        return self.run_tool("wafw00f", f"{url}", timeout=30)
    
    def whatweb_identify(self, url):
        """Identify web technologies"""
        return self.run_tool("whatweb", f"{url} -v", timeout=30)
    
    def amass_enum(self, domain):
        """Attack surface mapping"""
        return self.run_tool("amass", f"enum -d {domain}", timeout=600)


# Global instance
hunter = HunterMCPServer()

def get_hunter():
    return hunter
