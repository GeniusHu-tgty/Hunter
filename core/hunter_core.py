#!/usr/bin/env python3
"""
Hunter Core Scanner - Automated Pentest Toolkit
Usage: python hunter_core.py <command> <target>
"""

import subprocess
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

class HunterCore:
    def __init__(self):
        self.output_dir = Path(r"C:\Tools\output")
        self.wordlist_dir = Path(r"C:\Tools\wordlists")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def run_cmd(self, cmd, timeout=300):
        """Execute a command and return output"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR] {e}"
    
    def recon(self, target):
        """Full reconnaissance pipeline"""
        print(f"[*] Starting recon on {target}")
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.output_dir / f"{domain}_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Subdomain enumeration
        print("[1/7] Subdomain enumeration...")
        subs = self.run_cmd(f"subfinder -d {domain} -silent")
        (report_dir / "subdomains.txt").write_text(subs)
        
        # 2. DNS resolution
        print("[2/7] DNS resolution...")
        resolved = self.run_cmd(f'echo "{subs}" | dnsx -silent')
        (report_dir / "resolved.txt").write_text(resolved)
        
        # 3. HTTP probing
        print("[3/7] HTTP probing...")
        live = self.run_cmd(f'echo "{resolved}" | httpx -silent -status-code -title -tech-detect')
        (report_dir / "live_hosts.txt").write_text(live)
        
        # 4. Port scanning
        print("[4/7] Port scanning...")
        hosts = [line.split()[0] for line in resolved.strip().split('\n') if line.strip()]
        for host in hosts[:10]:  # Limit to first 10 hosts
            ports = self.run_cmd(f"naabu -host {host} -top-ports 100 -silent", timeout=120)
            (report_dir / f"ports_{host}.txt").write_text(ports)
        
        # 5. URL discovery
        print("[5/7] URL discovery...")
        urls_gau = self.run_cmd(f'echo "{domain}" | gau')
        urls_katana = self.run_cmd(f"katana -u https://{domain} -d 2 -jc -silent", timeout=120)
        all_urls = set(urls_gau.strip().split('\n') + urls_katana.strip().split('\n'))
        (report_dir / "urls.txt").write_text('\n'.join(sorted(all_urls)))
        
        # 6. Technology detection
        print("[6/7] Technology detection...")
        tech = self.run_cmd(f"whatweb https://{domain} -v")
        (report_dir / "technologies.txt").write_text(tech)
        
        # 7. Directory brute force
        print("[7/7] Directory enumeration...")
        dirs = self.run_cmd(
            f"gobuster dir -u https://{domain} -w {self.wordlist_dir / 'common.txt'} -t 50 -q",
            timeout=120
        )
        (report_dir / "directories.txt").write_text(dirs)
        
        print(f"[+] Recon complete. Results in: {report_dir}")
        return report_dir
    
    def vuln_scan(self, target):
        """Vulnerability scanning pipeline"""
        print(f"[*] Starting vuln scan on {target}")
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.output_dir / f"{domain}_vuln_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Nuclei CVE scan
        print("[1/4] Nuclei CVE scan...")
        cve = self.run_cmd(f"nuclei -u {target} -tags cve -severity critical,high -timeout 10", timeout=300)
        (report_dir / "nuclei_cve.txt").write_text(cve)
        
        # 2. Nuclei exposure scan
        print("[2/4] Nuclei exposure scan...")
        exposure = self.run_cmd(f"nuclei -u {target} -tags exposure -severity high,medium -timeout 10", timeout=300)
        (report_dir / "nuclei_exposure.txt").write_text(exposure)
        
        # 3. Nuclei misconfig scan
        print("[3/4] Nuclei misconfig scan...")
        misconfig = self.run_cmd(f"nuclei -u {target} -tags misconfig -severity high,medium -timeout 10", timeout=300)
        (report_dir / "nuclei_misconfig.txt").write_text(misconfig)
        
        # 4. Directory enumeration with larger wordlist
        print("[4/4] Deep directory enumeration...")
        dirs = self.run_cmd(
            f"gobuster dir -u {target} -w {self.wordlist_dir / 'raft-small-directories.txt'} -t 50 -q",
            timeout=300
        )
        (report_dir / "directories.txt").write_text(dirs)
        
        print(f"[+] Vuln scan complete. Results in: {report_dir}")
        return report_dir
    
    def web_scan(self, target):
        """Web application testing pipeline"""
        print(f"[*] Starting web scan on {target}")
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.output_dir / f"{domain}_web_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Technology detection
        print("[1/5] Technology detection...")
        tech = self.run_cmd(f"httpx -u {target} -tech-detect -status-code -title")
        (report_dir / "tech.txt").write_text(tech)
        
        # 2. JS analysis
        print("[2/5] JavaScript analysis...")
        js_files = self.run_cmd(f"katana -u {target} -d 2 -jc -silent | grep '\\.js$'")
        (report_dir / "js_files.txt").write_text(js_files)
        
        # 3. Parameter discovery
        print("[3/5] Parameter discovery...")
        urls = self.run_cmd(f"katana -u {target} -d 2 -jc -silent")
        (report_dir / "urls.txt").write_text(urls)
        
        # 4. XSS testing
        print("[4/5] XSS testing...")
        xss = self.run_cmd(f'echo "{urls}" | dalfox pipe -silent', timeout=120)
        (report_dir / "xss.txt").write_text(xss)
        
        # 5. SQL injection testing
        print("[5/5] SQL injection testing...")
        sql_urls = [u for u in urls.strip().split('\n') if '?' in u][:20]
        for url in sql_urls:
            sqlmap_out = self.run_cmd(f'sqlmap -u "{url}" --batch --level=1 --risk=1', timeout=60)
            if "vulnerable" in sqlmap_out.lower() or "injectable" in sqlmap_out.lower():
                (report_dir / f"sqlmap_{hash(url)}.txt").write_text(sqlmap_out)
        
        print(f"[+] Web scan complete. Results in: {report_dir}")
        return report_dir


def main():
    if len(sys.argv) < 3:
        print("Usage: python hunter_core.py <command> <target>")
        print("Commands: recon, vuln, web")
        sys.exit(1)
    
    command = sys.argv[1]
    target = sys.argv[2]
    
    hunter = HunterCore()
    
    if command == "recon":
        hunter.recon(target)
    elif command == "vuln":
        hunter.vuln_scan(target)
    elif command == "web":
        hunter.web_scan(target)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
