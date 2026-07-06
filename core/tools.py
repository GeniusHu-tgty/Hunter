"""
Hunter外部工具集成模块
提供对nuclei, subfinder, httpx, naabu, ffuf, nmap, sqlmap等工具的统一接口
"""
import subprocess
import json
import os

GOPATH = os.path.expanduser("~/go")
TOOLS_BIN = os.path.join(GOPATH, "bin")
FFUF_BIN = r"C:\Tools\ffuf"
NMAP_BIN = r"C:\Program Files (x86)\Nmap"

class ToolRunner:
    """统一工具执行接口"""
    
    @staticmethod
    def run(cmd, timeout=300):
        """执行命令并返回结果"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, 
                text=True, timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Timeout", "returncode": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}

class NucleiScanner:
    """CVE漏洞扫描"""
    
    @staticmethod
    def scan(target, severity="critical,high,medium", templates=None):
        cmd = f'"{TOOLS_BIN}\\nuclei.exe" -u "{target}" -severity {severity} -silent -json'
        if templates:
            cmd += f' -t "{templates}"'
        return ToolRunner.run(cmd, timeout=600)
    
    @staticmethod
    def scan_list(targets_file, severity="critical,high"):
        cmd = f'"{TOOLS_BIN}\\nuclei.exe" -l "{targets_file}" -severity {severity} -silent -json'
        return ToolRunner.run(cmd, timeout=1800)

class SubdomainEnumerator:
    """子域名枚举"""
    
    @staticmethod
    def enumerate(domain, silent=True):
        cmd = f'"{TOOLS_BIN}\\subfinder.exe" -d {domain}'
        if silent:
            cmd += ' -silent'
        return ToolRunner.run(cmd, timeout=120)

class PortScanner:
    """端口扫描"""
    
    @staticmethod
    def scan_naabu(host, ports="top-1000"):
        cmd = f'"{TOOLS_BIN}\\naabu.exe" -host {host} -{ports} -silent -json'
        return ToolRunner.run(cmd, timeout=300)
    
    @staticmethod
    def scan_nmap(host, args="-sV -sC -T4"):
        cmd = f'"{NMAP_BIN}\\nmap.exe" {args} {host}'
        return ToolRunner.run(cmd, timeout=600)

class HTTPProber:
    """HTTP探测"""
    
    @staticmethod
    def probe(targets, title=True, tech=True, status=True):
        cmd = f'echo {targets} | "{TOOLS_BIN}\\httpx.exe"'
        if title: cmd += ' -title'
        if tech: cmd += ' -tech-detect'
        if status: cmd += ' -status-code'
        cmd += ' -silent -json'
        return ToolRunner.run(cmd, timeout=120)

class DirectoryFuzzer:
    """目录模糊测试"""
    
    @staticmethod
    def fuzz_ffuf(url, wordlist, mc="200,301,302,403"):
        cmd = f'"{FFUF_BIN}\\ffuf.exe" -u "{url}" -w "{wordlist}" -mc {mc} -silent -json'
        return ToolRunner.run(cmd, timeout=300)

class SQLInjector:
    """SQL注入测试"""
    
    @staticmethod
    def test(url, data=None, cookie=None, level=3, risk=2):
        cmd = f'sqlmap -u "{url}" --batch --level={level} --risk={risk}'
        if data:
            cmd += f' --data="{data}"'
        if cookie:
            cmd += f' --cookie="{cookie}"'
        cmd += ' --output-dir=%TEMP%\\sqlmap_output'
        return ToolRunner.run(cmd, timeout=600)

class WAFDetector:
    """WAF检测"""
    
    @staticmethod
    def detect(url):
        cmd = f'wafw00f "{url}"'
        return ToolRunner.run(cmd, timeout=30)

class URLCollector:
    """URL历史发现"""
    
    @staticmethod
    def collect(domain):
        cmd = f'"{TOOLS_BIN}\\gau.exe" {domain}'
        return ToolRunner.run(cmd, timeout=120)

class WebCrawler:
    """Web爬虫"""
    
    @staticmethod
    def crawl(url, depth=3):
        cmd = f'"{TOOLS_BIN}\\katana.exe" -u "{url}" -d {depth} -silent'
        return ToolRunner.run(cmd, timeout=300)
