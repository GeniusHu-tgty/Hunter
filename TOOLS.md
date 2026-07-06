# Hunter Pentest Framework - Tools Inventory
# Generated: 2026-06-05 23:50:33

## Go-based Tools (23 tools)

### Reconnaissance
- nuclei - Vulnerability scanner (v3.8.0)
- subfinder - Subdomain discovery
- amass - Attack surface mapping
- assetfinder - Asset discovery
- uncover - Host discovery

### Scanning
- naabu - Port scanner
- httpx - HTTP toolkit
- tlsx - TLS toolkit
- cdncheck - CDN detection
- mapcidr - CIDR toolkit

### Web Testing
- ffuf - Web fuzzer
- gobuster - Directory brute-forcer
- katana - Web crawler
- gau - URL fetcher
- waybackurls - Wayback URL fetcher
- dalfox - XSS scanner

### DNS
- dnsx - DNS toolkit

### Utilities
- httprobe - HTTP prober
- unfurl - URL parser
- meg - Request sender
- anew - Line appender
- qsreplace - Query string replacer
- notify - Notification tool

## Python Tools (6 tools)

- sqlmap - SQL injection tool
- wafw00f - WAF detection
- dirsearch - Directory scanner
- whatweb - Web technology identifier
- wpscan - WordPress scanner
- impacket - Network protocols library

## System Tools (3 tools)

- nmap - Network scanner
- nikto - Web server scanner
- curl - HTTP client

## Wordlists (16 files)

Location: C:\Tools\wordlists

- common.txt - Common web paths (367 bytes)
- big.txt - Large web paths (162.5 KB)
- raft-small-directories.txt (159.4 KB)
- raft-small-files.txt (144.9 KB)
- raft-medium-directories.txt (244.6 KB)
- raft-medium-files.txt (219.1 KB)
- raft-large-directories.txt (529.3 KB)
- raft-large-files.txt (482 KB)
- quickhits.txt - Quick hits (39.2 KB)
- logins.txt - Login paths (1.1 KB)
- wordpress.txt - WordPress paths (57.6 KB)
- api-endpoints.txt - API endpoints (4.3 KB)
- subdomains-top1million-5000.txt (29.4 KB)
- subdomains-top1million-110000.txt (1.3 MB)
- dns-Jhaddix.txt (25.3 MB)
- usernames.txt - Common usernames (112 bytes)

## Quick Scan Scripts

Location: C:\Users\Administrator\.agents\skills\hunter\core\scripts

1. quick_recon.ps1 - Full reconnaissance
2. quick_vuln.ps1 - Vulnerability scanning
3. quick_web.ps1 - Web application testing

## Configuration Script

Location: C:\Users\Administrator\.agents\skills\hunter\core\tools_config.ps1

## Usage Examples

### Quick Recon
`powershell
.\quick_recon.ps1 -Target example.com
`

### Quick Vuln Scan
`powershell
.\quick_vuln.ps1 -Target https://example.com
`

### Quick Web Scan
`powershell
.\quick_web.ps1 -Target https://example.com
`

### Nuclei Full Scan
`powershell
nuclei -u https://example.com -severity critical,high,medium
`

### Subdomain Enumeration
`powershell
subfinder -d example.com -o subdomains.txt
`

### Port Scanning
`powershell
naabu -host example.com -top-ports 1000
`

### Directory Brute Force
`powershell
gobuster dir -u https://example.com -w C:\Tools\wordlists\common.txt
`

### XSS Scanning
`powershell
cat urls.txt | dalfox pipe
`

### SQL Injection
`powershell
sqlmap -u "https://example.com/?id=1" --batch --level=3 --risk=2
`

## Environment Variables

- GOPROXY: https://goproxy.cn,direct
- all_proxy: http://127.0.0.1:7890

## Notes

1. All Go tools are installed to C:\Users\Administrator\go\bin
2. Python tools are installed to C:\Program Files\Python314\Scripts
3. Nmap is located at C:\Program Files (x86)\Nmap
4. Nikto is located at C:\Tools\nikto\program
5. Wordlists are stored in C:\Tools\wordlists
6. Output files are saved to C:\Tools\output

## Tool Count Summary

- Go tools: 23
- Python tools: 6
- System tools: 3
- Wordlists: 16
- Total tools: 32


## Impacket CLI Tools (6 tools)

- secretsdump - Extract credentials
- psexec - Remote execution
- smbclient - SMB client
- ntlmrelayx - NTLM relay attack
- wmiexec - WMI remote execution
- dcomexec - DCOM remote execution

## Status: READY

All tools are installed and verified. The Hunter framework is ready for penetration testing.

