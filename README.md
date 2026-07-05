# Hunter v7 - AI-Driven Penetration Testing Framework

## Overview

Hunter is an AI-driven penetration testing framework that combines automated tools with intelligent analysis. Claude is the brain, and the tools are the hands.

## Tool Inventory

### Go-based Tools (28 tools)
| Tool | Purpose | Version |
|------|---------|---------|
| nuclei | Vulnerability scanner | v3.8.0 |
| subfinder | Subdomain discovery | Latest |
| naabu | Port scanner | Latest |
| httpx | HTTP toolkit | Latest |
| katana | Web crawler | Latest |
| gau | URL fetcher | Latest |
| uncover | Host discovery | Latest |
| tlsx | TLS toolkit | Latest |
| cdncheck | CDN detection | Latest |
| mapcidr | CIDR toolkit | Latest |
| ffuf | Web fuzzer | v2.1.0 |
| gobuster | Directory brute-forcer | Latest |
| dnsx | DNS toolkit | Latest |
| dalfox | XSS scanner | Latest |
| notify | Notification tool | Latest |
| amass | Attack surface mapping | Latest |
| waybackurls | Wayback URL fetcher | Latest |
| assetfinder | Asset discovery | Latest |
| httprobe | HTTP prober | Latest |
| unfurl | URL parser | Latest |
| meg | Request sender | Latest |
| anew | Line appender | Latest |
| qsreplace | Query string replacer | Latest |
| subjack | Subdomain takeover | Latest |
| hakrevdns | Reverse DNS | Latest |
| hakrawler | Web crawler | Latest |
| getjs | JS file discovery | Latest |
| subjs | JS file discovery | Latest |

### Python Tools (8 tools)
| Tool | Purpose |
|------|---------|
| sqlmap | SQL injection |
| wafw00f | WAF detection |
| dirsearch | Directory scanner |
| whatweb | Web technology identifier |
| wpscan | WordPress scanner |
| droopescan | CMS scanner |
| hashid | Hash identifier |
| arjun | Hidden parameter discovery |

### System Tools (3 tools)
| Tool | Purpose | Version |
|------|---------|---------|
| nmap | Network scanner | 7.80 |
| nikto | Web server scanner | Latest |
| curl | HTTP client | Latest |

### Special Tools (4 tools)
| Tool | Purpose |
|------|---------|
| impacket | Network protocols library |
| jwt_tool | JWT testing |
| perl | Scripting runtime |
| Python 3.14 | Scripting runtime |

## Wordlists

Location: `C:\Tools\wordlists\`

| File | Size | Description |
|------|------|-------------|
| common.txt | 367 B | Common web paths |
| big.txt | 162.5 KB | Large web paths |
| raft-small-directories.txt | 159.4 KB | Small directory list |
| raft-small-files.txt | 144.9 KB | Small file list |
| raft-medium-directories.txt | 244.6 KB | Medium directory list |
| raft-medium-files.txt | 219.1 KB | Medium file list |
| raft-large-directories.txt | 529.3 KB | Large directory list |
| raft-large-files.txt | 482 KB | Large file list |
| quickhits.txt | 39.2 KB | Quick hits |
| logins.txt | 1.1 KB | Login paths |
| wordpress.txt | 57.6 KB | WordPress paths |
| api-endpoints.txt | 4.3 KB | API endpoints |
| subdomains-top1million-5000.txt | 29.4 KB | Top 5K subdomains |
| subdomains-top1million-110000.txt | 1.3 MB | Top 110K subdomains |
| dns-Jhaddix.txt | 25.3 MB | DNS wordlist |
| usernames.txt | 112 B | Common usernames |

## Quick Scan Scripts

### Reconnaissance
```powershell
.\quick_recon.ps1 -Target example.com
```

### Vulnerability Scanning
```powershell
.\quick_vuln.ps1 -Target https://example.com
```

### Web Application Testing
```powershell
.\quick_web.ps1 -Target https://example.com
```

## Core Scanner

```bash
python hunter_core.py recon example.com
python hunter_core.py vuln https://example.com
python hunter_core.py web https://example.com
```

## MCP Server

```python
from mcp_server import get_hunter

hunter = get_hunter()

# Subdomain enumeration
result = hunter.subfinder_enum("example.com")

# Vulnerability scanning
result = hunter.nuclei_scan("https://example.com", severity="critical,high")

# Port scanning
result = hunter.naabu_scan("example.com", "top-1000")

# XSS testing
result = hunter.dalfox_xss("https://example.com/?id=1")

# SQL injection
result = hunter.sqlmap_test("https://example.com/?id=1", level=3, risk=2)
```

## Environment Variables

```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
$env:all_proxy = "http://127.0.0.1:7890"
```

## Directory Structure

```
hunter/
├── SKILL.md                 # Skill definition
├── TOOLS.md                 # Tools inventory
├── README.md                # This file
└── core/
    ├── hunter_core.py       # Core scanner
    ├── mcp_server.py        # MCP integration
    ├── tools_config.ps1     # Tools configuration
    └── scripts/
        ├── quick_recon.ps1  # Quick reconnaissance
        ├── quick_vuln.ps1   # Quick vulnerability scan
        └── quick_web.ps1    # Quick web scan
```

## Usage Examples

### Full Reconnaissance
```bash
# 1. Subdomain enumeration
subfinder -d example.com -o subdomains.txt

# 2. DNS resolution
cat subdomains.txt | dnsx -o resolved.txt

# 3. HTTP probing
cat resolved.txt | httpx -o live.txt

# 4. Port scanning
cat live.txt | naabu -top-ports 1000 -o ports.txt

# 5. URL discovery
gau example.com > urls.txt
katana -u https://example.com -d 3 -jc >> urls.txt

# 6. Vulnerability scanning
nuclei -l live.txt -severity critical,high,medium
```

### Web Application Testing
```bash
# 1. Technology detection
httpx -u https://example.com -tech-detect

# 2. Directory enumeration
gobuster dir -u https://example.com -w C:\Tools\wordlists\common.txt

# 3. XSS testing
dalfox url "https://example.com/?id=1"

# 4. SQL injection
sqlmap -u "https://example.com/?id=1" --batch --level=3

# 5. Parameter discovery
arjun -u https://example.com
```

### Network Scanning
```bash
# 1. Port scanning
nmap -sV -sC -oA scan example.com

# 2. Service enumeration
nmap -sV -p 80,443,8080 example.com

# 3. Vulnerability scanning
nmap --script vuln example.com
```

## Tool Installation

### Go Tools
```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# ... etc
```

### Python Tools
```powershell
pip install sqlmap wafw00f dirsearch whatweb wpscan droopescan hashid arjun
```

### System Tools
```powershell
winget install Nmap.Nmap
# nikto - git clone https://github.com/sullo/nikto.git
```

## Contributing

1. Add new tools to the inventory
2. Update TOOLS.md
3. Create wrapper scripts in core/scripts/
4. Update MCP server integration

## License

For authorized penetration testing only. Always obtain proper authorization before testing.


## Burp Evidence Workflow

1. Export your request, response, screenshots, and any JSON notes from Burp into one folder.
2. Use `core.burp_adapter.suggest_hunter_prefix(target, vuln_slug)` to get a Hunter-friendly prefix.
3. Use `core.burp_import.import_burp_evidence(source_dir, target, vuln_slug, destination_dir)` to copy and rename the files into Hunter's evidence directory.
4. Let Hunter pick them up automatically in the final report appendix.


### One-click Burp import

```powershell
.\core\scripts\quick_burp_import.ps1 -SourceDir "C:\BurpExports\gnnu" -Target "https://jwgl.gnnu.edu.cn" -VulnSlug "idor"
```

This copies Burp-exported request/response/screenshots/evidence files into Hunter's evidence directory using Hunter-friendly naming.


## Related Projects

- [Open-tgtylab](https://github.com/GeniusHu-tgty/Open-tgtylab) — 安全研究工作台，集成逆向工程、CTF、移动安全、Web安全于一体
