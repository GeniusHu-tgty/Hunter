# Hunter Tools Configuration Script
# Run this script to verify and configure all Hunter tools

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Hunter Pentest Framework v7" -ForegroundColor Cyan
Write-Host "  Tools Configuration" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:GOPROXY = "https://goproxy.cn,direct"
$env:all_proxy = "http://127.0.0.1:7890"

Write-Host "Environment Variables:" -ForegroundColor Yellow
Write-Host "  GOPROXY: $env:GOPROXY"
Write-Host "  all_proxy: $env:all_proxy"
Write-Host ""

# Go-based tools
Write-Host "Go-based Tools:" -ForegroundColor Yellow
$goTools = @(
    @{Name="nuclei"; Desc="Vulnerability scanner"},
    @{Name="subfinder"; Desc="Subdomain discovery"},
    @{Name="naabu"; Desc="Port scanner"},
    @{Name="httpx"; Desc="HTTP toolkit"},
    @{Name="katana"; Desc="Web crawler"},
    @{Name="gau"; Desc="URL fetcher"},
    @{Name="uncover"; Desc="Host discovery"},
    @{Name="tlsx"; Desc="TLS toolkit"},
    @{Name="cdncheck"; Desc="CDN detection"},
    @{Name="mapcidr"; Desc="CIDR toolkit"},
    @{Name="ffuf"; Desc="Web fuzzer"},
    @{Name="gobuster"; Desc="Directory brute-forcer"},
    @{Name="dnsx"; Desc="DNS toolkit"},
    @{Name="dalfox"; Desc="XSS scanner"},
    @{Name="notify"; Desc="Notification tool"},
    @{Name="amass"; Desc="Attack surface mapping"},
    @{Name="waybackurls"; Desc="Wayback URL fetcher"},
    @{Name="assetfinder"; Desc="Asset discovery"},
    @{Name="httprobe"; Desc="HTTP prober"},
    @{Name="unfurl"; Desc="URL parser"},
    @{Name="meg"; Desc="Request sender"},
    @{Name="anew"; Desc="Line appender"},
    @{Name="qsreplace"; Desc="Query string replacer"}
)

foreach ($tool in $goTools) {
    $path = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($path) {
        Write-Host "  [OK] $($tool.Name) - $($tool.Desc)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($tool.Name) - $($tool.Desc)" -ForegroundColor Red
    }
}

Write-Host ""

# Python tools
Write-Host "Python Tools:" -ForegroundColor Yellow
$pyTools = @(
    @{Name="sqlmap"; Desc="SQL injection tool"},
    @{Name="wafw00f"; Desc="WAF detection"},
    @{Name="dirsearch"; Desc="Directory scanner"},
    @{Name="whatweb"; Desc="Web technology identifier"},
    @{Name="wpscan"; Desc="WordPress scanner"},
    @{Name="impacket"; Desc="Network protocols library"}
)

foreach ($tool in $pyTools) {
    $path = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($path) {
        Write-Host "  [OK] $($tool.Name) - $($tool.Desc)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($tool.Name) - $($tool.Desc)" -ForegroundColor Red
    }
}

Write-Host ""

# System tools
Write-Host "System Tools:" -ForegroundColor Yellow
$sysTools = @(
    @{Name="nmap"; Desc="Network scanner"},
    @{Name="nikto"; Desc="Web server scanner"},
    @{Name="curl"; Desc="HTTP client"}
)

foreach ($tool in $sysTools) {
    $path = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($path) {
        Write-Host "  [OK] $($tool.Name) - $($tool.Desc)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($tool.Name) - $($tool.Desc)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Configuration Complete" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
