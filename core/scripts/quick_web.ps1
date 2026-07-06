# Hunter Quick Web Scan
param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Hunter Quick Web Scan" -ForegroundColor Cyan
Write-Host "  Target: $Target" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

$env:GOPROXY = "https://goproxy.cn,direct"

Write-Host "`n[1/5] Technology detection..." -ForegroundColor Yellow
httpx -u $Target -tech-detect -status-code -title -o "C:\Tools\output\$Target-web-tech.txt" 2>&1

Write-Host "`n[2/5] URL crawling..." -ForegroundColor Yellow
katana -u $Target -d 3 -jc -o "C:\Tools\output\$Target-urls.txt" 2>&1

Write-Host "`n[3/5] Parameter discovery..." -ForegroundColor Yellow
katana -u $Target -d 2 -jc | grep -oP '[^?]&+' | sort -u | head -100 | Out-File "C:\Tools\output\$Target-params.txt"

Write-Host "`n[4/5] XSS scanning..." -ForegroundColor Yellow
Get-Content "C:\Tools\output\$Target-urls.txt" | dalfox pipe -o "C:\Tools\output\$Target-xss.txt" 2>&1

Write-Host "`n[5/5] SQL injection testing..." -ForegroundColor Yellow
Get-Content "C:\Tools\output\$Target-urls.txt" | grep -i "id=" | head -20 | ForEach-Object { sqlmap -u $_ --batch --level=1 --risk=1 2>&1 }

Write-Host "`n=== Web Scan Complete ===" -ForegroundColor Green
Write-Host "Results saved to C:\Tools\output\$Target-*.txt"
