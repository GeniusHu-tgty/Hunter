# Hunter Quick Vulnerability Scan
param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Hunter Quick Vuln Scan" -ForegroundColor Cyan
Write-Host "  Target: $Target" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

$env:GOPROXY = "https://goproxy.cn,direct"

Write-Host "`n[1/4] Nuclei CVE scan..." -ForegroundColor Yellow
nuclei -u $Target -tags cve -severity critical,high -timeout 10 -o "C:\Tools\output\$Target-nuclei-cve.txt" 2>&1

Write-Host "`n[2/4] Nuclei exposure scan..." -ForegroundColor Yellow
nuclei -u $Target -tags exposure -severity high,medium -timeout 10 -o "C:\Tools\output\$Target-nuclei-exposure.txt" 2>&1

Write-Host "`n[3/4] Nuclei misconfig scan..." -ForegroundColor Yellow
nuclei -u $Target -tags misconfig -severity high,medium -timeout 10 -o "C:\Tools\output\$Target-nuclei-misconfig.txt" 2>&1

Write-Host "`n[4/4] Directory enumeration..." -ForegroundColor Yellow
gobuster dir -u $Target -w "C:\Tools\wordlists\common.txt" -t 50 -o "C:\Tools\output\$Target-gobuster.txt" 2>&1

Write-Host "`n=== Vuln Scan Complete ===" -ForegroundColor Green
Write-Host "Results saved to C:\Tools\output\$Target-*.txt"
