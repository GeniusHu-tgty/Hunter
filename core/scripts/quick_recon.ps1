# Hunter Quick Recon Script
param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Hunter Quick Recon" -ForegroundColor Cyan
Write-Host "  Target: $Target" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

$env:GOPROXY = "https://goproxy.cn,direct"

Write-Host "`n[1/5] Subdomain enumeration..." -ForegroundColor Yellow
$subdomains = subfinder -d $Target -silent 2>&1
$subdomains | Out-File "C:\Tools\output\$Target-subdomains.txt"
Write-Host "Found: $($subdomains.Count) subdomains"

Write-Host "`n[2/5] DNS resolution..." -ForegroundColor Yellow
$resolved = $subdomains | dnsx -silent 2>&1
$resolved | Out-File "C:\Tools\output\$Target-resolved.txt"
Write-Host "Resolved: $($resolved.Count) domains"

Write-Host "`n[3/5] HTTP probing..." -ForegroundColor Yellow
$liveHosts = $resolved | httpx -silent 2>&1
$liveHosts | Out-File "C:\Tools\output\$Target-live.txt"
Write-Host "Live: $($liveHosts.Count) hosts"

Write-Host "`n[4/5] Port scanning (top 100)..." -ForegroundColor Yellow
$liveHosts | ForEach-Object { $_ -replace 'https?://', '' } | naabu -top-ports 100 -silent 2>&1 | Out-File "C:\Tools\output\$Target-ports.txt"

Write-Host "`n[5/5] Technology detection..." -ForegroundColor Yellow
$liveHosts | httpx -tech-detect -silent 2>&1 | Out-File "C:\Tools\output\$Target-tech.txt"

Write-Host "`n=== Recon Complete ===" -ForegroundColor Green
Write-Host "Results saved to C:\Tools\output\$Target-*.txt"
