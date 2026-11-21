# Start demo na Windowsie jedną komendą (PowerShell):  .\start.ps1
# Wymaga Docker Desktop i Git for Windows (z niego bierzemy bash). Niczego nie trzeba ustawiać:
# .env i hasła przygotowuje scripts/ensure_env.sh.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker nie dziala. Uruchom Docker Desktop, poczekaj az wystartuje i sprobuj ponownie." -ForegroundColor Red
    exit 1
}

$candidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $candidates += (Join-Path (Split-Path (Split-Path $gitCmd.Source)) "bin\bash.exe")
}
$bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $bash) {
    Write-Host "Nie znalazlem Git Bash. Zainstaluj Git for Windows: https://git-scm.com/download/win" -ForegroundColor Red
    exit 1
}

& $bash -lc "cd '$($PSScriptRoot -replace '\\','/')' && ./start.sh"
exit $LASTEXITCODE
