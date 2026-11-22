# Konta demo (admin, editor, modifier, viewer, analityk, operator, redaktor, obserwator) na Windowsie:
#   .\konta.cmd   albo   powershell -ExecutionPolicy Bypass -File .\konta.ps1
# Zakłada konta w Keycloaku, zapisuje je w panelu IAM i wypisuje loginy, hasła oraz kod TOTP.
# Stos musi działać (najpierw .\start.cmd).
# Continue: docker pisze postęp na stderr, a PowerShell 5 przy "Stop" traktuje to jako błąd.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

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

# CRLF z gita na Windowsie psuje skrypty .sh i .env (tak samo jak w start.ps1).
foreach ($file in @("scripts\demo_users.sh", ".env")) {
    if (Test-Path $file) {
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $file))
        if ($bytes -contains 13) {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes) -replace "`r`n", "`n" -replace "`r", ""
            [System.IO.File]::WriteAllText((Resolve-Path $file), $text, (New-Object System.Text.UTF8Encoding($false)))
        }
    }
}

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) { $env:SENTINEL_DOCKER_DIR = Split-Path $dockerCmd.Source }

# Obraz api musi mieć polecenie register-users (zapis kont w panelu IAM): przebudowa, jeśli kod
# się zmienił (gdy nic się nie zmieniło, trwa kilka sekund).
Write-Host "==> Przebudowa i restart api"
docker compose up -d --build api
if ($LASTEXITCODE -ne 0) { Write-Host "Nie udalo sie uruchomic api. Najpierw .\start.cmd" -ForegroundColor Red; exit 1 }
for ($i = 0; $i -lt 30; $i++) {
    docker compose exec -T api python -c "import app.cli" *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
}

# Bez trybu demo (start z --bez-demo) te same konta zakłada SENTINEL_ACCOUNTS=1.
$demo = (Test-Path .env) -and (Select-String -Path .env -Pattern '^DEMO_MODE=true\s*$' -Quiet)
$accounts = if ($demo) { "" } else { "SENTINEL_ACCOUNTS=1 " }

$unixPath = $PSScriptRoot -replace '\\', '/'
& $bash -lc "cd '$unixPath' && ${accounts}bash ./scripts/demo_users.sh"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Konsola: http://localhost:8080/admin/" -ForegroundColor Green
Write-Host "Hasla i kod TOTP (data\demo-credentials.env):" -ForegroundColor Green
Get-Content data\demo-credentials.env
