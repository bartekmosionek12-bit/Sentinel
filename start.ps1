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

# Kopia z Windowsa (git z core.autocrlf=true) ma CRLF w skryptach .sh, a wtedy bash ich nie uruchomi
# ("required file not found"). Zamieniamy CRLF na LF tutaj, zanim bash cokolwiek przeczyta.
$skip = '\\(node_modules|\.git|\.venv|dist)\\'
Get-ChildItem -Path $PSScriptRoot -Recurse -File -Include *.sh, .env, .env.example -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip } |
    ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        if ($bytes -contains 13) {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes) -replace "`r`n", "`n" -replace "`r", ""
            [System.IO.File]::WriteAllText($_.FullName, $text, (New-Object System.Text.UTF8Encoding($false)))
        }
    }

# Katalog docker.exe przekazujemy do Git Bash, gdyby nie miał go w PATH.
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) { $env:SENTINEL_DOCKER_DIR = Split-Path $dockerCmd.Source }

$unixPath = $PSScriptRoot -replace '\\', '/'
& $bash -lc "cd '$unixPath' && bash ./start.sh"
exit $LASTEXITCODE
