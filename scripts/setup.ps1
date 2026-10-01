# One-time local setup on Windows (PowerShell). Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "== Backend: virtual environment and dependencies"
Push-Location "$root\backend"
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
try { & .\.venv\Scripts\python.exe -m pip install yara-python } catch { Write-Warning "yara-python not installed (optional)." }
Pop-Location

Write-Host "== Frontend: npm dependencies"
Push-Location "$root\frontend"
npm install
Pop-Location

if (-not (Test-Path "$root\.env")) {
    Copy-Item "$root\.env.example" "$root\.env"
    $secret = & "$root\backend\.venv\Scripts\python.exe" -c "import secrets; print(secrets.token_urlsafe(48))"
    (Get-Content "$root\.env") -replace '^SECRET_KEY=$', "SECRET_KEY=$secret" | Set-Content -Encoding utf8 "$root\.env"
    Write-Host "Created .env with a random SECRET_KEY. Change ADMIN_PASSWORD before real use."
}

Write-Host "== Demo dataset"
& "$root\backend\.venv\Scripts\python.exe" "$root\scripts\generate_demo_data.py"
Write-Host "Setup complete. Start with: powershell -File scripts\run_dev.ps1"
