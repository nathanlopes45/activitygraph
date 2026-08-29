# ActivityGraph interview demo launcher (Windows PowerShell).
#
#   Right-click this file -> "Run with PowerShell", or from a terminal:
#       ./run-demo.ps1
#
# It builds a synthetic household of traffic, runs it through the real
# pipeline, seeds a 30-day history, and opens the live dashboard in your
# browser. No admin rights, no real capture. Ctrl-C to stop.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "No virtual environment found at .venv\" -ForegroundColor Yellow
    Write-Host "Create it once with:" -ForegroundColor Yellow
    Write-Host "    python -m venv .venv"
    Write-Host "    .venv\Scripts\python.exe -m pip install -e ."
    exit 1
}

Write-Host "Starting the ActivityGraph demo dashboard..." -ForegroundColor Green
& $py "demo\serve_demo.py" @args
