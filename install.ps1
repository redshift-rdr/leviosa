# Creates a virtual environment and installs aiohttp offline from the bundled
# wheels. Run from the repo root:  .\install.ps1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$venvDir = Join-Path $scriptDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment in $venvDir ..."
    python -m venv $venvDir
} else {
    Write-Host "Virtual environment already exists at $venvDir"
}

Write-Host "Installing aiohttp from bundled_requirements ..."
& $venvPython -m pip install --no-index --find-links="$scriptDir\bundled_requirements" aiohttp

Write-Host "Done. Activate with: .\.venv\Scripts\Activate.ps1"
