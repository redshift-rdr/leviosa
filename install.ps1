# Create a virtual environment and install declared dependencies offline.
# Run from the repo root: .\install.ps1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$venvDir = Join-Path $scriptDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment in $venvDir ..."
    python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
} else {
    Write-Host "Virtual environment already exists at $venvDir"
}

# Use the same constraints as normal installation instead of selecting an
# arbitrary aiohttp release from the wheel directory.
$requirements = @(& $venvPython -c "import sys,tomllib; print(*tomllib.load(open(sys.argv[1], 'rb'))['project']['dependencies'], sep='\n')" "$scriptDir\pyproject.toml")
if ($LASTEXITCODE -ne 0) { throw "Cannot read dependency constraints; Python 3.11 or newer is required." }

Write-Host "Installing declared dependencies from bundled_requirements ..."
& $venvPython -m pip install --no-index --find-links="$scriptDir\bundled_requirements" @requirements
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed. Check that the bundled wheels match your Python version and architecture." }

Write-Host "Done. Activate with: .\.venv\Scripts\Activate.ps1"
