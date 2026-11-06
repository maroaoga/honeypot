$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CheckRoot = Join-Path $env:TEMP ("honeypot-clean-install-" + [guid]::NewGuid().ToString("N"))
$VenvPath = Join-Path $CheckRoot "venv"
$CleanPython = Join-Path $VenvPath "Scripts\python.exe"
$CheckDatabase = Join-Path $CheckRoot "clean-install.db"
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    New-Item -ItemType Directory -Path $CheckRoot | Out-Null
    Push-Location $ProjectRoot
    try {
        python -m venv $VenvPath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the clean virtual environment."
        }

        & $CleanPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            throw "Could not install project requirements in the clean environment."
        }

        & $CleanPython -m database.init_db $CheckDatabase
        if ($LASTEXITCODE -ne 0) {
            throw "Could not initialize the clean-check database."
        }

        & $CleanPython -m pytest -q
        if ($LASTEXITCODE -ne 0) {
            throw "The project tests failed in the clean environment."
        }

        & $CleanPython -m integration.run `
            --config (Join-Path $ProjectRoot "config\integration.yaml") `
            --database (Join-Path $CheckRoot "pipeline.db") `
            --labels (Join-Path $CheckRoot "pipeline_labels.csv") `
            --no-dashboard
        if ($LASTEXITCODE -ne 0) {
            throw "The end-to-end pipeline failed in the clean environment."
        }
        $Stopwatch.Stop()
        Write-Output ("Clean-install check passed in {0:N2} seconds." -f $Stopwatch.Elapsed.TotalSeconds)
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path -LiteralPath $CheckRoot) {
        Remove-Item -LiteralPath $CheckRoot -Recurse -Force
    }
}
