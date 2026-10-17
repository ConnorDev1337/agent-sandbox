# Run the defense-in-depth demo: build, run, collect evidence, summarize, tear down.
#
# Usage: examples\defense-in-depth\run.ps1 [--keep] [--out DIR]
#        [--toolguard-src DIR] [--scanner-src DIR]
#
# Python: $env:PYTHON if set, else this checkout's .venv, else python. It must be
# able to import agent_sandbox (the driver falls back to this checkout's src\).
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here '..\..')).Path

$python = $env:PYTHON
if (-not $python) {
    foreach ($candidate in @((Join-Path $repo '.venv\Scripts\python.exe'),
                             (Join-Path $repo '.venv/bin/python'))) {
        if (Test-Path $candidate) {
            $python = $candidate
            break
        }
    }
}
if (-not $python) {
    $python = 'python'
}

& $python (Join-Path $here 'demo.py') @args
exit $LASTEXITCODE
