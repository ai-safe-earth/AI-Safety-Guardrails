# ai-safety-audit verify step (phase 5), PowerShell mirror of verify.sh.
# aisafe-audit: ignore-file
# Detects the project's test command and prints it, then resolves `aisafe` through the same
# pinned bootstrap chain as audit.ps1 for `aisafe measure` and, when AISAFE_PROBE_URL is set,
# `aisafe probe`. Nothing runs unless AISAFE_VERIFY_RUN=1: tests, measure and probe may call
# model providers. This script never adds --i-have-authorization.
# AISAFE_VERIFY_SKIP_TESTS=1 leaves the project's tests out (phase 3 runs the offline measure only).
# Reports go under .aisafe-audit/ like every other artefact of the flow; the next audit reads
# them there as evidence (REPORTED <age>) whether or not .gitignore lists the directory.
$AISAFE_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
$run = if ($env:AISAFE_VERIFY_RUN) { $env:AISAFE_VERIFY_RUN } else { "0" }
$skipTests = if ($env:AISAFE_VERIFY_SKIP_TESTS) { $env:AISAFE_VERIFY_SKIP_TESTS } else { "0" }
$status = 0
$reportDir = ".aisafe-audit"
$measureReport = "$reportDir/measure-report.json"
$probeReport = "$reportDir/probe-report.json"

# --- 1. Test command, from manifests (first match wins) ---------------------
$testCmd = $null
if ((Test-Path pyproject.toml) -or (Test-Path pytest.ini) -or (Test-Path setup.cfg)) {
    $testCmd = @("pytest")
} elseif ((Test-Path package.json) -and (Select-String -Path package.json -Pattern '"test"\s*:' -Quiet)) {
    $testCmd = @("npm", "test")
} elseif (Test-Path go.mod) {
    $testCmd = @("go", "test", "./...")
} elseif (Test-Path Cargo.toml) {
    $testCmd = @("cargo", "test")
}

if ($null -eq $testCmd) {
    Write-Output "tests: no test command detected (looked for pyproject.toml/pytest.ini/setup.cfg, package.json test script, go.mod, Cargo.toml)"
} else {
    Write-Output "tests: $($testCmd -join ' ')"
    if ($skipTests -eq "1") {
        Write-Output "tests: skipped (AISAFE_VERIFY_SKIP_TESTS=1)"
    } elseif ($run -eq "1") {
        $testArgs = @($testCmd | Select-Object -Skip 1)
        & $testCmd[0] @testArgs
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("tests: FAILED ($($testCmd -join ' ') exited non-zero)")
            $status = 1
        }
    } else {
        Write-Output "tests: not run (set AISAFE_VERIFY_RUN=1 to run)"
    }
}

# --- 2. aisafe through the same bootstrap chain as audit.ps1 ------------------
function Test-Aisafe {
    return [bool]((Get-Command aisafe -ErrorAction SilentlyContinue) -or
                  (Get-Command uvx -ErrorAction SilentlyContinue) -or
                  (Get-Command pipx -ErrorAction SilentlyContinue))
}

function Invoke-Aisafe {
    if (Get-Command aisafe -ErrorAction SilentlyContinue) {
        & aisafe @args
    } elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
        & uvx --from "aisafe==$AISAFE_VERSION" aisafe @args
    } elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
        & pipx run --spec "aisafe==$AISAFE_VERSION" aisafe @args
    } else {
        $global:LASTEXITCODE = 127
    }
}

# Summary counts from a probe report. Only `passed` means passed; the other five
# are never folded into it.
function Write-ProbeSummary($path) {
    $text = Get-Content -Raw $path
    foreach ($key in @("sent", "passed", "failed", "errors", "skipped", "inconclusive")) {
        $m = [regex]::Match($text, "`"$key`"\s*:\s*([0-9]+)")
        $value = if ($m.Success) { $m.Groups[1].Value } else { "?" }
        Write-Output "probe ${key}: $value"
    }
    Write-Output "probe: only 'passed' means passed; failed, errors, skipped and inconclusive are separate"
}

if (-not (Test-Aisafe)) {
    [Console]::Error.WriteLine("measure skipped: aisafe not importable in target")
    if ($env:AISAFE_PROBE_URL) {
        [Console]::Error.WriteLine("probe skipped: aisafe not importable in target")
    }
    exit $status
}

# --- 3. aisafe measure, when a pipeline config exists -------------------------
# GuardrailPipeline.from_config builds guards from the top-level stage keys input:,
# processing:, output: and policy:; `pipeline:` is optional and holds only run settings,
# and a file with no stage key enables no guards (aisafe measure then exits 2 itself).
$pipelineCfg = $null
$candidates = @("guardrails.yaml", "aisafe.yaml")
if (Test-Path config) {
    $candidates += Get-ChildItem -Path config -File -Include *.yaml, *.yml -Recurse:$false -Name |
        ForEach-Object { "config/$_" }
}
foreach ($candidate in $candidates) {
    if (-not (Test-Path $candidate -PathType Leaf)) { continue }
    if (Select-String -Path $candidate -Pattern '^(input|processing|output|policy):' -Quiet) {
        $pipelineCfg = $candidate
        break
    }
}

if ($null -eq $pipelineCfg) {
    Write-Output "measure: no pipeline config found (looked for guardrails.yaml, aisafe.yaml, config/*.yaml with a top-level input:, processing:, output: or policy: stage key)"
} else {
    Write-Output "measure: aisafe measure --config $pipelineCfg -o $measureReport"
    if ($run -eq "1") {
        New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
        Invoke-Aisafe measure --config $pipelineCfg -o $measureReport
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("measure: FAILED (aisafe measure exited non-zero)")
            $status = 1
        }
    } else {
        Write-Output "measure: not run (set AISAFE_VERIFY_RUN=1 to run)"
    }
}

# --- 4. aisafe probe, only when AISAFE_PROBE_URL is set --------------------------
if ($env:AISAFE_PROBE_URL) {
    Write-Output "probe: aisafe probe $($env:AISAFE_PROBE_URL) -o $probeReport"
    Write-Output "probe: a non-loopback target needs --i-have-authorization; this script never adds it"
    if ($run -eq "1") {
        New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
        Invoke-Aisafe probe $env:AISAFE_PROBE_URL -o $probeReport
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("probe: exited non-zero (1 = a case got through, 2 = errors/skipped/inconclusive present)")
            $status = 1
        }
        if (Test-Path $probeReport) {
            Write-ProbeSummary $probeReport
        }
    } else {
        Write-Output "probe: not run (set AISAFE_VERIFY_RUN=1 to run)"
    }
}

exit $status
