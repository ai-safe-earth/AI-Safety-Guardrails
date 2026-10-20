# ai-safety-audit hook bootstrap: run `aisafe hook` through a pinned install chain (PowerShell mirror of hook.sh).
# aisafe-audit: ignore-file
# The host's JSON payload on stdin passes through untouched; a missing aisafe fails OPEN (exit 0).
$AISAFE_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if (Get-Command aisafe -ErrorAction SilentlyContinue) {
    $origin = "path:" + (Get-Command aisafe).Source
    $input | & aisafe hook @args --origin $origin --expect-version $AISAFE_VERSION
    # `aisafe hook run` exits 0 on every path, its own errors included. Any other status means
    # the `aisafe` on PATH is not this project's (PyPI's `aisafeguard` installs one too):
    # fail open and say which ran.
    if ($LASTEXITCODE -ne 0 -and $args.Count -gt 0 -and $args[0] -eq "run") {
        [Console]::Error.WriteLine("aisafe-hook: $origin exited $LASTEXITCODE (not this project's aisafe?); hook skipped")
        if (($args -join " ") -match "--host cursor") { Write-Output '{"permission":"allow"}' }
        exit 0
    }
} elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
    $input | & uvx --from "aisafe==$AISAFE_VERSION" aisafe hook @args --origin uvx --expect-version $AISAFE_VERSION
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    $input | & pipx run --spec "aisafe==$AISAFE_VERSION" aisafe hook @args --origin pipx --expect-version $AISAFE_VERSION
} else {
    [Console]::Error.WriteLine("aisafe-hook: aisafe not found (install 'aisafe==$AISAFE_VERSION'); hook skipped")
    if (($args -join " ") -match "--host cursor") { Write-Output '{"permission":"allow"}' }
    exit 0
}
exit $LASTEXITCODE
