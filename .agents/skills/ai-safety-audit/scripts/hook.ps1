# ai-safety-audit hook bootstrap: run `aisg hook` through a pinned install chain (PowerShell mirror of hook.sh).
# aisg-audit: ignore-file
# The host's JSON payload on stdin passes through untouched; a missing aisg fails OPEN (exit 0).
$AISG_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if (Get-Command aisg -ErrorAction SilentlyContinue) {
    $origin = "path:" + (Get-Command aisg).Source
    $input | & aisg hook @args --origin $origin --expect-version $AISG_VERSION
} elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
    $input | & uvx --from "anyaisafe==$AISG_VERSION" aisg hook @args --origin uvx --expect-version $AISG_VERSION
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    $input | & pipx run --spec "anyaisafe==$AISG_VERSION" aisg hook @args --origin pipx --expect-version $AISG_VERSION
} else {
    [Console]::Error.WriteLine("aisg-hook: aisg not found (install 'anyaisafe==$AISG_VERSION'); hook skipped")
    if (($args -join " ") -match "--host cursor") { Write-Output '{"permission":"allow"}' }
    exit 0
}
exit $LASTEXITCODE
