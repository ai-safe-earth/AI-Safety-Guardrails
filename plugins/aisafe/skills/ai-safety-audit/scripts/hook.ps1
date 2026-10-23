# ai-safety-audit hook bootstrap: run `aisafe hook` through a pinned install chain (PowerShell mirror of hook.sh).
# aisafe-audit: ignore-file
# The host's JSON payload on stdin passes through untouched; a missing aisafe fails OPEN (exit 0).
$AISAFE_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
$hookArgs = @($args)
function Skip-Hook([string]$why) {
    # A hook is a gate on someone else's editor: say why on stderr, let the action through.
    # Cursor reads an empty answer to a permission hook as a block, so give it an allow.
    [Console]::Error.WriteLine("aisafe-hook: $why; hook skipped")
    if (($hookArgs -join " ") -match "--host cursor") { Write-Output '{"permission":"allow"}' }
    exit 0
}
if (Get-Command aisafe -ErrorAction SilentlyContinue) {
    $launcher = (Get-Command aisafe).Source
    $input | & aisafe hook @hookArgs --origin "path:$launcher" --expect-version $AISAFE_VERSION
} elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
    $launcher = "uvx"
    $input | & uvx --from "aisafe==$AISAFE_VERSION" aisafe hook @hookArgs --origin uvx --expect-version $AISAFE_VERSION
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    $launcher = "pipx"
    $input | & pipx run --spec "aisafe==$AISAFE_VERSION" aisafe hook @hookArgs --origin pipx --expect-version $AISAFE_VERSION
} else {
    Skip-Hook "aisafe not found (install 'aisafe==$AISAFE_VERSION')"
}
$rc = $LASTEXITCODE
# `aisafe hook run` exits 0 on every path, its own errors included. Any other status means it
# never ran: the `aisafe` on PATH is not this project's (PyPI's `aisafeguard` installs one too),
# or uvx/pipx could not fetch the pinned release (offline, index down). Fail open, say which failed.
if ($rc -ne 0 -and $hookArgs.Count -gt 0 -and $hookArgs[0] -eq "run") {
    Skip-Hook "$launcher exited $rc (not this project's aisafe, or the pinned release could not be fetched)"
}
exit $rc
