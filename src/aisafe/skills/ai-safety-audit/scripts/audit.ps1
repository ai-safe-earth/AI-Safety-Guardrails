# ai-safety-audit bootstrap: run `aisafe audit` through a pinned install chain (PowerShell mirror of audit.sh).
# aisafe-audit: ignore-file
$AISAFE_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if (Get-Command aisafe -ErrorAction SilentlyContinue) {
    $resolved = (Get-Command aisafe).Source
    $version = (& aisafe --version 2>$null) -replace '^aisafe ', ''
    if (-not $version) { $version = "unknown" }
    [Console]::Error.WriteLine("aisafe: $resolved version $version (pinned $AISAFE_VERSION)")
    & aisafe audit @args
} elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
    [Console]::Error.WriteLine("aisafe: uvx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)")
    & uvx --from "aisafe==$AISAFE_VERSION" aisafe audit @args
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    [Console]::Error.WriteLine("aisafe: pipx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)")
    & pipx run --spec "aisafe==$AISAFE_VERSION" aisafe audit @args
} else {
    [Console]::Error.WriteLine("aisafe not found. Install one of:")
    [Console]::Error.WriteLine("  uv tool install 'aisafe==$AISAFE_VERSION'   (uv works without a pre-installed Python)")
    if ((Get-Command python3 -ErrorAction SilentlyContinue) -or (Get-Command python -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("  pipx install 'aisafe==$AISAFE_VERSION'")
        [Console]::Error.WriteLine("  pip install 'aisafe==$AISAFE_VERSION'")
    } else {
        [Console]::Error.WriteLine("  (no python3/python on PATH: install uv first, e.g. https://docs.astral.sh/uv/getting-started/installation/)")
    }
    exit 2
}
exit $LASTEXITCODE
