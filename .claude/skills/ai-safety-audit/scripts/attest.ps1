# ai-safety-audit attest bootstrap (phase 7): run `aisg attest` through a pinned install chain (PowerShell mirror of attest.sh).
# aisg-audit: ignore-file
$AISG_VERSION = "0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if (Get-Command aisg -ErrorAction SilentlyContinue) {
    $resolved = (Get-Command aisg).Source
    $version = (& aisg --version 2>$null) -replace '^aisg ', ''
    if (-not $version) { $version = "unknown" }
    [Console]::Error.WriteLine("aisg: $resolved version $version (pinned $AISG_VERSION)")
    & aisg attest @args
} elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
    [Console]::Error.WriteLine("aisg: uvx aisguard==$AISG_VERSION (pinned $AISG_VERSION)")
    & uvx --from "aisguard==$AISG_VERSION" aisg attest @args
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    [Console]::Error.WriteLine("aisg: pipx aisguard==$AISG_VERSION (pinned $AISG_VERSION)")
    & pipx run --spec "aisguard==$AISG_VERSION" aisg attest @args
} else {
    [Console]::Error.WriteLine("aisg not found. Install one of:")
    [Console]::Error.WriteLine("  uv tool install 'aisguard==$AISG_VERSION'   (uv works without a pre-installed Python)")
    if ((Get-Command python3 -ErrorAction SilentlyContinue) -or (Get-Command python -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("  pipx install 'aisguard==$AISG_VERSION'")
        [Console]::Error.WriteLine("  pip install 'aisguard==$AISG_VERSION'")
    } else {
        [Console]::Error.WriteLine("  (no python3/python on PATH: install uv first, e.g. https://docs.astral.sh/uv/getting-started/installation/)")
    }
    exit 2
}
exit $LASTEXITCODE
