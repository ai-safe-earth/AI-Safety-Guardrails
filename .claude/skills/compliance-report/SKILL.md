---
name: compliance-report
description: Reproduce the EU AI Act compliance CI gate locally — run euaiact_lint across all four output formats and gate on the JSON error count. Writes report files.
disable-model-invocation: true
---

# Compliance report

Reproduces `.github/workflows/eu-ai-act-compliance.yml` locally. Run from the **repo root**.
Target: `$ARGUMENTS` if given, otherwise `modules/ integrations/ examples/ devtools/`.

## Run

```bash
aisg lint <target>
aisg lint <target> --format json     --output euaiact-report.json
aisg lint <target> --format sarif    --output euaiact-results.sarif
aisg lint <target> --format markdown --output euaiact-report.md
```

## Gate

CI fails on `report["summary"]["errors"] > 0` — warnings do not block. Check it:

```bash
python -c "import json; d=json.load(open('euaiact-report.json')); print(d['summary'])"
```

## Report back

- The `summary` block: error count, warning count, files scanned.
- Every ERROR finding with its rule ID, file, and line. Use
  `aisg lint --list-rules` to explain any rule ID you cite.
- Whether the gate would pass or fail in CI.

Then say where the four output files landed, and offer to delete them — they are build artifacts,
not tracked files. In CI the SARIF goes to GitHub Code Scanning, the markdown becomes a sticky PR
comment, and the JSON is retained 90 days under Art. 12; none of that happens locally.

## Sibling check

`aisg misalign` takes the same flags and formats and is **not** part of the CI
gate. Run it too if asked for a full audit.
