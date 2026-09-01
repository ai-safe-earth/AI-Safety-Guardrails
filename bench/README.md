# bench/ — rule precision measurement

Measures what fraction of each `euaiact-lint` rule's findings are real. The
answer decides whether a rule fires by default or is demoted behind
`aisg lint --experimental`.

Nothing here estimates, extrapolates or defaults a verdict. Every number in
`precision.md` traces back to a row a human labelled in `findings.csv`.

## Workflow

```bash
python bench/run.py          # 1. clone the corpus, lint it, emit findings.csv
#                              2. label the verdict column by hand
python bench/score.py        # 3. emit precision.md
#                              4. paste measured_precision onto the rule classes
```

### 1. Run the corpus

```bash
python bench/run.py                      # all 20 repos
python bench/run.py --only babyagi dspy  # a subset
python bench/run.py --keep-clones        # keep checkouts in bench/.cache
```

Each repo is fetched at the exact SHA pinned in `corpus.yaml`, scanned, and
deleted again unless `--keep-clones`. Raw reports land in `bench/results/` and
every finding becomes one row in `bench/findings.csv`.

Re-running is safe: verdicts already entered are carried over by
`(repo, file, line, rule_id)`, so labelling work survives a re-scan.

### 2. Label by hand

Open `bench/findings.csv` and fill the `verdict` column. Exactly three values:

| verdict | meaning |
|---|---|
| `tp` | The rule is right. This code really does have the problem described. |
| `fp` | The rule is wrong here. The pattern matched but the obligation does not apply. |
| `unclear` | Cannot decide without more context than the snippet gives. |

`unclear` is excluded from the precision denominator, not counted against the
rule. Use it honestly — a rule whose sample is mostly `unclear` shows up as a
thin sample rather than as a confident-looking ratio.

### 3. Score

```bash
python bench/score.py
python bench/score.py --min-precision 0.90   # try a stricter bar
python bench/score.py --allow-partial        # score the labelled subset only
```

`score.py` **refuses to run** while any row is unlabelled, or carries a value
outside `{tp, fp, unclear}`. That is deliberate: precision over a partly
labelled sample is not a measurement. `--allow-partial` overrides it, and the
report then says so at the top.

Output is `bench/precision.md`: per-rule precision with sample sizes, the rules
that fell below the threshold, the rules that never fired, and the three worst
false positives quoted verbatim from source.

### 4. Feed it back into the registry

`score.py` prints a paste-ready block. Set it on the rule class:

```python
class Rule_014a_FullyAutomatedHighRiskDecision(BaseRule):
    rule_id = "EU-AIA-014a"
    ...
    measured_precision = 0.625   # from bench/precision.md
```

Anything below `MIN_PRECISION` (0.80, in
`aisg/modules/policy/code_analyzer/analyzer.py`) stops firing unless the user
passes `--experimental`.

## What `measured_precision = None` means

**Unmeasured, not perfect.** A rule that has never been measured keeps firing
by default, because silencing a rule requires evidence and gating everything
unmeasured would mute the entire linter.

Two distinct cases both read as unmeasured, and `precision.md` separates them:

- **Never fired** — produced no findings anywhere in the corpus. Says nothing
  about precision; the corpus simply contains no code that trips it.
- **All `unclear`** — fired, but no finding could be judged either way.

Neither is evidence of quality. Do not fill in a number for either.

## Corpus

`corpus.yaml` — 20 public repositories that call LLMs, spanning agent
frameworks, RAG stacks, prompting libraries, a provider gateway and chat UIs.
Each pinned to a 40-character commit SHA resolved with `git ls-remote`, so a
precision figure stays reproducible as upstreams move.

To refresh a pin, re-resolve it — never edit a SHA by hand:

```bash
git ls-remote https://github.com/<owner>/<repo> HEAD
```

Changing a pin invalidates the verdicts for that repo. Re-label them.

## Files

| Path | Committed | What |
|---|---|---|
| `corpus.yaml` | yes | The 20 repos and their pinned SHAs |
| `run.py` | yes | Clone → lint → `findings.csv` |
| `score.py` | yes | Labelled CSV → `precision.md` |
| `findings.csv` | yes | One row per finding; `verdict` filled in by hand |
| `results/*.json` | yes | Raw reports, source of the verbatim snippets |
| `results/*.sarif` | yes | Raw SARIF per repo |
| `precision.md` | yes | Generated. Do not edit; re-run `score.py` |
| `.cache/` | no | Transient checkouts (gitignored) |
