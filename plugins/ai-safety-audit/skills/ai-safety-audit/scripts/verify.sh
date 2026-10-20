#!/bin/sh
# aisafe-audit: ignore-file
# ai-safety-audit verify step (phase 5). Detects the project's test command and prints it,
# then resolves `aisafe` through the same pinned bootstrap chain as audit.sh for
# `aisafe measure` and, when AISAFE_PROBE_URL is set, `aisafe probe`.
# Nothing runs unless AISAFE_VERIFY_RUN=1: tests, measure and probe may call model providers.
# AISAFE_VERIFY_SKIP_TESTS=1 leaves the project's tests out (phase 3 runs the offline measure only).
# This script never adds --i-have-authorization; a remote probe target needs the user to add it.
# Reports go under .aisafe-audit/ like every other artefact of the flow; the next audit reads
# them there as evidence (REPORTED <age>) whether or not .gitignore lists the directory.
set -u
AISAFE_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
run="${AISAFE_VERIFY_RUN:-0}"
skip_tests="${AISAFE_VERIFY_SKIP_TESTS:-0}"
status=0
report_dir=".aisafe-audit"
measure_report="$report_dir/measure-report.json"
probe_report="$report_dir/probe-report.json"

# --- 1. Test command, from manifests (first match wins) ---------------------
test_cmd=""
if [ -f pyproject.toml ] || [ -f pytest.ini ] || [ -f setup.cfg ]; then
  test_cmd="pytest"
elif [ -f package.json ] && grep -q '"test"[[:space:]]*:' package.json; then
  test_cmd="npm test"
elif [ -f go.mod ]; then
  test_cmd="go test ./..."
elif [ -f Cargo.toml ]; then
  test_cmd="cargo test"
fi

if [ -z "$test_cmd" ]; then
  echo "tests: no test command detected (looked for pyproject.toml/pytest.ini/setup.cfg, package.json test script, go.mod, Cargo.toml)"
else
  echo "tests: $test_cmd"
  if [ "$skip_tests" = "1" ]; then
    echo "tests: skipped (AISAFE_VERIFY_SKIP_TESTS=1)"
  elif [ "$run" = "1" ]; then
    # shellcheck disable=SC2086  # intentional word splitting of the detected command
    if ! $test_cmd; then
      echo "tests: FAILED ($test_cmd exited non-zero)" >&2
      status=1
    fi
  else
    echo "tests: not run (set AISAFE_VERIFY_RUN=1 to run)"
  fi
fi

# --- 2. aisafe through the same bootstrap chain as audit.sh -------------------
have_aisafe() {
  command -v aisafe >/dev/null 2>&1 || command -v uvx >/dev/null 2>&1 || command -v pipx >/dev/null 2>&1
}

run_aisafe() {
  if command -v aisafe >/dev/null 2>&1; then
    aisafe "$@"
  elif command -v uvx >/dev/null 2>&1; then
    uvx --from "aisafe==$AISAFE_VERSION" aisafe "$@"
  elif command -v pipx >/dev/null 2>&1; then
    pipx run --spec "aisafe==$AISAFE_VERSION" aisafe "$@"
  else
    return 127
  fi
}

# Summary counts from a probe report: sent/passed/failed/errors/skipped/inconclusive.
# `summary` is the first object carrying these keys, so the first match is the right one.
# Only `passed` means passed; the other five are never folded into it.
print_probe_summary() {
  for key in sent passed failed errors skipped inconclusive; do
    value=$(grep -oE "\"$key\"[[:space:]]*:[[:space:]]*[0-9]+" "$1" | head -n 1 | grep -oE '[0-9]+$')
    echo "probe $key: ${value:-?}"
  done
  echo "probe: only 'passed' means passed; failed, errors, skipped and inconclusive are separate"
}

if ! have_aisafe; then
  echo "measure skipped: aisafe not importable in target" >&2
  if [ -n "${AISAFE_PROBE_URL:-}" ]; then
    echo "probe skipped: aisafe not importable in target" >&2
  fi
  exit "$status"
fi

# --- 3. aisafe measure, when a pipeline config exists -------------------------
# GuardrailPipeline.from_config builds guards from the top-level stage keys input:,
# processing:, output: and policy:; `pipeline:` is optional and holds only run settings,
# and a file with no stage key enables no guards (aisafe measure then exits 2 itself).
pipeline_cfg=""
for candidate in guardrails.yaml aisafe.yaml config/*.yaml config/*.yml; do
  [ -f "$candidate" ] || continue
  if grep -Eq '^(input|processing|output|policy):' "$candidate"; then
    pipeline_cfg="$candidate"
    break
  fi
done

if [ -z "$pipeline_cfg" ]; then
  echo "measure: no pipeline config found (looked for guardrails.yaml, aisafe.yaml, config/*.yaml with a top-level input:, processing:, output: or policy: stage key)"
else
  echo "measure: aisafe measure --config $pipeline_cfg -o $measure_report"
  if [ "$run" = "1" ]; then
    mkdir -p "$report_dir"
    if ! run_aisafe measure --config "$pipeline_cfg" -o "$measure_report"; then
      echo "measure: FAILED (aisafe measure exited non-zero)" >&2
      status=1
    fi
  else
    echo "measure: not run (set AISAFE_VERIFY_RUN=1 to run)"
  fi
fi

# --- 4. aisafe probe, only when AISAFE_PROBE_URL is set --------------------------
if [ -n "${AISAFE_PROBE_URL:-}" ]; then
  echo "probe: aisafe probe $AISAFE_PROBE_URL -o $probe_report"
  echo "probe: a non-loopback target needs --i-have-authorization; this script never adds it"
  if [ "$run" = "1" ]; then
    mkdir -p "$report_dir"
    if ! run_aisafe probe "$AISAFE_PROBE_URL" -o "$probe_report"; then
      echo "probe: exited non-zero (1 = a case got through, 2 = errors/skipped/inconclusive present)" >&2
      status=1
    fi
    if [ -f "$probe_report" ]; then
      print_probe_summary "$probe_report"
    fi
  else
    echo "probe: not run (set AISAFE_VERIFY_RUN=1 to run)"
  fi
fi

exit "$status"
