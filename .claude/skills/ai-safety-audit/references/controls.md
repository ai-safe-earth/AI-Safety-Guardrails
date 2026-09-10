# Controls per audit rule

One section per `AUD` rule: the control to propose, its tier, and the control mapping the
finding carries. Use it in phase 3 together with `apply/<language>.md`.

How to read this file:

- **Tier**: T1 = a config or permission change; T2 = add a gate or a file; T3 = restructure
  code. Propose the cheapest tier that removes the blast radius, not the cheapest one that
  makes the finding go away.
- **Mapping**: `ASI` = OWASP Top 10 for Agentic Applications (ASI01 goal hijack, ASI02 tool
  misuse, ASI03 identity and privilege abuse, ASI04 supply chain, ASI05 unexpected code
  execution, ASI06 memory and context poisoning, ASI07 inter-agent communication, ASI08
  cascading failures, ASI09 human-agent trust, ASI10 rogue agents); `LLM` = OWASP Top 10 for
  LLM Applications 2025 (LLM01 prompt injection, LLM02 sensitive information disclosure,
  LLM03 supply chain, LLM04 data and model poisoning, LLM05 improper output handling, LLM06
  excessive agency, LLM07 system prompt leakage, LLM08 vector and embedding weaknesses,
  LLM09 misinformation, LLM10 unbounded consumption); `EU` = EU AI Act article; `NIST` = AI
  RMF function and subcategory. The `controls` field in the report is the authoritative
  tuple for the installed version; the tuples below were recorded when this file was
  written. They are evidence for a human reviewer. Never state or imply compliance with any
  of them, and never present a mapping as a verdict.
- **Detector vs gate**: a detector (prompt-injection guard, PII scanner, judge) lowers the
  probability that bad content passes; a gate (approval, allowlist, sandbox, budget) lowers
  the impact when it does. Never prescribe a detector as the sole control for a P1-P4 finding.
- **Package**: what this package offers for the rule, copied from the rule's
  `recommendation.package` (the JSON is authoritative; the column below was recorded when
  this file was written). Mechanism is one of gate, budget, detector, record, measurement,
  document, none. "Same control: yes" means wiring the symbols IS the control the rule asks
  for; "no" means the package adds a different mechanism, offered in addition to, not
  instead of, the control. "Leaves open" is quoted every time the symbol is offered. A
  detector is never the control for a P1-P4 finding, whatever the column says about
  symbols. aisg symbols are Python-only; the control applies in every language.
- Every rule is `[UNMEASURED]`. Say so.

## Package column

| rule | Package (mechanism) | same control? | symbols |
|---|---|---|---|
| AUD-101 | none | no | -- |
| AUD-102 | budget | no | `RateLimiter` |
| AUD-103 | gate | yes | `ToolPolicyGuard`, `ToolPolicy` |
| AUD-104 | gate | no | `ToolPolicyGuard`, `LLMToolFilter` |
| AUD-105 | budget | yes | `ToolPolicyGuard` |
| AUD-106 | none | no | -- |
| AUD-107 | none | no | -- |
| AUD-108 | detector | no | `aisg audit` |
| AUD-201 | gate | yes | `ToolPolicyGuard` |
| AUD-202 | gate | yes | `ToolPolicyGuard` |
| AUD-203 | gate | no | `ToolPolicyGuard` |
| AUD-301 | gate | no | `ToolPolicyGuard`, `PIIDetector` |
| AUD-302 | detector | no | `PromptInjectionGuard` |
| AUD-303 | detector | no | `PromptInjectionGuard` |
| AUD-401 | gate | no | `ToolPolicyGuard`, `LLMToolFilter` |
| AUD-402 | gate | no | `ToolPolicyGuard` |
| AUD-403 | gate | no | `ToolPolicyGuard`, `LLMToolFilter` |
| AUD-404 | none | no | -- |
| AUD-405 | gate | no | `ToolPolicyGuard`, `ToolPolicy` |
| AUD-406 | gate | no | `ToolPolicyGuard` |
| AUD-501 | detector | no | `aisg audit` |
| AUD-502 | detector | no | `aisg audit` |
| AUD-503 | detector | no | `PIIDetector`, `PIIRestorer` |
| AUD-504 | detector | no | `PIIDetector`, `AuditLogger` |
| AUD-505 | detector | no | `PIIDetector` |
| AUD-601 | measurement | no | `aisg measure` |
| AUD-602 | detector | no | `aisg audit` |
| AUD-603 | none | no | -- |
| AUD-604 | detector | no | `PromptInjectionGuard` |
| AUD-605 | detector | no | `aisg audit` |
| AUD-606 | detector | no | `aisg audit` |
| AUD-701 | record | yes | `TelemetryProvider` |
| AUD-702 | record | no | `AuditLogger` |
| AUD-703 | document | no | `aisg init` |
| AUD-801 | measurement | yes | `aisg measure` |
| AUD-802 | gate | yes | `GuardrailPipeline`, `LLMToolFilter` |
| AUD-803 | measurement | no | `PromptInjectionGuard`, `aisg measure` |
| AUD-804 | gate | yes | `LLMJudgeBase` |
| AUD-805 | detector | no | `LLMOutputFilter`, `aisg measure` |
| AUD-901 | measurement | yes | `aisg measure`, `aisg probe` |
| AUD-902 | measurement | no | `aisg probe`, `aisg measure` |
| AUD-903 | measurement | yes | `aisg measure`, `aisg probe` |
| AUD-904 | measurement | no | `aisg measure` |
| AUD-1001 | document | yes | `aisg init` |
| AUD-1002 | document | no | `aisg init` |
| AUD-1003 | document | no | `aisg init` |

Eleven rules have `same control: yes`. Those are the only rows the plan table can assign to
"package", and only when the finding's language is Python (by the file's extension; else
its unit's language; else, for a repo-scoped finding, the root unit's) and the file is not
a protected path (host permission and MCP files, CI workflows and pipeline files, `.env*`,
secrets files, `.pre-commit-config.yaml`). An accepted finding is not package work either;
it sits under the accepted group. Every one of the eleven still has a "leaves open" text;
read it out with the diff.

## Alternatives table

The report's `recommendation.alternatives` names projects from this table. Say plainly when
one of them fits the codebase better than this package.

| project | what it gives you | what it does not cover |
|---|---|---|
| this package (`aisg`) | `ToolPolicyGuard` (per-role allow/deny, argument globs, approval callback, session budget), `PIIDetector` (redact / block / flag / tokenize with restore), `PromptInjectionGuard` (mention-vs-use aware), `RateLimiter`, `LLMToolFilter` (judge with a fail-closed high-risk list), `AuditLogger`, `TelemetryProvider`, YAML presets, `aisg measure` to score a pipeline against attack and benign corpora | sandboxing, host permission files, dependency vulnerabilities, package pinning, evals of the model itself |
| NeMo Guardrails | Colang flows for input, output, dialog and tool-call rails; a config directory the app loads; good when the conversation shape itself needs control | not a process sandbox, not a permission system; detectors and flows run in-process with the app |
| Guardrails AI | validators from a hub applied to inputs and outputs, structured-output validation, re-ask on failure | tool gating, budgets, host permissions |
| LLM Guard | input and output scanners (prompt injection, secrets, PII anonymise and de-anonymise, toxicity, banned topics, relevance) | gates; it is a scanner library and says so |
| Llama Guard | a classifier model over prompts and responses against a hazard taxonomy; runs behind an inference host | anything that is not a classification: no gating, no budgets, adds a model call per check; its own failure mode must be fail-closed for high-risk tools |

## P1 Blast radius

### AUD-101 Host permission over-grant (critical / medium / low)

- Control (T1): remove `Bash`, `Bash(*)` and shell-family wildcards from `permissions.allow`;
  list the exact commands instead. Remove `defaultMode: "bypassPermissions"`,
  `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, `yolo`, `autoAccept`,
  `--dangerously-skip-permissions` from CI and hooks. Sub-finding `/interpreter`
  (`Bash(python*)`, `Bash(npx*)`, ...): narrow to the scripts actually needed. Sub-finding
  `/docs`: a README that mentions the flag; usually no change.
- Rule 4 of SKILL.md applies: show the diff, wait for approval.
- Package: none. `ToolPolicyGuard` only sees tools dispatched through `run_processing`; it
  is not on the host-grant path.
- Mapping: ASI03, ASI05, LLM06, EU:Art.14, NIST:GOVERN-1.7.

### AUD-102 Agent loop without an iteration cap (high)

- Control (T2): a named cap in the enclosing function (`max_iterations`, `max_turns`,
  `recursion_limit`, `deadline`) checked every iteration; a wall-clock deadline for loops
  that wait on tools.
- Package: budget, same control: no, `RateLimiter`. Leaves open: RateLimiter is a
  per-identity sliding window on requests and words; it does not cap loop iterations. The
  loop cap is `max_iterations` in your loop.
- Mapping: ASI08, LLM10, EU:Art.15, NIST:MANAGE-2.3.

### AUD-103 Fetch/browse tool without a URL allowlist (high)

- Control (T2): parse the URL, compare the host against an allowlist, refuse everything
  else; `ToolPolicy.argument_rules` with a `https://trusted.example/*` glob is the one-line
  form in this package. Add a size cap and a timeout on the fetch.
- Package: gate, same control: yes, `ToolPolicyGuard`, `ToolPolicy`. Leaves open:
  `argument_rules` apply only to calls dispatched through `run_processing`. The glob matches
  the argument text; it does not resolve hosts or block private address ranges.
- Mapping: ASI01, ASI02, LLM01, NIST:MAP-5.1.

### AUD-104 Exec tool without sandbox (critical)

- Control (T2): run the command inside a sandbox (container, gVisor, firejail, nsjail, a
  hosted sandbox such as e2b or modal) with no network by default and a read-only mount;
  never `shell=True`; argv only. If a sandbox is out of reach today, gate the tool
  (AUD-201) and say the sandbox is still owed.
- Package: gate, same control: no, `ToolPolicyGuard`, `LLMToolFilter`. Leaves open: A
  sandbox is structural. A gate in front of the tool and a fail-closed judge decide whether
  a command runs; neither confines what it can reach once it does.
- Mapping: ASI05, ASI02, LLM06, EU:Art.15, NIST:MANAGE-2.3.

### AUD-105 No per-session tool budget (medium)

- Control (T2): `ToolPolicyGuard(max_tool_calls_per_session=N, max_calls_per_tool=M)`
  with one context dict reused across the session; or a counter in the agent state
  checked before every dispatch.
- Package: budget, same control: yes, `ToolPolicyGuard`. Leaves open:
  `max_tool_calls_per_session` and `max_calls_per_tool` count only calls dispatched through
  `run_processing` with the shared context dict. A tool called directly is not counted.
- Mapping: ASI08, LLM10, NIST:MANAGE-2.3.

### AUD-106 Broad credentials in agent scope (high)

- Control (T1): give the agent process its own scoped credential (read-only DB role,
  fine-grained token, a bucket-scoped key) and move broad ones out of its env. A finding with
  `gitignored: true` came from a developer machine's `.env`; say so.
- Rule 4 of SKILL.md applies.
- Package: none. `PIIDetector` has no credential entity and there is no "secret guard"; the
  control is a scoped token.
- Mapping: ASI03, LLM02, LLM06, NIST:GOVERN-6.1.

### AUD-107 No kill switch (medium)

- Control (T2): one env var or settings field read at runtime at the top of every request
  or loop iteration (`AGENT_DISABLED`, `settings.kill_switch`) that stops dispatch when
  set. A declaration nobody reads does not count; sub-finding `/inert` means the target
  declares `GUARDRAILS_DISABLE_ALL`, which this package does not honour.
- Package: none. No kill-switch guard exists and `GUARDRAILS_DISABLE_ALL` is inert; the
  control is a real disable path.
- Mapping: ASI10, ASI08, EU:Art.14, NIST:MANAGE-2.4.

### AUD-108 Unsafe hooks / CI supply (high)

- Control (T1): replace `curl ... | sh`, `npx -y <pkg>`, `pip install` from `http://` and
  `--trusted-host` with pinned, checksummed installs; keep hooks to commands the repo ships.
- Rule 4 of SKILL.md applies (CI workflows and host hook files).
- Package: detector, same control: no, `aisg audit`. Leaves open: The audit in CI reports a
  regression after the fact. Pinning the hook and dropping the network step is the control;
  the audit changes neither.
- Mapping: ASI04, LLM03, NIST:GOVERN-6.1.

## P2 Irreversible-action gates

### AUD-201 Irreversible tool with no approval gate (critical)

- Control (T2): an approval step on the tool's call path: `ToolPolicyGuard(require_approval=
  [...], approval_callback=...)`, LangGraph `interrupt_before` with a checkpointer, an
  agent-framework `needs_approval` / `human_input` flag, or a queue a human drains. The gate
  must be able to say no; a callback that always returns true is AUD-202.
- Package: gate, same control: yes, `ToolPolicyGuard`. Leaves open: `require_approval` needs
  a real `approval_callback`, and only tools dispatched through `run_processing` with the
  tool call passed explicitly reach it. Action.HUMAN sets `passed=False`, not `blocked`; the
  caller has to honour it.
- Mapping: ASI02, ASI09, LLM06, EU:Art.14, NIST:MANAGE-2.4.

### AUD-202 Inert or bypassed gate (critical)

- Control (T2): supply the missing half: the `approval_callback` for `require_approval`, the
  `checkpointer` for `interrupt_before`; delete `auto_approve=True`,
  `human_in_the_loop=False`, `confirm=False` on destructive wrappers. `aisg measure` can show
  that the gate returns a decision; the audit cannot.
- Package: gate, same control: yes, `ToolPolicyGuard`. Leaves open: A bypass flag in code or
  config, and a LangGraph interrupt compiled without a checkpointer, are removed by hand.
  The guard adds a gate; it does not delete the one that is inert.
- Mapping: ASI09, ASI02, LLM06, EU:Art.14, NIST:MANAGE-2.4.

### AUD-203 No dry-run / idempotency on irreversible tool (medium)

- Control (T3): a `dry_run` parameter that returns the planned effect without performing it;
  an idempotency key on every external write so a retried loop cannot double-charge or
  double-send.
- Package: gate, same control: no, `ToolPolicyGuard`. Leaves open: A `dry_run` parameter and
  an idempotency key are changes inside the tool. The gate decides whether the call is made;
  it does not make a repeated call safe.
- Mapping: ASI02, LLM06, NIST:MANAGE-2.3.

## P3 Trust-boundary separation

### AUD-301 LETHAL TRIFECTA (critical)

- Control (T3): split the scope so no single function or unit holds all three legs. Common
  splits: a reader agent with private data and no external action feeding a writer agent
  that sees only a structured, validated summary; untrusted content quarantined into a
  separate model call whose output is data, not instructions; every external action behind
  an approval gate (AUD-201) with `PIIDetector(action="tokenize")` in front of the model so
  private values never reach it in the first place.
- Package: gate, same control: no, `ToolPolicyGuard`, `PIIDetector`. Leaves open: The
  control is a structural split between the scope that reads untrusted content and the scope
  that acts. A gate on the action plus a detector on ingress lowers the odds of one bad
  turn; all three legs still meet in one loop.
- Mapping: ASI01, ASI02, ASI06, LLM01, LLM02, LLM06, EU:Art.9, EU:Art.15, NIST:MAP-5.1,
  NIST:MANAGE-2.2.

### AUD-302 Untrusted content concatenated into a prompt (high)

- Control (T2): delimit and label untrusted spans, put them in a user turn rather than the
  system prompt, run a sanitiser (`PromptInjectionGuard`, LLM Guard, Lakera, Rebuff) on the
  path, and keep instructions and data in separate message parts. A detector alone is not
  enough when the model can act (see AUD-201).
- Package: detector, same control: no, `PromptInjectionGuard`. Leaves open: Delimiting the
  untrusted span and keeping it in the user turn is the control. The guard lowers the
  probability that an injection lands; it does not change what an injection that lands can
  do.
- Mapping: ASI01, ASI06, LLM01, EU:Art.15, NIST:MAP-5.1, NIST:MEASURE-2.7.

### AUD-303 System prompt built from request data (high)

- Control (T3): the system prompt is a constant; per-request values go into a user message
  or a structured field the model reads as data.
- Package: detector, same control: no, `PromptInjectionGuard`. Leaves open: A static system
  prompt is the control. Running the guard over the request field screens what goes in; the
  system prompt is still built from it.
- Mapping: ASI01, LLM01, LLM07, EU:Art.15, NIST:MAP-5.1, NIST:MEASURE-2.7.

## P4 Output-sink taint

All six: the control is the same shape. Model output is data; it never becomes a command,
a query string, markup, a URL or a path without going through a validator that knows the
sink. A `match_kind: grep` finding is co-located and unverified; say so, then look at the
code before proposing a change.

### AUD-401 Model output -> shell (critical)

- Control (T3): no shell; argv arrays only (`subprocess.run([...])`, `execFile`,
  `exec.Command(name, args...)`); an allowlist of commands the model may name; a sandbox
  (AUD-104) around the rest.
- Package: gate, same control: no, `ToolPolicyGuard`, `LLMToolFilter`. Leaves open: Argv
  lists, `shell=False` and a sandbox are changes at the sink. The gate decides whether the
  call is dispatched; the string still reaches a shell when it is.
- Mapping: ASI02, ASI05, LLM05, LLM06, EU:Art.15, NIST:MANAGE-2.2, NIST:MEASURE-2.7.

### AUD-402 Model output -> eval / dynamic import (critical)

- Control (T3): remove `eval` / `exec` / `new Function` / `vm.runIn*` on model-derived
  strings; parse a structured format (`json.loads` into a schema) and dispatch by name from
  a fixed table.
- Package: gate, same control: no, `ToolPolicyGuard`. Leaves open: Removing eval/exec from
  the path is the control. A gate on the tool that wraps it decides whether the tool runs,
  not what the interpreter evaluates.
- Mapping: ASI02, ASI05, LLM05, LLM06, EU:Art.15, NIST:MANAGE-2.2.

### AUD-403 Model output -> SQL (critical)

- Control (T3): parameterised queries only; a read-only role for the agent's connection;
  never format a model string into SQL text.
- Package: gate, same control: no, `ToolPolicyGuard`, `LLMToolFilter`. Leaves open:
  Parameterised queries are the control. A gate and a fail-closed judge decide whether the
  call is made; the text is still a query once it is.
- Mapping: ASI02, LLM05, LLM06, EU:Art.15, NIST:MANAGE-2.2.

### AUD-404 Model output -> HTML (high)

- Control (T3): escape by default (`html.escape`, auto-escaping templates, `html/template`,
  React text nodes) and sanitise the rare rich-text case (DOMPurify, bleach); never
  `innerHTML =`, `dangerouslySetInnerHTML`, `mark_safe(`, `template.HTML(` on model output.
- Package: none. There is no `OutputSanitizer`; `llm_output_filter` is a judge and
  `toxicity_output` a pattern list, and neither escapes HTML. The control is
  escape/sanitise/CSP at the sink.
- Mapping: LLM05, LLM02, EU:Art.15, NIST:MEASURE-2.7.

### AUD-405 Model output -> URL / request (high)

- Control (T3): parse, then allowlist the host (AUD-103); no redirects to private ranges;
  timeouts and size caps; the request is a tool with a gate when it writes.
- Package: gate, same control: no, `ToolPolicyGuard`, `ToolPolicy`. Leaves open: The glob
  matches the argument text before dispatch. Resolving the host, rejecting private ranges
  and stripping credentials from the request happen at the resolver and stay open.
- Mapping: ASI02, LLM05, LLM06, EU:Art.15, NIST:MANAGE-2.2.

### AUD-406 Model output -> filesystem path (high)

- Control (T3): resolve against a fixed base directory and reject anything outside it; write
  only under a work directory; no `shutil.rmtree` on model-derived paths.
- Package: gate, same control: no, `ToolPolicyGuard`. Leaves open: Path confinement
  (resolve, then check the root) is the control. The gate asks before a write tool runs; it
  does not check where the path points.
- Mapping: ASI02, LLM05, LLM06, EU:Art.15, NIST:MANAGE-2.2.

## P5 Secrets and PII

### AUD-501 Secret literal in source (critical)

- Control (T1): move the value to the environment or a secrets manager, rotate it (a
  committed key is compromised regardless of history rewriting), add a pre-commit secret
  scanner. A `bucket: measured` finding was corroborated by gitleaks or detect-secrets.
- Rule 4 of SKILL.md applies.
- Package: detector, same control: no, `aisg audit`. Leaves open: Moving the value out,
  rotating it and adding a pre-commit scanner are the control. The audit in CI reports a
  value that is already committed.
- Mapping: ASI03, LLM02, EU:Art.15, NIST:MEASURE-2.7, NIST:GOVERN-6.1.

### AUD-502 Secret in MCP / host config (critical)

- Control (T1): reference the variable (`"env": {"API_KEY": "${API_KEY}"}` or the host's
  own env passthrough) instead of the literal; rotate.
- Rule 4 of SKILL.md applies.
- Package: detector, same control: no, `aisg audit`. Leaves open: Replacing the value with a
  `${VAR}` reference and rotating it are the control. The audit in CI reports the literal;
  it does not move it.
- Mapping: ASI03, ASI04, LLM02, EU:Art.15, NIST:MEASURE-2.7, NIST:GOVERN-6.1.

### AUD-503 Secret or PII bound into a prompt (high)

- Control (T2): `PIIDetector(action="tokenize")` on the input stage and restore on output;
  never bind `os.environ[...]` or a secrets-manager value into prompt text; pass credentials
  to tools out of band.
- Package: detector, same control: no, `PIIDetector`, `PIIRestorer`. Leaves open: Tokenising
  covers the PII half only: `action="tokenize"` is regex-only and matches the detector's own
  entity types. A credential passed into the prompt has no entity type here and stays open
  until it is passed at call time.
- Mapping: ASI03, LLM02, LLM07, EU:Art.10, EU:Art.15, NIST:MEASURE-2.7.

### AUD-504 Verbatim prompt/response logging (medium)

- Control (T2): log hashes and lengths (`AuditLogger(include_content_hash=True)`), or
  redact through `PIIDetector` before logging; never `print(response)` in production paths.
- Package: detector, same control: no, `PIIDetector`, `AuditLogger`. Leaves open: Redaction
  in front of the logger lowers what a log line exposes; the verbatim log call is the
  control and stays where it is. AuditLogger hashes only the pipeline's own records, not
  your log lines.
- Mapping: LLM02, EU:Art.10, EU:Art.12, NIST:MEASURE-2.10, NIST:GOVERN-1.6.

### AUD-505 Literal PII in prompts / fixtures / logs (low)

- Control (T2): replace with placeholders (`user@example.com`, `555-01xx`, RFC 5737 IPs);
  delete committed log samples; scrub eval datasets. Snippets in the report are redacted.
- Package: detector, same control: no, `PIIDetector`. Leaves open: Replacing the literal
  values in the fixtures is the control. The detector finds them in a corpus; the file is
  edited by hand.
- Mapping: LLM02, EU:Art.10, NIST:MEASURE-2.10, NIST:MAP-4.1.

## P6 Supply chain

### AUD-601 Unpinned model id (medium)

- Control (T1): a dated or versioned model id (`-2025-..`, a snapshot name, a digest tag),
  recorded in one place; `aisg measure` and `aisg probe` reports carry `models[]` so AUD-903
  can see a change.
- Package: measurement, same control: no, `aisg measure`. Leaves open: Pinning the id is an
  edit to the call site. `aisg measure` records the id it saw in its report, so a later
  drift is visible; it does not pin anything.
- Mapping: ASI04, LLM03, EU:Art.9, EU:Art.15, NIST:MANAGE-3.1, NIST:GOVERN-6.1.

### AUD-602 Unpinned MCP server / bootstrap (high)

- Control (T1): `npx -y pkg@1.2.3`, `uvx --from 'pkg==1.2.3'`, `pip install 'pkg==1.2.3'`,
  `docker run image@sha256:...`; a lockfile for MCP servers where the host supports one.
- Package: detector, same control: no, `aisg audit`. Leaves open: Pinning the MCP command
  and keeping a lockfile is the control. The audit in CI reports an unpinned entry; it does
  not pin it.
- Mapping: ASI04, LLM03, EU:Art.15, NIST:GOVERN-6.1, NIST:MANAGE-3.1.

### AUD-603 Remote or plaintext MCP transport (high)

- Control (T1): loopback or `https://` with an authenticated endpoint; name known-good
  internal hosts with `--trusted-mcp-hosts` so they stop counting as untrusted.
- Package: none. `--trusted-mcp-hosts` is an audit input after a documented review, not a
  control.
- Mapping: ASI04, ASI07, LLM03, EU:Art.15, NIST:MEASURE-2.7, NIST:MAP-5.1.

### AUD-604 MCP tool-description poisoning (critical)

- Control (T1): remove the server or pin it to a reviewed version; treat tool descriptions
  as untrusted input the model reads on every turn. This rule is never downgraded as a
  "mention": a description that discusses an injection phrase still carries it into context.
- Package: detector, same control: no, `PromptInjectionGuard`. Leaves open: Running the
  guard over tool descriptions at registration screens the text once. Removing the server,
  or pinning a reviewed version, is the control.
- Mapping: ASI01, ASI04, ASI06, LLM01, LLM03, EU:Art.15, NIST:MEASURE-2.7.

### AUD-605 Unpinned weights / `trust_remote_code` (high)

- Control (T1): `revision=` on `from_pretrained` and `hf_hub_download`; drop
  `trust_remote_code=True` or vendor the code; `torch.load(..., weights_only=True)`; no
  `pickle.load` on model files.
- Package: detector, same control: no, `aisg audit`. Leaves open: Verified, pinned weights
  are the control. The audit in CI reports the unpinned load; it never opens or checks the
  artefact.
- Mapping: ASI04, ASI05, LLM03, LLM04, EU:Art.15, NIST:GOVERN-6.1.

### AUD-606 Dependency vulnerabilities (high; per tool)

- Control (T1): upgrade or pin as the scanner advises; this is the one rule that is
  `MEASURED` (pip-audit, npm audit, osv-scanner ran now). When it is UNKNOWN, the scanner
  was not on PATH; install it and rerun.
- Package: detector, same control: no, `aisg audit`. Leaves open: The audit folds in the
  output of a scanner that is already installed; it installs nothing and queries no advisory
  feed itself. Upgrading is the control.
- Mapping: ASI04, LLM03, EU:Art.15, NIST:GOVERN-6.1, NIST:MANAGE-3.1.

## P7 Observability, audit log, incident path

### AUD-701 No observability on LLM calls (medium; `/apm-only` low)

- Control (T2): tracing that records prompts, tool calls and model ids: `TelemetryProvider`
  from this package (OTel GenAI attributes), Langfuse, LangSmith, Traceloop, Phoenix, Weave.
  Generic APM (Sentry, Datadog) does not satisfy the rule and yields `/apm-only`.
- Package: record, same control: yes, `TelemetryProvider`. Leaves open: Only calls that go
  through `run_full` are traced; an LLM call made outside the pipeline is not.
  TelemetryProvider sets the process-global tracer and meter providers, so construct it once
  per process.
- Mapping: ASI08, ASI10, LLM10, EU:Art.12, EU:Art.26, NIST:MEASURE-2.4, NIST:MANAGE-4.1.

### AUD-702 No tool-call audit log (high)

- Control (T2): an append-only record per tool call (who, what, arguments hash, decision,
  outcome): `AuditLogger` attached to the pipeline, structlog, or the shape in
  `apply/generic.md`.
- Package: record, same control: no, `AuditLogger`. Leaves open: An AuditRecord carries the
  stage, content hashes and the checks that ran; it does not carry the tool name, its
  arguments, the caller or the outcome. log() is async but writes with blocking I/O.
- Mapping: ASI02, ASI10, LLM06, EU:Art.12, EU:Art.14, NIST:MEASURE-2.4, NIST:MANAGE-4.1.

### AUD-703 No incident path (low)

- Control (T2): a `SECURITY.md` with a contact and a response window, an incident runbook,
  `incident_contact` on the system card.
- Package: document, same control: no, `aisg init`. Leaves open: `incident_contact` on the
  card is a place to write the contact down. The runbook -- who is paged, how harm is
  reported, how the system is stopped -- is the control and is written by you.
- Mapping: ASI08, ASI10, EU:Art.26, EU:Art.73, NIST:GOVERN-4.3, NIST:MANAGE-4.3.

## P8 Detection guards

### AUD-801 Guard present but unmeasured (medium)

- Control (T2): run `aisg measure --config <pipeline.yaml>` (phase 5, with approval) or an
  equivalent eval, commit the report, and keep it newer than the guard config. A guard with
  no measurement is a claim.
- Package: measurement, same control: yes, `aisg measure`. Leaves open: Only guards
  registered with this package can be measured in-process; a third-party guard needs its own
  harness. The numbers go into a Profile from the measure output and are never typed in by
  hand.
- Mapping: ASI01, LLM01, EU:Art.9, EU:Art.15, NIST:MEASURE-2.5, NIST:MEASURE-2.7.

### AUD-802 Guard configured fail-open (high)

- Control (T1): `fail_open: false`; no `except Exception: pass` around a guard call; for LLM
  judges, a fail-closed list for high-risk tools (`LLMToolFilter.high_risk_fail_closed`).
- Package: gate, same control: yes, `GuardrailPipeline`, `LLMToolFilter`. Leaves open:
  `fail_open: false` on the pipeline and `high_risk_fail_closed` on the tool filter cover
  the package's own guards. A try/except that swallows a guard's error in your own code is
  untouched and is removed by hand.
- Mapping: ASI01, ASI08, LLM01, LLM05, EU:Art.15, NIST:MEASURE-2.7, NIST:MANAGE-2.3.

### AUD-803 Reported guard below threshold (high, `REPORTED <age>`)

- Control (T1): retune or replace the guard named in `threshold_failures`, re-measure, or
  disable it and say what replaces it. The finding is as old as the report it came from.
- Package: measurement, same control: no, `PromptInjectionGuard`, `aisg measure`. Leaves
  open: Re-tuning is a judgement made from the measure output: `sensitivity` exists only on
  PromptInjectionGuard, and every other guard is re-tuned by editing its patterns or
  switching it off. The new report has to be generated again.
- Mapping: ASI01, LLM01, EU:Art.9, EU:Art.15, NIST:MEASURE-2.5, NIST:MANAGE-1.3.

### AUD-804 LLM judge without credentials or timeout (medium)

- Control (T1): declare the key the judge needs, set a timeout, and decide what happens
  when it fails (fail-closed for high-risk tools). Without credentials the judge silently
  costs seconds per request and returns its fallback.
- Package: gate, same control: yes, `LLMJudgeBase`. Leaves open: `timeout` and
  `fail_open=False` apply to this package's judges only; a judge from another library keeps
  its own defaults. Declaring the key in .env.example is an edit to your repository.
- Mapping: ASI08, LLM10, EU:Art.15, NIST:MEASURE-2.7, NIST:MANAGE-2.3.

### AUD-805 Keyword-only content filter (low)

- Control (T2): keep the list if it is cheap, but put a measured guard beside it
  (`PromptInjectionGuard`, a toxicity classifier, LLM Guard) and measure both.
- Package: detector, same control: no, `LLMOutputFilter`, `aisg measure`. Leaves open:
  LLMOutputFilter is a judge: it needs credentials, a timeout and a fail-closed setting
  (AUD-804) before it adds anything. toxicity_output is a pattern list like the one reported
  here, not a classifier.
- Mapping: ASI01, LLM01, LLM05, EU:Art.15, NIST:MEASURE-2.7.

## P9 Evaluation loop

### AUD-901 No evals in CI (high)

- Control (T2): a CI step that runs `aisg measure`, promptfoo, deepeval, inspect_ai, garak,
  pyrit or an equivalent against a committed corpus, with a threshold that fails the build.
- Package: measurement, same control: yes, `aisg measure`, `aisg probe`. Leaves open: The CI
  workflow edit is yours to make, and `aisg probe` needs an endpoint that is being served. A
  run on every change is the control; what the run reports is a separate question.
- Mapping: ASI01, LLM01, EU:Art.9, EU:Art.15, NIST:MEASURE-2.5, NIST:MEASURE-2.7.

### AUD-902 Probe report shows failed / inconclusive / errored / skipped cases (high / medium / low, `REPORTED <age>`)

- Control (T2): fix the guard for `failed`; rerun with a working endpoint for `errors`;
  add `--system-canary` for `skipped`; read the `inconclusive` cases by hand (the endpoint
  reflected the payload). Only `passed` means passed.
- Package: measurement, same control: no, `aisg probe`, `aisg measure`. Leaves open: A new
  run shows what still gets through. Fixing the guard or the endpoint behind each case that
  got through is the work, and it is done by hand.
- Mapping: ASI01, ASI02, LLM01, LLM07, EU:Art.15, NIST:MEASURE-2.7, NIST:MANAGE-2.2.

### AUD-903 Model changed since last report (medium, `REPORTED <age>`)

- Control (T2): re-measure after every model id change; keep `models[]` in the report in
  step with the code. An undated report yields "report age unknown" under UNKNOWN.
- Package: measurement, same control: yes, `aisg measure`, `aisg probe`. Leaves open:
  Regenerating the report against the current model id and config is the control. The report
  goes stale again on the next model or config change.
- Mapping: EU:Art.9, EU:Art.15, NIST:MEASURE-2.5, NIST:MANAGE-4.1.

### AUD-904 No benign corpus (medium)

- Control (T2): add benign cases that a naive guard would flag (security questions, test
  code quoting an attack, docs with `### System:` headings) and assert they survive.
  Attacks alone make "block everything" the optimal guard.
- Package: measurement, same control: no, `aisg measure`. Leaves open: aisg measure scores
  the package guards against its own benign corpus. Benign cases in your own eval config are
  the control this rule looks for, and adding them is by hand.
- Mapping: LLM01, EU:Art.15, NIST:MEASURE-2.5, NIST:MEASURE-2.6.

## P10 Governance

### AUD-1001 No system card (low)

- Control (T2): `aisg init --defaults` writes `ai-system-card.yaml`; fill in the fields it
  has: system id, name and purpose, role, `risk_tier` (with its caveat),
  `annex_iii_category`, `affected_persons`, deployment, `incident_contact`. There is no
  model or data field; a blank or `TODO`-prefixed `incident_contact` still counts as absent
  for AUD-703, whose snippet then says the card `has an unfilled incident_contact`.
- Package: document, same control: yes, `aisg init`. Leaves open: Every field in the card is
  the operator's own assertion; aisg init writes the file and the risk-tier caveat, nothing
  more. Whether the entries are true is not something the tool can check.
- Mapping: EU:Art.11, EU:Art.13, NIST:GOVERN-1.2, NIST:MAP-1.1.

### AUD-1002 Risk tier undetermined (info)

- Control (T2): the operator records their determination on the system card. Classification
  under Art. 6 / Annex III is a legal determination made by the operator, not a tool output;
  the audit does not infer a tier and you must not either.
- Package: document, same control: no, `aisg init`. Leaves open: Classification is a legal
  determination the operator makes; aisg init only records the answer. The determination
  itself is outside the package.
- Mapping: EU:Art.6, EU:Art.9, NIST:MAP-1.1, NIST:MAP-5.1.

### AUD-1003 Annex III domain keywords without card category (info)

- Control (T2): if the prompts really do cover such a domain, record the category on the
  system card so the operator's determination is visible; if they do not, say so on the
  card. This never fires on README or CHANGELOG text.
- Package: document, same control: no, `aisg init`. Leaves open: Whether the prompts serve
  an Annex III domain is a legal determination the operator makes; aisg init only records
  the category or a reason for none.
- Mapping: EU:Art.6, EU:Art.11, NIST:MAP-1.1, NIST:MAP-5.1.
