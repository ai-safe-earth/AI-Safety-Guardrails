"""
src/aisg/devtools/probe.py
--------------------------
`aisg probe <url>` -- send a fixed attack corpus to a live HTTP endpoint and
report which payloads got through.

    aisg probe http://localhost:8000/chat \\
        --request-template '{"message":"{{payload}}"}' \\
        --response-path '$.response'

What this is:  a deterministic regression harness. Fixed payloads, fixed
               detectors, no LLM anywhere in the loop. The same corpus against
               the same endpoint gives the same verdicts.

What this is NOT:  evidence of compliance. A clean run means these specific
                   payloads did not produce these specific markers. It says
                   nothing about payloads not in the corpus, and nothing about
                   any legal obligation. The report never uses the word
                   "compliant" and neither should anything built on it.

Probing a host you are not authorised to test may be unlawful. Non-loopback
targets are refused unless --i-have-authorization is passed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = "aisg/1"
PLACEHOLDER = "{{payload}}"
DEFAULT_REPORT = "probe-report.json"

__all__ = ["main", "build_parser", "load_corpus", "run_case", "detector_hit", "is_loopback"]


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@dataclass
class ProbeCase:
    id: str
    family: str
    payload: str
    expected_behaviour: str
    detector_type: str
    detector_value: str
    detector_flags: str = ""
    seed_pattern: str = ""
    note: str = ""


@dataclass
class CaseResult:
    case: ProbeCase
    status: str  # passed | failed | error
    http_status: int | None = None
    response_text: str = ""
    latency_ms: float = 0.0
    error: str = ""
    matched: str = ""
    extras: dict = field(default_factory=dict)


VALID_BEHAVIOURS = {"block", "sanitize", "refuse"}
VALID_DETECTORS = {"substring", "regex"}

# Status codes that plausibly mean "the endpoint rejected this payload" -- a
# guard doing its job. The detector still runs on the body, because an error
# page that echoes the payload back is itself a leak.
REJECTION_CODES = {400, 403, 406, 409, 413, 422}

# Everything else non-2xx means the case was NOT exercised: wrong URL, missing
# auth, throttling, a broken server. Calling that "passed" would be a false
# clean bill of health, so it is reported as an error instead.


def load_corpus(families: list[str] | None = None) -> list[ProbeCase]:
    """Load every probes/*.yaml shipped with the package."""
    try:
        import yaml
    except ModuleNotFoundError:  # pragma: no cover - pyyaml is a core dep
        raise SystemExit("pyyaml is required: pip install pyyaml") from None

    wanted = {f.strip().lower() for f in families} if families else None
    cases: list[ProbeCase] = []
    seen_ids: set[str] = set()

    root = resources.files("aisg.probes")
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if not entry.name.endswith(".yaml"):
            continue
        data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
        family = data.get("family") or entry.name[: -len(".yaml")]
        if wanted is not None and family.lower() not in wanted:
            continue
        for raw in data.get("cases", []):
            det = raw.get("detector") or {}
            dtype = det.get("type", "substring")
            if dtype not in VALID_DETECTORS:
                raise SystemExit(f"{entry.name}: case {raw.get('id')} has detector type {dtype!r}")
            behaviour = raw.get("expected_behaviour", "block")
            if behaviour not in VALID_BEHAVIOURS:
                raise SystemExit(
                    f"{entry.name}: case {raw.get('id')} has expected_behaviour {behaviour!r}"
                )
            cid = str(raw.get("id", ""))
            if not cid:
                raise SystemExit(f"{entry.name}: a case is missing its id")
            if cid in seen_ids:
                raise SystemExit(f"duplicate case id {cid!r}")
            seen_ids.add(cid)
            cases.append(
                ProbeCase(
                    id=cid,
                    family=family,
                    payload=raw["payload"],
                    expected_behaviour=behaviour,
                    detector_type=dtype,
                    detector_value=str(det.get("value", "")),
                    detector_flags=str(det.get("flags", "") or ""),
                    seed_pattern=str(raw.get("seed_pattern", "") or ""),
                    note=str(raw.get("note", "") or ""),
                )
            )
    if wanted is not None and not cases:
        known = sorted(available_families())
        raise SystemExit(f"--families matched nothing. Available: {', '.join(known)}")
    return cases


def available_families() -> set[str]:
    try:
        import yaml
    except ModuleNotFoundError:  # pragma: no cover
        return set()
    out = set()
    for entry in resources.files("aisg.probes").iterdir():
        if entry.name.endswith(".yaml"):
            data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
            out.add(data.get("family") or entry.name[: -len(".yaml")])
    return out


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detector_hit(case: ProbeCase, text: str) -> str:
    """
    Return the matched text if the attack SUCCEEDED, else "".

    A hit means the marker the case looks for is present in the reply -- the
    payload got through. No match is the good outcome.
    """
    if not text or not case.detector_value:
        return ""
    if case.detector_type == "substring":
        return case.detector_value if case.detector_value in text else ""
    flags = re.IGNORECASE if "i" in case.detector_flags.lower() else 0
    try:
        m = re.search(case.detector_value, text, flags)
    except re.error:
        return ""
    return m.group(0) if m else ""


# ---------------------------------------------------------------------------
# Request construction / response extraction
# ---------------------------------------------------------------------------


def build_body(template: str, payload: str) -> bytes:
    """
    Substitute the payload into the JSON template.

    The template is parsed FIRST and the placeholder replaced inside decoded
    string values, then re-serialised. Substituting into the raw text would
    produce invalid JSON the moment a payload contained a quote, a backslash or
    a newline -- and most of this corpus does.
    """
    try:
        parsed = json.loads(template)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--request-template is not valid JSON: {exc}") from None

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return node.replace(PLACEHOLDER, payload)
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    return json.dumps(walk(parsed)).encode("utf-8")


_PATH_TOKEN = re.compile(r"\[(\d+)\]|\['([^']*)'\]|\[\"([^\"]*)\"\]|\.([^.\[\]]+)|^([^.\[\]]+)")


def extract_path(data: Any, path: str) -> str:
    """
    Read a value out of a JSON response using a small JSONPath subset:
    `$.a.b`, `$.a[0].b`, `$['a']['b']`. No wildcards, filters or recursion --
    deterministic and dependency-free.

    Returns "" when the path does not resolve, and the whole response
    JSON-encoded when `path` is "$" or empty.
    """
    if not path or path == "$":
        return data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)

    rest = path[1:] if path.startswith("$") else path
    node = data
    pos = 0
    while pos < len(rest):
        m = _PATH_TOKEN.match(rest, pos)
        if not m:
            return ""
        idx, sq, dq, dot, bare = m.groups()
        key = idx or sq or dq or dot or bare
        pos = m.end()
        if idx is not None:
            if not isinstance(node, list):
                return ""
            i = int(idx)
            if i >= len(node):
                return ""
            node = node[i]
        else:
            if not isinstance(node, dict) or key not in node:
                return ""
            node = node[key]
    return node if isinstance(node, str) else json.dumps(node, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def is_loopback(url: str) -> bool:
    """True only for loopback targets. Anything unresolvable counts as remote."""
    host = (urlparse(url).hostname or "").strip("[]")
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # A hostname that is not a literal IP. It may well resolve to loopback,
        # but this harness will not guess -- treat it as remote.
        return False


def authorization_error(url: str) -> str:
    host = urlparse(url).hostname or url
    return (
        f"Refusing to probe {host!r}: it is not a loopback address.\n"
        "\n"
        "This command sends prompt-injection, PII and tool-abuse payloads to a\n"
        "live endpoint. Doing that to a host you do not own or have written\n"
        "permission to test may be unlawful, and may trip the target's own\n"
        "abuse detection.\n"
        "\n"
        "Loopback targets (localhost, 127.0.0.0/8, ::1) run without a flag.\n"
        "For anything else, confirm you are authorised:\n"
        "\n"
        f"    aisg probe {url} --i-have-authorization ...\n"
        "\n"
        "A hostname that is not a literal IP is treated as remote even if it\n"
        "resolves to loopback -- pass 127.0.0.1 explicitly if that is what you\n"
        "mean."
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def run_case(
    case: ProbeCase,
    url: str,
    template: str,
    response_path: str,
    timeout: float,
    headers: dict[str, str],
) -> CaseResult:
    body = build_body(template, case.payload)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-supplied
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return CaseResult(
            case=case,
            status="error",
            latency_ms=(time.perf_counter() - started) * 1000,
            error=f"{type(exc).__name__}: {exc}",
        )
    latency = (time.perf_counter() - started) * 1000

    try:
        parsed = json.loads(raw)
        text = extract_path(parsed, response_path)
    except json.JSONDecodeError:
        # Not JSON -- scan the raw body rather than silently seeing nothing.
        text = raw

    matched = detector_hit(case, text)

    if 200 <= status < 300 or status in REJECTION_CODES:
        outcome = "failed" if matched else "passed"
        err = ""
    else:
        # Never report "passed" for a case that never reached a working
        # endpoint -- that is a false clean bill of health.
        outcome = "error"
        err = f"HTTP {status}: endpoint did not process the payload"

    return CaseResult(
        case=case,
        status=outcome,
        error=err,
        http_status=status,
        response_text=text,
        latency_ms=latency,
        matched=matched,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_table(results: list[CaseResult]) -> str:
    rows = [("CASE", "FAMILY", "EXPECTED", "HTTP", "MS", "RESULT")]
    for r in results:
        rows.append(
            (
                r.case.id,
                r.case.family,
                r.case.expected_behaviour,
                str(r.http_status if r.http_status is not None else "-"),
                f"{r.latency_ms:.0f}",
                {"passed": "passed", "failed": "GOT THROUGH", "error": "error"}[r.status],
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    out = []
    for i, row in enumerate(rows):
        out.append("  ".join(cell.ljust(widths[j]) for j, cell in enumerate(row)).rstrip())
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    return "\n".join(out)


def build_report(results: list[CaseResult], url: str, response_path: str, template: str) -> dict:
    families: dict[str, dict] = {}
    for r in results:
        f = families.setdefault(r.case.family, {"sent": 0, "passed": 0, "failed": 0, "errors": 0})
        f["sent"] += 1
        f["passed" if r.status == "passed" else "failed" if r.status == "failed" else "errors"] += 1

    sent = len(results)
    failed = sum(1 for r in results if r.status == "failed")
    errors = sum(1 for r in results if r.status == "error")

    return {
        "schema": SCHEMA_VERSION,
        "tool": {"name": "aisg probe", "corpus_families": sorted(families)},
        "target": {"url": url, "response_path": response_path, "request_template": template},
        "summary": {
            "sent": sent,
            "passed": sent - failed - errors,
            "failed": failed,
            "errors": errors,
        },
        "by_family": families,
        # Deliberately absent: any compliance verdict. This records what these
        # payloads did against this endpoint, nothing more.
        "disclaimer": (
            "Deterministic probe results for a fixed corpus. Not an assessment "
            "of compliance with any regulation, and not evidence of the absence "
            "of vulnerabilities outside this corpus."
        ),
        "cases": [
            {
                "id": r.case.id,
                "family": r.case.family,
                "expected_behaviour": r.case.expected_behaviour,
                "seed_pattern": r.case.seed_pattern,
                "status": r.status,
                "http_status": r.http_status,
                "latency_ms": round(r.latency_ms, 1),
                "detector": {"type": r.case.detector_type, "value": r.case.detector_value},
                "matched": r.matched,
                "error": r.error,
                "response_excerpt": _truncate(r.response_text, 2000),
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisg probe",
        description="Send a fixed attack corpus to an HTTP endpoint and report what got through.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Results are not evidence of compliance. A clean run means these\n"
            "payloads did not produce these markers -- nothing more.\n"
            "\n"
            "Example:\n"
            "  aisg probe http://localhost:8000/chat \\\n"
            '      --request-template \'{"message":"{{payload}}"}\' \\\n'
            "      --response-path '$.response'\n"
        ),
    )
    p.add_argument("url", help="Endpoint to probe (POST, JSON in and out)")
    p.add_argument(
        "--request-template",
        default='{"message":"{{payload}}"}',
        help='JSON body with {{payload}} as the placeholder (default: {"message":"{{payload}}"})',
    )
    p.add_argument(
        "--response-path",
        default="$.response",
        help="JSONPath subset to the reply text, e.g. $.choices[0].message.content",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Max requests per second (0 = no limit)",
    )
    p.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    p.add_argument(
        "--families",
        nargs="*",
        default=None,
        help="Only run these families (default: all)",
    )
    p.add_argument(
        "--header",
        "-H",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra request header; repeatable",
    )
    p.add_argument("--output", "-o", default=DEFAULT_REPORT, help=f"Report path ({DEFAULT_REPORT})")
    p.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm you are authorised to probe a non-loopback host",
    )
    p.add_argument("--list-cases", action="store_true", help="Print the corpus and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_cases:
        for c in load_corpus(args.families):
            print(f"{c.id:<10} {c.family:<26} {c.expected_behaviour:<9} {_truncate(c.payload, 60)}")
        return 0

    if not is_loopback(args.url) and not args.i_have_authorization:
        print(authorization_error(args.url), file=sys.stderr)
        return 2

    headers = {}
    for h in args.header:
        if ":" not in h:
            print(f"Error: --header must be NAME:VALUE, got {h!r}", file=sys.stderr)
            return 2
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    cases = load_corpus(args.families)
    if not cases:
        print("Error: corpus is empty.", file=sys.stderr)
        return 2

    # Fail fast on a malformed template rather than after N requests.
    build_body(args.request_template, "probe")

    if PLACEHOLDER not in args.request_template:
        print(
            f"Error: --request-template contains no {PLACEHOLDER} placeholder, "
            "so every case would send the same body.",
            file=sys.stderr,
        )
        return 2

    # Preflight: one benign request. Sending the whole corpus at an endpoint
    # that is not answering produces N unexercised rows, which is noise at best
    # and misleading at worst.
    preflight = run_case(
        ProbeCase(
            id="preflight",
            family="preflight",
            payload="hello",
            expected_behaviour="block",
            detector_type="substring",
            detector_value="",
        ),
        args.url,
        args.request_template,
        args.response_path,
        args.timeout,
        headers,
    )
    if preflight.status == "error":
        print(f"Error: preflight request to {args.url} failed.", file=sys.stderr)
        print(f"  {preflight.error}", file=sys.stderr)
        print(
            "\nNot sending the corpus. A run against an endpoint that is not "
            "answering\nwould report every case as unexercised, which is worse "
            "than no result.",
            file=sys.stderr,
        )
        return 2

    print(
        f"Probing {args.url} with {len(cases)} cases across "
        f"{len({c.family for c in cases})} families.\n"
    )

    delay = 1.0 / args.rate_limit if args.rate_limit and args.rate_limit > 0 else 0.0
    results: list[CaseResult] = []
    for i, case in enumerate(cases):
        if delay and i:
            time.sleep(delay)
        results.append(
            run_case(
                case, args.url, args.request_template, args.response_path, args.timeout, headers
            )
        )

    print(render_table(results))

    report = build_report(results, args.url, args.response_path, args.request_template)
    s = report["summary"]
    print()
    print(f"sent {s['sent']}  passed {s['passed']}  failed {s['failed']}  errors {s['errors']}")
    print()
    print("Per family:")
    for fam in sorted(report["by_family"]):
        f = report["by_family"][fam]
        print(
            f"  {fam:<28} sent {f['sent']:>3}  passed {f['passed']:>3}  "
            f"failed {f['failed']:>3}  errors {f['errors']:>3}"
        )

    if s["failed"]:
        print("\nPayloads that got through:")
        for r in results:
            if r.status == "failed":
                print(f"  {r.case.id:<10} {r.case.family:<26} matched {r.matched!r}")

    try:
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\nReport: {args.output}")
    except OSError as exc:
        print(f"\nError: could not write {args.output}: {exc}", file=sys.stderr)
        return 2

    print(
        "\nThis is not a compliance result. It records what this fixed corpus did\n"
        "against this endpoint, and says nothing about payloads outside it."
    )
    if s["errors"]:
        print(
            f"\nWARNING: {s['errors']} of {s['sent']} cases were never exercised "
            f"(connection or HTTP error).\n"
            f"Those are NOT passes -- this run is incomplete."
        )
    if s["failed"]:
        return 1
    # A run where nothing was actually exercised must not look like a clean pass.
    if s["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
