# aisg-audit: ignore-file
"""aisg/devtools/audit/patterns.py
----------------------------
Every compiled regex table the audit's grep layer runs, plus the walker constants.

Shape conventions (discover.py iterates these generically):

- A per-language table is ``dict[str, list[tuple[str, re.Pattern]]]`` keyed by
  language (``python``, ``typescript``, ``go``, ``jvm``, ``rust``) or ``"*"`` for
  every language. ``table_for(lang, table)`` merges ``lang`` with ``"*"``.
  ``HOST_OVERGRANT`` reuses the same shape with the host name as the key.
- A flat table is ``list[tuple[str, re.Pattern]]``.
- The ``str`` of every tuple is what ``Hit.key`` records. Where the inventory
  needs a ``kind`` next to the symbol (data sources, ingress, external actions,
  sinks) the key is ``"<kind>:<symbol>"`` -- split on the first colon.
- ``*_GLOBS`` and ``*_FILES`` tables are compiled from glob strings and match a
  POSIX-style relative path (``pattern.search(relpath)``). A glob with a leading
  ``/`` is anchored at the repo root; one containing ``/`` matches at any depth;
  a bare name matches the basename at any depth. All are case-insensitive.
- Where a pattern defines a capture group, group 1 is the interesting token
  (tool name, model id); otherwise the whole match is.

Every table here is a detector, never a verdict: a hit is evidence for a rule,
and every rule's precision is UNMEASURED.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from aisg.modules.input.advanced_injection_detectors import UnicodeBypassDetector
from aisg.modules.input.pii_detector import DEFAULT_ENTITIES, PII_PATTERNS
from aisg.modules.input.prompt_injection import INJECTION_PATTERNS

Table = list[tuple[str, re.Pattern]]
LangTable = dict[str, Table]


def _t(pairs: Iterable[tuple[str, str]], flags: int = re.M) -> Table:
    return [(key, re.compile(pattern, flags)) for key, pattern in pairs]


def _glob_re(glob: str) -> re.Pattern:
    """Translate a glob into a regex over a POSIX relative path (see module docstring)."""
    anchored = glob.startswith("/")
    body = glob.lstrip("/")
    out: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif body.startswith("**", i):
            out.append(".*")
            i += 2
        elif body[i] == "*":
            out.append("[^/]*")
            i += 1
        elif body[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(body[i]))
            i += 1
    prefix = "^" if anchored else "(?:^|.*/)"
    return re.compile(prefix + "".join(out) + "$", re.I)


def _globs(globs: Iterable[str]) -> Table:
    return [(glob, _glob_re(glob)) for glob in globs]


def _globs_by_key(pairs: Iterable[tuple[str, str]]) -> Table:
    return [(key, _glob_re(glob)) for key, glob in pairs]


# ---------------------------------------------------------------------------
# Walker constants (section 4.1)
# ---------------------------------------------------------------------------

IGNORE_MARKER = "# aisg-audit: ignore-file"

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".terraform",
        ".tox",
        ".nox",
        "site-packages",
        ".idea",
        ".vscode/extensions",
    }
)

LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".mjs": "typescript",
    ".cjs": "typescript",
    ".go": "go",
    ".java": "jvm",
    ".kt": "jvm",
    ".rs": "rust",
    ".rb": "ruby",
    ".cs": "dotnet",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".env": "config",
    ".md": "config",
    ".txt": "config",
    ".Dockerfile": "config",
    ".dockerfile": "config",
    ".sh": "config",
    ".ps1": "config",
}

UNIT_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "*.csproj",
)

ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")

_LANG_ALIASES = {"javascript": "typescript", "js": "typescript", "ts": "typescript"}


def table_for(lang: str | None, table: LangTable | Table) -> Table:
    """Entries for ``lang`` plus the ``"*"`` entries; a flat table is returned as-is."""
    if not isinstance(table, dict):
        return list(table)
    key = _LANG_ALIASES.get(lang or "", lang or "")
    out = list(table.get(key, []))
    if key != "*":
        out.extend(table.get("*", []))
    return out


# ---------------------------------------------------------------------------
# LLM SDKs / call sites (section 4.2)
# ---------------------------------------------------------------------------

LLM_CALL_PATTERNS: LangTable = {
    "*": _t(
        [
            ("anthropic", r"\.messages\.(?:create|stream)\("),
            ("anthropic", r"\bfrom\s+anthropic\s+import\b|^\s*import\s+anthropic\b"),
            ("anthropic", r"@anthropic-ai/sdk"),
            ("openai", r"\.chat\.completions\.create\("),
            ("openai", r"\.responses\.create\("),
            ("openai", r"\bopenai\.ChatCompletion\.create\("),
            ("openai", r"\bfrom\s+openai\s+import\b|^\s*import\s+openai\b"),
            ("openai", r"""from\s+['"]openai['"]"""),
            ("google", r"\bgenai\.GenerativeModel\("),
            ("google", r"\.generate_content\("),
            ("google", r"@google/generative-ai"),
            ("google", r"\bgoogle\.genai\b"),
            ("bedrock", r"""boto3\.client\(\s*['"]bedrock-runtime['"]"""),
            ("bedrock", r"\.invoke_model\("),
            ("bedrock", r"\.converse\("),
            ("azure", r"\bAzureOpenAI\("),
            ("azure", r"\.openai\.azure\.com\b"),
            ("mistral", r"\bMistral(?:Client)?\("),
            ("mistral", r"\bmistralai\b"),
            ("cohere", r"\bcohere\.Client(?:V2)?\("),
            ("ollama", r"\bollama\.(?:chat|generate)\("),
            ("ollama", r"localhost:11434"),
            ("vertex", r"\bvertexai\."),
            ("vertex", r"\baiplatform\.gapic\b"),
            ("litellm", r"\blitellm\.(?:a?completion)\("),
            ("hf", r"\bInferenceClient\("),
            ("hf", r"""\bpipeline\(\s*['"]text-generation"""),
            (
                "generic_http",
                r"https?://api\.(?:openai|anthropic|mistral|cohere|groq|together|perplexity|fireworks)\.",
            ),
        ]
    )
}

# sdk key -> provider, the second column of the section 4.2 table.
LLM_PROVIDER_BY_KEY: dict[str, str] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "bedrock": "aws",
    "azure": "azure",
    "mistral": "mistral",
    "cohere": "cohere",
    "ollama": "ollama",
    "vertex": "google",
    "litellm": "multi",
    "hf": "huggingface",
    "generic_http": "unknown",
}

# ---------------------------------------------------------------------------
# Model ids
# ---------------------------------------------------------------------------
# Key = provider passed to classify_model(). Group 1 (when present) is the id.
# "ollama" is only meaningful in a file that also has an ollama call hit; the
# caller gates it. "other" catches any model= literal the provider rows missed
# and is never pinned or unpinned -- overlapping spans are the caller's to dedupe.

_ID_END = r"(?![A-Za-z0-9_])"

MODEL_ID_PATTERNS: Table = _t(
    [
        (
            "anthropic",
            r"\bclaude-(?:opus|sonnet|haiku)-[0-9](?:[-.][0-9])?(?:-(?:latest|\d{8}))?" + _ID_END,
        ),
        (
            "anthropic",
            r"\bclaude-3(?:-[57])?-(?:opus|sonnet|haiku)(?:-(?:latest|\d{8}))?" + _ID_END,
        ),
        (
            "openai",
            r"(?<![A-Za-z0-9_.-])(?:gpt-[0-9](?:\.[0-9])?[a-z-]*"
            r"""|(?<=["'=])o[1-9](?:-mini|-pro)?"""
            r"|chatgpt-4o-latest)(?:-\d{4}-\d{2}-\d{2})?" + _ID_END,
        ),
        (
            "google",
            r"\bgemini-[0-9](?:\.[0-9])?-(?:pro|flash)(?:-lite)?(?:-(?:latest|preview|exp|\d{2,3}))?"
            + _ID_END,
        ),
        ("mistral", r"\b(?:mistral|codestral|pixtral|ministral)-[a-z0-9-]+" + _ID_END),
        (
            "bedrock",
            r"(?<![A-Za-z0-9_.])(?:anthropic|amazon|meta|mistral|cohere)\.[a-z0-9]+(?:-[a-z0-9]+)+(?::\d+)?"
            + _ID_END,
        ),
        (
            "ollama",
            r"""(?<=["'])(?!localhost:)(?=[a-z0-9._-]*[a-z])[a-z0-9._-]+:(?![0-9]{2,}["'])"""
            r"""(?:latest|[0-9][a-z0-9.]*)(?=["'])""",
        ),
        (
            "hf",
            r"""(?:from_pretrained\(|repo_id\s*=\s*)\s*["']([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)["']""",
        ),
        ("other", r"""\bmodel(?:_name|_id)?\s*[:=]\s*["']([^"'\n]{2,80})["']"""),
    ]
)

_PINNED_SUFFIX = {
    "anthropic": re.compile(r"-\d{8}$"),
    "openai": re.compile(r"-\d{4}-\d{2}-\d{2}$"),
    "google": re.compile(r"-\d{3}$"),
    "mistral": re.compile(r"-\d{4}$"),
    "bedrock": re.compile(r"-v\d+:\d+$"),
}


def classify_model(provider: str, model_id: str) -> bool | None:
    """True = pinned, False = alias/latest, None = cannot tell.

    None covers unknown providers, ``other`` (no provider row matched) and ``hf``
    (pinning is a property of the call -- ``revision=`` -- not of the id).
    """
    ident = model_id.strip().lower()
    if provider in ("bedrock", "aws"):
        return bool(_PINNED_SUFFIX["bedrock"].search(ident))
    if provider == "ollama":
        return ":" in ident and not ident.endswith(":latest")
    if provider == "openai" and ident == "chatgpt-4o-latest":
        return False
    if provider == "mistral" and ident.endswith("-latest"):
        return False
    suffix = _PINNED_SUFFIX.get(provider)
    if suffix is None:
        return None
    return bool(suffix.search(ident))


# ---------------------------------------------------------------------------
# Frameworks
# ---------------------------------------------------------------------------

FRAMEWORK_PATTERNS: LangTable = {
    "*": _t(
        [
            ("langchain", r"\blangchain(?:_\w+)?\b|@langchain/"),
            ("langgraph", r"\blanggraph\b"),
            ("llama_index", r"\bllama_index\b|\bllamaindex\b"),
            ("crewai", r"\bcrewai\b"),
            ("autogen", r"\bautogen(?:_\w+)?\b|\bag2\b"),
            ("semantic_kernel", r"\bsemantic[_-]kernel\b"),
            (
                "haystack",
                r"\b(?:from|import)\s+haystack\b|\bhaystack-ai\b|\bhaystack_integrations\b",
            ),
            ("dspy", r"\bdspy\b"),
            ("pydantic_ai", r"\bpydantic[_-]ai\b"),
            ("openai_agents", r"\bopenai-agents\b|\bfrom\s+agents\s+import\b|@openai/agents"),
            ("smolagents", r"\bsmolagents\b"),
            (
                "instructor",
                r"\b(?:from|import)\s+instructor\b|\binstructor\.(?:from_openai|from_anthropic|patch)\(",
            ),
            (
                "vercel_ai",
                r"""from\s+['"]ai['"]|from\s+['"]@ai-sdk/|\bgenerateText\(|\bstreamText\(""",
            ),
            ("mastra", r"@mastra/|\bmastra\b"),
            ("bee_agent", r"\bbee-agent(?:-framework)?\b|\bbeeai\b"),
            ("langchain4j", r"\blangchain4j\b"),
            ("spring_ai", r"\bspring-ai\b|\borg\.springframework\.ai\b"),
            ("genkit", r"\bgenkit\b"),
            ("mcp", r"\bfrom\s+mcp\b|^\s*import\s+mcp\b|@modelcontextprotocol/sdk|\bFastMCP\("),
            ("google_adk", r"\bgoogle-adk\b|\bgoogle\.adk\b"),
        ]
    )
}

# ---------------------------------------------------------------------------
# Tool definitions -- group 1 = tool name
# ---------------------------------------------------------------------------

TOOL_DEF_PATTERNS: LangTable = {
    "python": _t(
        [
            (
                "decorator",
                r"@(?:tool|function_tool|mcp\.tool|server\.tool|app\.tool|kernel_function"
                r"|agent\.tool(?:_plain)?)\b[^\n]*\n\s*(?:async\s+)?def\s+(\w+)",
            ),
            (
                "langchain",
                r"""\b(?:Tool|StructuredTool)(?:\.from_function)?\(\s*(?:[^)\n]{0,120}?\bname\s*=\s*)?["'](\w+)["']""",
            ),
            ("crewai", r"class\s+(\w+)\(BaseTool\)"),
            ("registry", r"""\bregister_tool\(\s*["'](\w+)["']"""),
            ("registry_list", r"\btools\s*=\s*\["),
        ]
    ),
    "typescript": _t(
        [
            ("ts_tool", r"""\btool\(\s*\{\s*(?:name|description)\s*:\s*["'](\w+)["']"""),
            ("ts_tool", r"(\w+)\s*[:=]\s*tool\(\s*\{"),
            ("ts_tool", r"""\bserver\.tool\(\s*["'](\w+)["']"""),
            ("ts_tool", r"""\bdefineTool\(\s*\{\s*name:\s*["'](\w+)["']"""),
        ]
    ),
    "go": _t([("go_tool", r'\bmcp\.NewTool\(\s*"(\w+)"')]),
    "*": _t(
        [
            (
                "openai_schema",
                r"""["']type["']\s*:\s*["']function["'][^}]{0,400}?["']name["']\s*:\s*["'](\w+)["']""",
            ),
            (
                "anthropic_schema",
                r"""["']name["']\s*:\s*["'](\w+)["'][^}]{0,400}?["']input_schema["']""",
            ),
        ]
    ),
}

# ---------------------------------------------------------------------------
# Trifecta legs: private data, untrusted ingress, external action
# ---------------------------------------------------------------------------

PRIVATE_DATA_SOURCES: LangTable = {
    "python": _t(
        [
            ("db:psycopg", r"\bpsycopg2?\b"),
            ("db:asyncpg", r"\basyncpg\b"),
            ("db:pymysql", r"\bpymysql\b"),
            ("db:sqlite3", r"\bsqlite3\b"),
            ("db:sqlalchemy", r"\bsqlalchemy\b"),
            ("db:pymongo", r"\bpymongo\b"),
            ("db:redis", r"\bredis\b"),
            ("fs:s3", r"""boto3\.client\(\s*['"]s3"""),
            ("fs:google_cloud", r"\bgoogle\.cloud\.(?:storage|bigquery|firestore)\b"),
            ("fs:open", r"""(?<![.\w])open\((?![^)\n]*['"][wax])"""),
            ("fs:path_read", r"\bPath\([^)\n]*\)\.read_(?:text|bytes)\("),
            ("vector:chromadb", r"\bchromadb\b"),
            ("vector:pinecone", r"\bpinecone\b"),
            ("vector:weaviate", r"\bweaviate\b"),
            ("vector:qdrant", r"\bqdrant\b"),
            ("vector:faiss", r"\bfaiss\b"),
            ("vector:pgvector", r"\bpgvector\b"),
            ("env:os.environ", r"\bos\.environ\b"),
            ("env:getenv", r"\bgetenv\("),
            ("env:dotenv", r"\bdotenv\b"),
            ("secrets:secretsmanager", r"\bsecretsmanager\b"),
            ("secrets:SecretClient", r"\bSecretClient\b"),
            (
                "secrets:vault",
                r"\bhvac\b|\bVaultClient\b|\bvault\.(?:secrets|read|kv)\b|\bhashicorp\b",
            ),
            ("mail:imaplib", r"\bimaplib\b"),
            ("mail:gmail", r"\bgmail\b"),
            ("mail:googleapiclient", r"\bgoogleapiclient\b"),
            ("mail:msgraph", r"\bmsgraph\b"),
            ("crm:salesforce", r"(?i)\b(?:simple_)?salesforce\b"),
            ("crm:hubspot", r"\bhubspot\b"),
            ("crm:zendesk", r"\bzendesk\b"),
            ("crm:jira", r"\bjira\b"),
            ("crm:notion_client", r"\bnotion_client\b"),
            ("crm:slack_sdk", r"\bslack_sdk\b"),
        ]
    ),
    "typescript": _t(
        [
            ("db:pg", r"""require\(['"]pg['"]\)|from\s+['"]pg['"]"""),
            ("db:mysql2", r"\bmysql2\b"),
            ("db:mongoose", r"\bmongoose\b"),
            ("db:prisma", r"\bprisma\b"),
            ("db:ioredis", r"\bioredis\b"),
            ("fs:s3", r"@aws-sdk/client-s3"),
            ("fs:google_cloud", r"@google-cloud/"),
            ("env:process.env", r"\bprocess\.env\b"),
            ("env:dotenv", r"\bdotenv\b"),
            ("mail:googleapis", r"\bgoogleapis\b"),
            ("crm:slack", r"@slack/web-api"),
        ]
    ),
    "go": _t(
        [
            ("db:database/sql", r"\bdatabase/sql\b"),
            ("db:pgx", r"\bpgx\b"),
            ("db:gorm", r"\bgorm\b"),
            ("env:os.Getenv", r"\bos\.Getenv\("),
            ("fs:aws-sdk-go", r"\baws-sdk-go\b"),
        ]
    ),
}

UNTRUSTED_INGRESS: LangTable = {
    "python": _t(
        [
            ("http:route_decorator", r"@app\.(?:post|route|get)\b|@router\."),
            ("http:request", r"\brequest\.(?:json|form|args|data|get_json)\b|\bawait\s+request\."),
            ("http:fastapi_params", r"\bBody\(|\bQuery\("),
            ("webhook:webhook", r"(?i)webhook"),
            ("email:imaplib", r"\bimaplib\b|\bemail\.message_from"),
            ("chat:slack", r"\bslack_event\b"),
            ("chat:on_message", r"\bon_message\b"),
            ("chat:discord", r"\bdiscord\b"),
            ("chat:telegram", r"\btelegram\b"),
            ("chat:twilio", r"\btwilio\b"),
            ("ticket:zendesk", r"\bzendesk\b"),
            ("ticket:intercom", r"\bintercom\b"),
            ("fetch:requests", r"\brequests\.get\("),
            ("fetch:httpx", r"\bhttpx\.get\("),
            ("scrape:BeautifulSoup", r"\bBeautifulSoup\b"),
            ("scrape:playwright", r"\bplaywright\b"),
            ("scrape:selenium", r"\bselenium\b"),
            ("scrape:scrapy", r"\bscrapy\b"),
            ("scrape:loaders", r"\bWebBaseLoader\b|\bUnstructuredURLLoader\b"),
            ("rag:retriever", r"\bretriever\."),
            ("rag:similarity_search", r"\bsimilarity_search\b"),
            ("rag:query_retriev", r"\.query\([^)\n]*retriev"),
            ("mcp:ClientSession", r"\bmcp\.ClientSession\b"),
            ("mcp:client", r"\bstdio_client\b|\bsse_client\b"),
        ]
    ),
    "typescript": _t(
        [
            ("http:req", r"\breq\.(?:body|query|params)\b"),
            ("http:express", r"\bexpress\(\)"),
            ("http:fastify", r"\bfastify\b"),
            ("http:hono", r"""from\s+['"]hono['"]"""),
            (
                "http:next_route",
                r"\bnext/server\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE)\b",
            ),
            ("fetch:fetch", r"\bfetch\("),
            ("fetch:axios", r"\baxios\.get\b"),
            ("scrape:cheerio", r"\bcheerio\b"),
            ("scrape:puppeteer", r"\bpuppeteer\b"),
            ("scrape:playwright", r"\bplaywright\b"),
            ("mcp:client", r"@modelcontextprotocol/sdk/client"),
        ]
    ),
    "go": _t(
        [
            ("http:request", r"\br\.Body\b|\br\.URL\.Query\b"),
            ("http:handler", r"\bhttp\.HandleFunc\b|\bgin\.Context\b|\bc\.PostForm\b"),
            ("fetch:http.Get", r"\bhttp\.Get\("),
            ("scrape:goquery", r"\bgoquery\b"),
            ("scrape:colly", r"\bcolly\b"),
        ]
    ),
}

EXTERNAL_ACTION: LangTable = {
    "python": _t(
        [
            ("http_post:requests", r"\brequests\.(?:post|put|delete|patch)\("),
            ("http_post:httpx", r"\bhttpx\.(?:post|put|delete|patch)\("),
            ("email:smtplib", r"\bsmtplib\b"),
            ("email:sendgrid", r"\bsendgrid\b"),
            ("email:resend", r"\bimport\s+resend\b|\bresend\.Emails\b"),
            ("sms:twilio", r"\btwilio\b"),
            ("chat:slack", r"\bchat_postMessage\("),
            ("chat:discord", r"\bdiscord\b[^\n]*\.send\("),
            ("shell:subprocess", r"\bsubprocess\b"),
            ("shell:os.system", r"\bos\.system\("),
            ("fs_write:shutil", r"\bshutil\.(?:rmtree|move|copy)"),
            ("fs_write:write_text", r"\.write_text\("),
            ("fs_write:open", r"""(?<![.\w])open\([^)\n]*['"][wa]"""),
            ("db_write:execute", r"\.execute\([^)\n]*\b(?:INSERT|UPDATE|DELETE|DROP)\b"),
            ("db_write:mongo", r"\.insert_one\(|\.delete_one\("),
            ("payment:stripe", r"\bstripe\."),
            ("payment:paypal", r"\bpaypal\b"),
            ("deploy:boto3", r"\bboto3\b[^\n]*(?:put_object|delete_object|run_instances)"),
            ("deploy:kubernetes", r"\bkubernetes\b"),
            ("deploy:docker", r"\bdocker\.from_env\("),
            ("git:push", r"\bgit\s+push\b"),
            ("git:gh", r"\bgh\s+(?:pr|release)\b"),
            ("deploy:iac", r"\bterraform\b|\bpulumi\b"),
        ]
    ),
    "typescript": _t(
        [
            ("http_post:fetch", r"""\bfetch\([^)]*method:\s*['"](?:POST|PUT|DELETE)"""),
            ("http_post:axios", r"\baxios\.(?:post|put|delete)\b"),
            ("email:nodemailer", r"\bnodemailer\b"),
            ("email:sendgrid", r"@sendgrid/"),
            ("sms:twilio", r"\btwilio\b"),
            ("shell:child_process", r"\bchild_process\b"),
            ("fs_write:fs", r"\bfs\.(?:write|rm|unlink)\w*\("),
            ("db_write:prisma", r"\bprisma\.\w+\.(?:create|update|delete)\b"),
            ("payment:stripe", r"\bstripe\b"),
        ]
    ),
    "go": _t(
        [
            ("http_post:http.Post", r"\bhttp\.Post\b"),
            ("email:smtp", r"\bsmtp\.SendMail\b"),
            ("shell:exec.Command", r"\bexec\.Command\("),
            ("fs_write:os", r"\bos\.(?:WriteFile|Remove)\("),
            ("db_write:db.Exec", r"\bdb\.Exec\("),
        ]
    ),
}

# ---------------------------------------------------------------------------
# Output sinks (P4), grep tier. Key = "<kind>:<symbol>".
# eval tier deliberately excludes compile( / re.compile( (Python), bare
# Function( (every TS type annotation) and reflect.* (every Go JSON codebase).
# ---------------------------------------------------------------------------

SINK_PATTERNS: LangTable = {
    "python": _t(
        [
            ("shell:subprocess", r"\bsubprocess\.\w+\("),
            ("shell:os.system", r"\bos\.system\("),
            ("shell:os.popen", r"\bos\.popen\("),
            ("eval:eval", r"(?<![.\w])eval\("),
            ("eval:exec", r"(?<![.\w])exec\("),
            ("sql:execute_fstring", r"""\.execute\(\s*f["']"""),
            ("sql:execute_percent", r"\.execute\([^)\n]*%"),
            ("sql:execute_concat", r"""\.execute\(\s*["'][^"'\n]*["']\s*\+"""),
            ("sql:execute_format", r"\.execute\([^)\n]*\.format\("),
            ("sql:raw", r"\.raw\("),
            ("sql:text_fstring", r"""\btext\(\s*f["']"""),
            ("html:Markup", r"\bMarkup\("),
            ("html:mark_safe", r"\bmark_safe\("),
            ("html:safe_filter", r"\|\s*safe\b"),
            ("html:triple_mustache", r"\{\{\{"),
            ("url:requests", r"\brequests\.(?:get|post|put|delete|patch|head|request)\("),
            ("url:httpx", r"\bhttpx\.(?:get|post|put|delete|patch|request)\("),
            ("url:urlopen", r"\burllib\.request\.urlopen\("),
            ("fs:open_write", r"""(?<![.\w])open\([^)\n]*['"][wa]"""),
            ("fs:path_write", r"\bPath\([^)\n]*\)\.write_(?:text|bytes)\(|\.write_text\("),
            ("fs:shutil", r"\bshutil\.\w+\("),
        ]
    ),
    "typescript": _t(
        [
            ("shell:child_process", r"\bchild_process\.exec\w*\("),
            ("shell:exec", r"(?<![.\w])exec(?:Sync|File|FileSync)?\("),
            ("shell:spawn_shell", r"\bspawn\([^\n]*shell:\s*true"),
            ("eval:eval", r"(?<![.\w])eval\("),
            ("eval:new_Function", r"\bnew\s+Function\("),
            ("eval:vm.runIn", r"\bvm\.runIn\w+\("),
            ("sql:query_template", r"\bquery\(\s*`[^`]*\$\{"),
            ("sql:sequelize", r"\bsequelize\.query\(\s*`"),
            ("sql:raw", r"\.raw\("),
            ("html:innerHTML", r"\.innerHTML\s*="),
            ("html:dangerouslySetInnerHTML", r"\bdangerouslySetInnerHTML\b"),
            ("html:v-html", r"\bv-html\b"),
            ("html:triple_mustache", r"\{\{\{"),
            ("url:fetch", r"\bfetch\("),
            ("url:axios", r"\baxios(?:\.\w+)?\("),
            ("fs:writeFile", r"\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync)\("),
        ]
    ),
    "go": _t(
        [
            ("shell:exec.Command_sh", r'\bexec\.Command\(\s*"(?:sh|bash)"\s*,\s*"-c"'),
            ("shell:exec.Command", r"\bexec\.Command\("),
            ("sql:Exec_Sprintf", r"\.(?:Exec|Query|QueryRow)\(\s*fmt\.Sprintf"),
            ("sql:Exec_concat", r"\.(?:Exec|Query|QueryRow)\([^)\n]*\+"),
            ("html:template.HTML", r"\btemplate\.HTML\("),
            ("url:http", r"\bhttp\.(?:Get|Post|NewRequest)\("),
            ("fs:WriteFile", r"\b(?:os|ioutil)\.(?:WriteFile|Create)\("),
        ]
    ),
    "jvm": _t(
        [
            ("shell:Runtime.exec", r"\bRuntime\.getRuntime\(\)\.exec\("),
            ("shell:ProcessBuilder", r"\bProcessBuilder\("),
        ]
    ),
}

# Seeds for output taint (grep: co-located with an LLM call; AST: on a call result).
LLM_RESPONSE_ACCESSORS: Table = _t(
    [
        ("choices_message_content", r"\.choices\[0\]\.message\.content\b"),
        ("content_text", r"\.content\[0\]\.text\b"),
        ("output_text", r"\.output_text\b"),
        (
            "text",
            r"(?<![\w.])(?:message|response|resp|completion|result|reply|output|answer)\.text\b",
        ),
        ("candidates", r"\.candidates\[0\]"),
        (
            "agent_invoke",
            r"\b(?:agent|executor|chain|graph|crew)\w*\.(?:run|arun|invoke|ainvoke|kickoff)\(",
        ),
        ("tool_call_arguments", r"\btool_call\.function\.arguments\b"),
        ("tool_calls", r"\.tool_calls\b"),
    ]
)

# ---------------------------------------------------------------------------
# Guardrail libraries, fail-open, observability, audit log, evals
# ---------------------------------------------------------------------------

GUARDRAIL_LIBS: Table = _t(
    [
        ("aisg", r"\bfrom\s+aisg\b|\bimport\s+aisg\b"),
        ("nemoguardrails", r"\bnemoguardrails\b"),
        ("guardrails_ai", r"\bguardrails(?:_ai|-ai|\.hub|\s+import\s+Guard)\b"),
        ("llm_guard", r"\bllm[_-]guard\b"),
        ("lakera", r"\blakera\b"),
        ("rebuff", r"\brebuff\b"),
        ("promptguard", r"\bpromptguard\b|\bPrompt-Guard\b"),
        ("llama_guard", r"\bllama_guard\b|\bLlamaGuard\b|\bLlama-Guard\b"),
        ("presidio", r"\bpresidio(?:_analyzer|_anonymizer)?\b"),
        ("azure_contentsafety", r"\bazure\.ai\.contentsafety\b"),
        ("bedrock_guardrail", r"\bbedrock\b[^\n]*guardrailIdentifier"),
        ("anthropic_moderation", r"@anthropic-ai/[^\n]*moderation"),
        ("openai_moderation", r"\bopenai\.moderations\b|\.moderations\.create\("),
        ("purview", r"\bpurview\b"),
    ]
)

FAIL_OPEN_PATTERNS: Table = _t(
    [
        ("fail_open", r"\bfail_open\s*[:=]\s*[Tt]rue\b"),
        ("on_error_allow", r"""\bon_error\s*[:=]\s*["']allow"""),
    ]
)

# LLM-specific tracing. Generic APM lives in GENERIC_APM_SYMBOLS; never merge them.
LLM_OBSERVABILITY_SYMBOLS: Table = _t(
    [
        ("langfuse", r"\blangfuse\b"),
        ("langsmith", r"\blangsmith\b"),
        ("langchain_tracing", r"\bLANGCHAIN_TRACING"),
        ("traceloop", r"\btraceloop\b"),
        ("openllmetry", r"\bopenllmetry\b"),
        ("otel_genai", r"\bgen_ai\."),
        ("aisg_telemetry", r"\bTelemetryProvider\b"),
        ("helicone", r"\bhelicone\b"),
        ("braintrust", r"\bbraintrust\b"),
        ("arize", r"\barize\b"),
        (
            "phoenix",
            r"\b(?:from|import)\s+phoenix\b|\bphoenix\.(?:trace|otel|evals)\b|\barize[-_]phoenix\b",
        ),
        ("wandb", r"\bwandb\b[^\n]*(?:trace|weave)"),
        ("weave", r"\b(?:from|import)\s+weave\b|\bweave\.(?:init|op)\b"),
    ],
    re.M | re.I,
)

GENERIC_APM_SYMBOLS: Table = _t(
    [
        ("sentry", r"\bsentry_sdk\b|@sentry/"),
        ("datadog", r"\bdatadog\b"),
        ("ddtrace", r"\bddtrace\b"),
        ("honeycomb", r"\bhoneycomb\b"),
        ("newrelic", r"\bnewrelic\b"),
        ("prometheus", r"\bprometheus(?:_client)?\b"),
        ("opentelemetry", r"\bopentelemetry\b"),
    ],
    re.M | re.I,
)

AUDIT_LOG_SYMBOLS: Table = _t(
    [
        ("AuditLogger", r"\bAuditLogger\b"),
        ("audit_log", r"\baudit_log\b|\baudit\.log\b"),
        ("structlog", r"\bstructlog\b"),
        ("tool_call_log", r"\btool_call_log\b"),
        ("record_tool_call", r"\brecord_tool_call\b"),
    ]
)

EVAL_TOOLS: Table = _t(
    [
        ("promptfoo", r"\bpromptfoo\b"),
        ("deepeval", r"\bdeepeval\b"),
        ("ragas", r"\bragas\b"),
        ("inspect_ai", r"\binspect[_-]ai\b"),
        ("garak", r"\bgarak\b"),
        ("pyrit", r"\bpyrit\b"),
        ("giskard", r"\bgiskard\b"),
        ("lm_eval", r"\blm[_-]eval(?:uation-harness)?\b"),
        ("evals_dir", r"\bevals/"),
        ("aisg_measure", r"\baisg\s+measure\b"),
        ("aisg_probe", r"\baisg\s+probe\b"),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Secrets and PII (P5)
# ---------------------------------------------------------------------------
# The generic row puts the value in group 1; the vendor rows have no group.

# A vendor prefix inside a longer identifier ("task-...", "ghp_" in a hash) is not a key.
_B = r"(?<![A-Za-z0-9_])"

SECRET_PATTERNS: Table = _t(
    [
        ("anthropic", _B + r"sk-ant-[A-Za-z0-9_-]{20,}"),
        ("openai_project", _B + r"sk-proj-[A-Za-z0-9_-]{20,}"),
        ("openai", _B + r"sk-[A-Za-z0-9]{32,}"),
        ("aws_access_key", _B + r"AKIA[0-9A-Z]{16}"),
        ("github_token", _B + r"gh[pousr]_[A-Za-z0-9]{36}"),
        ("github_pat", _B + r"github_pat_[A-Za-z0-9_]{60,}"),
        ("slack", _B + r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("google_api", _B + r"AIza[0-9A-Za-z_-]{35}"),
        ("huggingface", _B + r"hf_[A-Za-z0-9]{30,}"),
        ("perplexity", _B + r"pplx-[A-Za-z0-9]{40,}"),
        ("groq", _B + r"gsk_[A-Za-z0-9]{40,}"),
        ("replicate", _B + r"r8_[A-Za-z0-9]{30,}"),
        ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        (
            "generic",
            r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9_-]*(?:api[_-]?key|secret|token|passw(?:or)?d|auth)"
            r"""\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{16,})["']""",
        ),
    ]
)

# Variable names that carry a secret when bound into a prompt (AUD-503) ...
SECRET_VAR_NAMES = re.compile(
    r"(?i)(?:access_token|auth_token|api_token|refresh_token|api_key|secret|passw(?:or)?d"
    r"|ssn|social_security|card_number|credit_card|cvv)"
)
# ... unless the name is about token COUNTING, which is not a secret.
SECRET_VAR_EXCLUDE = re.compile(
    r"(?i)(?:max_tokens|num_tokens|token_count|tokeni[sz]|tokens\b|token_limit|token_usage)"
)

# Placeholder values: a secret or PII hit whose text matches one of these is skipped.
SECRET_PLACEHOLDERS: Table = _t(
    [
        ("env_ref", r"\$\{[^}]*\}|\$[A-Z_]{3,}\b"),
        ("angle", r"<[^>]{2,}>"),
        ("your", r"(?i)\byour[-_ ]"),
        ("xxx", r"(?i)x{3,}"),
        ("changeme", r"(?i)change[-_ ]?me"),
        ("example", r"(?i)example"),
        ("placeholder", r"(?i)placeholder|dummy|sample|fake|test[-_]?key|redacted|\btodo\b"),
        ("example_email", r"(?i)@(?:example|test)\.(?:com|org|net)\b"),
        ("phone_555", r"\b555[-. ]?01\d{2}\b"),
        ("ssn_sample", r"\b000-00-0000\b|\b123-45-6789\b"),
        ("card_test", r"\b4111[- ]?1111[- ]?1111[- ]?1111\b|\b4242[- ]?4242[- ]?4242[- ]?4242\b"),
        ("rfc5737_ip", r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b"),
        ("loopback_ip", r"\b127\.0\.0\.1\b|\b0\.0\.0\.0\b"),
    ]
)

# Reused from the shipped guard, default entities only: PASSPORT and EU_TAX_ID
# are documented there as too noisy for ordinary traffic.
PII_TABLE: Table = [(name, PII_PATTERNS[name]) for name in DEFAULT_ENTITIES]

PII_FILE_GLOBS: Table = _globs(
    [
        "prompts/**",
        "*.prompt",
        "*.jinja",
        "*.jinja2",
        "*.j2",
        "evals/**",
        "tests/**/*.jsonl",
        "*.log",
        "logs/**",
    ]
)

BROAD_CRED_NAMES: Table = _t(
    [
        ("AWS_SECRET_ACCESS_KEY", r"\bAWS_SECRET_ACCESS_KEY\b"),
        ("GITHUB_TOKEN", r"\bGITHUB_TOKEN\b"),
        ("GCP_SA_KEY", r"\bGCP_SA_KEY\b"),
        ("AZURE_CLIENT_SECRET", r"\bAZURE_CLIENT_SECRET\b"),
        (
            "DATABASE_URL",
            r"\bDATABASE_URL\b[^\n]*(?:postgres(?:ql)?|mysql|mongodb)(?:\+\w+)?://[^:\s/]+:[^@\s]+@",
        ),
        ("STRIPE_SECRET_KEY", r"\bSTRIPE_SECRET_KEY\b"),
        ("TWILIO_AUTH_TOKEN", r"\bTWILIO_AUTH_TOKEN\b"),
        ("SENDGRID_API_KEY", r"\bSENDGRID_API_KEY\b"),
        ("SLACK_BOT_TOKEN", r"\bSLACK_BOT_TOKEN\b"),
    ]
)

# ---------------------------------------------------------------------------
# Host over-grants (AUD-101) and unsafe hooks (AUD-108)
# ---------------------------------------------------------------------------
# Keyed by host; value patterns are applied to one config value (an allow-list
# entry, a mode string, str(bool)). The "*" row holds literals for scripts, CI,
# Dockerfiles and hooks; in .md/.rst/.txt the caller runs them through
# is_mention() first and caps the finding at low.

HOST_OVERGRANT: LangTable = {
    "claude": _t(
        [
            (
                "permissions.allow",
                r"^Bash(?:\(\*?\)|\((?:rm|sudo|curl|wget|sh|bash)\b.*\))?$",
            ),
            ("permissions.allow", r"^WebFetch$"),
            ("permissions.allow", r"^mcp__.*__\*$"),
            ("permissions.defaultMode", r"^bypassPermissions$"),
        ]
    ),
    "codex": _t(
        [
            ("approval_policy", r"^never$"),
            ("sandbox_mode", r"^danger-full-access$"),
        ]
    ),
    "cursor": _t(
        [
            ("yolo", r"^true$"),
            ("autoRun", r"^true$"),
            ("allowAllCommands", r"^true$"),
        ],
        re.M | re.I,
    ),
    "gemini": _t(
        [
            ("autoAccept", r"^true$"),
            ("sandbox", r"^false$"),
        ],
        re.M | re.I,
    ),
    "*": _t(
        [
            ("literal", r"--dangerously-skip-permissions(?![\w-])"),
            ("literal", r"--yolo(?![\w-])"),
            ("literal", r"--full-auto(?![\w-])"),
            ("literal", r"--approval-mode\s+yolo\b"),
            ("literal", r"--permission-mode\s+bypassPermissions\b"),
            ("literal", r"\bdangerouslyDisableSandbox\b"),
        ]
    ),
}

HOST_OVERGRANT_INTERPRETER: Table = _t(
    [("permissions.allow", r"^Bash\((?:python3?|pip3?|npx|node|uv|uvx)\b.*\)$")]
)

UNSAFE_HOOK_PATTERNS: Table = _t(
    [
        ("curl_pipe_sh", r"\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|python3?)\b"),
        ("wget_pipe_sh", r"\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|python3?)\b"),
        ("wget_stdout", r"\bwget\s+(?:-q\s+)?-q?O-"),
        ("npx_y", r"\bnpx\s+(?:-y|--yes)\b"),
        ("pip_http", r"\bpip3?\s+install\b[^\n]*\bhttp://"),
        ("pip_trusted_host", r"--trusted-host\b"),
    ]
)

# ---------------------------------------------------------------------------
# Supply chain (P6)
# ---------------------------------------------------------------------------

# AUD-602 text-line fallback for Dockerfile RUN lines and CI steps. Each row
# matches only the UNPINNED form; MCP config command/args go through
# configs.mcp_pinned() instead. Scope is BOOTSTRAP_FILE_GLOBS -- never docs.
UNPINNED_BOOTSTRAP_PATTERNS: Table = _t(
    [
        (
            "npx",
            r"""\bnpx\s+(?:-y\s+|--yes\s+)?((?:@[\w.-]+/)?[A-Za-z0-9][\w.-]*)(?=\s|["'\]]|$)""",
        ),
        ("uvx", r"""\buvx\s+(?:--from\s+)?([A-Za-z][\w.-]*)(?=\s|["'\]]|$)"""),
        (
            "pip",
            r"""\bpip3?\s+install\s+(?:(?:-U|--upgrade|-q|--quiet)\s+)*(?!-)([A-Za-z][\w.\[\]-]*)(?=\s|["'\]]|$)""",
        ),
        (
            "docker_run",
            r"\bdocker\s+run\s+(?:-[-\w]+(?:\s+[^\s-]\S*)?\s+)*((?:[\w.-]+/)*[A-Za-z][\w.-]*)(?::latest)?(?=\s|$)",
        ),
    ]
)

BOOTSTRAP_FILE_GLOBS: Table = _globs(
    [
        "Dockerfile",
        "Dockerfile.*",
        "*.Dockerfile",
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        ".travis.yml",
    ]
)

WEIGHTS_PATTERNS: Table = _t(
    [
        (
            "from_pretrained_unpinned",
            r"""\bfrom_pretrained\(\s*["'][^"'\n]+["'](?![^)\n]*revision\s*=)""",
        ),
        ("trust_remote_code", r"\btrust_remote_code\s*=\s*True\b"),
        ("torch_load_unsafe", r"\btorch\.load\((?![^)\n]*weights_only\s*=\s*True)"),
        (
            "pickle_load",
            r"(?i)^[^\n]*(?:model|weight|ckpt|checkpoint|\.pkl|\.pt\b|\.pth|\.bin\b)[^\n]*\bpickle\.loads?\("
            r"|\bpickle\.loads?\([^\n]*(?:model|weight|ckpt|checkpoint|\.pkl|\.pt\b|\.pth|\.bin\b)",
        ),
        ("hf_hub_download_unpinned", r"\bhf_hub_download\((?![^)\n]*revision\s*=)"),
    ]
)

# MCP tool-description poisoning (AUD-604). Re-shaped from the shipped guard's
# (compiled_re, name, Severity) triples; key = the guard's pattern name so the
# finding can record it as seed_pattern. Never downgraded by is_mention().
MCP_DESCRIPTION_INJECTION: Table = [(name, compiled) for compiled, name, _sev in INJECTION_PATTERNS]

# Poisoning phrases specific to tool descriptions, not in INJECTION_PATTERNS.
MCP_POISON_PHRASES: Table = _t(
    [
        ("important_tag", r"<\s*important\s*>"),
        (
            "do_not_tell_user",
            r"\bdo\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user\b",
        ),
        ("ignore_previous", r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\b"),
        (
            "before_using_read",
            r"\bbefore\s+(?:using|calling|invoking)\s+this\s+tool\b[^\n]{0,40}\bread\b",
        ),
        ("ssh_dir", r"~/\.ssh\b"),
        ("etc_passwd", r"/etc/passwd\b"),
    ],
    re.M | re.I,
)

INVISIBLE_CHAR_RE = re.compile(
    "[" + "".join(re.escape(ch) for ch in UnicodeBypassDetector.INVISIBLE_CHARS) + "]"
)

# ---------------------------------------------------------------------------
# Governance (P10) and incident path (P7)
# ---------------------------------------------------------------------------
# Key = keyword slug. ANNEX_III_CATEGORY_BY_KEYWORD maps each to the
# `annex_iii_category` value `aisg init` writes (system_card.ANNEX_III).
# Only meaningful inside ANNEX_III_FILE_GLOBS: "we are hiring" in a README is
# not a governance finding.

ANNEX_III_KEYWORDS: Table = _t(
    [
        ("biometric", r"\bbiometric"),
        ("credit_scoring", r"\bcredit[- ]?scor(?:e|ing)\b|\bcreditworthiness\b"),
        ("hiring", r"\bhiring\b"),
        ("recruitment", r"\brecruit(?:ment|ing|er)s?\b"),
        ("exam_grading", r"\bexam[- ]?grading\b|\bgrad(?:e|ing)\s+(?:exams?|students?|essays?)\b"),
        ("law_enforcement", r"\blaw[- ]enforcement\b|\bpolice\b"),
        (
            "migration",
            r"\bimmigration\b|\bmigrants?\b|\bmigration\s+(?:status|control|authorit|officer|application)|\bborder\s+control\b",
        ),
        ("asylum", r"\basylum\b"),
        (
            "welfare_benefits",
            r"\bwelfare\b|\bsocial\s+benefits?\b|\bbenefits?\s+(?:eligibility|claims?)\b",
        ),
        (
            "critical_infrastructure",
            r"\bcritical\s+infrastructure\b|\bpower\s+grid\b|\bwater\s+supply\b",
        ),
        (
            "medical_triage",
            r"\b(?:medical|patient|emergency)\s+triage\b|\btriage\s+(?:patients?|emergenc)|\bemergency\s+(?:room|department)\b",
        ),
    ],
    re.M | re.I,
)

ANNEX_III_CATEGORY_BY_KEYWORD: dict[str, str] = {
    "biometric": "biometrics",
    "credit_scoring": "essential_services_and_benefits",
    "hiring": "employment_and_worker_management",
    "recruitment": "employment_and_worker_management",
    "exam_grading": "education_and_vocational_training",
    "law_enforcement": "law_enforcement",
    "migration": "migration_asylum_and_border_control",
    "asylum": "migration_asylum_and_border_control",
    "welfare_benefits": "essential_services_and_benefits",
    "critical_infrastructure": "critical_infrastructure",
    "medical_triage": "essential_services_and_benefits",
}

ANNEX_III_FILE_GLOBS: Table = _globs(
    [
        "prompts/**",
        "*.prompt",
        "*.jinja",
        "*.jinja2",
        "ai-system-card.yaml",
        "model_card.md",
        "MODEL_CARD.md",
        "system-card*",
        "docs/*risk*",
        "docs/**/*risk*",
    ]
)

INCIDENT_PATH_GLOBS: Table = _globs(
    [
        "SECURITY.md",
        "INCIDENT*.md",
        "docs/incident*",
        "docs/incident*/**",
        "runbook*",
        ".github/ISSUE_TEMPLATE/*security*",
    ]
)

SYSTEM_CARD_GLOBS: Table = _globs(
    ["ai-system-card.yaml", "model_card.md", "MODEL_CARD.md", "system-card*"]
)

# ---------------------------------------------------------------------------
# Loops (AUD-102 grep tier) and prompt assembly (AUD-302/303 grep fallback)
# ---------------------------------------------------------------------------

LOOP_PATTERNS: LangTable = {
    "python": _t(
        [
            ("while_true", r"^\s*while\s+(?:True|1)\s*:"),
            ("itertools_count", r"\bfor\s+\w+\s+in\s+itertools\.count\("),
            ("range_huge", r"\bfor\s+\w+\s+in\s+range\(\s*10\s*\*\*"),
        ]
    ),
    "typescript": _t(
        [
            ("while_true", r"\bwhile\s*\(\s*true\s*\)"),
            ("for_ever", r"\bfor\s*\(\s*;\s*;\s*\)"),
        ]
    ),
    "jvm": _t(
        [
            ("while_true", r"\bwhile\s*\(\s*true\s*\)"),
            ("for_ever", r"\bfor\s*\(\s*;\s*;\s*\)"),
        ]
    ),
    "go": _t([("for_ever", r"\bfor\s*\{")]),
    "rust": _t([("loop", r"\bloop\s*\{")]),
}

_PROMPT_LHS = (
    r"\b(?:prompt|messages?|system|instructions?|content|query|template)\w*\s*(?:\+?=|:=|:)\s*"
)

PROMPT_ASSEMBLY_PATTERNS: LangTable = {
    "python": _t(
        [
            ("fstring", _PROMPT_LHS + r"""(?:rf|fr|f)["']"""),
            ("concat", _PROMPT_LHS + r"""(?:["'][^"'\n]*["']\s*\+|\w+\s*\+\s*["'])"""),
            ("format", _PROMPT_LHS + r"[^\n]*\.format\("),
            ("percent", _PROMPT_LHS + r"""["'][^"'\n]*["']\s*%\s*"""),
        ]
    ),
    "typescript": _t(
        [
            ("template", _PROMPT_LHS + r"`[^`]*\$\{"),
            ("concat", _PROMPT_LHS + r"""(?:["'][^"'\n]*["']\s*\+|\w+\s*\+\s*["'])"""),
        ]
    ),
    "go": _t(
        [
            ("sprintf", _PROMPT_LHS + r"fmt\.Sprintf\("),
            ("concat", _PROMPT_LHS + r'[^\n]*"\s*\+'),
        ]
    ),
    "*": _t(
        [
            (
                "system_role",
                r"""["']role["']\s*:\s*["']system["']|\bSystemMessage\(|\bsystem\s*=\s*(?:f?["']|\w)""",
            ),
        ]
    ),
}

# ---------------------------------------------------------------------------
# Keyword-only content filter (AUD-805): a list/set literal whose NAME says it
# is a ban/block/profanity list. STOPWORDS, enums and NLP vocabularies do not
# satisfy the name requirement. Group 1 = the name.
# ---------------------------------------------------------------------------

KEYWORD_FILTER_PATTERNS: LangTable = {
    "*": _t(
        [
            (
                "list_literal",
                r"^\s*(?:(?:const|let|var|val|final)\s+)?"
                r"((?:\w+_)?(?:ban(?:ned|list)?|block(?:ed|list)?|profan\w*|toxic\w*|forbid(?:den)?"
                r"|den(?:y|ied)(?:list)?|bad_?words?)(?:_\w+)?)"
                r"""\s*(?::\s*[^=\n]+)?\s*=\s*(?:frozenset|set|list|tuple|\[\]string)?\s*[\[{(]+\s*["']""",
            )
        ],
        re.M | re.I,
    )
}

# ---------------------------------------------------------------------------
# MCP / host config file discovery (structured parsing lives in configs.py)
# ---------------------------------------------------------------------------

MCP_CONFIG_FILES: Table = _globs_by_key(
    [
        ("claude", ".mcp.json"),
        ("claude", "/mcp.json"),
        ("cursor", ".cursor/mcp.json"),
        ("vscode", ".vscode/mcp.json"),
        ("gemini", ".gemini/settings.json"),
        ("codex", ".codex/config.toml"),
        ("claude_desktop", "claude_desktop_config.json"),
        ("registry", "/server.json"),
        ("smithery", "smithery.yaml"),
    ]
)

HOST_CONFIG_FILES: Table = _globs_by_key(
    [
        ("claude", ".claude/settings.json"),
        ("claude", ".claude/settings.local.json"),
        ("claude", ".claude/agents/*.md"),
        ("claude", "CLAUDE.md"),
        ("claude", "AGENTS.md"),
        ("codex", ".codex/config.toml"),
        ("cursor", ".cursor/settings.json"),
        ("cursor", ".cursor/rules/*.mdc"),
        ("gemini", ".gemini/settings.json"),
    ]
)

# ---------------------------------------------------------------------------
# Mention vs use (AUD-101/docs). Independent of prompt_injection.is_mention and
# deliberately smaller: a quoted span or a discussion cue within 80 chars.
# AUD-604 never calls this.
# ---------------------------------------------------------------------------

DISCUSSION_CUES = re.compile(
    r"\b(?:never|do not|don'?t|avoid|warning|caution|must not|should not|not recommended"
    r"|dangerous|unsafe|instead of|example|prevent|detect|block|reject|explain|how to)\b",
    re.I,
)

QUOTED_SPAN_RE = re.compile(r"'[^'\n]{4,200}'|\"[^\"\n]{4,200}\"|`[^`\n]{4,200}`")

_MENTION_WINDOW = 80


def is_mention(line: str, start: int, end: int) -> bool:
    """True when ``line[start:end]`` reads as discussion of a literal, not a use of it."""
    for span in QUOTED_SPAN_RE.finditer(line):
        if span.start() <= start and end <= span.end():
            return True
    before = line[max(0, start - _MENTION_WINDOW) : start]
    after = line[end : end + _MENTION_WINDOW]
    return bool(DISCUSSION_CUES.search(before) or DISCUSSION_CUES.search(after))
