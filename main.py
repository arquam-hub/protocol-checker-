# protocol-checker-

#security protocol analyser - passes anb/anbx files to seepseek and gpt 
#report is generated csv file run: python protocol_checker.py --input_dir path/to/protocols --output_file results.csv
#needs api keys as env vars or in config.ini
#chat and reasoning mode available 
#libraries
import argparse
import configparser
import csv
import json
import os
import random
import re
import sys
import time
from concurrent.futures import FIRST_COMPLETED, TimeoutError as FuturesTimeoutError, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
#compatible with deepseek and openai
from openai import OpenAI

try:
    import httpx
except Exception:
    httpx = None


# ---------------------------------------------------------------------------
# Model lists for chat and reasoning modes
# ---------------------------------------------------------------------------
#both reasoning and chat models start with most capable  
DEEPSEEK_CHAT_MODELS = [
    "deepseek-chat",
    "deepseek-chat-latest",
    "deepseek-v3",
]
DEEPSEEK_REASONING_MODELS = [
    "deepseek-reasoner",
    "deepseek-chat",
]
OPENAI_CHAT_MODELS = [
    "gpt-5.2",
    "gpt-5.2-chat-latest",
    "gpt-4o",
    "gpt-4o-latest",
    "gpt-4-turbo",
    "gpt-4",
]
OPENAI_REASONING_MODELS = [
    "gpt-5.2-thinking",
    "gpt-5.2-pro",
    "gpt-5.2",
    "gpt-5.2-chat-latest",
    "o3",
    "o1",
]

MODEL_MODE: str = "reasoning"

DEFAULT_DEEPSEEK_MODEL = DEEPSEEK_REASONING_MODELS[0]
DEFAULT_OPENAI_MODEL = OPENAI_REASONING_MODELS[0]

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
MODEL_ORDER = ("DeepSeek", "GPT")
SECTION_HEADERS = {
    "TYPES",
    "KNOWLEDGE",
    "ACTIONS",
    "PROTOCOL",
    "RULES",
    "MODEL",
    "END",
}


# Configurable timeout / retry constants (requirement B)
#generous timeout limits, reasoning models take time (tried and tested)

PER_MODEL_REQUEST_TIMEOUT_SECONDS = 480.0
PER_PROTOCOL_TIMEOUT_SECONDS = 540.0
PER_MODEL_MAX_RETRIES = 2
HEARTBEAT_INTERVAL_SECONDS = 15.0
RAW_RESPONSE_MAX_CHARS = 2000



#specific keys and goal definitions provided within prompt to help ai understand language
#
PROMPT_TEMPLATE = """
You are a security protocol verifier using symbolic reasoning.

You are given:
1) an anonymized Alice-and-Bob / AnB / AnBx protocol body, and
2) an explicit list of goals to analyze.

--- NOTATION REFERENCE ---
Use the following Alice-and-Bob notation when interpreting the protocol:

Keys:
  pk(X)        : public key of X used for encryption
  sk(X)        : public key of X used for signature verification
  inv(pk(X))   : private key of X used for decryption
  inv(sk(X))   : private key of X used for signature
  shk(X,Y)     : pre-shared symmetric key between X and Y

Encryption:
  {{|Msg|}}K        : symmetric encryption of Msg under key K (e.g. AES, DES)
  {{Msg}}pk(A)      : asymmetric encryption of Msg under public key of A (e.g. RSA)
  {{Msg}}inv(sk(A)) : digital signature of Msg using private key of A (e.g. RSA, DSA)

Where:
  Msg is a message, K is a symmetric key, A is an agent

Hashing:
  hash(Msg)    : cryptographic hash of Msg (e.g. MD5, SHA-1, SHA-2, SHA-3)
  hmac(K, Msg) : keyed HMAC of Msg under symmetric key K (e.g. HMAC-SHA1, HMAC-SHA2)

--- GOAL DEFINITIONS ---
Authentication (hierarchy, weakest to strongest):
  1. Aliveness: When agent B completes a run apparently with A, then A has previously been running the protocol.
  2. Weak Agreement: Adds the requirement that A specifically thought it was running the protocol with B.
  3. Non-injective Agreement: Adds the requirement that A and B agree on specific data items (such as nonces and keys) and the roles they played.
  4. Injective Agreement: The strongest form — adds a one-to-one relationship between the runs of A and B, preventing replay attacks where B believes multiple runs occurred corresponding to a single run by A. Equivalent to what OFMC/ProVerif verify as injective agreement.

Secrecy:
  Weak Secrecy: An attacker cannot derive a protected term from intercepted messages.
    Expressed as: A confidentially sends Msg to B, or A ->* B: Msg, or Msg secret between A and B.
  Strong Secrecy: An attacker cannot distinguish between protocol executions that differ only by their secret inputs.

--- RULES ---
- Analyze ONLY the listed goals. Never invent extra goals.
- Use Dolev-Yao attacker assumptions (network control, no cryptographic breaks without keys).
- For EVERY goal, output:
  - status: satisfied, violated, or unknown
  - justification: 2 to 6 sentences
  - two_session_trace: always present, exactly two sessions (Session 1 and Session 2)
- Do not mention filenames, folders, or real protocol names. Refer only to protocol_id.

Return JSON only. No markdown.
Schema:
{{{{
  "model": "<string>",
  "protocol_id": "<string>",
  "analysis": [
    {{{{
      "goal_id": <int>,
      "goal": "<goal text>",
      "status": "satisfied|violated|unknown",
      "justification": "<2-6 sentences>",
      "two_session_trace": "Session 1: ...\\nSession 2: ..."
    }}}}
  ]
}}}}

PROTOCOL_ID:
{protocol_id}

PROTOCOL_BODY:
{protocol_body}

GOALS:
{goals_block}
""".strip()


# 
# data classes
# 
@dataclass
class ModelResult:
    model_name: str
    raw_response_text: str
    parsed_response: Dict[str, Any]
    model_variant: str = ""


@dataclass
class RuntimeSettings:
    deepseek_api_key: str
    openai_api_key: str
    deepseek_model: str
    openai_model: str


# 
# config helpers 
# model selection helpers (requirement A) will use env vars first, then config.ini, then defaults. Config file is created if missing, with placeholders for keys and models. Models can be overridden in config or via env vars, but must not be left as placeholders.
def script_config_path() -> Path:
    return Path(__file__).resolve().parent / "config.ini"

#
def ensure_config_ini(config_path: Path) -> None:
    if config_path.exists():
        return
    config_template = (
        "[keys]\n"
        "deepseek_api_key = YOUR_DEEPSEEK_KEY_HERE\n"
        "openai_api_key = YOUR_OPENAI_KEY_HERE\n\n"
        "[models]\n"
        f"deepseek_model = {DEFAULT_DEEPSEEK_MODEL}\n"
        f"openai_model = {DEFAULT_OPENAI_MODEL}\n"
    )
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config_template)

# sanitization helpers for config values and protocol text
def sanitize_key(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if v.startswith("YOUR_") and v.endswith("_HERE"):
        return ""
    return v

# consider a config value a placeholder if it's empty or looks like a placeholder (e.g. YOUR_KEY_HERE)
def is_placeholder_model(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return True
    if v.startswith("YOUR_") and v.endswith("_HERE"):
        return True
    return False

# fetch value from env var first, then config, with sanitization and stripping
def env_or_config(env_name: str, config_value: str) -> str:
    env_val = os.getenv(env_name, "").strip()
    if env_val:
        return env_val
    return (config_value or "").strip()

# load runtime settings, ensuring config file exists and values are sanitized
def load_runtime_settings() -> RuntimeSettings:
    config_path = script_config_path()
    ensure_config_ini(config_path)

    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")

    deepseek_key = sanitize_key(env_or_config("DEEPSEEK_API_KEY", config.get("keys", "deepseek_api_key", fallback="")))
    openai_key = sanitize_key(env_or_config("OPENAI_API_KEY", config.get("keys", "openai_api_key", fallback="")))

    deepseek_model = env_or_config(
        "DEEPSEEK_MODEL",
        config.get("models", "deepseek_model", fallback=""),
    )
    openai_model = env_or_config(
        "OPENAI_MODEL",
        config.get("models", "openai_model", fallback=""),
    )

    return RuntimeSettings(
        deepseek_api_key=deepseek_key,
        openai_api_key=openai_key,
        deepseek_model=deepseek_model.strip(),
        openai_model=openai_model.strip(),
    )


#
# comment stripping helpers
#strip block comments (/* */ and (* *)) and inline comments (//, #, %) while respecting string literals
def strip_block_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)
    return text


def strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if line.startswith("//", i):
                return line[:i].rstrip()
            if ch in {"#", "%"}:
                return line[:i].rstrip()
        i += 1
    return line.rstrip()

# strip all comments from text, both block and inline
def strip_all_comments(text: str) -> str:
    text = strip_block_comments(text)
    out_lines: List[str] = []
    for raw in text.splitlines():
        clean = strip_inline_comment(raw)
        stripped = clean.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("%"):
            continue
        out_lines.append(clean)
    return "\n".join(out_lines)


# 
# protocol parsing helpers
# keep in mind that goals are often listed in a section starting with "GOALS" and ending with "END GOALS" or the next section header, but sometimes they are just listed inline after "GOALS:" or at the end of the protocol. We want to be flexible in extracting them while avoiding false positives from other sections. Also, we want to preserve the order of goals and remove duplicates while maintaining their original phrasing as much as possible.
def is_section_header(line: str) -> bool:
    upper = line.strip().upper().rstrip(":")
    if upper in SECTION_HEADERS:
        return True
    m = re.match(r"^([A-Z][A-Z0-9 _-]{1,40})\s*:\s*$", line.strip().upper())
    return bool(m and m.group(1).strip() in SECTION_HEADERS)

# extract goals from protocol text, looking for "GOALS" section or inline listing, while stripping comments and ignoring other sections. 
def extract_goals(protocol_text_raw: str) -> List[str]:
    text = strip_all_comments(protocol_text_raw)
    lines = text.splitlines()

    goals: List[str] = []
    in_goals = False

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        upper = line.upper()
        if not in_goals:
            if upper.startswith("GOALS"):
                in_goals = True
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    goals.append(parts[1].strip())
            continue

        if upper.startswith("END GOALS"):
            break
        if upper == "END":
            break
        if is_section_header(line):
            break

        cleaned = re.sub(r"^[-*\s]*\d*[.)]?\s*", "", line).strip()
        cleaned = strip_inline_comment(cleaned).strip()
        if cleaned:
            goals.append(cleaned)

    uniq: List[str] = []
    seen = set()
    for g in goals:
        if g not in seen:
            seen.add(g)
            uniq.append(g)
    return uniq


def anonymize_text_values(text: str, real_path: str, protocol_id: str) -> str:
    path_obj = Path(real_path)
    filename = path_obj.name
    stem = path_obj.stem
    out = text.replace(str(path_obj), protocol_id)
    out = out.replace(filename, protocol_id)
    out = out.replace(stem, protocol_id)
    for part in path_obj.parts:
        token = str(part).strip()
        if len(token) >= 4:
            out = out.replace(token, protocol_id)
    return out

# strip the GOALS section out of the body before sending - the goals go in
# separately so the model sees them as an explicit task list, not buried in protocol text.
def sanitise_protocol_body(protocol_text_raw: str, real_path: str, protocol_id: str) -> str:
    text = strip_all_comments(protocol_text_raw)
    # # replace any trace of the real file path or filename with the protocol ID.
# without this the model sometimes leaks the real name into its JSON output
# which breaks the truth comparison matching later.
    text = anonymize_text_values(text, real_path, protocol_id)

    out_lines: List[str] = []
    in_goals = False

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if re.match(r"^(protocol|name|title|filename|file)\b.*$", stripped, flags=re.IGNORECASE):
            continue

        upper = stripped.upper()
        if not in_goals and upper.startswith("GOALS"):
            in_goals = True
            continue

        if in_goals:
            if upper.startswith("END GOALS") or upper == "END" or is_section_header(stripped):
                in_goals = False
            continue

        out_lines.append(stripped)

    return "\n".join(out_lines).strip()


def sanitise_goals(goals: Sequence[str], real_path: str, protocol_id: str) -> List[str]:
    cleaned: List[str] = []
    for goal in goals:
        g = anonymize_text_values(goal, real_path, protocol_id)
        g = strip_inline_comment(g).strip()
        if g:
            cleaned.append(g)
    return cleaned


def build_prompt(protocol_id: str, protocol_body: str, goals: Sequence[str]) -> str:
    goals_block = "\n".join(f"{idx}. {goal}" for idx, goal in enumerate(goals, start=1))
    return PROMPT_TEMPLATE.format(
        protocol_id=protocol_id,
        protocol_body=protocol_body,
        goals_block=goals_block,
    )


# ---------------------------------------------------------------------------
# JSON parsing and normalization helpers
def safe_json_loads(maybe_json: str) -> Optional[Dict[str, Any]]:
    s = (maybe_json or "").strip()
    if not s:
        return None
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return parsed
        return None
    except json.JSONDecodeError:
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                parsed = json.loads(s[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                return None
    return None


def ensure_two_session_trace(trace: str) -> str:
    trace = (trace or "").strip()
    if "Session 1:" in trace and "Session 2:" in trace:
        return trace
    return "Session 1: Not clearly provided by model.\nSession 2: Not clearly provided by model."

# status normalization and export helpers - we want to be flexible in accepting various forms of satisfied/violated/unknown from the model, but we want to normalize them into a consistent internal representation for analysis and reporting. Also, when exporting results, we want to use "attack found" and "no attack" for better readability, while still allowing "unknown" to pass through.
def normalize_status(value: str) -> str:
    s = (value or "").strip().lower()
    if s.startswith("sat"):
        return "satisfied"
    if s.startswith("vio") or s.startswith("fail"):
        return "violated"
    return "unknown"


def export_status(value: str) -> str:
    internal = normalize_status(value)
    if internal == "violated":
        return "attack found"
    if internal == "satisfied":
        return "no attack"
    return "unknown"


def normalize_attack_label(value: str) -> str:
    s = (value or "").strip().lower()
    if s == "attack found":
        return "attack found"
    if s == "no attack":
        return "no attack"
    if s == "unknown":
        return "unknown"
    return export_status(s)

# sentence splitting helper for justification analysis - we want to be flexible in accepting various forms of justification from the model, but we want to split them into sentences for analysis.
def split_sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p for p in parts if p.strip()]



# Timeout / error helpers
# detect various errors
def build_openai_timeout() -> Any:
    if httpx is None:
        return PER_MODEL_REQUEST_TIMEOUT_SECONDS
    try:
        return httpx.Timeout(
            timeout=PER_MODEL_REQUEST_TIMEOUT_SECONDS,
            connect=10.0,
            read=PER_MODEL_REQUEST_TIMEOUT_SECONDS,
            write=PER_MODEL_REQUEST_TIMEOUT_SECONDS,
        )
    except Exception:
        return PER_MODEL_REQUEST_TIMEOUT_SECONDS

#
def short_error(exc: Exception) -> str:
    msg = str(exc).strip()
    if msg:
        return msg
    return exc.__class__.__name__

# try to extract http status code, helps pinpoint error
def get_status_code(exc: Exception) -> Optional[int]:
    for attr in ("status_code",):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    resp = getattr(exc, "response", None)
    if resp is not None:
        code = getattr(resp, "status_code", None)
        if isinstance(code, int):
            return code
    return None

#permanent auth errors = no retries
#temporary quota errors = disable provider with no retries
def is_permanent_auth_error(exc: Exception) -> bool:
    code = get_status_code(exc)
    if code in {400, 401, 403}:
        return True
    msg = short_error(exc).lower()
    auth_tokens = [
        "invalid api key",
        "incorrect api key",
        "authentication",
        "unauthorized",
        "forbidden",
        "permission denied",
    ]
    return any(token in msg for token in auth_tokens)

#
def is_quota_error(exc: Exception) -> bool:
    code = get_status_code(exc)
    if code == 402:
        return True
    msg = short_error(exc).lower()
    quota_tokens = [
        "insufficient funds",
        "insufficient_funds",
        "quota exceeded",
        "billing",
        "payment required",
        "exceeded your current quota",
        "insufficient_quota",
    ]
    if any(token in msg for token in quota_tokens):
        return True
    if code == 429:
        if any(token in msg for token in ["quota", "billing", "funds", "limit exceeded"]):
            return True
    return False

#in case no error fallback method 
def is_model_not_found_error(exc: Exception) -> bool:
    code = get_status_code(exc)
    if code == 404:
        return True
    msg = short_error(exc).lower()
    return any(token in msg for token in [
        "model not found",
        "model_not_found",
        "does not exist",
        "not available",
        "unsupported model",
        "invalid model",
    ])

#temporary busy server = try fallback or retry
def is_server_overload_error(exc: Exception) -> bool:
    code = get_status_code(exc)
    if code == 503:
        return True
    msg = short_error(exc).lower()
    return any(token in msg for token in [
        "high demand",
        "overloaded",
        "capacity",
        "server is busy",
        "service is busy",
        "try again later",
        "temporarily unavailable",
        "resource exhausted",
    ])

#temporary errors that may succeed on retry, including timeouts, connection issues, and server overloads
def is_transient_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, FuturesTimeoutError, ConnectionError, OSError)):
        return True

    code = get_status_code(exc)
    if code == 429:
        return True
    if code is not None and 500 <= code <= 599:
        return True

    msg = short_error(exc).lower()
    transient_tokens = [
        "timeout",
        "timed out",
        "temporar",
        "rate limit",
        "too many requests",
        "connection",
        "network",
        "service unavailable",
        "try again",
    ]
    return any(token in msg for token in transient_tokens)


def backoff_seconds(retry_index: int) -> float:
    base = [2.0, 5.0, 10.0]
    wait_base = base[retry_index] if retry_index < len(base) else 10.0
    return min(10.0, wait_base) + random.uniform(0.0, 0.5)


def run_with_timeout(fn, timeout_seconds: float):
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fn)
    try:
        return future.result(timeout=max(0.0, timeout_seconds))
    except FuturesTimeoutError as exc:
        future.cancel()
        raise TimeoutError(f"operation timed out after {timeout_seconds:.1f}s") from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


# 
# normalize analysis helper
# rebuilds clean analysis from model response 
#if goals skipped or partial response results still produced
#row for every goal missing = unknown not blank
# incomplete responses accepted 
def normalize_analysis(
    model_name: str,
    protocol_id: str,
    goals: Sequence[str],
    parsed: Optional[Dict[str, Any]],
    fallback_reason: Optional[str] = None,
) -> Dict[str, Any]:
    #index ans by id =can do quick lookups
    #goal id missing = skipped 
    by_goal: Dict[int, Dict[str, Any]] = {}
    if parsed and isinstance(parsed.get("analysis"), list):
        for item in parsed["analysis"]:
            if not isinstance(item, dict):
                continue
            try:
                gid = int(item.get("goal_id"))
            except Exception:
                continue
            by_goal[gid] = item

    analysis: List[Dict[str, Any]] = []
    for idx, goal in enumerate(goals, start=1):
        #empty dict for no response
        item = by_goal.get(idx, {})
        status = normalize_status(str(item.get("status", "unknown")))
        justification = str(item.get("justification", "")).strip()

        if fallback_reason:
            #if provider fails = oveeride = error as just
            status = "unknown"
            justification = fallback_reason
        else:
            if not justification:
                justification = "Model response did not include a usable justification."

            sent_count = len(split_sentences(justification))
            #short justification enough context in file 
            ##long justification = trimmed to keep readable
            if sent_count < 2:
                justification = (
                    justification
                    + " Analysis confidence is limited due to missing detail."
                    + " Additional symbolic verification is recommended."
                )
            elif sent_count > 6:
                justification = " ".join(split_sentences(justification)[:6])

        analysis.append(
            {
                "goal_id": idx,
                "goal": goal,
                "status": status,
                "justification": justification,
                "two_session_trace": ensure_two_session_trace(str(item.get("two_session_trace", ""))),
            }
        )

    return {"model": model_name, "protocol_id": protocol_id, "analysis": analysis}


# model = runs once b4 main loop to pick which model each runner should start with 
#per protocl fallback handled = _try_model
def resolve_openai_model(client: OpenAI, configured_model: str) -> Tuple[str, str]:
    #put config model 1st then list as fallback options
    """Try configured model, then fall back through preferred list. Returns (model, note)."""
    candidates = []
    if configured_model and not is_placeholder_model(configured_model):
        candidates.append(configured_model)
    candidates.extend(m for m in OPENAI_REASONING_MODELS if m not in candidates)

    # validate models agaisnt what account has access to 
    # some accounts may not have listing access
    # so if listing fails = try candidates and let the runner handle 404 fallback
    available_ids: set = set()
    try:
        model_list = client.models.list()
        available_ids = {m.id for m in model_list}
    except Exception:
        pass # listing fails = fallback to trying candidates and let runner handle 404 if not found

    if available_ids:
        for candidate in candidates:
            if candidate in available_ids:
                # which model picked and why = useful for debugging and analysis, especially if fallback used
                note = "validated" if candidate == candidates[0] else f"fallback (validated from model list)"
                return candidate, note

    # no validation possible return 1st model and let 404 handler in
    #if model string invalid = _try_model will handle
    return candidates[0], "selected (not validated via listing)"


def resolve_deepseek_model(configured_model: str) -> Tuple[str, str]:
    #not sure about deepseek model listing endpoint so skipped 
    #validation + trust config 
    #
    """DeepSeek doesn't reliably support model listing; use configured or default."""
    if configured_model and not is_placeholder_model(configured_model):
        return configured_model, "configured"
    return DEFAULT_DEEPSEEK_MODEL, "default"


# model runners 
#each model = own runner class with analyse method that takes prompt and returns ModelResult
#baserunner = fallback
#deepseek runner and openai runner implement actual calls, with error handling and fallback logic. Each runner handles its own model selection and retries, and returns a ModelResult with the raw response and the normalized analysis. If a runner is disabled due to quota or auth errors, it will return an unknown result with the reason for disablement in the justification.
class BaseRunner:
    # shared diasbae mechanism, once called returns without hitting api
    #used for quota and auth failures
    #assumed retrying will maybe cost more money and keep failing so no point 
    name = "Base"
    disabled = False
    disabled_reason = ""

    def disable(self, reason: str) -> None:
        self.disabled = True
        self.disabled_reason = reason
        print(f"[!] PROVIDER DISABLED: {self.name} — {reason}")

    def analyse(self, prompt: str, protocol_id: str, goals: Sequence[str]) -> ModelResult:
        # if disabled = return unknown with reason, no api call
        # runs if runner added and implement analyse() forgotten
        if self.disabled:
            parsed = normalize_analysis(
                self.name, protocol_id, goals, None,
                f"Provider {self.name} disabled: {self.disabled_reason}",
            )
            return ModelResult(self.name, "", parsed, model_variant=f"{self.name} disabled")
        parsed = normalize_analysis(self.name, protocol_id, goals, None, "Runner not implemented.")
        return ModelResult(self.name, "", parsed, model_variant=f"{self.name} (not implemented)")


class DeepSeekRunner(BaseRunner):
    name = "DeepSeek"
    #deepseek uses openai but different base url
    def __init__(self, api_key: str, model_config: str, mode: str = "reasoning"):
        self.api_key = (api_key or "").strip()
        self.mode = mode
        preferred = DEEPSEEK_REASONING_MODELS if mode == "reasoning" else DEEPSEEK_CHAT_MODELS
        self.model = preferred[0]
        self.fallback_models = preferred[1:]
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=DEEPSEEK_BASE_URL,
            timeout=build_openai_timeout(),
        ) if self.api_key else None
        if self.api_key:
            print(f"  [DeepSeek] Model: {self.model} (mode={self.mode})")
        else:
            print(f"  [DeepSeek] No API key set — will output unknown")
    # low temp keeps responses consistent 
    def _call_model(self, prompt: str, model: str) -> str:
        response = self.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Return JSON only. No markdown."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            stream=False,
        )
        return getattr(response.choices[0].message, "content", "") or ""
    #reset to primary model on every call 
    # no inheriting fallback model from previous protocol
    def analyse(self, prompt: str, protocol_id: str, goals: Sequence[str]) -> ModelResult:
        if self.disabled:
            parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                        f"Provider disabled: {self.disabled_reason}")
            return ModelResult(self.name, "", parsed, model_variant=f"{self.name} disabled")
        if not self.api_key:
            parsed = normalize_analysis(self.name, protocol_id, goals, None, "API key not set (DEEPSEEK_API_KEY).")
            return ModelResult(self.name, "", parsed, model_variant=f"{self.name} (no API key)")

        preferred = DEEPSEEK_REASONING_MODELS if self.mode == "reasoning" else DEEPSEEK_CHAT_MODELS
        self.model = preferred[0]
        self.fallback_models = preferred[1:]
        models_to_try = [self.model] + self.fallback_models
        ##try each model in order, if model-not-found or overload error try next, if quota or auth error disable provider, if other error retry with backoff, if retries exhausted return unknown with reason
        for model_candidate in models_to_try:
            result = self._try_model(prompt, protocol_id, goals, model_candidate)
            if result is not None:
                return result
            # If we get here, model-not-found= try next

        print(f"  [!] {self.name}: all model candidates exhausted for {protocol_id}, will retry next protocol")
        parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                    f"All {self.name} model candidates failed.")
        return ModelResult(self.name, "", parsed, model_variant=f"{self.name} ({self.mode}, all models failed)")
    
    #ai failed = possibly temporary =next protocol try again from top of list 


    def _try_model(self, prompt: str, protocol_id: str, goals: Sequence[str], model: str) -> Optional[ModelResult]:
        # none returned to signal next model or modelresult to show this procider limit reached for this protocol
        total_attempts = 1 + PER_MODEL_MAX_RETRIES
        for attempt in range(1, total_attempts + 1):
            print(f"  START model={self.name}({model}) protocol={protocol_id} attempt={attempt}")
            call_started = time.monotonic()
            try:
                raw_text = run_with_timeout(
                    lambda: self._call_model(prompt, model),
                    PER_MODEL_REQUEST_TIMEOUT_SECONDS,
                )
                elapsed = time.monotonic() - call_started
                print(f"  END model={self.name} protocol={protocol_id} seconds={elapsed:.2f} chars={len(raw_text)}")
                parsed_raw = safe_json_loads(raw_text)
                parsed = normalize_analysis(self.name, protocol_id, goals, parsed_raw)
                return ModelResult(self.name, raw_text, parsed, model_variant=f"{model} ({self.mode})")
            except Exception as exc:
                reason = short_error(exc)
                print(f"  FAIL model={self.name}({model}) protocol={protocol_id} reason={reason}")
                if is_model_not_found_error(exc):
                    print(f"  [!] Model {model} not found for {self.name}, trying fallback...")
                    return None  # signal to try next model
                if is_server_overload_error(exc):
                    print(f"  [!] Model {model} overloaded for {self.name}, trying fallback...")
                    return None  # signal to try next model
                if is_quota_error(exc):
                    self.disable(f"Quota/funds error: {reason}")
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Provider disabled (quota): {reason}")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, quota error)")
                if is_permanent_auth_error(exc):
                    self.disable(f"Auth error: {reason}")
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Provider disabled (auth): {reason}")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, auth error)")
                if not is_transient_error(exc) or attempt >= total_attempts:
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Error calling {self.name}: {reason}; retries exhausted.")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, failed)")
                time.sleep(backoff_seconds(attempt - 1))

        parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                    f"Error calling {self.name}: retries exhausted.")
        return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, retries exhausted)")


class OpenAIRunner(BaseRunner):
    name = "GPT"

    def __init__(self, api_key: str, model_config: str, mode: str = "reasoning"):
        self.api_key = (api_key or "").strip()
        self.mode = mode
        self.client = OpenAI(api_key=self.api_key, timeout=build_openai_timeout()) if self.api_key else None
        preferred = OPENAI_REASONING_MODELS if mode == "reasoning" else OPENAI_CHAT_MODELS
        self.model = preferred[0]
        self.fallback_models = preferred[1:]
        if self.api_key:
            print(f"  [GPT] Model: {self.model} (mode={self.mode})")
        else:
            print(f"  [GPT] No API key set — will output unknown")

    def _call_model(self, prompt: str, model: str) -> str:
        # gpt does not use temp but reasoning effort paramaters
        is_reasoning = self.mode == "reasoning" or model.startswith(("gpt-5.2-thinking", "gpt-5.2-pro", "o1", "o3"))
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Return JSON only. No markdown."},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        if is_reasoning:
            kwargs["reasoning_effort"] = "high"
        else:
            kwargs["temperature"] = 0.1
        response = self.client.chat.completions.create(**kwargs)
        return getattr(response.choices[0].message, "content", "") or ""

    def analyse(self, prompt: str, protocol_id: str, goals: Sequence[str]) -> ModelResult:
        if self.disabled:
            parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                        f"Provider disabled: {self.disabled_reason}")
            return ModelResult(self.name, "", parsed, model_variant=f"{self.name} disabled")
        if not self.api_key:
            parsed = normalize_analysis(self.name, protocol_id, goals, None, "API key not set (OPENAI_API_KEY).")
            return ModelResult(self.name, "", parsed, model_variant=f"{self.name} (no API key)")

        preferred = OPENAI_REASONING_MODELS if self.mode == "reasoning" else OPENAI_CHAT_MODELS
        self.model = preferred[0]
        self.fallback_models = preferred[1:]
        models_to_try = [self.model] + self.fallback_models
        for model_candidate in models_to_try:
            result = self._try_model(prompt, protocol_id, goals, model_candidate)
            if result is not None:
                return result

        print(f"  [!] {self.name}: all model candidates exhausted for {protocol_id}, will retry next protocol")
        parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                    f"All {self.name} model candidates failed.")
        return ModelResult(self.name, "", parsed, model_variant=f"{self.name} ({self.mode}, all models failed)")

    def _try_model(self, prompt: str, protocol_id: str, goals: Sequence[str], model: str) -> Optional[ModelResult]:
        total_attempts = 1 + PER_MODEL_MAX_RETRIES
        for attempt in range(1, total_attempts + 1):
            print(f"  START model={self.name}({model}) protocol={protocol_id} attempt={attempt}")
            call_started = time.monotonic()
            try:
                raw_text = run_with_timeout(
                    lambda: self._call_model(prompt, model),
                    PER_MODEL_REQUEST_TIMEOUT_SECONDS,
                )
                elapsed = time.monotonic() - call_started
                print(f"  END model={self.name} protocol={protocol_id} seconds={elapsed:.2f} chars={len(raw_text)}")
                parsed_raw = safe_json_loads(raw_text)
                parsed = normalize_analysis(self.name, protocol_id, goals, parsed_raw)
                return ModelResult(self.name, raw_text, parsed, model_variant=f"{model} ({self.mode})")
            except Exception as exc:
                reason = short_error(exc)
                print(f"  FAIL model={self.name}({model}) protocol={protocol_id} reason={reason}")
                if is_model_not_found_error(exc):
                    print(f"  [!] Model {model} not found for {self.name}, trying fallback...")
                    return None
                if is_server_overload_error(exc):
                    print(f"  [!] Model {model} overloaded for {self.name}, trying fallback...")
                    return None
                if is_quota_error(exc):
                    self.disable(f"Quota/funds error: {reason}")
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Provider disabled (quota): {reason}")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, quota error)")
                if is_permanent_auth_error(exc):
                    self.disable(f"Auth error: {reason}")
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Provider disabled (auth): {reason}")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, auth error)")
                if not is_transient_error(exc) or attempt >= total_attempts:
                    parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                                f"Error calling {self.name}: {reason}; retries exhausted.")
                    return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, failed)")
                time.sleep(backoff_seconds(attempt - 1))

        parsed = normalize_analysis(self.name, protocol_id, goals, None,
                                    f"Error calling {self.name}: retries exhausted.")
        return ModelResult(self.name, "", parsed, model_variant=f"{model} ({self.mode}, retries exhausted)")



# file collection 
#
def collect_files(inputs: Sequence[str], recursive: bool, exts: Optional[Sequence[str]]) -> List[str]:
    # if no ext = default to anb and anbx 
    # normalise extensions to lowercase so both resolve to same thing 
    ext_list = list(exts) if exts else ["anb", "anbx"]
    norm_exts = {f".{e.lower().lstrip('.')}" for e in ext_list}

    collected: List[str] = []
    for item in inputs:
        # resolve to path object, expand ~ and resolve to absolute path, strip quotes in case input is quoted

        path = Path(str(item).strip().strip('"').strip("'"))
        path = path.expanduser().resolve()

        if path.is_file() and path.suffix.lower() in norm_exts:
            collected.append(str(path))
            continue
        #
        if path.is_dir():
            # sorted() = consistent file order for each protocol
            #numbering = predictable and reproducible results, helps with debugging and analysis, especially if model responses vary by file order
            iterator = path.rglob("*") if recursive else path.glob("*")
            for p in sorted(iterator):
                if p.is_file() and p.suffix.lower() in norm_exts:
                    collected.append(str(p.resolve()))
            continue

        print(f"[!] Skipping unknown path: {path}")
    # remv duplicates while keeping order in case duplicates exist in same file 
    # 
    seen = set()
    out: List[str] = []
    for p in collected:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# reuslts builder for if timeout happens 
#placeholder results = consistent output 
def timeout_result_for_model(model_name: str, protocol_id: str, goals: Sequence[str], reason: str) -> ModelResult:
    # goal is given clear timeout reason 
    # reason for lack of analysis 

    analysis = [
        {
            "goal_id": idx,
            "goal": goal,
            "status": "unknown",
            "justification": reason,
            "two_session_trace": ensure_two_session_trace(""),
        }
        for idx, goal in enumerate(goals, start=1)
    ]
    parsed = {"model": model_name, "protocol_id": protocol_id, "analysis": analysis}
    return ModelResult(model_name=model_name, raw_response_text="", parsed_response=parsed,
                       model_variant=f"{model_name} (timeout)")

#timeout result built in for each model
def timeout_results(protocol_id: str, goals: Sequence[str], reason: str) -> List[ModelResult]:
    return [timeout_result_for_model(name, protocol_id, goals, reason) for name in MODEL_ORDER]


# ---------------------------------------------------------------------------
# Parallel model execution
# ---------------------------------------------------------------------------
# runs models in parralel for each protocol and collect results
def run_models_parallel(
    runners: Sequence[BaseRunner],
    prompt: str,
    protocol_id: str,
    goals_sanitized: Sequence[str],
    model_workers: int,
    timeout_seconds: float,
) -> Tuple[List[ModelResult], bool]:
    by_name: Dict[str, ModelResult] = {}
    timeout_hit = False
    timeout_reason = f"Per-protocol timeout ({PER_PROTOCOL_TIMEOUT_SECONDS:.0f}s) reached."

    total_timeout = max(0.0, timeout_seconds)
    started = time.monotonic()
    deadline = started + total_timeout

    # skip disabled runners
    # if all runners disabled = return timeout results for all models to keep output consistent and clear that no providers were active, rather than showing missing results which could be confusing
    active_runners = [r for r in runners if not r.disabled]
    disabled_runners = [r for r in runners if r.disabled]
    for r in disabled_runners:
        parsed = normalize_analysis(r.name, protocol_id, goals_sanitized, None,
                                    f"Provider disabled: {r.disabled_reason}")
        by_name[r.name] = ModelResult(r.name, "", parsed, model_variant=f"{r.name} disabled")

    if not active_runners:
        for name in MODEL_ORDER:
            if name not in by_name:
                by_name[name] = timeout_result_for_model(name, protocol_id, goals_sanitized, "No active providers.")
        return [by_name[name] for name in MODEL_ORDER], False

    pool = ThreadPoolExecutor(max_workers=max(1, model_workers))
    #which model they belong to 
    future_map = {pool.submit(runner.analyse, prompt, protocol_id, goals_sanitized): runner.name
                  for runner in active_runners}
    pending = set(future_map.keys())
    timed_out_models = set()
    next_heartbeat = started + HEARTBEAT_INTERVAL_SECONDS

    try:
        while pending:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                timeout_hit = True
                timed_out_models = {future_map[f] for f in pending}
                break

            #cap wait at heartbeat can print progress 
            #every 15sec
            #first_completed = collect each result as it comes instead of waiting till everything completed 
            done, pending = wait(
                pending,
                timeout=min(HEARTBEAT_INTERVAL_SECONDS, max(0.0, remaining)),
                return_when=FIRST_COMPLETED,
            )

            for future in done:
                model_name = future_map[future]
                try:
                    by_name[model_name] = future.result()
                except Exception as exc:
                    parsed = normalize_analysis(
                        model_name=model_name,
                        protocol_id=protocol_id,
                        goals=goals_sanitized,
                        parsed=None,
                        fallback_reason=f"Error calling {model_name}: {exc}; retries exhausted.",
                    )
                    by_name[model_name] = ModelResult(model_name=model_name, raw_response_text="",
                                                      parsed_response=parsed,
                                                      model_variant=f"{model_name} (failed)")

            now = time.monotonic()
            #print progress every 15sec so clear in script 
            #to show hasnt hung and tell you what is happening with models
            if pending and now >= next_heartbeat:
                done_count = len(future_map) - len(pending)
                elapsed = now - started
                print(
                    f"  Heartbeat protocol={protocol_id}: done={done_count}/{len(future_map)} "
                    f"pending={len(pending)} elapsed={elapsed:.1f}s"
                )
                next_heartbeat = now + HEARTBEAT_INTERVAL_SECONDS

        if pending:
            timeout_hit = True
            timed_out_models = {future_map[f] for f in pending}
            for future in pending:
                future.cancel()
    finally:
        # cancel_futures=true drops qued work but not force a stop
        #threads blocked on network = will finsih 
        # if timeout hit = assume threads will never finish and just exit process when done, so cancel all to free resources and avoid hanging on shutdown
        if timeout_hit:
            pool.shutdown(wait=False, cancel_futures=True)
        else:
            pool.shutdown(wait=False, cancel_futures=False)
    # gap fill anything not in by_name usually happens in timeout 
    for name in MODEL_ORDER:
        if name in by_name:
            continue
        if timeout_hit and name in timed_out_models:
            by_name[name] = timeout_result_for_model(name, protocol_id, goals_sanitized, timeout_reason)
        else:
            parsed = normalize_analysis(
                model_name=name,
                protocol_id=protocol_id,
                goals=goals_sanitized,
                parsed=None,
                fallback_reason=f"Model result missing for {name}.",
            )
            #shouldnt really happen unless model runner code has a bug or unexpected error, but just in case to avoid missing results and make it clear in output what happened, fill with unknown and reason for missing
            by_name[name] = ModelResult(model_name=name, raw_response_text="", parsed_response=parsed,
                                        model_variant=f"{name} (missing)")

    return [by_name[name] for name in MODEL_ORDER], timeout_hit

# CSV / audit helpers
# #reindex model list by goal_id integer so csv writer
#can do direct lookup for each goal
#skips entries where goal id missing
def analysis_by_goal(raw: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for item in raw.get("analysis", []) or []:
        if not isinstance(item, dict):
            continue
        try:
            gid = int(item.get("goal_id"))
        except Exception:
            continue
        out[gid] = item
    return out


def truncate_text(text: str, max_chars: int = RAW_RESPONSE_MAX_CHARS) -> str:
    #full responses go in json
    #will flag in csv if response too long 
    t = (text or "").strip()
    if len(t) <= max_chars:
        return t
    return t[:max_chars] + "... [truncated]"


#column order in every csv this script produces 
#dictwriter uses list for header and row validation 
CSV_FIELDNAMES = [
    "timestamp_start_overall",
    "timestamp_end_overall",
    "overall_runtime_seconds",
    "protocol_index",
    "protocol_id",
    "protocol_name",
    "real_file_path",
    "protocol_runtime_seconds",
    "model_name",
    "model_variant",
    "goal_id",
    "goal_text",
    "status",
    "justification",
    "two_session_trace",
    "raw_response_text",
]


def init_csv(out_path: str) -> None:
    #called once before main loop 
    """Write CSV header once."""
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()


def append_protocol_csv(
    out_path: str,
    row_data: Dict[str, Any],
    start_iso: str,
    end_iso: str,
    overall_runtime_seconds: float,
) -> None:
    #one row per goal per model 
    #lookup maps built so inner loop not searching through lists 
    """Append rows for one protocol and flush."""
    goals = row_data["goals_raw"]
    result_map = {result.model_name: analysis_by_goal(result.parsed_response) for result in row_data["results"]}
    raw_text_map = {result.model_name: truncate_text(result.raw_response_text) for result in row_data["results"]}
    variant_map = {result.model_name: result.model_variant for result in row_data["results"]}

    with open(out_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        for gid, goal in enumerate(goals, start=1):
            for model_name in MODEL_ORDER:
                item = result_map.get(model_name, {}).get(gid, {})
                writer.writerow(
                    {
                        "timestamp_start_overall": start_iso,
                        "timestamp_end_overall": end_iso,
                        "overall_runtime_seconds": overall_runtime_seconds,
                        "protocol_index": row_data["protocol_index"],
                        "protocol_id": row_data["protocol_id"],
                        "protocol_name": row_data["protocol_name"],
                        "real_file_path": row_data["file_path"],
                        "protocol_runtime_seconds": round(row_data["protocol_runtime_seconds"], 3),
                        "model_name": model_name,
                        "model_variant": variant_map.get(model_name, ""),
                        "goal_id": gid,
                        "goal_text": goal,
                        "status": export_status(str(item.get("status", "unknown"))),
                        "justification": str(item.get("justification", "")).strip(),
                        "two_session_trace": ensure_two_session_trace(str(item.get("two_session_trace", ""))),
                        "raw_response_text": raw_text_map.get(model_name, ""),
                    }
                )
        f.flush() #ensure data written to disk after each protocol, helps with crash safety and allows partial results to be available even if script interrupted

#full record including promp and response 
#one json line each protocol so partial files still readable 
def append_audit_jsonl(out_path: str, audit_entry: Dict[str, Any]) -> None:
    """Append one JSONL line per protocol (crash-safe)."""
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
        f.flush()


# truth comparison 
#reads output and compares manually 
#up to three truth files

def normalize_protocol_match_key(name: str, stem_only: bool) -> str:
    #reduces protocl name to lowercase so different formatting between files do not cause matches 
    base = Path(str(name or "").strip()).name
    if stem_only:
        base = Path(base).stem
    s = base.lower().strip()
    s = re.sub(r"[\s_-]+", "-", s)
    s = re.sub(r"[^a-z0-9.\-]+", "", s)
    s = s.replace(".", "-")
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s


def normalize_goal_text_key(text: str) -> str:
    s = (text or "").lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^a-z0-9 ]+", "", s)
    return s.strip()

#minimal cleaning of truth verdict to preserve original wording as possible dont want to alter anything 
def clean_truth_verdict(value: str) -> str:
    """Minimal safe cleaning only: strip whitespace, collapse internal whitespace.
    Preserve original wording and casing."""
    s = (value or "").strip()
    s = re.sub(r"\s+", " ", s)
    return s

#detect which column contains which header 
# matches it then returnsd 
def detect_column(headers: Sequence[str], candidates: Sequence[str]) -> Optional[str]:
    table = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c in table:
            return table[c]
    return None

#handle comparison files where goal id and text share column 
#if value is integer treated as id or text

def extract_goal_id_text(
    row: Dict[str, Any],
    goal_id_col: Optional[str],
    goal_text_col: Optional[str],
) -> Tuple[str, str]:
    raw_id = str(row.get(goal_id_col, "")).strip() if goal_id_col else ""
    raw_text = str(row.get(goal_text_col, "")).strip() if goal_text_col else ""

    if goal_id_col and goal_text_col and goal_id_col == goal_text_col:
        v = raw_id
        if re.fullmatch(r"\d+", v):
            return v, ""
        return "", v

    goal_id = raw_id if re.fullmatch(r"\d+", raw_id) else ""
    goal_text = raw_text
    if not goal_text and raw_id and not re.fullmatch(r"\d+", raw_id):
        goal_text = raw_id
    return goal_id, goal_text


VERDICT_CANDIDATES = ["attack", "status", "result", "verdict", "outcome", "decision", "label"]

#extra precautions in how the files name goal ids 
def extract_truth_protocol_base_and_goal(raw_name: str) -> Tuple[str, str]:
    """Split a truth protocol name like 'AnBx_BlindForwarding_01' into
    base name 'AnBx_BlindForwarding' and goal id '1' (leading zeros stripped).
    If the name doesn't match the pattern, return (full name, '')."""
    m = re.match(r"^(.+?)_(\d+)$", raw_name.strip())
    if m:
        base = m.group(1)
        goal_id = str(int(m.group(2)))  # strip leading zeros
        return base, goal_id
    return raw_name.strip(), ""

#main parsing function for truth files, supports csv and json with flexible column naming and structure, extracts protocol name, goal id, goal text, and verdict for each record, applies minimal cleaning to verdict to preserve original wording as much as possible while ensuring consistent formatting for matching, handles cases where goal id and text are in the same column, and allows protocol name to include goal id suffix for matching if explicit goal_id column is not provided
def parse_truth_csv(path: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        if not headers:
            raise ValueError(f"Truth CSV has no header: {path}")

        protocol_col = detect_column(headers, ["protocol", "protocol_name", "name", "file", "filename"])
        status_col = detect_column(headers, VERDICT_CANDIDATES)
        goal_id_col = detect_column(headers, ["goal_id", "goal_number", "id", "goal"])
        goal_text_col = detect_column(headers, ["goal_text", "text", "description", "goal"])

        if not protocol_col or not status_col:
            raise ValueError(f"Truth CSV missing required protocol/status columns: {path}")

        for row in reader:
            protocol_name_raw = str(row.get(protocol_col, "")).strip()
            # verbatim copy of verdict — minimal cleaning only
            status = clean_truth_verdict(str(row.get(status_col, "")))
            goal_id, goal_text = extract_goal_id_text(row, goal_id_col, goal_text_col)

            # split protocol name suffix into base + goal id if applicable
            base_name, suffix_goal_id = extract_truth_protocol_base_and_goal(protocol_name_raw)
            # use the base name as the protocol name for matching
            protocol_name = base_name if suffix_goal_id else protocol_name_raw
            # if no explicit goal_id was found from the goal_id column, use the suffix
            if not goal_id and suffix_goal_id:
                goal_id = suffix_goal_id

            if not protocol_name:
                continue
            records.append(
                {
                    "protocol_name": protocol_name,
                    "goal_id": goal_id,
                    "goal_text": goal_text,
                    "status": status,
                }
            )
    return records


def iter_json_dict_records(obj: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        scalar_count = sum(not isinstance(v, (dict, list)) for v in obj.values())
        if scalar_count >= 2:
            out.append(obj)
        for v in obj.values():
            out.extend(iter_json_dict_records(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(iter_json_dict_records(item))
    return out


def parse_truth_json(path: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    dict_rows = iter_json_dict_records(data)
    if not dict_rows:
        raise ValueError(f"Truth JSON did not contain usable records: {path}")

    header_union = set()
    for r in dict_rows:
        for k in r.keys():
            header_union.add(str(k))
    headers = sorted(header_union)

    protocol_col = detect_column(headers, ["protocol", "protocol_name", "name", "file", "filename"])
    status_col = detect_column(headers, VERDICT_CANDIDATES)
    goal_id_col = detect_column(headers, ["goal_id", "goal_number", "id", "goal"])
    goal_text_col = detect_column(headers, ["goal_text", "text", "description", "goal"])

    if not protocol_col or not status_col:
        raise ValueError(f"Truth JSON missing required protocol/status fields: {path}")

    for row in dict_rows:
        protocol_name_raw = str(row.get(protocol_col, "")).strip()
        status = clean_truth_verdict(str(row.get(status_col, "")))
        goal_id, goal_text = extract_goal_id_text(row, goal_id_col, goal_text_col)

        # split protocol name suffix into base + goal id if applicable
        base_name, suffix_goal_id = extract_truth_protocol_base_and_goal(protocol_name_raw)
        protocol_name = base_name if suffix_goal_id else protocol_name_raw
        if not goal_id and suffix_goal_id:
            goal_id = suffix_goal_id

        if not protocol_name:
            continue
        records.append(
            {
                "protocol_name": protocol_name,
                "goal_id": goal_id,
                "goal_text": goal_text,
                "status": status,
            }
        )

    return records


def parse_truth_file(path: str) -> Dict[str, Any]:
    #four lookup paths per protocol 
#four paths because ai output and comp file may differ 
#
    p = Path(path)
    ext = p.suffix.lower()
    if ext == ".csv":
        rows = parse_truth_csv(path)
    elif ext == ".json":
        rows = parse_truth_json(path)
    else:
        raise ValueError(f"Unsupported truth file type (must be .csv or .json): {path}")

    exact_map: Dict[str, Dict[str, str]] = {}
    stem_map: Dict[str, Dict[str, str]] = {}

    def ensure_proto_maps(container: Dict[str, Dict[str, str]], key: str) -> Dict[str, str]:
        if key not in container:
            container[key] = {}
        return container[key]

    for row in rows:
        proto_exact = normalize_protocol_match_key(row["protocol_name"], stem_only=False)
        proto_stem = normalize_protocol_match_key(row["protocol_name"], stem_only=True)
        gid_key = str(row["goal_id"]).strip()
        gtxt_key = normalize_goal_text_key(row["goal_text"])
        status = row["status"]  # verbatim

        e_id = ensure_proto_maps(exact_map, f"{proto_exact}::id")
        e_tx = ensure_proto_maps(exact_map, f"{proto_exact}::tx")
        s_id = ensure_proto_maps(stem_map, f"{proto_stem}::id")
        s_tx = ensure_proto_maps(stem_map, f"{proto_stem}::tx")

        if gid_key:
            e_id.setdefault(gid_key, status)
            s_id.setdefault(gid_key, status)
        if gtxt_key:
            e_tx.setdefault(gtxt_key, status)
            s_tx.setdefault(gtxt_key, status)

    return {
        "basename": p.name,
        "path": str(p.resolve()),
        "exact_map": exact_map,
        "stem_map": stem_map,
    }

# loookup function for each goal in ai output
#tries exact match with protocol name including goal id suffix first, then stem-only match, and within each tries goal id match first then goal text match, returns verbatim status if found or blank if no match
def lookup_truth_status(
    truth_source: Dict[str, Any],
    protocol_name: str,
    goal_id: str,
    goal_text: str,
) -> str:
    """Return verbatim truth verdict or empty string if unmatched."""
    proto_exact = normalize_protocol_match_key(protocol_name, stem_only=False)
    proto_stem = normalize_protocol_match_key(protocol_name, stem_only=True)
    gid_key = str(goal_id or "").strip()
    gtxt_key = normalize_goal_text_key(goal_text)

    for container, pkey in (
        (truth_source["exact_map"], proto_exact),
        (truth_source["stem_map"], proto_stem),
    ):
        id_map = container.get(f"{pkey}::id", {})
        tx_map = container.get(f"{pkey}::tx", {})
        if gid_key and gid_key in id_map:
            return id_map[gid_key]
        if gtxt_key and gtxt_key in tx_map:
            return tx_map[gtxt_key]

    return ""  # unmatched → blank


def run_truth_comparison(
    ai_csv_path: str,
    truth_paths: List[str],
    comparison_csv_out: str,
    comparison_html_out: Optional[str],
) -> None:
    print("[stage] truth comparison")

    if not truth_paths:
        print("[!] No truth files provided; skipping comparison.")
        return

    ai_rows: List[Dict[str, str]] = []
    with open(ai_csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ai_rows.append({k: (v if v is not None else "") for k, v in row.items()})

    truth_sources = [parse_truth_file(p) for p in truth_paths]
    truth_result_cols = [f"{src['basename']}_result" for src in truth_sources]

    # collect protocols and goals from ai csv
    protocols: Dict[str, Dict[str, Any]] = {}
    for row in ai_rows:
        protocol_name = row.get("protocol_name", "").strip()
        protocol_id = row.get("protocol_id", "").strip()
        goal_id = row.get("goal_id", "").strip()
        goal_text = row.get("goal_text", "").strip()
        model = row.get("model_name", "").strip()
        status = row.get("status", "").strip()  # AI exported as-is

        if not protocol_name:
            continue

        proto = protocols.setdefault(
            protocol_name,
            {
                "protocol_id": protocol_id,
                "goals": {},
            },
        )
        #handle cases where two goals share same id or same text not both
        gkey = f"{goal_id}::{goal_text}"
        if gkey not in proto["goals"]:
            proto["goals"][gkey] = {
                "goal_id": goal_id,
                "goal_text": goal_text,
                "models": {m: "" for m in MODEL_ORDER},
            }
        if model in MODEL_ORDER:
            proto["goals"][gkey]["models"][model] = status

    protocol_names_sorted = sorted(protocols.keys(), key=lambda x: x.lower())
    fieldnames = [
        "protocol_name",
        "protocol_id",
        "goal_id",
        "goal_text",
        "DeepSeek_result",
        "GPT_result",
    ] + truth_result_cols

    total_goal_rows = 0

    with open(comparison_csv_out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol_name in protocol_names_sorted:
            pdata = protocols[protocol_name]
            goals = list(pdata["goals"].values())

            def goal_sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
                gid = item.get("goal_id", "").strip()
                if gid.isdigit():
                    return (0, f"{int(gid):08d}")
                return (1, item.get("goal_text", "").lower())

            goals.sort(key=goal_sort_key)
            total_goal_rows += len(goals)

            for g in goals:
                row_out: Dict[str, str] = {
                    "protocol_name": protocol_name,
                    "protocol_id": pdata["protocol_id"],
                    "goal_id": g["goal_id"],
                    "goal_text": g["goal_text"],
                    "DeepSeek_result": g["models"]["DeepSeek"],
                    "GPT_result": g["models"]["GPT"],
                }

                for src in truth_sources:
                    truth_status = lookup_truth_status(src, protocol_name, g["goal_id"], g["goal_text"])
                    row_out[f"{src['basename']}_result"] = truth_status  # verbatim or blank

                writer.writerow(row_out)

    # optional HTML
    if comparison_html_out:
        _generate_comparison_html(comparison_csv_out, comparison_html_out, fieldnames, truth_result_cols)

    print(f"[+] Comparison complete:")
    print(f"    Protocols: {len(protocol_names_sorted)}")
    print(f"    Goal rows: {total_goal_rows}")
    print(f"    CSV: {comparison_csv_out}")
    if comparison_html_out:
        print(f"    HTML: {comparison_html_out}")

# escape important because names etc could have special characters which break html 
def _generate_comparison_html(csv_path: str, html_path: str, fieldnames: List[str],
                              truth_cols: List[str]) -> None:
    rows: List[Dict[str, str]] = []
    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})

    th_cells = "".join(f"<th>{escape(fn)}</th>" for fn in fieldnames)
    tbody_rows: List[str] = []
    for row in rows:
        cells = "".join(f"<td>{escape(row.get(fn, ''))}</td>" for fn in fieldnames)
        tbody_rows.append(f"<tr>{cells}</tr>")

    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'/>"
        "<title>Truth Comparison</title>"
        "<style>"
        "body{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fa;color:#1f2937;margin:0;}"
        "main{max-width:1600px;margin:0 auto;padding:20px;}"
        "table{width:100%;border-collapse:collapse;table-layout:auto;}"
        "th,td{border:1px solid #d5dbe3;padding:8px;vertical-align:top;word-wrap:break-word;}"
        "th{background:#eef2f6;text-align:left;position:sticky;top:0;}"
        "</style></head><body><main>"
        "<h1>AI vs Truth Comparison</h1>"
        f"<table><thead><tr>{th_cells}</tr></thead>"
        f"<tbody>{''.join(tbody_rows)}</tbody></table>"
        "</main></body></html>"
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)


# 
# CLI --run with --help to see options
#with comparison add --truth-files

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch AnB/AnBx protocol checker with anonymized LLM analysis "
                    "(CSV output, per-protocol timeout, incremental writes)."
    )
    #
    parser.add_argument("inputs", nargs="+", help="Input files and/or folders.")
    parser.add_argument("--recursive", action="store_true", help="Recurse into input directories.")
    parser.add_argument("--ext", nargs="*", default=None, help="Extensions to include (default: anb anbx).")
    parser.add_argument("--out", default="report.csv", help="AI results CSV output path.")
    parser.add_argument(
        "--model-workers",
        type=int,
        default=3,
        help="Max concurrent model calls per protocol.",
    )
    parser.add_argument("--json-out", default=None, help="Optional path for audit JSONL output (incremental).")
    parser.add_argument(
        "--truth-files",
        nargs="+",
        default=None,
        metavar="TRUTH",
        help="1-3 truth files (.csv or .json) for offline comparison.",
    )
    parser.add_argument("--comparison-out", default="comparison.csv", help="Comparison CSV output path.")
    parser.add_argument(
        "--comparison-html",
        default=None,
        help="Optional comparison HTML output path.",
    )
    return parser.parse_args()



# Main
# 
def main() -> None:
    args = parse_args()

    # interactive mode selection 
    #change MODEL_MODE variable if you want hardcode 
    print("Select model mode:")
    print("  1 = Chat models (faster, lower cost)")
    print("  2 = Reasoning models (slower, higher quality)")
    while True:
        choice = input("Enter 1 or 2: ").strip()
        if choice == "1":
            MODEL_MODE = "chat"
            break
        elif choice == "2":
            MODEL_MODE = "reasoning"
            break
        else:
            print("Please enter 1 or 2.")
    print(f"  Mode selected: {MODEL_MODE}")

    # stage: loading configuration
    print("[stage] loading configuration / selecting models")
    settings = load_runtime_settings()
    #wall clock in csv timestamps
    start_ts = datetime.now()
    start_iso = start_ts.isoformat(timespec="seconds")

    # stage: collecting files
    print("[stage] collecting files")
    files = collect_files(args.inputs, recursive=args.recursive, exts=args.ext)
    if not files:
        print("[!] No protocol files found.")
        sys.exit(1)
    print(f"  Found {len(files)} protocol file(s)")

    # stage: initializing runners (model selection happens here)
    print("[stage] initializing runners")
    #runners used across all protocols
    #resets to primary model at start of protocol
    runners: List[BaseRunner] = [
        DeepSeekRunner(api_key=settings.deepseek_api_key, model_config=settings.deepseek_model, mode=MODEL_MODE),
        OpenAIRunner(api_key=settings.openai_api_key, model_config=settings.openai_model, mode=MODEL_MODE),
    ]

    # initialize incremental CSV
    #happens before loop
    print("[stage] writing outputs (initializing CSV)")
    init_csv(args.out)

    protocol_rows_summary: List[Dict[str, Any]] = []
    timeout_protocol_count = 0
    total_files = len(files)

    for idx, path in enumerate(files, start=1):
        protocol_start_dt = datetime.now()
        protocol_start_perf = time.monotonic()
        protocol_id = f"PROTO_{idx:04d}"
        protocol_timeout_hit = False

        print(f"\n[stage] processing protocol {idx}/{total_files}")

        try:
            raw_text = read_text_file(path)
        except Exception as exc:
            print(f"[!] Could not read {path}: {exc}")
            continue

        goals_raw = extract_goals(raw_text)
        if not goals_raw:
            print(f"[!] No explicit GOALS section found in: {path}")
            continue

        protocol_body = sanitise_protocol_body(raw_text, real_path=path, protocol_id=protocol_id)
        goals_sanitized = sanitise_goals(goals_raw, real_path=path, protocol_id=protocol_id)
        prompt = build_prompt(protocol_id=protocol_id, protocol_body=protocol_body, goals=goals_sanitized)

        print(
            f"  protocol_id={protocol_id} file={Path(path).name} "
            f"goals={len(goals_raw)} body_len={len(protocol_body)} prompt_len={len(prompt)}"
        )

        # stage: running models
        #timout includes whole protocol not api calls only
        print(f"[stage] running models for {protocol_id}")
        elapsed_before_models = time.monotonic() - protocol_start_perf
        remaining_time = max(0.0, PER_PROTOCOL_TIMEOUT_SECONDS - elapsed_before_models)

        if remaining_time <= 0:
            protocol_timeout_hit = True
            results = timeout_results(
                protocol_id=protocol_id,
                goals=goals_sanitized,
                reason=f"Per-protocol timeout ({PER_PROTOCOL_TIMEOUT_SECONDS:.0f}s) reached.",
            )
            models_done = 0
        else:
            results, model_timeout_hit = run_models_parallel(
                runners=runners,
                prompt=prompt,
                protocol_id=protocol_id,
                goals_sanitized=goals_sanitized,
                model_workers=args.model_workers,
                timeout_seconds=remaining_time,
            )
            if model_timeout_hit:
                protocol_timeout_hit = True
            models_done = sum(1 for r in results if r.raw_response_text)

        protocol_end_dt = datetime.now()
        protocol_runtime_seconds = max(0.0, time.monotonic() - protocol_start_perf)
        if protocol_timeout_hit:
            timeout_protocol_count += 1

        print(
            f"  protocol_id={protocol_id} runtime={protocol_runtime_seconds:.3f}s "
            f"timeout_hit={protocol_timeout_hit} models_done={models_done}/{len(MODEL_ORDER)}"
        )

        row_data = {
            "protocol_index": idx,
            "protocol_name": Path(path).name,
            "file_path": str(Path(path).resolve()),
            "protocol_id": protocol_id,
            "goals_raw": goals_raw,
            "goals_sent_to_llm": goals_sanitized,
            "results": results,
            "protocol_start_time": protocol_start_dt.isoformat(timespec="seconds"),
            "protocol_end_time": protocol_end_dt.isoformat(timespec="seconds"),
            "protocol_runtime_seconds": protocol_runtime_seconds,
            "protocol_timeout_hit": protocol_timeout_hit,
        }

        # incremental csv write
        #write to csv immediately so crash doesnt lose all the work
        end_ts_current = datetime.now()
        append_protocol_csv(
            out_path=args.out,
            row_data=row_data,
            start_iso=start_iso,
            end_iso=end_ts_current.isoformat(timespec="seconds"),
            overall_runtime_seconds=round((end_ts_current - start_ts).total_seconds(), 3),
        )

        # incremental audit JSONL
        if args.json_out:
            audit_entry = {
                "protocol_index": idx,
                "protocol_name": Path(path).name,
                "file_path": str(Path(path).resolve()),
                "protocol_id": protocol_id,
                "goals_extracted": goals_raw,
                "sanitized_protocol_sent": protocol_body,
                "prompt_sent": prompt,
                "protocol_start_time": protocol_start_dt.isoformat(timespec="seconds"),
                "protocol_end_time": protocol_end_dt.isoformat(timespec="seconds"),
                "protocol_runtime_seconds": round(protocol_runtime_seconds, 3),
                "protocol_timeout_hit": protocol_timeout_hit,
                "models": [
                    {
                        "model": result.model_name,
                        "raw_response_text": result.raw_response_text,
                        "parsed_response": result.parsed_response,
                    }
                    for result in results
                ],
            }
            append_audit_jsonl(args.json_out, audit_entry)
        #extra nice to have for summary of that run 
        protocol_rows_summary.append(
            {
                "protocol_id": protocol_id,
                "protocol_name": Path(path).name,
                "runtime_seconds": round(protocol_runtime_seconds, 3),
                "timeout_hit": protocol_timeout_hit,
            }
        )

    end_ts = datetime.now()
    overall_runtime_seconds = round((end_ts - start_ts).total_seconds(), 3)

    print(f"\n[+] CSV report written: {args.out}")
    if args.json_out:
        print(f"[+] Audit JSONL written: {args.json_out}")

    print("[+] Summary:")
    print(f"    Total protocols found: {len(files)}")
    print(f"    Protocols processed: {len(protocol_rows_summary)}")
    print(f"    Overall runtime (seconds): {overall_runtime_seconds}")
    print(f"    Protocols hit per-protocol timeout: {timeout_protocol_count}")

    # --- write _summary.txt report ---
    if protocol_rows_summary:
        runtimes = [r["runtime_seconds"] for r in protocol_rows_summary]
        avg_runtime = sum(runtimes) / len(runtimes)
        fastest = min(protocol_rows_summary, key=lambda r: r["runtime_seconds"])
        slowest = max(protocol_rows_summary, key=lambda r: r["runtime_seconds"])
    else:
        avg_runtime = 0.0
        fastest = {"protocol_name": "N/A", "runtime_seconds": 0.0}
        slowest = {"protocol_name": "N/A", "runtime_seconds": 0.0}

    summary_path = re.sub(r"\.csv$", "_summary.txt", args.out, flags=re.IGNORECASE)
    if summary_path == args.out:
        summary_path = args.out + "_summary.txt"

    overall_minutes = overall_runtime_seconds / 60.0
    input_folders = ", ".join(args.inputs)

    summary_lines = [
        f"Generation timestamp : {end_ts.isoformat(timespec='seconds')}",
        f"Input folder(s)     : {input_folders}",
        f"Total protocols found: {len(files)}",
        f"Protocols processed  : {len(protocol_rows_summary)}",
        f"Protocols timed out  : {timeout_protocol_count}",
        f"Overall runtime      : {overall_runtime_seconds}s ({overall_minutes:.2f} min)",
        f"Avg per-protocol     : {avg_runtime:.3f}s",
        f"Fastest protocol     : {fastest['protocol_name']} ({fastest['runtime_seconds']:.3f}s)",
        f"Slowest protocol     : {slowest['protocol_name']} ({slowest['runtime_seconds']:.3f}s)",
        "",
        "Per-protocol breakdown:",
        f"{'Protocol ID':<14} {'Filename':<40} {'Runtime (s)':>12} {'Timeout':>8}",
        "-" * 78,
    ]
    for row in protocol_rows_summary:
        summary_lines.append(
            f"{row['protocol_id']:<14} {row['protocol_name']:<40} {row['runtime_seconds']:>12.3f} "
            f"{'YES' if row['timeout_hit'] else 'no':>8}"
        )

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines) + "\n")

    print(f"[+] Summary file written: {summary_path}")
    #scopr of project includes three comparison files no need to include more 
    if args.truth_files:
        if len(args.truth_files) > 3:
            print("[!] Warning: more than 3 truth files provided; using first 3.")
            args.truth_files = args.truth_files[:3]
        run_truth_comparison(
            ai_csv_path=args.out,
            truth_paths=list(args.truth_files),
            comparison_csv_out=args.comparison_out,
            comparison_html_out=args.comparison_html,
        )


if __name__ == "__main__":
    main()
