"""Build-level governance for the kanban dev factory — the "orchestrator as
Ezra" spine.

This is the native, in-engine governor. It mirrors the budget breaker
(:mod:`hermes_cli.kanban_budget`) in shape and discipline:

    * READ-FIRST  — it never mutates task state from the hot path.
    * FAIL-OPEN   — any error returns "allow"; governance must never wedge a
                    worker the way the ``ag/`` auth bug did.
    * STDLIB-ONLY (+ optional pyyaml) — no third-party hard dependency.
    * BUILD-SCOPED — governance is resolved for the whole build (the root task
                     and its subtree), resolved by walking ``task_links`` just
                     like the budget breaker.

What it governs (ported from EZRA, github.com/BAS-More/ezra-claude-code):

    * GOV-PROTECTED — the signature EZRA rule: a write to a *protected path*
      is only authorised when an ACTIVE decision (ADR) in the build's
      governance references that path. No decision => the write is gated.
    * Oversight dial — monitor | warn | gate | strict, exactly EZRA's levels:
        monitor : record only (never block)
        warn    : allow, but the worker sees the warning in the tool result
        gate    : BLOCK on critical/high findings, allow lower
        strict  : BLOCK on any finding
      Default is ``warn`` so enabling the governor can never harden an
      existing build into a wedge without an explicit opt-in.

This module is pure logic over (a) the kanban DB (to resolve the build root +
its workspace) and (b) a small ``.ezra/``-shaped governance store on disk in
the build's workspace. The plugin (``plugins/factory-governor``) and the
decompose/merge wiring are thin callers of the functions here.

Two check families run here:
  * GOV-PROTECTED — decisions, protected paths, oversight policy (the layer
    security-guidance has no concept of).
  * SEC-SECRETS — hardcoded-secret detection (ports EZRA's SEC layer and
    closes its gaps: AWS_SECRET_ACCESS_KEY, bare AKIA values, Stripe
    sk_live/sk_test, GitHub ghp_/github_pat_, etc.). The bundled
    ``security-guidance`` plugin scans for dangerous *code patterns* (eval,
    pickle, ...) but does NOT scan for hardcoded credentials, so this is
    complementary, not duplicative.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sqlite3

try:  # pyyaml ships in the engine venv; degrade to a tiny reader if absent.
    import yaml as _yaml
except Exception:  # pragma: no cover - defensive
    _yaml = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Oversight levels, lowest→highest enforcement. Mirrors EZRA's
# settings.oversight.level (monitor/warn/gate/strict).
LEVEL_MONITOR = "monitor"
LEVEL_WARN = "warn"
LEVEL_GATE = "gate"
LEVEL_STRICT = "strict"
_VALID_LEVELS = {LEVEL_MONITOR, LEVEL_WARN, LEVEL_GATE, LEVEL_STRICT}

# Default level when a build has governance but no explicit level. WARN is the
# safe default — enabling the governor never silently blocks a worker.
DEFAULT_LEVEL = LEVEL_WARN

# Severities a finding can carry, for the gate/strict decision.
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The on-disk governance directory, EZRA-compatible. Lives in the build root's
# workspace so every worker on the build (each in its own worktree off the
# same root workspace, or the shared dir) resolves the same governance.
EZRA_DIRNAME = ".ezra"
GOVERNANCE_FILENAME = "governance.yaml"
DECISIONS_DIRNAME = "decisions"

# Tools whose args carry "a path being written", and which arg holds the path.
# Same surface security-guidance scans, so the two gates cover identical writes.
_PATH_TOOLS: Dict[str, str] = {
    "write_file": "path",
    "patch": "path",
    "skill_manage": "file_path",
    "str_replace_editor": "path",
    "edit_file": "path",
}

# Content args to scan for hardcoded secrets, by tool (superset of the path keys
# above — same surface security-guidance reads). The first populated string wins.
_CONTENT_KEYS: Tuple[str, ...] = ("content", "new_string", "file_content", "patch")

# Cap on how much content we scan for secrets — a 10 MB blob has poor S/N and
# would slow the agent loop. Matches security-guidance's _MAX_SCAN_BYTES.
_MAX_SECRET_SCAN_BYTES = 256 * 1024


# ---------------------------------------------------------------------------
# SEC-SECRETS — hardcoded-secret detection (ports EZRA's SEC layer + closes its
# gaps). Pattern set researched + adversarially verified + empirically corpus-
# tested (0 false positives on a benign-code corpus; catches the AWS/Stripe/
# GitHub/bare-AKIA cases EZRA's regex missed). Provider-prefixed value matches
# are 'critical'; the generic name+value heuristic is 'high'.
# ---------------------------------------------------------------------------

# (name, compiled_regex, severity). Order is irrelevant — we report the first hit
# per line. All compile under stdlib ``re``.
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = []
for _name, _src, _sev in [
    ("AWS access key id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "critical"),
    ("GitHub token", r"\bgh[pousr]_[0-9A-Za-z]{36,40}\b", "critical"),
    ("GitHub fine-grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{59,}\b", "critical"),
    ("Stripe key", r"\b[sr]k_(?:live|test|prod)_[0-9A-Za-z]{20,99}\b", "critical"),
    ("Anthropic API key", r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{24,}", "critical"),
    ("OpenAI scoped key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}", "critical"),
    ("OpenAI legacy key", r"(?<![A-Za-z0-9_/-])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])", "critical"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", "critical"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z]{8,}(?:-[0-9A-Za-z]{8,})+-[0-9A-Za-z]{10,}\b", "critical"),
    ("Slack webhook URL", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}", "critical"),
    ("PEM private key", r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----", "critical"),
    ("Azure storage AccountKey", r"AccountKey=[A-Za-z0-9/+]{86}==", "critical"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "high"),
    # AWS secret access key, anchored on the canonical env-var name (EZRA's gap):
    # require a 40-char base64-ish value, reject a 40-hex SHA and all-same-char.
    ("AWS secret access key",
     r'(?i)(?<![A-Za-z0-9_])aws_?secret_?access_?key\s*[:=]\s*["\']?'
     r'(?![A-Fa-f0-9]{40}(?![A-Za-z0-9/+]))'
     r'(?!([A-Za-z0-9/+])\1{39})'
     r'[A-Za-z0-9/+]{40}["\']?', "critical"),
    # Generic: a sensitively-named var assigned a quoted long value. The inline
    # negative-lookaheads strip placeholder / env-ref / version / JWT noise; the
    # PLACEHOLDER allowlist below is the belt-and-suspenders second layer.
    ("sensitive name + quoted value",
     r'''(?i)\b\w{0,30}(?:secret|api[_-]?key|access[_-]?key|auth[_-]?token|'''
     r'''access[_-]?token|[_-]token|password|passwd|client[_-]?secret|'''
     r'''private[_-]?key)\w{0,8}\s*[:=]\s*["']'''
     r'''(?![A-Za-z0-9/+_=.\-]*(?:PLACEHOLDER|CHANGE[_-]?ME|REPLACE|TODO|'''
     r'''XXXX|YOUR[_-]|GOES[_-]?HERE|DUMMY|FAKE|SAMPLE|EXAMPLE|process\.env|'''
     r'''os\.environ)[A-Za-z0-9/+_=.\-]*["'])'''
     r'''(?!eyJ[A-Za-z0-9_\-]+["'])'''
     r'''(?:(?=[A-Za-z0-9/+_=.\-]*[A-Za-z])(?=[A-Za-z0-9/+_=.\-]*[0-9])'''
     r'''[A-Za-z0-9/+_=.\-]{12,}|[A-Za-z0-9/+]{24,}={0,2})["']''', "high"),
]:
    try:
        _SECRET_PATTERNS.append((_name, re.compile(_src), _sev))
    except re.error:  # pragma: no cover — defensive; a bad pattern is skipped, not fatal
        pass

# Additional distinctively-prefixed vendor keys (low FP risk — vendor-owned
# namespaces). Appended to the same critical-severity scan.
for _name, _src in [
    ("GitLab PAT", r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    ("SendGrid key", r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
    ("npm token", r"\bnpm_[0-9A-Za-z]{36,40}\b"),
    ("HuggingFace token", r"\bhf_[0-9A-Za-z]{30,}\b"),
    ("Twilio API key SID", r"\bSK[0-9a-fA-F]{32}\b"),
    ("Telegram bot token", r"\b\d{8,10}:[A-Za-z0-9_-]{35,}\b"),
    ("Square access token", r"\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,}\b"),
    ("Google OAuth token", r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
]:
    try:
        _SECRET_PATTERNS.append((_name, re.compile(_src), "critical"))
    except re.error:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Entropy fallback — catches UNPREFIXED high-entropy secrets that no vendor
# pattern covers (e.g. `api_key = "<40 random hex/base64>"`). Method validated
# against gitleaks/detect-secrets/trufflehog research + empirically tuned: the
# STRUCTURAL EXCLUSIONS do the real work (entropy alone can't tell a git SHA
# from a hex secret — both ~3.9 bits/char), entropy is the last coarse filter.
# Precision-favouring (FP at a write gate is worse than a miss): requires a
# quoted value assigned to a secret-keyword-bearing name, applies SHA/UUID/SRI/
# media/placeholder exclusions, then a per-charset entropy floor. Severity is
# MEDIUM (warn-at-gate, not hard block) — entropy is fuzzier than a prefix.
# ---------------------------------------------------------------------------

_ENT_HEX_THRESHOLD = 3.3    # detect-secrets default 3.0; raised for the gate
_ENT_B64_THRESHOLD = 4.5    # detect-secrets/trufflehog default
_ENT_MIN_HEX = 32
_ENT_MIN_B64 = 24
_ENT_MAX_LEN = 200          # above this is almost always media/blob, not a key
_HEXCHARS = set("0123456789abcdefABCDEF")

# Quoted value (16-200 chars) assigned via = / := / : to a named LHS.
_ENT_ASSIGN = re.compile(r"""([A-Za-z_][A-Za-z0-9_]{0,40})\s*[:=]+\s*["']([^"']{16,200})["']""")
# Strong secret keyword in the LHS name — also overrides the SHA exclusion
# (a var literally named api_key/secret holding 40 hex is a key, not a commit).
_ENT_STRONG_NAME = re.compile(r"(?i)(?:secret|api[_-]?key|apikey|token|passw|private[_-]?key|access[_-]?key|auth)")
# Structural exclusions — if the value matches any, it is NOT a secret.
_ENT_SHA = re.compile(r"^[0-9a-f]{7}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$")
_ENT_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ENT_SRI = re.compile(r"^(?:sha256|sha384|sha512)-")
_ENT_MEDIA = re.compile(r"^(?:iVBOR|/9j/|R0lGOD|JVBER|d09GR|data:)")
_ENT_RUN = re.compile(r"^(.)\1{7,}$")
_ENT_B64CHARSET = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_ENT_PLACEHOLDER = (
    "example", "dummy", "sample", "placeholder", "fake", "changeme",
    "replace", "your_", "your-", "goes_here", "goes-here", "deadbeef",
    "cafebabe", "foobar", "lorem", "xxxx", "0000",
)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    import math
    h = 0.0
    for ch in set(s):
        p = s.count(ch) / len(s)
        h -= p * math.log2(p)
    return h


def _entropy_findings(line: str) -> List[Dict[str, Any]]:
    """Entropy-based detection for one line. Returns at most one finding.

    Precision-favouring pipeline: assignment+keyword context -> placeholder ->
    structural exclusions -> charset split -> entropy floor.
    """
    out: List[Dict[str, Any]] = []
    for m in _ENT_ASSIGN.finditer(line):
        name, val = m.group(1), m.group(2)
        if not _ENT_STRONG_NAME.search(name):
            # Also accept a keyword appearing before the assignment on the line.
            if not _ENT_STRONG_NAME.search(line[:m.start()]):
                continue
        low = val.lower()
        if any(s in low for s in _ENT_PLACEHOLDER):
            continue
        strong = _ENT_STRONG_NAME.search(name) is not None
        # SHA exclusion is conditional on the name not being a strong keyword.
        if _ENT_SHA.match(val) and not strong:
            continue
        if (_ENT_UUID.match(val) or _ENT_SRI.match(val)
                or _ENT_MEDIA.match(val) or _ENT_RUN.match(val)):
            continue
        if val.isdigit() or len(val) > _ENT_MAX_LEN:
            continue
        is_hex = all(c in _HEXCHARS for c in val)
        if is_hex:
            if len(val) < _ENT_MIN_HEX:
                continue
            if _shannon(val) >= _ENT_HEX_THRESHOLD:
                out.append({"code": "SEC-SECRETS", "severity": "medium",
                            "message": f"possible hardcoded secret (high-entropy hex assigned to '{name}')"})
                return out
        else:
            if len(val) < _ENT_MIN_B64 or not _ENT_B64CHARSET.match(val):
                continue
            if _shannon(val) >= _ENT_B64_THRESHOLD:
                out.append({"code": "SEC-SECRETS", "severity": "medium",
                            "message": f"possible hardcoded secret (high-entropy value assigned to '{name}')"})
                return out
    return out


# Placeholder allowlist — suppress a match whose matched text is an obvious
# dummy/example. Value-scoped so a real secret beside a placeholder still fires.
_PLACEHOLDER_LITERALS = {
    "akiaiosfodnn7example", "your-key-here", "your-api-key-here",
    "your-token-here", "changeme", "change-me", "redacted", "todo", "tbd",
}
_PLACEHOLDER_SUBSTRINGS = (
    "example", "dummy", "sample", "placeholder", "fake", "changeme",
    "replace", "your_", "your-", "goes_here", "goes-here", "test_key",
    "do_not_use", "process.env", "os.environ", "${", "<", ">",
)


def _is_placeholder(matched: str) -> bool:
    low = matched.lower()
    if low.strip("\"'") in _PLACEHOLDER_LITERALS:
        return True
    return any(s in low for s in _PLACEHOLDER_SUBSTRINGS)


def scan_secrets(content: str) -> List[Dict[str, Any]]:
    """Return SEC-SECRETS findings for ``content``. Empty if clean / too big.

    Line-by-line, first matching pattern per line, placeholder-allowlisted.
    Pure + side-effect-free; FAIL-SAFE (any error → no findings).
    """
    try:
        if not content:
            return []
        if len(content.encode("utf-8", errors="ignore")) > _MAX_SECRET_SCAN_BYTES:
            return []
        findings: List[Dict[str, Any]] = []
        for i, line in enumerate(content.splitlines(), start=1):
            if len(line) > 4096:  # skip pathological minified lines
                continue
            matched = False
            for name, rx, sev in _SECRET_PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                if _is_placeholder(m.group(0)):
                    continue
                findings.append({
                    "code": "SEC-SECRETS",
                    "severity": sev,
                    "message": f"possible hardcoded {name} at line {i}",
                    "line": i,
                })
                matched = True
                break  # one finding per line is enough
            # Entropy fallback only if no explicit provider/generic pattern hit
            # this line (avoids double-reporting the same secret).
            if not matched:
                for ef in _entropy_findings(line):
                    ef["line"] = i
                    findings.append(ef)
        return findings
    except Exception:
        return []


def _extract_write_content(tool_name: str, args: Any) -> Optional[str]:
    """The content being written, for secret scanning. None if not a write."""
    if tool_name not in _PATH_TOOLS or not isinstance(args, dict):
        return None
    for k in _CONTENT_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


# ---------------------------------------------------------------------------
# Tiny YAML fallback (only used if pyyaml is somehow unavailable)
# ---------------------------------------------------------------------------

def _load_yaml(text: str) -> Any:
    if _yaml is not None:
        try:
            return _yaml.safe_load(text)
        except Exception:
            return None
    # Minimal fallback: we only ever need flat-ish governance.yaml. Returning
    # None makes callers treat the build as ungoverned (fail-open).
    return None


def _dump_yaml(data: Any) -> str:
    if _yaml is not None:
        try:
            return _yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
        except Exception:
            pass
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Build-root + workspace resolution (mirrors kanban_budget._resolve_root_id)
# ---------------------------------------------------------------------------

def _resolve_root_id(conn: sqlite3.Connection, task_id: str) -> str:
    """Walk parent links up to the build root (a task with no parents)."""
    seen: set[str] = set()
    cur = task_id
    for _ in range(256):
        if cur in seen:
            break
        seen.add(cur)
        row = conn.execute(
            "SELECT parent_id FROM task_links WHERE child_id = ? LIMIT 1",
            (cur,),
        ).fetchone()
        if row is None:
            return cur
        cur = row["parent_id"] if isinstance(row, sqlite3.Row) else row[0]
    return cur


def _root_workspace(conn: sqlite3.Connection, root_id: str) -> Optional[Path]:
    """The workspace path of the build root, where ``.ezra/`` lives."""
    try:
        row = conn.execute(
            "SELECT workspace_path FROM tasks WHERE id = ?", (root_id,)
        ).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    wp = row["workspace_path"] if isinstance(row, sqlite3.Row) else row[0]
    if not wp:
        return None
    try:
        return Path(wp)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Governance store (.ezra/ shaped, EZRA-compatible)
# ---------------------------------------------------------------------------

def ezra_dir(workspace: Path) -> Path:
    return workspace / EZRA_DIRNAME


def load_governance(workspace: Path) -> Dict[str, Any]:
    """Resolve effective governance for a build.

    Precedence (EZRA-style layering):
      1. Per-build ``<workspace>/.ezra/governance.yaml`` (if present) — wins.
      2. Config-level ``kanban.governance`` block in config.yaml — the durable
         default that governs EVERY build with zero per-build setup.
      3. ``{}`` — ungoverned (fail-open: the gate allows everything).

    The per-build file does NOT merge with config; if it exists it fully
    defines that build's governance (so a build can deliberately run looser or
    tighter than the global default). This mirrors EZRA's project-over-global
    settings precedence.
    """
    gpath = ezra_dir(workspace) / GOVERNANCE_FILENAME
    try:
        if gpath.exists():
            data = _load_yaml(gpath.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return _config_governance()


def _config_governance() -> Dict[str, Any]:
    """The ``kanban.governance`` block from config.yaml, or ``{}``.

    Shape mirrors a governance.yaml: ``{protected_paths: [...],
    oversight: {level: ...}, decisions: [...]}``. Lets an operator govern the
    whole factory from one durable, backed-up config block.
    """
    try:
        from hermes_cli.config import load_config
        cfg = load_config()
        kb_cfg = cfg.get("kanban") if isinstance(cfg, dict) else None
        gov = (kb_cfg or {}).get("governance") if isinstance(kb_cfg, dict) else None
        return gov if isinstance(gov, dict) else {}
    except Exception:
        return {}


def load_active_decision_paths(workspace: Path) -> List[str]:
    """Return the union of affected-path globs from every ACTIVE decision.

    A decision authorises a protected-path write only while its status is
    ACTIVE (EZRA semantics — SUPERSEDED/DEPRECATED decisions don't authorise).
    Decisions live as ``<.ezra>/decisions/ADR-*.yaml`` AND/OR may be inlined in
    governance.yaml under ``decisions:``. Both are honoured.
    """
    paths: List[str] = []

    # 1. governance.yaml inline decisions
    gov = load_governance(workspace)
    for dec in gov.get("decisions", []) or []:
        if not isinstance(dec, dict):
            continue
        if str(dec.get("status", "ACTIVE")).upper() != "ACTIVE":
            continue
        paths.extend(_decision_paths(dec))

    # 2. decisions/ADR-*.yaml files
    ddir = ezra_dir(workspace) / DECISIONS_DIRNAME
    try:
        if ddir.is_dir():
            for f in sorted(ddir.glob("*.yaml")):
                try:
                    dec = _load_yaml(f.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(dec, dict):
                    continue
                if str(dec.get("status", "ACTIVE")).upper() != "ACTIVE":
                    continue
                paths.extend(_decision_paths(dec))
    except Exception:
        pass

    return paths


def _decision_paths(dec: Dict[str, Any]) -> List[str]:
    """Pull affected-path globs out of a decision record (several shapes)."""
    out: List[str] = []
    enf = dec.get("enforcement")
    if isinstance(enf, dict):
        ap = enf.get("affected_paths")
        if isinstance(ap, list):
            out.extend(str(p) for p in ap if p)
        elif isinstance(ap, str) and ap:
            out.append(ap)
    # Also accept a top-level affected_paths for convenience.
    ap2 = dec.get("affected_paths")
    if isinstance(ap2, list):
        out.extend(str(p) for p in ap2 if p)
    elif isinstance(ap2, str) and ap2:
        out.append(ap2)
    return out


def resolve_level(workspace: Path) -> str:
    """Oversight level for the build. Defaults to WARN."""
    gov = load_governance(workspace)
    lvl = str(
        (gov.get("oversight", {}) or {}).get("level")
        or gov.get("oversight_level")
        or DEFAULT_LEVEL
    ).strip().lower()
    return lvl if lvl in _VALID_LEVELS else DEFAULT_LEVEL


def resolve_protected_paths(workspace: Path) -> List[str]:
    """Glob patterns the build marks protected (writes need an ACTIVE ADR)."""
    gov = load_governance(workspace)
    pp = gov.get("protected_paths")
    if isinstance(pp, list):
        return [str(p) for p in pp if p]
    if isinstance(pp, str) and pp:
        return [pp]
    return []


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./")


def _path_matches(path: str, patterns: List[str]) -> Optional[str]:
    """Return the first matching glob, else None. Forgiving on separators."""
    np = _norm(path)
    base = np.rsplit("/", 1)[-1]
    for pat in patterns:
        npat = _norm(pat)
        if (
            fnmatch.fnmatch(np, npat)
            or fnmatch.fnmatch(base, npat)
            or fnmatch.fnmatch(np, npat.rstrip("/") + "/*")
            or np == npat
        ):
            return pat
    return None


def _extract_write_path(tool_name: str, args: Any) -> Optional[str]:
    key = _PATH_TOOLS.get(tool_name)
    if key is None or not isinstance(args, dict):
        return None
    val = args.get(key)
    return val if isinstance(val, str) and val else None


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

def check_tool_call(
    conn: sqlite3.Connection,
    task_id: str,
    tool_name: str,
    args: Any,
    *,
    workspace_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Governance preflight for a single tool call inside a kanban worker.

    READ-ONLY, FAIL-OPEN. Returns:

        {
          "decision": "allow" | "warn" | "block",
          "level": <oversight level in force>,
          "findings": [ {code, severity, message, path}, ... ],
          "root_id": <build root>,
          "message": <human string for warn/block, or None>,
        }

    Two concerns are evaluated, accumulated into one decision:
      * GOV-PROTECTED — write to a protected path with no ACTIVE decision.
        Needs the build's workspace governance to know what's protected.
      * SEC-SECRETS — a hardcoded secret in the write content. Fires on ANY
        governed write regardless of path/protection (a secret is bad
        wherever it lands); this is the layer that closes EZRA's gaps and
        works even on an ungoverned build.

    A non-write tool, or any internal error => allow (FAIL-OPEN).
    """
    base = {
        "decision": "allow",
        "level": DEFAULT_LEVEL,
        "findings": [],
        "root_id": task_id,
        "message": None,
    }
    try:
        write_path = _extract_write_path(tool_name, args)
        if write_path is None:
            return base  # not a governed write

        root_id = _resolve_root_id(conn, task_id)
        base["root_id"] = root_id

        workspace: Optional[Path] = None
        if workspace_override:
            workspace = Path(workspace_override)
        else:
            workspace = _root_workspace(conn, root_id)

        findings: List[Dict[str, Any]] = []

        # --- GOV-PROTECTED (needs workspace governance) ---------------------
        if workspace is not None:
            protected = resolve_protected_paths(workspace)
            if protected:
                hit = _path_matches(write_path, protected)
                if hit is not None:
                    authorised = load_active_decision_paths(workspace)
                    if _path_matches(write_path, authorised) is None:
                        findings.append({
                            "code": "GOV-PROTECTED",
                            "severity": "high",
                            "message": (
                                f"write to protected path '{write_path}' "
                                f"(matched '{hit}') has no ACTIVE decision "
                                f"authorising it. Record an ADR whose "
                                f"enforcement.affected_paths covers this path, "
                                f"or route the change through the owning task."
                            ),
                            "path": write_path,
                        })

        # --- SEC-SECRETS (path-independent; scans the write content) --------
        content = _extract_write_content(tool_name, args)
        if content:
            for sf in scan_secrets(content):
                sf["path"] = write_path
                findings.append(sf)

        if not findings:
            return base  # clean write

        # Level: the build's configured oversight level when we have a
        # workspace; otherwise default. SEC-SECRETS findings are critical/high,
        # so at the WARN default they surface to the worker; a build that wants
        # them to hard-block sets oversight.level=gate (config default does).
        level = resolve_level(workspace) if workspace is not None else DEFAULT_LEVEL
        result = _apply_level(base, level, findings, root_id)
        # Self-audit: record any non-allow decision (best-effort, never raises).
        audit_event(
            task_id=task_id,
            root_id=root_id,
            tool_name=tool_name,
            decision=result["decision"],
            level=result["level"],
            findings=result["findings"],
        )
        return result
    except Exception:
        # Fail-open. Governance must never wedge a worker.
        return base


def _apply_level(
    base: Dict[str, Any],
    level: str,
    findings: List[Dict[str, Any]],
    root_id: str,
) -> Dict[str, Any]:
    base["level"] = level
    base["findings"] = findings
    base["root_id"] = root_id
    if not findings:
        base["decision"] = "allow"
        return base

    worst = max(_SEV_ORDER.get(f.get("severity", "low"), 0) for f in findings)
    msg = "; ".join(f["message"] for f in findings)

    if level == LEVEL_MONITOR:
        base["decision"] = "allow"
        base["message"] = None
    elif level == LEVEL_WARN:
        base["decision"] = "warn"
        base["message"] = f"⚠️ governance ({level}): {msg}"
    elif level == LEVEL_GATE:
        # Block high/critical, warn on the rest.
        if worst >= _SEV_ORDER["high"]:
            base["decision"] = "block"
            base["message"] = f"⛔ governance blocked ({level}): {msg}"
        else:
            base["decision"] = "warn"
            base["message"] = f"⚠️ governance ({level}): {msg}"
    elif level == LEVEL_STRICT:
        base["decision"] = "block"
        base["message"] = f"⛔ governance blocked ({level}): {msg}"
    return base


# ---------------------------------------------------------------------------
# Decision recording (orchestrator-as-governor, called at decompose)
# ---------------------------------------------------------------------------

def seed_governance(
    workspace: Path,
    *,
    project: str = "",
    protected_paths: Optional[List[str]] = None,
    oversight_level: Optional[str] = None,
    decisions: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Path]:
    """Create/refresh ``<workspace>/.ezra/governance.yaml`` for a build.

    Called by the decompose path (the orchestrator) so a build carries its
    governance from the start. Idempotent-ish: it merges into an existing
    governance.yaml rather than clobbering (protected_paths/decisions union).

    ``oversight_level`` is only changed when explicitly passed — a caller that
    only adds protected paths (e.g. ``record_decision``) must NOT silently
    reset the build's level. When unset and no level exists yet, defaults to
    WARN. An explicit level always wins. Returns the path written, or None.

    NEVER raises — decision recording is best-effort and must not break
    decomposition.
    """
    try:
        ed = ezra_dir(workspace)
        ed.mkdir(parents=True, exist_ok=True)
        gpath = ed / GOVERNANCE_FILENAME
        existing = load_governance(workspace)

        # Level resolution: explicit arg wins; else preserve existing; else WARN.
        if oversight_level is not None:
            level = (oversight_level or "").strip().lower()
            if level not in _VALID_LEVELS:
                level = DEFAULT_LEVEL
        else:
            level = str(
                (existing.get("oversight", {}) or {}).get("level")
                or existing.get("oversight_level")
                or DEFAULT_LEVEL
            ).strip().lower()
            if level not in _VALID_LEVELS:
                level = DEFAULT_LEVEL

        merged_protected = sorted(
            set(existing.get("protected_paths", []) or [])
            | set(protected_paths or [])
        )

        merged_decisions = list(existing.get("decisions", []) or [])
        if decisions:
            have = {
                (d.get("id") or "") for d in merged_decisions if isinstance(d, dict)
            }
            for d in decisions:
                if isinstance(d, dict) and (d.get("id") or "") not in have:
                    merged_decisions.append(d)

        gov = dict(existing)
        gov["project"] = existing.get("project") or project
        gov["protected_paths"] = merged_protected
        gov["oversight"] = {"level": level}
        gov["decisions"] = merged_decisions
        gov["_governed_by"] = "hermes-factory-governor"
        gov["_updated_at"] = _now_iso()

        gpath.write_text(_dump_yaml(gov), encoding="utf-8")
        return gpath
    except Exception:
        return None


def record_decision(
    workspace: Path,
    *,
    decision: str,
    affected_paths: List[str],
    rationale: str = "",
    category: str = "architecture",
    status: str = "ACTIVE",
    decision_id: Optional[str] = None,
) -> Optional[str]:
    """Write an ADR file under ``<workspace>/.ezra/decisions/``. EZRA-shaped.

    Returns the decision id, or None on failure. Best-effort, never raises.
    """
    try:
        ddir = ezra_dir(workspace) / DECISIONS_DIRNAME
        ddir.mkdir(parents=True, exist_ok=True)
        if not decision_id:
            n = len(list(ddir.glob("ADR-*.yaml"))) + 1
            decision_id = f"ADR-{n:03d}"
        rec = {
            "id": decision_id,
            "status": status.upper(),
            "category": category,
            "decision": decision,
            "rationale": rationale,
            "enforcement": {
                "affected_paths": list(affected_paths or []),
                "auto_enforced": True,
            },
            "created_at": _now_iso(),
            "source": "hermes-factory-governor",
        }
        (ddir / f"{decision_id}.yaml").write_text(_dump_yaml(rec), encoding="utf-8")
        # Also ensure those paths are protected so the ADR has teeth.
        seed_governance(workspace, protected_paths=list(affected_paths or []))
        return decision_id
    except Exception:
        return None


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Audit trail (governance events) — factory-local, append-only JSONL
# ---------------------------------------------------------------------------

def _audit_path() -> Optional[Path]:
    """Resolve the governance audit log path.

    Order:
      1. ``HERMES_GOVERN_AUDIT`` env (explicit override).
      2. ``<kanban_home>/governance-audit.jsonl`` (default, lives with the
         board so it's captured by the same backups as the DB).
    Returns None if even the home dir can't be resolved (=> audit skipped,
    never an error).
    """
    env = os.environ.get("HERMES_GOVERN_AUDIT")
    if env:
        try:
            return Path(env)
        except Exception:
            return None
    try:
        from hermes_cli.kanban_db import kanban_home
        return kanban_home() / "governance-audit.jsonl"
    except Exception:
        return None


def audit_event(
    *,
    task_id: str,
    root_id: str,
    tool_name: str,
    decision: str,
    level: str,
    findings: List[Dict[str, Any]],
) -> None:
    """Append one governance decision to the audit JSONL. Best-effort.

    Only non-allow decisions are recorded (allow is the overwhelming common
    case and would drown the log). Never raises.
    """
    if decision == "allow":
        return
    p = _audit_path()
    if p is None:
        return
    rec = {
        "ts": _now_iso(),
        "kind": "govern",
        "task_id": task_id,
        "root_id": root_id,
        "tool": tool_name,
        "decision": decision,
        "level": level,
        "findings": [
            {"code": f.get("code"), "severity": f.get("severity"), "path": f.get("path")}
            for f in (findings or [])
        ],
    }
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
