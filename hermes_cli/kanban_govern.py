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

SEC-* pattern checks are deliberately NOT duplicated here — the bundled
``security-guidance`` plugin already owns content-pattern scanning. The
governor owns the GOV layer (decisions, protected paths, oversight policy)
that security-guidance has no concept of. Together they are the two halves of
EZRA's PreToolUse gate.
"""

from __future__ import annotations

import fnmatch
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

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

    Only GOV-PROTECTED is evaluated here (write to a protected path with no
    ACTIVE decision). SEC-* patterns belong to the security-guidance plugin.
    A non-write tool, an ungoverned build, or any internal error => allow.
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
        if workspace is None:
            return base  # no workspace => can't resolve governance => allow

        protected = resolve_protected_paths(workspace)
        if not protected:
            return base  # build declares nothing protected

        hit = _path_matches(write_path, protected)
        if hit is None:
            return base  # not a protected path

        # Protected path. Authorised only if an ACTIVE decision references it.
        authorised_globs = load_active_decision_paths(workspace)
        if _path_matches(write_path, authorised_globs) is not None:
            return base  # an ACTIVE ADR authorises this write

        level = resolve_level(workspace)
        finding = {
            "code": "GOV-PROTECTED",
            "severity": "high",
            "message": (
                f"write to protected path '{write_path}' (matched '{hit}') "
                f"has no ACTIVE decision authorising it. Record an ADR "
                f"(/ezra:decide style) whose enforcement.affected_paths covers "
                f"this path, or route the change through the owning task."
            ),
            "path": write_path,
        }
        result = _apply_level(base, level, [finding], root_id)
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
