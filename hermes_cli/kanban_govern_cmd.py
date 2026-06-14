"""``hermes kanban govern`` — read + edit the factory governance posture.

The single CLI surface the Hermes One desktop "Factory" tab consumes (via
``execFile(hermes, ["kanban", "govern", "--json"])``) and that an operator can
use directly in a terminal. Aggregates everything the factory governor +
budget breaker + secret scanner expose into one JSON document, and writes
governance/budget settings back to the per-profile ``config.yaml`` files.

Subcommands::

    hermes kanban govern [--json]              # full status (default)
    hermes kanban govern set --level gate      # change oversight level (all profiles)
    hermes kanban govern set --secret-scan off # toggle SEC-SECRETS
    hermes kanban govern set --add-protected '**/*.pem'
    hermes kanban govern set --remove-protected '**/*.pem'
    hermes kanban govern set --hybrid on --for-profile code-reviewer
    hermes kanban govern killswitch on|off     # touch/remove the STOP sentinel

READ is FAIL-SOFT (a missing piece becomes null/empty, never an error) so the
GUI always renders. WRITE is explicit + validated; it edits only the keys it
owns and preserves the rest of each config.yaml.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

# The factory profiles whose config.yaml carry governance. Resolved live from
# the installed profile set, falling back to the canonical six.
_CANONICAL_PROFILES = [
    "architect", "backend-engineer", "frontend-engineer",
    "test-writer", "code-reviewer", "security-auditor",
]


def _factory_profiles() -> List[str]:
    try:
        from hermes_cli import profiles as profiles_mod
        names = [p.name for p in profiles_mod.list_profiles()]
        # Keep only those that actually carry a kanban.governance block, but
        # never return empty — fall back to the canonical set.
        govd = [n for n in names if n in _CANONICAL_PROFILES]
        return govd or _CANONICAL_PROFILES
    except Exception:
        return list(_CANONICAL_PROFILES)


def _profile_home(name: str) -> Optional[Path]:
    try:
        from hermes_cli.profiles import resolve_profile_env
        return Path(resolve_profile_env(name))
    except Exception:
        # Fall back to the conventional layout under HERMES_HOME root.
        try:
            from hermes_cli.config import get_hermes_home
            root = Path(get_hermes_home())
            # If we're already in a profile home, go up to the root.
            if root.name == name and root.parent.name == "profiles":
                cand = root
            else:
                cand = root / "profiles" / name
            return cand if cand.exists() else None
        except Exception:
            return None


def _profile_config_path(name: str) -> Optional[Path]:
    home = _profile_home(name)
    if home is None:
        return None
    p = home / "config.yaml"
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# YAML load/save (pyyaml; round-trips the whole file, edits only our keys)
# ---------------------------------------------------------------------------

def _yaml():
    try:
        import yaml
        return yaml
    except Exception:
        return None


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    y = _yaml()
    if y is None:
        return {}
    try:
        data = y.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _backup_once(path: Path) -> None:
    """One recoverable backup per edit (overwritten each call)."""
    try:
        path.with_name(path.name + ".bak-govern").write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


# NOTE: we deliberately do NOT round-trip config.yaml through yaml.safe_dump —
# that strips ALL comments (the commented Hybrid opt-in blocks, explanatory
# notes) and reorders keys. These are human-maintained files. Every writer
# below does a SURGICAL edit: it finds the exact target line by its YAML path
# and rewrites only that line (or inserts a minimal block), leaving the rest of
# the file — comments, ordering, formatting — byte-for-byte intact.


def _set_scalar_under(
    text: str, parent_key: str, child_key: str, value: str,
) -> Optional[str]:
    """Set ``parent_key:\\n  child_key: value`` (one level of nesting).

    Returns the new text, or None if the parent/child couldn't be located and
    inserted. Comment- and order-preserving — only the matched line changes (or
    a single child line is inserted under an existing parent).
    """
    import re
    lines = text.splitlines(keepends=True)
    # Find the top-level parent (no indentation) e.g. ``kanban:`` then its
    # nested child e.g. ``  governance:`` then ``    oversight:`` etc. We do a
    # path walk by increasing indentation.
    return _set_path(text, [parent_key, child_key], value)


def _set_path(text: str, key_path: List[str], value: str) -> Optional[str]:
    """Set the scalar at the nested ``key_path`` (e.g. ['kanban','governance',
    'oversight','level']) to ``value``, preserving comments + structure.

    Walks the YAML by indentation. If an intermediate key is missing it is
    inserted with the right indentation. Only the final scalar line is rewritten
    or inserted; all other lines are untouched.
    """
    import re
    lines = text.split("\n")
    indent_unit = "  "

    def find_key(start: int, end: int, key: str, depth: int) -> int:
        pat = re.compile(r"^" + (indent_unit * depth) + re.escape(key) + r"\s*:")
        for i in range(start, end):
            if pat.match(lines[i]):
                return i
        return -1

    def block_end(start: int, depth: int) -> int:
        """Index after the last line belonging to the block opened at start."""
        i = start + 1
        while i < len(lines):
            ln = lines[i]
            if ln.strip() == "" or ln.lstrip().startswith("#"):
                i += 1
                continue
            cur_indent = len(ln) - len(ln.lstrip())
            if cur_indent <= depth * len(indent_unit):
                break
            i += 1
        return i

    start, end, depth = 0, len(lines), 0
    for d, key in enumerate(key_path):
        idx = find_key(start, end, key, d)
        is_last = d == len(key_path) - 1
        if idx == -1:
            # Insert this key (and remaining path) at the right indentation.
            ind = indent_unit * d
            insert_at = end if (start, end) != (0, len(lines)) else len(lines)
            # Build the nested remainder.
            block = []
            for j, k in enumerate(key_path[d:]):
                bind = indent_unit * (d + j)
                if d + j == len(key_path) - 1:
                    block.append(f"{bind}{k}: {value}")
                else:
                    block.append(f"{bind}{k}:")
            # Insert just inside the parent block.
            at = end
            lines[at:at] = block
            return "\n".join(lines)
        if is_last:
            # Rewrite the scalar on this line, preserving any trailing comment.
            m = re.match(r"^(\s*" + re.escape(key) + r"\s*:)(.*)$", lines[idx])
            prefix = m.group(1)
            trailing = m.group(2)
            cm = re.search(r"(\s+#.*)$", trailing)
            comment = cm.group(1) if cm else ""
            lines[idx] = f"{prefix} {value}{comment}"
            return "\n".join(lines)
        # descend
        start, depth = idx + 1, d + 1
        end = block_end(idx, d)
    return None


def _save_text(path: Path, text: str) -> bool:
    """Write ``text`` back, preserving the file's existing newline style.

    Our editors operate on ``\\n``-split lines; this re-applies the original
    file's dominant line ending (CRLF on Windows-authored configs) so an edit
    never churns every line in git/diff.
    """
    try:
        raw = path.read_bytes()
        newline = "\r\n" if raw.count(b"\r\n") >= raw.count(b"\n") - raw.count(b"\r\n") and b"\r\n" in raw else "\n"
        _backup_once(path)
        # Normalize any stray endings in `text` to the chosen newline.
        body = text.replace("\r\n", "\n").replace("\r", "\n")
        path.write_bytes(body.replace("\n", newline).encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# READ — assemble the full status document
# ---------------------------------------------------------------------------

def _governance_block(name: str) -> Dict[str, Any]:
    """The ``kanban.governance`` block from one profile's config.yaml."""
    cp = _profile_config_path(name)
    if cp is None:
        return {}
    cfg = _load_yaml_file(cp)
    kb = cfg.get("kanban") if isinstance(cfg, dict) else None
    gov = (kb or {}).get("governance") if isinstance(kb, dict) else None
    return gov if isinstance(gov, dict) else {}


def _profile_model(name: str) -> Optional[str]:
    """The configured model.default for a profile (the agent's LLM)."""
    cp = _profile_config_path(name)
    if cp is None:
        return None
    cfg = _load_yaml_file(cp)
    d = (cfg.get("model") or {}).get("default")
    return d if isinstance(d, str) and d else None


def _hybrid_enabled(name: str) -> bool:
    """Whether the Ezra-JS Hybrid is ON for a profile.

    The Hybrid now runs in-process via the factory-governor plugin, gated by
    ``FACTORY_GOVERNOR_HYBRID=1`` in the profile's ``.env`` (portable — no
    hardcoded shim path). We also still honour a legacy active ``hooks:`` block
    for back-compat with an un-migrated setup.
    """
    home = _profile_home(name)
    if home is not None:
        try:
            envf = home / ".env"
            if envf.exists():
                for ln in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    s = ln.strip()
                    if s.startswith("FACTORY_GOVERNOR_HYBRID="):
                        val = s.split("=", 1)[1].strip().strip("'\"").lower()
                        if val in {"1", "true", "yes", "on"}:
                            return True
        except Exception:
            pass
    # Legacy: an active hooks: block in config.yaml.
    cp = _profile_config_path(name)
    if cp is None:
        return False
    cfg = _load_yaml_file(cp)
    hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
    return bool(isinstance(hooks, dict) and hooks.get("pre_tool_call"))


def _secret_pattern_count() -> int:
    try:
        from hermes_cli import kanban_govern
        return len(kanban_govern._SECRET_PATTERNS)
    except Exception:
        return 0


def _killswitch_status(board: Optional[str]) -> Dict[str, Any]:
    try:
        from hermes_cli import kanban_budget
        paths = kanban_budget.kill_switch_paths(board)
        present = [str(p) for p in paths if p.exists()]
        return {"active": bool(present), "paths": [str(p) for p in paths], "present_at": present}
    except Exception:
        return {"active": False, "paths": [], "present_at": []}


def _recent_audit(limit: int = 25) -> List[Dict[str, Any]]:
    """Last N governance-audit.jsonl entries (most recent first)."""
    try:
        from hermes_cli import kanban_govern
        p = kanban_govern._audit_path()
    except Exception:
        p = None
    if p is None or not Path(p).exists():
        return []
    try:
        lines = Path(p).read_text(encoding="utf-8").splitlines()
        out: List[Dict[str, Any]] = []
        for ln in reversed(lines):
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
            if len(out) >= limit:
                break
        return out
    except Exception:
        return []


def _recent_budget_events(board: Optional[str], limit: int = 25) -> List[Dict[str, Any]]:
    """Recent ``budget_exceeded`` task events (most recent first)."""
    try:
        from hermes_cli import kanban_db as kb
        with kb.connect_closing(board=board) as conn:
            rows = conn.execute(
                "SELECT task_id, kind, payload, created_at FROM task_events "
                "WHERE kind = 'budget_exceeded' ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            out = []
            for r in rows:
                payload = r["payload"] if "payload" in r.keys() else None
                try:
                    payload = json.loads(payload) if isinstance(payload, str) else payload
                except Exception:
                    pass
                out.append({
                    "task_id": r["task_id"], "kind": r["kind"],
                    "payload": payload, "created_at": r["created_at"],
                })
            return out
    except Exception:
        return []


def _recent_builds(limit: int = 25) -> List[Dict[str, Any]]:
    """Recent factory build records from builds.jsonl, if present.

    PORTABLE path resolution (no machine-specific path required):
      1. $HERMES_FACTORY_BUILDS              — explicit override
      2. <HERMES_HOME>/factory-audit/builds.jsonl  — the portable default
      3. the legacy C:\\Dev path             — back-compat for the dev box only
    """
    candidates = [os.environ.get("HERMES_FACTORY_BUILDS")]
    try:
        from hermes_cli.config import get_hermes_home
        hh = Path(get_hermes_home())
        # If we're inside a profile home, climb to the engine root.
        if hh.parent.name == "profiles":
            hh = hh.parent.parent
        candidates.append(str(hh / "factory-audit" / "builds.jsonl"))
    except Exception:
        pass
    candidates.append(r"C:\Dev\tools\hermes-update-safety\factory-audit\builds.jsonl")
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if not p.exists():
            continue
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            out: List[Dict[str, Any]] = []
            for ln in reversed(lines):
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    out.append(json.loads(ln))
                except Exception:
                    continue
                if len(out) >= limit:
                    break
            return out
        except Exception:
            return []
    return []


def _active_builds(board: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """The orchestrator closed-loop view: every build with a recorded state
    (acceptance criteria + verify round + last verdict), joined with the root
    task's live status/title. Feeds the dashboard's "Builds" pane.

    Only meaningful when the loop is enabled, but harmless to surface always.
    Fully fail-soft."""
    try:
        from hermes_cli import kanban_govern
        from hermes_cli.kanban_db import kanban_home
        state_dir = kanban_home() / "build-state"
    except Exception:
        return []
    if not state_dir.exists():
        return []
    builds: List[Dict[str, Any]] = []
    try:
        files = sorted(state_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        files = list(state_dir.glob("*.json"))
    # Resolve live task fields in one connection.
    rows: Dict[str, Dict[str, Any]] = {}
    try:
        import hermes_cli.kanban_db as kb
        with kb.connect_closing(board=board) as conn:
            for f in files[:limit]:
                rid = f.stem
                r = conn.execute(
                    "SELECT title, status, assignee FROM tasks WHERE id = ?", (rid,)
                ).fetchone()
                if r is not None:
                    rows[rid] = {"title": r["title"], "status": r["status"],
                                 "assignee": r["assignee"]}
    except Exception:
        rows = {}
    for f in files[:limit]:
        try:
            st = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        rid = st.get("root_id") or f.stem
        live = rows.get(rid, {})
        builds.append({
            "root_id": rid,
            "title": live.get("title"),
            "task_status": live.get("status"),
            "orchestrator": live.get("assignee"),
            "loop_state": st.get("loop_state"),
            "verify_round": st.get("verify_round", 0),
            "max_verify_rounds": kanban_govern.max_verify_rounds(),
            "acceptance": st.get("acceptance", []),
            "last_verdict": st.get("last_verdict"),
            "last_summary": st.get("last_summary"),
            "unmet": st.get("unmet", []),
            "updated_at": st.get("_updated_at"),
        })
    return builds


def _orchestration_config() -> Dict[str, Any]:
    """The kanban orchestration knobs (orchestrator_profile, default_assignee, ...)."""
    try:
        from hermes_cli.config import load_config
        kb = (load_config().get("kanban") or {})
        return {
            "orchestrator_profile": kb.get("orchestrator_profile"),
            "default_assignee": kb.get("default_assignee"),
            "auto_decompose": kb.get("auto_decompose"),
            "auto_decompose_per_tick": kb.get("auto_decompose_per_tick"),
            "max_in_progress_per_profile": kb.get("max_in_progress_per_profile"),
            "dispatch_in_gateway": kb.get("dispatch_in_gateway"),
            "failure_limit": kb.get("failure_limit"),
            "orchestrator_loop": bool(kb.get("orchestrator_loop")),
            "max_verify_rounds": kb.get("max_verify_rounds") or 3,
        }
    except Exception:
        return {}


def build_status(board: Optional[str] = None) -> Dict[str, Any]:
    """Assemble the full governance/budget/orchestration/activity document."""
    try:
        from hermes_cli import kanban_govern
        valid_levels = sorted(kanban_govern._VALID_LEVELS)
        default_level = kanban_govern.DEFAULT_LEVEL
    except Exception:
        valid_levels = ["monitor", "warn", "gate", "strict"]
        default_level = "warn"

    profiles = _factory_profiles()
    per_profile = []
    for name in profiles:
        gov = _governance_block(name)
        per_profile.append({
            "profile": name,
            "level": (gov.get("oversight", {}) or {}).get("level") or gov.get("oversight_level"),
            "protected_paths": gov.get("protected_paths", []) or [],
            "secret_scan": gov.get("secret_scan", True) is not False,
            "hybrid": _hybrid_enabled(name),
            "model": _profile_model(name),
            "governed": bool(gov),
        })

    # Factory-wide rollup (the common case: all profiles share one posture).
    levels = {p["level"] for p in per_profile if p["level"]}
    rollup_level = next(iter(levels)) if len(levels) == 1 else (sorted(levels)[0] if levels else default_level)

    return {
        "schema": 1,
        "governance": {
            "valid_levels": valid_levels,
            "default_level": default_level,
            "level": rollup_level,
            "level_uniform": len(levels) <= 1,
            "secret_scan_patterns": _secret_pattern_count(),
            "profiles": per_profile,
        },
        "budget": _budget_status(board),
        "orchestration": _orchestration_config(),
        "builds": _active_builds(board),
        "activity": {
            "recent_governance_blocks": _recent_audit(),
            "recent_budget_events": _recent_budget_events(board),
            "recent_builds": _recent_builds(),
            "change_log": _recent_changes(),
        },
    }


def _budget_status(board: Optional[str]) -> Dict[str, Any]:
    """Budget breaker config + kill-switch + the factory default ceilings that
    new cards inherit (kanban.budget.default_*; 0/unset = unlimited)."""
    default_iter = None
    default_wall = None
    retry_cap = None
    try:
        from hermes_cli.config import load_config
        bud = (load_config().get("kanban") or {}).get("budget") or {}
        di = bud.get("default_max_iterations")
        dw = bud.get("default_wallclock_seconds")
        default_iter = int(di) if di not in (None, 0, "0") else None
        default_wall = int(dw) if dw not in (None, 0, "0") else None
    except Exception:
        pass
    try:
        from hermes_cli import kanban_govern
        retry_cap = kanban_govern.RETRY_CAP
    except Exception:
        pass
    return {
        "kill_switch": _killswitch_status(board),
        "dimensions": ["wallclock", "iterations", "killswitch", "usd (reserved)", "tokens (reserved)"],
        "default_max_iterations": default_iter,
        "default_wallclock_seconds": default_wall,
        "per_block_retry_cap": retry_cap,
    }


# ---------------------------------------------------------------------------
# WRITE — edit governance / hybrid / killswitch
# ---------------------------------------------------------------------------

def _set_level(level: str, profiles: List[str]) -> Dict[str, Any]:
    from hermes_cli import kanban_govern
    if level not in kanban_govern._VALID_LEVELS:
        return {"ok": False, "error": f"invalid level {level!r}; valid: {sorted(kanban_govern._VALID_LEVELS)}"}
    changed = []
    for name in profiles:
        cp = _profile_config_path(name)
        if cp is None:
            continue
        text = cp.read_text(encoding="utf-8")
        new = _set_path(text, ["kanban", "governance", "oversight", "level"], level)
        if new is not None and _save_text(cp, new):
            changed.append(name)
    return {"ok": bool(changed), "changed": changed, "level": level}


# 9Router model-id SHAPE compatibility (see memory 9router-model-shapes):
#   cc/  -> Anthropic-native  (engine-OK)
#   ag/  -> Anthropic-shape   (engine-OK, incl. cross-family GPT/Gemini)
#   cx/  -> OpenAI-shape      (BREAKS the Hermes anthropic adapter on tool calls)
# A model whose id is cx/* must be REJECTED at the write layer — not just warned
# in the UI — so a worker can never be silently pointed at a build-breaking id.
def _model_shape_ok(model_id: str) -> bool:
    mid = (model_id or "").strip().lower()
    return not mid.startswith("cx/")


def _set_model(model_id: str, profiles: List[str]) -> Dict[str, Any]:
    """Write ``model.default`` for each profile (surgical). Rejects cx/ ids."""
    model_id = (model_id or "").strip()
    if not model_id:
        return {"ok": False, "error": "empty model id"}
    if not _model_shape_ok(model_id):
        return {
            "ok": False,
            "error": (
                f"refusing model {model_id!r}: cx/ ids are OpenAI-shape and break "
                f"the Hermes anthropic adapter on tool calls. Use a cc/ or ag/ id."
            ),
        }
    changed = []
    for name in profiles:
        cp = _profile_config_path(name)
        if cp is None:
            continue
        text = cp.read_text(encoding="utf-8")
        new = _set_path(text, ["model", "default"], model_id)
        if new is not None and _save_text(cp, new):
            changed.append(name)
    return {"ok": bool(changed), "changed": changed, "model": model_id}


def _set_secret_scan(on: bool, profiles: List[str]) -> Dict[str, Any]:
    changed = []
    for name in profiles:
        cp = _profile_config_path(name)
        if cp is None:
            continue
        text = cp.read_text(encoding="utf-8")
        new = _set_path(text, ["kanban", "governance", "secret_scan"], "true" if on else "false")
        if new is not None and _save_text(cp, new):
            changed.append(name)
    return {"ok": bool(changed), "changed": changed, "secret_scan": on}


def _edit_protected(add: Optional[str], remove: Optional[str], profiles: List[str]) -> Dict[str, Any]:
    """Add/remove a protected-path glob. Protected paths are a YAML list, so a
    surgical line-edit inserts/removes a single ``- 'glob'`` list item under the
    existing ``protected_paths:`` key — comments + the rest of the list intact."""
    import re
    changed = []
    for name in profiles:
        cp = _profile_config_path(name)
        if cp is None:
            continue
        text = cp.read_text(encoding="utf-8")
        new = _edit_list_item(text, ["kanban", "governance", "protected_paths"], add, remove)
        if new is not None and _save_text(cp, new):
            changed.append(name)
    return {"ok": bool(changed), "changed": changed, "added": add, "removed": remove}


def _edit_list_item(
    text: str, key_path: List[str], add: Optional[str], remove: Optional[str],
) -> Optional[str]:
    """Add/remove a quoted scalar list item under the YAML list at key_path.

    Comment- and order-preserving. If the list key is missing, creates it with
    the single added item. Returns new text or None on failure.
    """
    import re
    lines = text.split("\n")
    indent_unit = "  "

    def find_key(start, end, key, depth):
        pat = re.compile(r"^" + (indent_unit * depth) + re.escape(key) + r"\s*:")
        for i in range(start, end):
            if pat.match(lines[i]):
                return i
        return -1

    # Walk to the list key.
    start, end = 0, len(lines)
    key_idx = -1
    for d, key in enumerate(key_path):
        idx = find_key(start, end, key, d)
        if idx == -1:
            # Insert the whole path + the item if adding.
            if not add:
                return text  # nothing to remove from a non-existent list
            block = []
            for j, k in enumerate(key_path[d:]):
                bind = indent_unit * (d + j)
                block.append(f"{bind}{k}:")
            block.append(f"{indent_unit * len(key_path)}- '{add}'")
            lines[end:end] = block
            return "\n".join(lines)
        if d == len(key_path) - 1:
            key_idx = idx
            break
        start = idx + 1
        # block end
        e = idx + 1
        while e < len(lines):
            ln = lines[e]
            if ln.strip() == "" or ln.lstrip().startswith("#"):
                e += 1; continue
            if len(ln) - len(ln.lstrip()) <= d * len(indent_unit):
                break
            e += 1
        end = e
    if key_idx == -1:
        return None

    item_indent = indent_unit * len(key_path)
    # Find list-item lines under the key.
    li = key_idx + 1
    item_lines = []
    while li < len(lines):
        ln = lines[li]
        if ln.strip() == "" or ln.lstrip().startswith("#"):
            li += 1; continue
        if len(ln) - len(ln.lstrip()) <= (len(key_path) - 1) * len(indent_unit):
            break
        if ln.lstrip().startswith("- "):
            item_lines.append(li)
        li += 1

    def item_value(i):
        return lines[i].lstrip()[2:].strip().strip("'\"")

    if remove:
        for i in item_lines:
            if item_value(i) == remove:
                del lines[i]
                return "\n".join(lines)
        return text  # not present
    if add:
        if any(item_value(i) == add for i in item_lines):
            return text  # already present
        insert_at = (item_lines[-1] + 1) if item_lines else (key_idx + 1)
        lines[insert_at:insert_at] = [f"{item_indent}- '{add}'"]
        return "\n".join(lines)
    return text


def _set_hybrid(on: bool, profiles: List[str]) -> Dict[str, Any]:
    """Toggle the Ezra-JS Hybrid by writing FACTORY_GOVERNOR_HYBRID to each
    profile's .env (portable; the in-process plugin reads it). Removes the line
    when turning off."""
    changed = []
    for name in profiles:
        home = _profile_home(name)
        if home is None:
            continue
        envf = home / ".env"
        try:
            lines = (
                envf.read_text(encoding="utf-8", errors="ignore").splitlines()
                if envf.exists() else []
            )
            lines = [
                ln for ln in lines
                if not ln.strip().startswith("FACTORY_GOVERNOR_HYBRID=")
            ]
            if on:
                lines.append("FACTORY_GOVERNOR_HYBRID=1")
            envf.write_text("\n".join(lines) + "\n", encoding="utf-8")
            changed.append(name)
        except Exception:
            continue
    return {"ok": bool(changed), "changed": changed, "hybrid": on}


def _root_config_path() -> Optional[Path]:
    """The ROOT config.yaml path (climbs out of a profile home if needed)."""
    try:
        from hermes_cli.config import get_hermes_home
        root = Path(get_hermes_home())
        if root.parent.name == "profiles":
            root = root.parent.parent
        cp = root / "config.yaml"
        return cp if cp.exists() else None
    except Exception:
        return None


def _set_orchestration(key: str, value: Any) -> Dict[str, Any]:
    """Write a kanban orchestration knob to the ROOT config.yaml."""
    cp = _root_config_path()
    if cp is None:
        return {"ok": False, "error": "root config.yaml not found"}
    try:
        text = cp.read_text(encoding="utf-8")
        # YAML scalar: strings verbatim, bool -> true/false, int -> the number.
        # Order matters — bool is a subclass of int, so test bool FIRST.
        if isinstance(value, str):
            yv = value
        elif isinstance(value, bool):
            yv = "true" if value else "false"
        elif isinstance(value, int):
            yv = str(value)
        else:
            yv = "true" if value else "false"
        new = _set_path(text, ["kanban", key], yv)
        ok = new is not None and _save_text(cp, new)
        return {"ok": ok, "key": key, "value": value, "path": str(cp)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _set_budget_default(key: str, value: Optional[int]) -> Dict[str, Any]:
    """Write a default budget ceiling to ROOT config kanban.budget.<key>.

    ``key`` is 'default_max_iterations' or 'default_wallclock_seconds'. A None
    value clears it (unlimited) by writing an explicit empty — but since the
    surgical writer doesn't delete keys, we write 0 to mean 'unlimited' and the
    consumer treats <=0 as unset.
    """
    cp = _root_config_path()
    if cp is None:
        return {"ok": False, "error": "root config.yaml not found"}
    try:
        text = cp.read_text(encoding="utf-8")
        yv = str(int(value)) if value is not None else "0"
        new = _set_path(text, ["kanban", "budget", key], yv)
        ok = new is not None and _save_text(cp, new)
        return {"ok": ok, "key": f"budget.{key}", "value": value, "path": str(cp)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Model catalog (shape-safe — only engine-compatible cc/ + ag/ ids)
# ---------------------------------------------------------------------------

def _router_base_url() -> Optional[str]:
    """The model base_url a factory profile points at (the 9Router endpoint)."""
    try:
        # Read any factory profile's model.base_url (they all share 9Router).
        for name in _factory_profiles():
            cp = _profile_config_path(name)
            if cp is None:
                continue
            cfg = _load_yaml_file(cp)
            bu = (cfg.get("model") or {}).get("base_url")
            if isinstance(bu, str) and bu:
                return bu.rstrip("/")
    except Exception:
        pass
    return None


def list_safe_models() -> Dict[str, Any]:
    """Fetch the model list from 9Router /v1/models and return only the
    engine-compatible cc/ + ag/ ids. Fail-soft: on any error, returns the
    distinct models currently configured across the factory profiles so the UI
    always has *something* selectable."""
    base = _router_base_url()
    safe: List[str] = []
    source = "router"
    if base:
        try:
            import json as _json
            import urllib.request
            req = urllib.request.Request(base + "/models", headers={"x-api-key": "9router-local"})
            with urllib.request.urlopen(req, timeout=5) as r:  # nosec - localhost
                data = _json.loads(r.read().decode("utf-8"))
            ids = [m.get("id") for m in data.get("data", []) if isinstance(m, dict)]
            safe = sorted({i for i in ids if isinstance(i, str) and (i.startswith("cc/") or i.startswith("ag/"))})
        except Exception:
            safe = []
    if not safe:
        # Fallback: the models currently in use across the profiles.
        source = "configured"
        cur = set()
        for name in _factory_profiles():
            cp = _profile_config_path(name)
            if cp is None:
                continue
            cfg = _load_yaml_file(cp)
            d = (cfg.get("model") or {}).get("default")
            if isinstance(d, str) and d:
                cur.add(d)
        safe = sorted(cur)
    return {"models": safe, "source": source, "base_url": base}


# ---------------------------------------------------------------------------
# Settings change-log (reversible history)
# ---------------------------------------------------------------------------

def _changelog_path() -> Optional[Path]:
    try:
        from hermes_cli.config import get_hermes_home
        root = Path(get_hermes_home())
        if root.parent.name == "profiles":
            root = root.parent.parent
        return root / "factory-governance-changelog.jsonl"
    except Exception:
        return None


def _log_change(action: str, target: str, key: str, old: Any, new: Any) -> None:
    """Append a reversible change record. Best-effort, never raises."""
    p = _changelog_path()
    if p is None:
        return
    try:
        import time as _t
        rec = {
            "id": f"chg_{int(_t.time()*1000)}",
            "ts": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
            "action": action, "target": target, "key": key,
            "old": old, "new": new,
        }
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _recent_changes(limit: int = 50) -> List[Dict[str, Any]]:
    p = _changelog_path()
    if p is None or not p.exists():
        return []
    try:
        out: List[Dict[str, Any]] = []
        for ln in reversed(p.read_text(encoding="utf-8").splitlines()):
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
            if len(out) >= limit:
                break
        return out
    except Exception:
        return []


def _killswitch(on: bool, board: Optional[str]) -> Dict[str, Any]:
    try:
        from hermes_cli import kanban_budget
        paths = kanban_budget.kill_switch_paths(board)
        target = paths[0] if paths else None
        if target is None:
            return {"ok": False, "error": "could not resolve kill-switch path"}
        if on:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("STOP — factory halted via govern killswitch\n", encoding="utf-8")
        else:
            for p in paths:
                try:
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
        return {"ok": True, "active": on, "path": str(target)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# CLI handler
# ---------------------------------------------------------------------------

def cmd_govern(args: argparse.Namespace) -> int:
    sub = getattr(args, "govern_action", None)
    board = getattr(args, "board", None)
    as_json = getattr(args, "json", False)

    if sub in (None, "status"):
        status = build_status(board)
        if as_json:
            print(json.dumps(status, indent=2, ensure_ascii=False))
        else:
            _print_status_human(status)
        return 0

    if sub == "set":
        results = []
        profiles = _factory_profiles()
        # Note: ``--for-profile`` (not ``--profile``) — hermes reserves the
        # global ``--profile`` / ``-p`` to switch the active profile, so it
        # never reaches this subparser. ``--for-profile`` scopes the change.
        if getattr(args, "for_profile", None):
            profiles = [args.for_profile]
        if getattr(args, "level", None):
            results.append(_set_level(args.level, profiles))
        if getattr(args, "secret_scan", None) is not None:
            results.append(_set_secret_scan(args.secret_scan == "on", profiles))
        if getattr(args, "add_protected", None):
            results.append(_edit_protected(args.add_protected, None, profiles))
        if getattr(args, "remove_protected", None):
            results.append(_edit_protected(None, args.remove_protected, profiles))
        if getattr(args, "hybrid", None) is not None:
            results.append(_set_hybrid(args.hybrid == "on", profiles))
        if getattr(args, "model", None):
            results.append(_set_model(args.model, profiles))
        for key in ("orchestrator_profile", "default_assignee"):
            val = getattr(args, key, None)
            if val is not None:
                results.append(_set_orchestration(key, val))
        if getattr(args, "auto_decompose", None) is not None:
            results.append(_set_orchestration("auto_decompose", args.auto_decompose == "on"))
        if getattr(args, "auto_decompose_per_tick", None) is not None:
            results.append(_set_orchestration("auto_decompose_per_tick", int(args.auto_decompose_per_tick)))
        if getattr(args, "max_in_progress", None) is not None:
            results.append(_set_orchestration("max_in_progress_per_profile", int(args.max_in_progress)))
        if getattr(args, "orchestrator_loop", None) is not None:
            results.append(_set_orchestration("orchestrator_loop", args.orchestrator_loop == "on"))
        if getattr(args, "max_verify_rounds", None) is not None:
            results.append(_set_orchestration("max_verify_rounds", int(args.max_verify_rounds)))
        if getattr(args, "default_max_iterations", None) is not None:
            results.append(_set_budget_default("default_max_iterations", args.default_max_iterations))
        if getattr(args, "default_wallclock", None) is not None:
            results.append(_set_budget_default("default_wallclock_seconds", args.default_wallclock))
        if not results:
            print("govern set: nothing to change (pass --level / --secret-scan / --add-protected / ...)", file=sys.stderr)
            return 2
        # Log each successful change to the reversible change-log. Each setter
        # result carries a recognizable key/value pair; pick the first present.
        scope = getattr(args, "for_profile", None) or "all"
        for r in results:
            if not r.get("ok"):
                continue
            for k in ("level", "secret_scan", "hybrid", "model", "added", "removed", "key", "value"):
                if k in r and r[k] is not None:
                    _log_change("set", scope, k, None, r[k])
                    break
        out = {"ok": all(r.get("ok") for r in results), "results": results}
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out["ok"] else 1

    if sub == "killswitch":
        on = getattr(args, "state", None) == "on"
        out = _killswitch(on, board)
        # Kill-switch is logged too (it's a high-impact change).
        if out.get("ok"):
            _log_change("killswitch", "all", "kill_switch", None, on)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out.get("ok") else 1

    if sub == "changelog":
        print(json.dumps({"change_log": _recent_changes(200)}, indent=2, ensure_ascii=False))
        return 0

    if sub == "models":
        print(json.dumps(list_safe_models(), indent=2, ensure_ascii=False))
        return 0

    print(f"govern: unknown subcommand {sub!r}", file=sys.stderr)
    return 2


def _print_status_human(s: Dict[str, Any]) -> None:
    g = s.get("governance", {})
    print("Factory governance")
    print(f"  oversight level : {g.get('level')}" + ("" if g.get("level_uniform") else "  (MIXED across profiles)"))
    print(f"  secret scan     : {g.get('secret_scan_patterns')} patterns (+ entropy)")
    print("  profiles:")
    for p in g.get("profiles", []):
        print(f"    - {p['profile']:18} level={p['level'] or '-':7} secret_scan={'on' if p['secret_scan'] else 'off':3} hybrid={'on' if p['hybrid'] else 'off'} protected={len(p['protected_paths'])}")
    ks = (s.get("budget", {}) or {}).get("kill_switch", {})
    print(f"  kill-switch     : {'ACTIVE' if ks.get('active') else 'off'}")
    blocks = (s.get("activity", {}) or {}).get("recent_governance_blocks", [])
    print(f"  recent blocks   : {len(blocks)}")
    for b in blocks[:8]:
        f = (b.get("findings") or [{}])[0]
        print(f"    {b.get('ts','')[:19]}  {b.get('decision','?'):5}  {f.get('code','?'):13}  {f.get('path','')}")


def register(subparsers) -> None:
    """Register ``govern`` under the kanban subparser. Called from kanban.py."""
    p = subparsers.add_parser("govern", help="View/edit factory governance (level, protected paths, secrets, budget)")
    p.add_argument("--json", action="store_true", help="Emit the full status as JSON")
    gsub = p.add_subparsers(dest="govern_action")

    gsub.add_parser("status", help="Show governance status (default)")

    pset = gsub.add_parser("set", help="Change a governance/orchestration setting")
    pset.add_argument("--level", choices=["monitor", "warn", "gate", "strict"], help="Oversight level (all factory profiles)")
    pset.add_argument("--secret-scan", dest="secret_scan", choices=["on", "off"], help="Toggle SEC-SECRETS scanning")
    pset.add_argument("--add-protected", dest="add_protected", metavar="GLOB", help="Add a protected-path glob")
    pset.add_argument("--remove-protected", dest="remove_protected", metavar="GLOB", help="Remove a protected-path glob")
    pset.add_argument("--hybrid", choices=["on", "off"], help="Ezra-JS Hybrid (per --for-profile)")
    pset.add_argument("--model", help="Set the agent's model (model.default). cc/ or ag/ ids only; cx/ is rejected (breaks the adapter).")
    pset.add_argument("--for-profile", dest="for_profile", help="Restrict the change to one profile (default: all factory profiles). NOT --profile (that's hermes's global active-profile switch).")
    pset.add_argument("--orchestrator-profile", dest="orchestrator_profile", help="Set kanban.orchestrator_profile (root config)")
    pset.add_argument("--default-assignee", dest="default_assignee", help="Set kanban.default_assignee (root config)")
    pset.add_argument("--auto-decompose", dest="auto_decompose", choices=["on", "off"], help="Toggle auto-decompose")
    pset.add_argument("--auto-decompose-per-tick", dest="auto_decompose_per_tick", type=int, help="Max triage tasks decomposed per dispatch tick")
    pset.add_argument("--max-in-progress", dest="max_in_progress", type=int, help="Max in-progress tasks per profile")
    pset.add_argument("--orchestrator-loop", dest="orchestrator_loop", choices=["on", "off"], help="Toggle the orchestrator closed-loop (verify assembled build vs acceptance, command corrections)")
    pset.add_argument("--max-verify-rounds", dest="max_verify_rounds", type=int, help="Max verify→correct→re-verify rounds before escalating to a human (default 3)")
    pset.add_argument("--default-max-iterations", dest="default_max_iterations", type=int, help="Default build iteration ceiling for new cards (0=unlimited)")
    pset.add_argument("--default-wallclock", dest="default_wallclock", type=int, help="Default build wall-clock ceiling (seconds) for new cards (0=unlimited)")

    pks = gsub.add_parser("killswitch", help="Touch/remove the STOP sentinel (halt/resume all spawns)")
    pks.add_argument("state", choices=["on", "off"], help="on = halt the factory, off = resume")

    gsub.add_parser("changelog", help="Show the reversible settings change-log (JSON)")
    gsub.add_parser("models", help="List engine-compatible (cc/ + ag/) models from 9Router for the model picker")
