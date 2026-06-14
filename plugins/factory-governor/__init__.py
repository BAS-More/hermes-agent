"""factory-governor plugin — the EZRA governance gate for kanban workers.

This is the GOV-layer twin of the bundled ``security-guidance`` plugin. Where
security-guidance scans write *content* for dangerous SEC-* patterns, this
enforces EZRA's structural rule: **a write to a protected path requires an
ACTIVE decision (ADR)** in the build's ``.ezra/`` governance — under a
per-build oversight dial (monitor / warn / gate / strict).

Two hooks, exactly mirroring security-guidance's shape:

* ``pre_tool_call``        — BLOCK the write when the build's oversight level
                             says so (gate: block high/critical; strict: block
                             any). Returns ``{"action":"block","message":...}``,
                             the canonical Hermes block directive.
* ``transform_tool_result`` — WARN mode: append the governance warning to the
                             tool result so the model self-corrects next turn
                             (used when the level is ``warn``/``monitor`` or a
                             ``gate`` finding is below the block threshold).

Discipline (mirrors kanban_budget + security-guidance):
  * READ-FIRST  — never mutates task state.
  * FAIL-OPEN   — any error => allow. Governance must never wedge a worker.
  * Opt-out via ``FACTORY_GOVERNOR_DISABLE=1`` (kill-switch parity).

The hook only does anything inside a kanban worker (it needs ``task_id`` to
resolve the build's governance). Outside a kanban context — interactive
``hermes chat``, the gateway answering a user — there is no ``task_id`` and
the gate is a silent no-op. So enabling this plugin globally is safe; it is
inert everywhere except factory builds.

All governance logic lives in :mod:`hermes_cli.kanban_govern`; this file is
just the plugin wiring + the DB-connect glue.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _disabled() -> bool:
    return os.environ.get("FACTORY_GOVERNOR_DISABLE", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _task_id(kwargs: Dict[str, Any]) -> str:
    """Resolve the kanban task id the worker is executing.

    The dispatcher pins ``HERMES_KANBAN_TASK`` in every worker's environment
    (kanban_db._default_spawn), which is the authoritative, reliable signal
    that this process is a kanban worker and which build it's on. We prefer it
    over the hook's ``task_id`` kwarg (the agent's ``effective_task_id``, which
    is only the kanban id in some invocation paths and a random per-turn UUID
    in others). Falling back to the kwarg keeps the gate working if a future
    caller passes a real kanban id without the env. Empty => not a kanban
    worker => governance is a silent no-op.
    """
    env_tid = os.environ.get("HERMES_KANBAN_TASK")
    if isinstance(env_tid, str) and env_tid:
        return env_tid
    tid = kwargs.get("task_id")
    return tid if isinstance(tid, str) and tid else ""


def _evaluate(tool_name: str, args: Any, task_id: str) -> Optional[Dict[str, Any]]:
    """Run the governor for one tool call. Returns the kanban_govern result
    dict, or None when there's nothing to govern / on any failure (fail-open).
    """
    if _disabled() or not task_id:
        return None
    try:
        from hermes_cli import kanban_govern, kanban_db
    except Exception:
        return None
    # Resolve the worker's board the same way the dispatcher does.
    board = os.environ.get("HERMES_KANBAN_BOARD") or None
    try:
        with kanban_db.connect_closing(board=board) as conn:
            return kanban_govern.check_tool_call(conn, task_id, tool_name, args)
    except Exception as exc:  # fail-open — never wedge the worker
        logger.debug("factory-governor: check failed (allowing): %s", exc)
        return None


def _hybrid_enabled() -> bool:
    """Whether the Ezra-JS Hybrid chain is on (EZRA's SEC/STD/best-practice
    engine via ezra_shim.js). Opt-in via env so it stays off by default."""
    return os.environ.get("FACTORY_GOVERNOR_HYBRID", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _ezra_hybrid_block(tool_name: str, args: Any) -> Optional[str]:
    """Run EZRA's real PreToolUse hooks via the shim, IN-PROCESS and PORTABLY.

    The shim lives next to this file, so it's located by ``__file__``-relative
    path — no machine-specific path, no shlex/spaces problem (the reason the
    old config ``hooks:`` command was not portable). Returns a block reason
    string, or None (allow). Fail-open: any error → None.
    """
    if not _hybrid_enabled():
        return None
    write_path = None
    content = None
    if isinstance(args, dict):
        write_path = args.get("path") or args.get("file_path")
        content = (
            args.get("content") or args.get("new_string")
            or args.get("file_content") or args.get("patch")
        )
    if not write_path or not content:
        return None
    try:
        import json
        import subprocess
        shim = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ezra_shim.js")
        if not os.path.exists(shim):
            return None
        payload = {
            "hook_event_name": "pre_tool_call",
            "tool_name": tool_name,
            "tool_input": {"path": write_path, "content": content},
            "session_id": "",
            "cwd": os.environ.get("HERMES_KANBAN_WORKSPACE") or os.getcwd(),
        }
        r = subprocess.run(
            ["node", shim],
            input=json.dumps(payload),
            capture_output=True, text=True, timeout=10,
        )
        out = (r.stdout or "").strip()
        if not out:
            return None
        data = json.loads(out)
        # Shim emits Claude-Code shape {"decision":"block","reason":...}.
        if isinstance(data, dict) and data.get("decision") == "block":
            return data.get("reason") or "EZRA hybrid blocked this write."
    except Exception as exc:  # fail-open
        logger.debug("factory-governor: ezra hybrid skipped (allowing): %s", exc)
    return None


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    **kwargs: Any,
) -> Optional[Dict[str, str]]:
    """Block the write only when the build's oversight level decides 'block'.

    Two layers, native-first: (1) the GOV/SEC governor (kanban_govern), then
    (2) the optional Ezra-JS Hybrid (EZRA's SEC/STD/best-practice engine via the
    shim). First block wins. Warn/monitor findings return None here and are
    surfaced by ``transform_tool_result`` instead.
    """
    res = _evaluate(tool_name, args, _task_id(kwargs))
    if res and res.get("decision") == "block":
        return {
            "action": "block",
            "message": (
                res.get("message")
                or "factory-governor blocked this write (governance policy)."
            ),
        }
    # Native governor allowed it — give the opt-in EZRA hybrid a look.
    hybrid = _ezra_hybrid_block(tool_name, args)
    if hybrid:
        return {"action": "block", "message": hybrid}
    return None


def _on_transform_tool_result(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    **kwargs: Any,
) -> Optional[str]:
    """Append the governance warning to the tool result in warn/monitor cases.

    Block decisions are handled by pre_tool_call (the tool never ran, so there
    is no result to decorate) — mirror security-guidance and do nothing here
    for them. Returning None leaves the result untouched.
    """
    res = _evaluate(tool_name, args, _task_id(kwargs))
    if not res:
        return None
    if res.get("decision") != "warn":
        return None
    msg = res.get("message")
    if not msg or not isinstance(result, str):
        return None
    # Don't decorate error results — the model already has bigger problems.
    try:
        import json
        parsed = json.loads(result)
        if isinstance(parsed, dict) and "error" in parsed and len(parsed) <= 2:
            return None
    except (ValueError, TypeError):
        pass
    return result + "\n\n---\n" + msg


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
