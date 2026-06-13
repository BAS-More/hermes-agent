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


def _task_id_from_kwargs(kwargs: Dict[str, Any]) -> str:
    """Extract the kanban task id the worker is executing.

    ``get_pre_tool_call_block_message`` passes ``task_id`` (the worker's
    ``effective_task_id``). Empty => not a kanban worker => no governance.
    """
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


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    **kwargs: Any,
) -> Optional[Dict[str, str]]:
    """Block the write only when the build's oversight level decides 'block'.

    Warn/monitor findings return None here and are surfaced by
    ``transform_tool_result`` instead (the write proceeds, the model sees the
    warning next turn) — exactly security-guidance's warn-mode contract.
    """
    res = _evaluate(tool_name, args, _task_id_from_kwargs(kwargs))
    if not res or res.get("decision") != "block":
        return None
    return {
        "action": "block",
        "message": (
            res.get("message")
            or "factory-governor blocked this write (governance policy)."
        ),
    }


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
    res = _evaluate(tool_name, args, _task_id_from_kwargs(kwargs))
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
