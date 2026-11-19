#!/usr/bin/env python3
"""
Dashboard stream events for the Hermes Desktop right-side agent panel.

The desktop client consumes structured dashboard events over the SAME SSE
channel the ``/v1/runs/{run_id}/events`` stream already uses (see
``gateway/platforms/api_server.py`` :meth:`_handle_run_events`). Every event
is a plain dict of the shape::

    {"type": "<name>", "payload": {...}, "session_id": "..."}

that is pushed verbatim into the run's ``asyncio.Queue`` and serialized to the
client with ``json.dumps(event)``.

**Why a contextvar sink?**

The agent core (todo tool, conversation loop, file tools) has no reference to
the ``api_server`` instance or the per-run queue. Wiring one through every call
site would be invasive. Instead the api_server registers a *sink* — a callable
``(event: dict) -> None`` that enqueues onto the active run's queue — into a
``contextvars.ContextVar`` for the duration of the run (set inside the same
``_run_sync`` block that calls ``set_session_vars``). Core modules then call the
typed ``emit_*`` helpers below, which read the sink from the context and invoke
it. This mirrors the existing ``gateway/session_context.py`` pattern: each
asyncio task / executor thread sees its own sink, so concurrent runs never
cross streams.

**Resilience contract**

- Every emit is wrapped in ``try/except`` and can NEVER raise into the agent
  turn. A failing dashboard emit is swallowed.
- When no sink is registered (headless/CLI runs, or a dashboard with zero
  connected clients), emit is a silent no-op.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Callable, Dict, List, Optional

# Sink callable: receives a fully-formed {"type", "payload", "session_id"} dict
# and is responsible for delivering it to connected dashboard client(s).
_DASHBOARD_SINK: ContextVar[Optional[Callable[[Dict[str, Any]], None]]] = ContextVar(
    "HERMES_DASHBOARD_SINK", default=None
)
# Session id stamped onto every emitted event so the desktop can route it.
_DASHBOARD_SESSION_ID: ContextVar[Optional[str]] = ContextVar(
    "HERMES_DASHBOARD_SESSION_ID", default=None
)

# Monotonic sequence for usage.update events (per process). The desktop uses
# this to drop out-of-order usage frames so the Usage ring never flickers
# backwards under concurrent turns.
_usage_seq: int = 0


# ---------------------------------------------------------------------------
# Sink registration (called by api_server per run)
# ---------------------------------------------------------------------------

def set_dashboard_sink(
    sink: Optional[Callable[[Dict[str, Any]], None]],
    session_id: Optional[str] = None,
) -> list:
    """Register the dashboard event sink for the current context.

    Returns reset tokens; pass them to :func:`clear_dashboard_sink` in a
    ``finally`` block. Safe to call with ``sink=None`` to explicitly disable
    emission for this context.
    """
    return [
        _DASHBOARD_SINK.set(sink),
        _DASHBOARD_SESSION_ID.set(session_id),
    ]


def clear_dashboard_sink(tokens: Optional[list] = None) -> None:
    """Reset the dashboard sink for the current context to the no-op default."""
    _DASHBOARD_SINK.set(None)
    _DASHBOARD_SESSION_ID.set(None)


def has_dashboard_sink() -> bool:
    """True when a sink is registered in the current context."""
    return _DASHBOARD_SINK.get() is not None


# ---------------------------------------------------------------------------
# Core emit primitive
# ---------------------------------------------------------------------------

def emit_dashboard_event(event_type: str, payload: Dict[str, Any]) -> bool:
    """Emit one dashboard event to the active run's stream.

    Builds ``{"type": event_type, "payload": payload, "session_id": <id>}`` and
    hands it to the registered sink. Returns ``True`` if the event was handed to
    a sink, ``False`` if it no-op'd (no sink) or the sink raised. NEVER raises.
    """
    try:
        sink = _DASHBOARD_SINK.get()
        if sink is None:
            return False
        event = {
            "type": event_type,
            "payload": payload,
            "session_id": _DASHBOARD_SESSION_ID.get(),
        }
        sink(event)
        return True
    except Exception:
        # A dashboard-emit failure must never break the agent turn.
        return False


# ---------------------------------------------------------------------------
# Typed emitters (the 6 desktop contract events)
# ---------------------------------------------------------------------------

def emit_todo_update(items: List[Dict[str, Any]]) -> bool:
    """type ``todo.update`` — full snapshot of the todo list (replaces wholesale).

    payload: ``{"items": [{"id", "content", "status"}, ...]}`` with status in
    ``pending|in_progress|completed|cancelled``.
    """
    try:
        normalized = [
            {
                "id": str(i.get("id", "")),
                "content": str(i.get("content", "")),
                "status": str(i.get("status", "pending")),
            }
            for i in (items or [])
        ]
    except Exception:
        return False
    return emit_dashboard_event("todo.update", {"items": normalized})


def emit_task_update(
    task_id: str,
    title: str,
    progress: int,
    state: str,
) -> bool:
    """type ``task.update`` — subagent / delegate_task lifecycle.

    payload: ``{"id", "title", "progress"(0-100), "state"}`` with state in
    ``queued|running|failed|succeeded``.
    """
    try:
        pct = max(0, min(100, int(progress)))
    except Exception:
        pct = 0
    return emit_dashboard_event(
        "task.update",
        {"id": str(task_id), "title": str(title), "progress": pct, "state": str(state)},
    )


def emit_diff_update(path: str, added: int, removed: int) -> bool:
    """type ``diff.update`` — line stats for a file the agent wrote/patched.

    payload: ``{"path", "added", "removed"}``.
    """
    try:
        added_n = max(0, int(added))
        removed_n = max(0, int(removed))
    except Exception:
        return False
    return emit_dashboard_event(
        "diff.update", {"path": str(path), "added": added_n, "removed": removed_n}
    )


def emit_review_update(path: str, line: int, comment: str) -> bool:
    """type ``review.update``.

    payload: ``{"path", "line", "comment"}``.
    """
    try:
        line_n = int(line)
    except Exception:
        line_n = 0
    return emit_dashboard_event(
        "review.update", {"path": str(path), "line": line_n, "comment": str(comment)}
    )


def emit_plan_update(steps: List[str]) -> bool:
    """type ``plan.update``.

    payload: ``{"steps": [string, ...]}``.
    """
    try:
        normalized = [str(s) for s in (steps or [])]
    except Exception:
        return False
    return emit_dashboard_event("plan.update", {"steps": normalized})


def emit_usage_update(
    context_pct: float,
    plan_pct: Optional[float] = None,
) -> bool:
    """type ``usage.update`` — token-window usage for the Usage ring.

    payload: ``{"contextPct"(0-100), "planPct"(0-100), "seq"(monotonic int)}``.
    ``planPct`` mirrors ``contextPct`` when no separate plan budget exists.
    A monotonic ``seq`` is always included.
    """
    global _usage_seq
    try:
        ctx = float(context_pct)
    except Exception:
        return False
    ctx = max(0.0, min(100.0, ctx))
    if plan_pct is None:
        plan = ctx
    else:
        try:
            plan = max(0.0, min(100.0, float(plan_pct)))
        except Exception:
            plan = ctx
    _usage_seq += 1
    return emit_dashboard_event(
        "usage.update",
        {"contextPct": round(ctx, 2), "planPct": round(plan, 2), "seq": _usage_seq},
    )


def _reset_usage_seq_for_tests() -> None:
    """Test helper — reset the monotonic usage sequence to 0."""
    global _usage_seq
    _usage_seq = 0
