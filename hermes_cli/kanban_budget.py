"""Build-level budget circuit breaker for the kanban dev factory.

A SECOND circuit breaker, distinct from the consecutive-failure breaker in
``_record_task_failure`` (kanban_db.py). Where that one trips on repeated
*failures*, this one trips on resource *spend* across a whole build:

    - wall clock   : elapsed since the build root's ``created_at``.
    - iterations   : count of ``task_runs`` rows across the build subtree.
    - KILL SWITCH  : a sentinel file checked on EVERY call; present => abort.
    - usd / tokens : RESERVED (USD fast-follow). Skipped while the per-build
                     ceilings are NULL, which they always are until a worker
                     records usage into ``task_runs.metadata``.

The breaker is checked BEFORE each spawn (preflight) by the dispatcher. It is
read-only over the DB — it never mutates task state; the *caller* (dispatcher)
blocks the root via ``block_task`` when ``check()`` reports tripped. This keeps
the breaker pure and testable.

Mirrors software-factory/packages/crew-router/src/breaker.js (check() + latch +
kill-switch), reimplemented in Python over sqlite. Kill-switch is non-latching
(remove the file to resume); ceiling trips are terminal for the build (the root
gets blocked and stays blocked until a human unblocks).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Optional

import sqlite3


# Sentinel filename. Lives at the kanban home root (shared across boards) and,
# when board-scoped, additionally under the board dir. Touch it to halt all
# spawns immediately; delete it to resume.
KILL_SWITCH_FILENAME = "STOP"


def kill_switch_paths(board: Optional[str] = None) -> list[Path]:
    """Return the sentinel paths checked by the breaker.

    A global ``<kanban_home>/STOP`` halts every board; a board-scoped
    ``<board_dir>/STOP`` halts just one. Both are honoured.
    """
    # Imported lazily to avoid a circular import (kanban_db imports this).
    from hermes_cli.kanban_db import kanban_home, board_dir

    paths: list[Path] = [kanban_home() / KILL_SWITCH_FILENAME]
    if board:
        try:
            paths.append(Path(board_dir(board)) / KILL_SWITCH_FILENAME)
        except Exception:
            pass
    return paths


def _kill_switch_present(board: Optional[str] = None) -> Optional[str]:
    """Return the path of the first present kill-switch file, else None."""
    for p in kill_switch_paths(board):
        try:
            if p.exists():
                return str(p)
        except Exception:
            continue
    return None


def _resolve_root_id(conn: sqlite3.Connection, task_id: str) -> str:
    """Walk parent links up to the build root (a task with no parents).

    Cycles are impossible in a well-formed DAG, but we bound the walk
    defensively so a malformed link can never spin forever.
    """
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
            return cur  # no parent => root
        cur = row["parent_id"] if isinstance(row, sqlite3.Row) else row[0]
    return cur


def _subtree_ids(conn: sqlite3.Connection, root_id: str) -> set[str]:
    """All task ids in the build: the root plus every transitive child."""
    ids: set[str] = {root_id}
    frontier = [root_id]
    for _ in range(4096):  # bound the BFS
        if not frontier:
            break
        nxt: list[str] = []
        for pid in frontier:
            for row in conn.execute(
                "SELECT child_id FROM task_links WHERE parent_id = ?", (pid,)
            ).fetchall():
                cid = row["child_id"] if isinstance(row, sqlite3.Row) else row[0]
                if cid not in ids:
                    ids.add(cid)
                    nxt.append(cid)
        frontier = nxt
    return ids


def check(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    board: Optional[str] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Preflight the budget breaker for the build containing ``task_id``.

    Read-only. Returns a status dict:
        {
          "ok": bool,            # True = clear to spawn
          "tripped": bool,
          "reason": str | None,
          "limit": str | None,   # 'killswitch'|'wallclock'|'iterations'|'usd'|'tokens'
          "root_id": str,
          "usage": {elapsed_seconds, iterations, usd, tokens},
          "limits": {wallclock_ceiling_seconds, max_build_iterations,
                     budget_ceiling_usd, max_tokens},
        }

    The kill-switch is evaluated first and wins over everything. Ceiling
    dimensions whose limit is NULL are skipped (no cap). USD/token branches
    are reserved: their ceilings are NULL until the USD fast-follow records
    usage, so they're inert today.
    """
    now = time.time() if now is None else now
    root_id = _resolve_root_id(conn, task_id)

    base_usage = {"elapsed_seconds": 0, "iterations": 0, "usd": 0.0, "tokens": 0}
    base_limits = {
        "wallclock_ceiling_seconds": None,
        "max_build_iterations": None,
        "budget_ceiling_usd": None,
        "max_tokens": None,
    }

    def _result(ok, tripped, reason, limit, usage, limits):
        return {
            "ok": ok,
            "tripped": tripped,
            "reason": reason,
            "limit": limit,
            "root_id": root_id,
            "usage": usage,
            "limits": limits,
        }

    # 1. Kill-switch — checked first, every call, board-scoped + global.
    ks = _kill_switch_present(board)
    if ks:
        return _result(
            False, True,
            f"kill-switch present at {ks} — halting all spawns",
            "killswitch", base_usage, base_limits,
        )

    root = conn.execute(
        "SELECT created_at, wallclock_ceiling_seconds, max_build_iterations, "
        "       budget_ceiling_usd, max_tokens "
        "FROM tasks WHERE id = ?",
        (root_id,),
    ).fetchone()
    if root is None:
        # No root row (shouldn't happen) => fail OPEN: don't block work on a
        # breaker lookup miss. The failure breaker still guards correctness.
        return _result(True, False, None, None, base_usage, base_limits)

    def _g(key):
        try:
            return root[key]
        except Exception:
            return None

    limits = {
        "wallclock_ceiling_seconds": _g("wallclock_ceiling_seconds"),
        "max_build_iterations": _g("max_build_iterations"),
        "budget_ceiling_usd": _g("budget_ceiling_usd"),
        "max_tokens": _g("max_tokens"),
    }

    # Fast path: build has no ceilings at all => clear, skip the subtree scan.
    if all(v is None for v in limits.values()):
        return _result(True, False, None, None, base_usage, limits)

    created_at = _g("created_at") or now
    elapsed = max(0, int(now - int(created_at)))

    # Iterations + (reserved) usd/tokens are aggregated over the subtree.
    subtree = _subtree_ids(conn, root_id)
    placeholders = ",".join("?" for _ in subtree)
    iterations = 0
    usd_spent = 0.0
    tokens_spent = 0
    if subtree:
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM task_runs WHERE task_id IN ({placeholders})",
            tuple(subtree),
        ).fetchone()
        iterations = int(row["n"] if isinstance(row, sqlite3.Row) else row[0])
        # USD/token roll-up is reserved: read task_runs.metadata JSON when the
        # USD fast-follow starts writing it. Until then these stay 0 and their
        # NULL ceilings mean the branches below are skipped.

    usage = {
        "elapsed_seconds": elapsed,
        "iterations": iterations,
        "usd": usd_spent,
        "tokens": tokens_spent,
    }

    # 2. Wall-clock ceiling.
    wc = limits["wallclock_ceiling_seconds"]
    if wc is not None and elapsed >= int(wc):
        return _result(
            False, True,
            f"wall-clock ceiling reached ({elapsed}s/{int(wc)}s) — STOP",
            "wallclock", usage, limits,
        )

    # 3. Iteration ceiling.
    mi = limits["max_build_iterations"]
    if mi is not None and iterations >= int(mi):
        return _result(
            False, True,
            f"iteration ceiling reached ({iterations}/{int(mi)} runs) — STOP",
            "iterations", usage, limits,
        )

    # 4. USD ceiling (RESERVED — skipped while ceiling is NULL).
    uc = limits["budget_ceiling_usd"]
    if uc is not None and usd_spent >= float(uc):
        return _result(
            False, True,
            f"USD ceiling reached (${usd_spent:.4f}/${float(uc):.4f}) — STOP",
            "usd", usage, limits,
        )

    # 5. Token ceiling (RESERVED — skipped while ceiling is NULL).
    tc = limits["max_tokens"]
    if tc is not None and tokens_spent >= int(tc):
        return _result(
            False, True,
            f"token ceiling reached ({tokens_spent}/{int(tc)}) — STOP",
            "tokens", usage, limits,
        )

    return _result(True, False, None, None, usage, limits)
