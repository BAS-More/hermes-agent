"""``hermes workspace`` subcommand parser.

Safe git safety snapshots (never lose uncommitted work) — see
``hermes_cli/workspace.py`` for the handler. Handler injected to avoid
importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_workspace_parser(subparsers, *, cmd_workspace: Callable) -> None:
    """Attach the ``workspace`` subcommand to ``subparsers``."""
    workspace_parser = subparsers.add_parser(
        "workspace",
        help="Git safety snapshots so you never lose uncommitted work",
        description=(
            "Snapshot uncommitted work to a dedicated safety ref without "
            "touching HEAD, the index, branches, or the working tree. "
            "Does NOT auto-commit to real branches or auto-merge."
        ),
    )
    ws_sub = workspace_parser.add_subparsers(dest="workspace_action")

    p_snap = ws_sub.add_parser("snapshot", aliases=["snap"], help="Take one safety snapshot now")
    p_snap.add_argument("path", nargs="?", default=None, help="Repo path (default: cwd)")

    p_list = ws_sub.add_parser("list", aliases=["ls"], help="List existing safety snapshots")
    p_list.add_argument("path", nargs="?", default=None, help="Repo path (default: cwd)")

    p_restore = ws_sub.add_parser("restore", help="Recover a snapshot (safe by default)")
    p_restore.add_argument("ref", help="Snapshot ref or commit to recover")
    p_restore.add_argument("path", nargs="?", default=None, help="Repo path (default: cwd)")
    p_restore.add_argument(
        "--into-worktree",
        action="store_true",
        help="Write the snapshot back into the working tree (may overwrite "
        "local edits; a safety snapshot of current state is taken first).",
    )

    p_status = ws_sub.add_parser("status", help="Show uncommitted state + merge advice")
    p_status.add_argument("path", nargs="?", default=None, help="Repo path (default: cwd)")

    p_watch = ws_sub.add_parser("watch", help="Run the background snapshot daemon (foreground)")
    p_watch.add_argument("paths", nargs="*", help="Repo path(s) to watch (default: cwd)")
    p_watch.add_argument(
        "--interval", type=float, default=300, help="Seconds between snapshots (default: 300)"
    )
    p_watch.add_argument(
        "--keep", type=int, default=50, help="Max snapshots to retain per repo (default: 50)"
    )

    workspace_parser.set_defaults(func=cmd_workspace)
