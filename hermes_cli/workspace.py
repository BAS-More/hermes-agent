"""``hermes workspace`` — git safety snapshots so you never lose uncommitted work.

Implements the safe subset of "auto-commit/auto-merge in the background even
after close" (per the LLM Council synthesis): SNAPSHOT uncommitted work to a
dedicated safety ref without ever touching HEAD, the index, branches, or the
working tree. No auto-commit to real branches, no auto-merge.

Subcommands:
  snapshot [PATH]      Take one safety snapshot now (default: cwd).
  list [PATH]          List existing safety snapshots.
  restore REF [PATH]   Show how to recover a snapshot (safe, non-destructive).
                       Add --into-worktree to actually write it back (gated).
  watch [PATH ...]     Run the background snapshot daemon in the foreground
                       (Ctrl-C to stop). Use a process manager / `&` to detach.
  status [PATH]        Show uncommitted state + any merge advice.
"""
from __future__ import annotations

import os
import sys
import time
from typing import List


def _resolve_repo(path: str | None) -> str:
    return os.path.abspath(path) if path else os.getcwd()


def workspace_command(args) -> None:
    from agent import workspace_safety as ws

    action = getattr(args, "workspace_action", None)

    if action in (None, ""):
        print(
            "usage: hermes workspace <subcommand>\n\n"
            "subcommands:\n"
            "  snapshot [PATH]      Take one safety snapshot now\n"
            "  list [PATH]          List existing safety snapshots\n"
            "  restore REF [PATH]   Recover a snapshot (safe by default)\n"
            "  watch [PATH ...]     Run the background snapshot daemon\n"
            "  status [PATH]        Show uncommitted state + merge advice\n"
        )
        return

    if action == "snapshot":
        repo = _resolve_repo(getattr(args, "path", None))
        if not ws.is_git_repo(repo):
            print(f"✗ Not a git repo: {repo}")
            sys.exit(1)
        try:
            res = ws.create_snapshot(repo)
        except ws.GitError as exc:
            print(f"✗ Snapshot failed: {exc}")
            sys.exit(1)
        if res is None:
            print("✓ Nothing to snapshot — working tree is clean.")
        else:
            print(
                f"✓ Snapshot saved: {res.ref}\n"
                f"  {res.files} file(s) from branch '{res.branch}' "
                f"(commit {res.commit[:12]}).\n"
                f"  Your working tree, index, and branches are unchanged."
            )
        return

    if action == "list":
        repo = _resolve_repo(getattr(args, "path", None))
        snaps = ws.list_snapshots(repo)
        if not snaps:
            print("No safety snapshots yet.")
            return
        print(f"Safety snapshots for {repo} (newest first):\n")
        for s in snaps:
            print(f"  {s['date']}  {s['commit'][:12]}  {s['ref']}")
        return

    if action == "restore":
        repo = _resolve_repo(getattr(args, "path", None))
        ref = getattr(args, "ref", None)
        if not ref:
            print("✗ restore requires a snapshot REF or commit.")
            sys.exit(1)
        into = bool(getattr(args, "into_worktree", False))
        if into:
            print(
                "⚠ This will write the snapshot into your working tree and may "
                "overwrite uncommitted local edits.\n"
                "  A snapshot of the CURRENT state is taken first for safety."
            )
            try:
                ws.create_snapshot(repo)  # safety-net before destructive restore
                msg = ws.restore_snapshot(repo, ref, into_worktree=True)
            except ws.GitError as exc:
                print(f"✗ Restore failed: {exc}")
                sys.exit(1)
            print(f"✓ {msg}")
        else:
            try:
                msg = ws.restore_snapshot(repo, ref, into_worktree=False)
            except ws.GitError as exc:
                print(f"✗ {exc}")
                sys.exit(1)
            print(msg)
        return

    if action == "status":
        repo = _resolve_repo(getattr(args, "path", None))
        if not ws.is_git_repo(repo):
            print(f"✗ Not a git repo: {repo}")
            sys.exit(1)
        dirty = ws.has_uncommitted_changes(repo)
        print(f"Repo: {ws.repo_toplevel(repo) or repo}")
        print(f"Uncommitted changes: {'yes' if dirty else 'no'}")
        snaps = ws.list_snapshots(repo)
        print(f"Safety snapshots: {len(snaps)}")
        advice = ws.detect_merge_advice(repo)
        if advice:
            print(f"\nMerge advice (not auto-applied):\n  {advice}")
        return

    if action == "watch":
        paths: List[str] = getattr(args, "paths", None) or [os.getcwd()]
        repos = [os.path.abspath(p) for p in paths]
        valid = [r for r in repos if ws.is_git_repo(r)]
        if not valid:
            print("✗ No valid git repos to watch.")
            sys.exit(1)
        interval = float(getattr(args, "interval", 300) or 300)
        keep = int(getattr(args, "keep", 50) or 50)

        def _report(res: ws.SnapshotResult) -> None:
            print(
                f"[{time.strftime('%H:%M:%S')}] snapshot {os.path.basename(res.repo)} "
                f"-> {res.ref} ({res.files} files)"
            )

        daemon = ws.WorkspaceSafetyDaemon(
            repos=valid, interval=interval, keep=keep, on_snapshot=_report
        )
        print(
            f"Watching {len(valid)} repo(s), snapshot every {interval:.0f}s. "
            f"Ctrl-C to stop (a final snapshot is taken on exit)."
        )
        daemon.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping (final snapshot)...")
            daemon.stop()
        return

    print(f"Unknown workspace subcommand: {action}")
    sys.exit(1)
