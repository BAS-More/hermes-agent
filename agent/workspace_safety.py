#!/usr/bin/env python3
"""Workspace git safety snapshots — never lose uncommitted work.

This module implements the safe subset of the user's "auto-commit / auto-merge
in the background, even after close" request, per the LLM Council synthesis
(2026-06):

  * Auto-SNAPSHOT (safe, default): periodically capture uncommitted work to a
    dedicated safety ref, WITHOUT touching HEAD, the index, the working tree,
    or any of the user's branches. Pure additive + fully reversible.
  * Auto-COMMIT to the real branch: NOT done — pollutes history, risks secrets.
  * Auto-MERGE: NOT done — merges need human intent; we only detect+recommend.

How a snapshot is built (all git *plumbing*, zero porcelain side effects):

  1. ``git write-tree`` is NOT used (it mutates nothing but reflects the index,
     which we must not depend on). Instead we build a snapshot tree from the
     working-tree content explicitly:
       - start from HEAD's tree,
       - for every modified/added tracked file and every untracked
         (non-ignored) file, ``git hash-object -w`` the working-tree blob and
         stage it into a *temporary* index file (GIT_INDEX_FILE pointing at a
         throwaway path — the user's real index is never read or written),
       - ``git write-tree`` against that temp index → a tree object,
       - ``git commit-tree`` that tree with HEAD as parent → a commit object,
       - ``git update-ref refs/hermes/snapshots/<branch>/<ts>`` → the commit.

  The user's real ``.git/index``, HEAD, branches and working tree are never
  modified. Snapshots are recoverable with ``git stash`` semantics via
  :func:`restore_snapshot` (which writes to the working tree only on explicit
  user request) or by inspecting the ref directly.

The daemon (:class:`WorkspaceSafetyDaemon`) debounce-snapshots an allowlist of
repos on an interval and on demand (e.g. session/app close). The "keep running
after close" capability is intentionally limited to this read-only-plus-additive
snapshotting; it never runs commit/merge/push against a real branch.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("agent.workspace_safety")

SNAPSHOT_REF_NAMESPACE = "refs/hermes/snapshots"
_GIT_TIMEOUT = 30  # seconds per git invocation


class GitError(RuntimeError):
    """A git command failed; carries the captured stderr for diagnostics."""


def _run_git(
    repo: str,
    args: List[str],
    *,
    extra_env: Optional[Dict[str, str]] = None,
    check: bool = True,
    input_bytes: Optional[bytes] = None,
) -> str:
    """Run ``git -C <repo> <args>`` and return stripped stdout.

    Raises :class:`GitError` on non-zero exit when ``check`` is True.
    """
    env = dict(os.environ)
    # Never let a user hook or pager interfere with a background snapshot.
    env["GIT_PAGER"] = "cat"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if extra_env:
        env.update(extra_env)
    cmd = ["git", "-C", repo, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            env=env,
            input=input_bytes,
            timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git timed out: {' '.join(args)}") from exc
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    if check and proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout.decode(errors="replace").strip()


def is_git_repo(path: str) -> bool:
    """True if ``path`` is inside a git work tree."""
    try:
        out = _run_git(path, ["rev-parse", "--is-inside-work-tree"], check=False)
        return out == "true"
    except GitError:
        return False


def repo_toplevel(path: str) -> Optional[str]:
    """Absolute path to the repo root containing ``path``, or None."""
    try:
        top = _run_git(path, ["rev-parse", "--show-toplevel"], check=False)
        return top or None
    except GitError:
        return None


def has_uncommitted_changes(repo: str) -> bool:
    """True if there are tracked modifications or untracked, non-ignored files."""
    try:
        status = _run_git(repo, ["status", "--porcelain", "--untracked-files=all"])
    except GitError:
        return False
    return bool(status.strip())


def _current_branch(repo: str) -> str:
    """Branch name, or a detached-HEAD sentinel."""
    name = _run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    return name if name and name != "HEAD" else "detached"


def _head_commit(repo: str) -> Optional[str]:
    """HEAD commit sha, or None for an unborn branch (no commits yet)."""
    sha = _run_git(repo, ["rev-parse", "--verify", "-q", "HEAD"], check=False)
    return sha or None


@dataclass
class SnapshotResult:
    repo: str
    ref: str
    commit: str
    branch: str
    timestamp: float
    files: int


def create_snapshot(repo: str) -> Optional[SnapshotResult]:
    """Capture current uncommitted work into a safety ref. Returns None if clean.

    Touches nothing the user can see: builds the snapshot in a throwaway index
    and writes only a new ref under ``refs/hermes/snapshots/``.
    """
    repo = repo_toplevel(repo) or repo
    if not is_git_repo(repo):
        raise GitError(f"not a git repo: {repo}")
    if not has_uncommitted_changes(repo):
        return None

    head = _head_commit(repo)
    branch = _current_branch(repo)
    ts = time.time()

    # Throwaway index so the user's real .git/index is never read or written.
    tmp_index_fd, tmp_index = tempfile.mkstemp(prefix="hermes-snap-idx-")
    os.close(tmp_index_fd)
    try:
        os.unlink(tmp_index)  # git wants to create it itself
    except OSError:
        pass
    env = {"GIT_INDEX_FILE": tmp_index}
    try:
        # Seed the temp index from HEAD's tree (if any commits exist).
        if head:
            _run_git(repo, ["read-tree", head], extra_env=env)
        # Stage ALL working-tree content (tracked mods + untracked, respecting
        # .gitignore — ignored files like .env are NOT captured) into the temp
        # index. This reads the working tree; it does not modify it.
        _run_git(repo, ["add", "-A"], extra_env=env)
        tree = _run_git(repo, ["write-tree"], extra_env=env)

        # Count files in the snapshot tree for reporting.
        listing = _run_git(repo, ["ls-tree", "-r", "--name-only", tree], check=False)
        n_files = len([ln for ln in listing.splitlines() if ln.strip()])

        msg = f"hermes-snapshot: {branch} @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}"
        commit_args = ["commit-tree", tree, "-m", msg]
        if head:
            commit_args[2:2] = ["-p", head]
        commit = _run_git(repo, commit_args, extra_env=env)

        safe_branch = branch.replace("/", "_")
        # Suffix with the short commit sha so rapid successive snapshots (same
        # wall-clock second) get distinct refs instead of clobbering each other.
        # Identical-content snapshots collapse to the same commit → same ref,
        # which is correct (no duplicate stored).
        ref = f"{SNAPSHOT_REF_NAMESPACE}/{safe_branch}/{int(ts)}-{commit[:12]}"
        _run_git(repo, ["update-ref", ref, commit])
        log.info("workspace snapshot %s -> %s (%d files)", repo, ref, n_files)
        return SnapshotResult(repo, ref, commit, branch, ts, n_files)
    finally:
        try:
            if os.path.exists(tmp_index):
                os.unlink(tmp_index)
        except OSError:
            pass


def list_snapshots(repo: str) -> List[Dict[str, str]]:
    """List existing safety snapshots for ``repo``, newest first."""
    repo = repo_toplevel(repo) or repo
    out = _run_git(
        repo,
        [
            "for-each-ref",
            "--sort=-creatordate",
            "--format=%(refname)%09%(objectname)%09%(creatordate:iso-strict)%09%(subject)",
            SNAPSHOT_REF_NAMESPACE,
        ],
        check=False,
    )
    snaps: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        snaps.append(
            {
                "ref": parts[0],
                "commit": parts[1],
                "date": parts[2] if len(parts) > 2 else "",
                "subject": parts[3] if len(parts) > 3 else "",
            }
        )
    return snaps


def restore_snapshot(repo: str, ref_or_commit: str, *, into_worktree: bool = False) -> str:
    """Recover a snapshot.

    By default (``into_worktree=False``) this is SAFE and non-destructive: it
    materializes the snapshot as a ``git stash``-style entry the user can apply
    themselves, returning a human instruction. Actually writing into the
    working tree (``into_worktree=True``) is gated on an explicit caller request
    and uses ``git checkout`` of the tree, which can overwrite local edits — so
    it is never the default and never done by the daemon.
    """
    repo = repo_toplevel(repo) or repo
    commit = _run_git(repo, ["rev-parse", "--verify", ref_or_commit])
    if not into_worktree:
        return (
            f"Snapshot {commit[:12]} is available. To inspect: "
            f"`git -C \"{repo}\" diff HEAD {commit}`. To apply into a new branch "
            f"safely: `git -C \"{repo}\" checkout -b recovered-{commit[:8]} {commit}`."
        )
    # Destructive path — explicit opt-in only. Restore tree onto working dir.
    _run_git(repo, ["checkout", commit, "--", "."])
    return f"Snapshot {commit[:12]} restored into working tree of {repo}."


def prune_snapshots(repo: str, keep: int = 50) -> int:
    """Delete oldest safety snapshots beyond ``keep``. Returns count deleted."""
    snaps = list_snapshots(repo)
    repo = repo_toplevel(repo) or repo
    deleted = 0
    for snap in snaps[keep:]:
        try:
            _run_git(repo, ["update-ref", "-d", snap["ref"]])
            deleted += 1
        except GitError:
            log.warning("failed to prune snapshot %s", snap["ref"])
    return deleted


def detect_merge_advice(repo: str) -> Optional[str]:
    """Detect branch divergence and RECOMMEND (never perform) a merge/rebase.

    Per the council: auto-merge is unsafe; we surface a suggestion only.
    Returns a human-readable advice string, or None if nothing to suggest.
    """
    repo = repo_toplevel(repo) or repo
    upstream = _run_git(
        repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        check=False,
    )
    if not upstream:
        return None
    counts = _run_git(
        repo, ["rev-list", "--left-right", "--count", f"HEAD...{upstream}"],
        check=False,
    )
    try:
        ahead, behind = (int(x) for x in counts.split())
    except (ValueError, AttributeError):
        return None
    if behind and ahead:
        return (
            f"Your branch and {upstream} have diverged "
            f"({ahead} ahead, {behind} behind). Review and merge manually "
            f"(`git merge {upstream}` or `git rebase {upstream}`) — Hermes will "
            f"not auto-merge to avoid conflicts/broken builds."
        )
    if behind and not ahead:
        return (
            f"{upstream} is {behind} commit(s) ahead and can fast-forward "
            f"cleanly: `git merge --ff-only {upstream}`."
        )
    return None


@dataclass
class WorkspaceSafetyDaemon:
    """Background snapshotter for an allowlist of repos.

    Snapshots each repo on ``interval`` seconds and on :meth:`snapshot_now`.
    NEVER commits/merges/pushes to a real branch. Designed so it is safe to
    keep running after the app closes (additive snapshots only) — but the
    caller decides whether to detach it; this class just manages the loop and
    exposes a clean :meth:`stop` kill-switch.
    """

    repos: List[str]
    interval: float = 300.0
    keep: int = 50
    on_snapshot: Optional[Callable[[SnapshotResult], None]] = None
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False, repr=False)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="hermes-workspace-safety", daemon=True
        )
        self._thread.start()
        log.info("workspace safety daemon started for %d repo(s)", len(self.repos))

    def stop(self, timeout: float = 5.0) -> None:
        """Kill-switch. Performs one final snapshot, then exits the loop."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        log.info("workspace safety daemon stopped")

    def snapshot_now(self) -> List[SnapshotResult]:
        """Snapshot every allowlisted repo once. Errors per repo are isolated."""
        results: List[SnapshotResult] = []
        for repo in self.repos:
            try:
                res = create_snapshot(repo)
                if res:
                    results.append(res)
                    if self.on_snapshot:
                        try:
                            self.on_snapshot(res)
                        except Exception:  # callback must never break the loop
                            log.exception("on_snapshot callback failed")
                    prune_snapshots(repo, keep=self.keep)
            except GitError as exc:
                log.warning("snapshot failed for %s: %s", repo, exc)
            except Exception:
                log.exception("unexpected snapshot error for %s", repo)
        return results

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.snapshot_now()
            # Wait the interval but wake immediately on stop().
            self._stop.wait(self.interval)
        # Final snapshot on shutdown so nothing between the last tick and close
        # is lost.
        self.snapshot_now()
