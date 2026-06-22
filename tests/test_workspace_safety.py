"""Tests for the workspace-restore + git-safety-snapshot feature.

Covers:
  * SessionDB.save/load/clear_workspace_state (pointers-only restore store)
  * agent.workspace_safety snapshot engine — the safety invariant that a
    snapshot NEVER mutates the working tree / index / HEAD, and that
    gitignored files (secrets) are excluded.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from hermes_state import SessionDB
from agent import workspace_safety as ws


# ---------------------------------------------------------------------------
# Workspace restore store (SessionDB)
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    return SessionDB(tmp_path / "t.db")


def test_workspace_state_round_trip(db):
    state = {"tabs": [{"session_id": "s1", "model": "opus", "brain_x2_mode": "fast"}],
             "active_tab": 0}
    db.save_workspace_state("desktop", state)
    got = db.load_workspace_state("desktop")
    assert got["active_tab"] == 0
    assert got["tabs"][0]["session_id"] == "s1"
    # version + timestamp surfaced for compat checks
    assert got["_state_version"] == SessionDB.WORKSPACE_STATE_VERSION
    assert isinstance(got["_saved_at"], float)


def test_workspace_state_per_surface_isolation(db):
    db.save_workspace_state("desktop", {"a": 1})
    db.save_workspace_state("cli", {"b": 2})
    assert db.load_workspace_state("desktop")["a"] == 1
    assert db.load_workspace_state("cli")["b"] == 2


def test_workspace_state_missing_returns_none(db):
    assert db.load_workspace_state("never-saved") is None


def test_workspace_state_corrupt_blob_degrades_to_none(db):
    # A corrupt snapshot must degrade to "start fresh", never crash restore.
    db.set_meta("workspace_state:cli", "not valid json {{{")
    assert db.load_workspace_state("cli") is None


def test_workspace_state_forward_incompatible_ignored(db):
    # Snapshot written by a newer Hermes: ignore rather than mis-parse.
    db.set_meta(
        "workspace_state:tui",
        json.dumps({"state_version": 999, "state": {"x": 1}}),
    )
    assert db.load_workspace_state("tui") is None


def test_workspace_state_clear(db):
    db.save_workspace_state("desktop", {"a": 1})
    db.clear_workspace_state("desktop")
    assert db.load_workspace_state("desktop") is None


def test_workspace_state_empty_surface_rejected(db):
    with pytest.raises(ValueError):
        db.save_workspace_state("", {"a": 1})
    assert db.load_workspace_state("") is None


# ---------------------------------------------------------------------------
# Git safety snapshot engine
# ---------------------------------------------------------------------------

def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def dirty_repo(tmp_path):
    """A git repo with: a .gitignore, a committed file, then uncommitted
    modifications + an untracked file + a gitignored secret."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / ".gitignore").write_text(".env\nsecret.key\n")
    (repo / "tracked.txt").write_text("v1\n")
    _git(repo, "add", ".gitignore", "tracked.txt")
    _git(repo, "commit", "-m", "init")
    # dirty state
    (repo / "tracked.txt").write_text("v2-MODIFIED\n")
    (repo / "newfile.txt").write_text("untracked\n")
    (repo / ".env").write_text("API_KEY=***\n")              # gitignored
    (repo / "secret.key").write_text("PRIVATE\n")            # gitignored
    return repo


def test_has_uncommitted_changes(dirty_repo):
    assert ws.has_uncommitted_changes(str(dirty_repo)) is True


def test_snapshot_does_not_mutate_working_tree(dirty_repo):
    before_status = _git(dirty_repo, "status", "--porcelain", "--untracked-files=all")
    before_head = _git(dirty_repo, "rev-parse", "HEAD")
    before_content = (dirty_repo / "tracked.txt").read_text()

    res = ws.create_snapshot(str(dirty_repo))
    assert res is not None
    assert res.ref.startswith(ws.SNAPSHOT_REF_NAMESPACE)

    # The safety invariant: nothing the user sees changed.
    assert _git(dirty_repo, "status", "--porcelain", "--untracked-files=all") == before_status
    assert _git(dirty_repo, "rev-parse", "HEAD") == before_head
    assert (dirty_repo / "tracked.txt").read_text() == before_content


def test_snapshot_excludes_gitignored_secrets(dirty_repo):
    res = ws.create_snapshot(str(dirty_repo))
    assert res is not None
    tree = _git(dirty_repo, "ls-tree", "-r", "--name-only", res.commit).split("\n")
    assert ".env" not in tree
    assert "secret.key" not in tree
    # but legitimate files ARE captured
    assert "tracked.txt" in tree
    assert "newfile.txt" in tree


def test_snapshot_clean_repo_returns_none(tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("x\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-m", "init")
    assert ws.create_snapshot(str(repo)) is None


def test_list_and_restore_snapshot_safe(dirty_repo):
    res = ws.create_snapshot(str(dirty_repo))
    snaps = ws.list_snapshots(str(dirty_repo))
    assert any(s["commit"] == res.commit for s in snaps)
    # safe restore is non-destructive — returns instructions, no worktree write
    before = (dirty_repo / "tracked.txt").read_text()
    msg = ws.restore_snapshot(str(dirty_repo), res.ref, into_worktree=False)
    assert res.commit[:12] in msg
    assert (dirty_repo / "tracked.txt").read_text() == before


def test_prune_snapshots_keeps_newest(dirty_repo):
    # create several snapshots (each tweak keeps the tree dirty)
    for i in range(4):
        (dirty_repo / "tracked.txt").write_text(f"rev{i}\n")
        ws.create_snapshot(str(dirty_repo))
    assert len(ws.list_snapshots(str(dirty_repo))) >= 4
    deleted = ws.prune_snapshots(str(dirty_repo), keep=2)
    assert deleted >= 1
    assert len(ws.list_snapshots(str(dirty_repo))) == 2


def test_not_a_git_repo(tmp_path):
    assert ws.is_git_repo(str(tmp_path)) is False
    with pytest.raises(ws.GitError):
        ws.create_snapshot(str(tmp_path))
