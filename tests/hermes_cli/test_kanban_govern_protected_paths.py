"""Regression tests for resolve_protected_paths schema handling.

Guards the GOV-PROTECTED gate against the two on-disk ``protected_paths``
schemas:

  * bare string globs           — ``["src/auth/**", ".env*"]``
  * ``{pattern, reason}`` maps  — the EZRA governance.yaml format

The original code coerced every entry with ``str(p)``, which turned a mapping
into its dict-repr (``"{'pattern': ...}"``) — a string that can never match a
real path, silently disabling the protected-path gate for dict-form config
(the format EZRA actually emits). These tests assert the *behavior contract*:
a real protected path resolves to its glob and is matched, regardless of which
schema the governance file uses.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from hermes_cli import kanban_govern as kg


def _write_governance(workspace: Path, body: str) -> None:
    ezra = workspace / kg.EZRA_DIRNAME
    ezra.mkdir(parents=True, exist_ok=True)
    (ezra / kg.GOVERNANCE_FILENAME).write_text(body, encoding="utf-8")


def test_resolve_protected_paths_string_schema(tmp_path):
    """A list of bare string globs resolves verbatim."""
    _write_governance(tmp_path, (
        "protected_paths:\n"
        "  - \"src/auth/**\"\n"
        "  - \".env*\"\n"
    ))
    assert kg.resolve_protected_paths(tmp_path) == ["src/auth/**", ".env*"]


def test_resolve_protected_paths_dict_schema(tmp_path):
    """A list of {pattern, reason} maps resolves to the patterns only — the
    EZRA governance.yaml format. This is the format the old str(p) coercion
    silently broke."""
    _write_governance(tmp_path, (
        "protected_paths:\n"
        "  - pattern: \"apps/api/src/modules/auth/**\"\n"
        "    reason: \"Authentication module changes are security-critical\"\n"
        "  - pattern: \".env*\"\n"
        "    reason: \"Environment files may contain secrets\"\n"
    ))
    resolved = kg.resolve_protected_paths(tmp_path)
    assert resolved == ["apps/api/src/modules/auth/**", ".env*"]
    # No dict-repr leakage — every entry is a usable glob, never "{'pattern'..."
    assert all("pattern" not in r and "{" not in r for r in resolved)


def test_resolve_protected_paths_mixed_and_empty_entries(tmp_path):
    """Mixed string + dict entries both resolve; entries with no usable
    pattern are dropped rather than emitted as empty/garbage globs."""
    _write_governance(tmp_path, (
        "protected_paths:\n"
        "  - \"docker/**\"\n"
        "  - pattern: \"infrastructure/terraform/**\"\n"
        "    reason: \"infra approval required\"\n"
        "  - reason: \"orphan entry with no pattern\"\n"
    ))
    resolved = kg.resolve_protected_paths(tmp_path)
    assert resolved == ["docker/**", "infrastructure/terraform/**"]


def test_dict_schema_protected_write_is_caught_end_to_end(tmp_path):
    """The behavior that actually matters: a write to a protected path declared
    in the dict schema produces a GOV-PROTECTED finding (no ACTIVE decision
    authorises it). Before the fix this returned a clean 'allow' because the
    pattern never matched.

    Posture matters for the *decision* (autonomy-v2 semantics): GOV-PROTECTED
    is not an EMERGENCY code, so under the default ``emergency_only=True`` the
    gate WARNS (guides the autonomous build) rather than hard-blocking. Setting
    ``emergency_only: false`` restores a hard block at gate level. We assert
    both — the finding must fire either way; that's the bug under test."""
    # --- default posture (emergency_only=True): finding fires, decision warns ---
    _write_governance(tmp_path, (
        "protected_paths:\n"
        "  - pattern: \"apps/api/src/modules/auth/**\"\n"
        "    reason: \"security-critical\"\n"
        "oversight:\n"
        "  level: gate\n"
    ))
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    # The gate resolves the build root by walking task_links; give the bare
    # in-memory DB that table so _resolve_root_id doesn't fail-open to 'allow'.
    # Empty table => task is its own root (no parents), which is what we want.
    conn.execute("CREATE TABLE task_links (parent_id TEXT, child_id TEXT)")

    def _check(path):
        return kg.check_tool_call(
            conn, "t_test", "write_file",
            {"path": path, "content": "export const x = 1\n"},
            workspace_override=str(tmp_path),
        )

    res = _check("apps/api/src/modules/auth/login.ts")
    codes = [f["code"] for f in res["findings"]]
    assert "GOV-PROTECTED" in codes, f"protected write not caught; findings={codes}"
    # Default emergency_only posture: a non-emergency GOV finding guides (warn),
    # it does not deadlock the autonomous build.
    assert res["decision"] == "warn"

    # A non-protected path under the same governance is clean.
    clean = _check("apps/web/src/index.ts")
    assert clean["decision"] == "allow"
    assert clean["findings"] == []

    # --- emergency_only=false: same protected write now HARD-BLOCKS at gate ---
    _write_governance(tmp_path, (
        "protected_paths:\n"
        "  - pattern: \"apps/api/src/modules/auth/**\"\n"
        "    reason: \"security-critical\"\n"
        "oversight:\n"
        "  level: gate\n"
        "emergency_only: false\n"
    ))
    blocked = _check("apps/api/src/modules/auth/login.ts")
    assert "GOV-PROTECTED" in [f["code"] for f in blocked["findings"]]
    assert blocked["decision"] == "block"
