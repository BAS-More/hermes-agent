#!/usr/bin/env node
'use strict';

/**
 * ezra_shim.js — adapter that lets EZRA's real PreToolUse hooks
 * (ezra-oversight.js, ezra-guard.js from BAS-More/ezra-claude-code) run as a
 * Hermes `pre_tool_call` shell-hook, lighting up the full Hybrid.
 *
 * WHY A SHIM: three contract mismatches make ezra-oversight.js a silent no-op
 * on a raw Hermes payload (verified empirically):
 *
 *   1. TOOL NAME — EZRA gates only tools matching /Write|Edit|MultiEdit/i.
 *      Hermes emits `write_file` / `patch` / `str_replace_editor`. Unmapped =>
 *      EZRA exits 0 immediately (no check).
 *   2. cwd / .ezra — EZRA bails unless `cwd` contains a `.ezra/` project dir
 *      (its standards/security/governance settings live there). A Hermes
 *      worker's cwd is its worktree, which usually has no `.ezra/`. The native
 *      governor (kanban_govern) already seeds `.ezra/` in the BUILD ROOT
 *      workspace — so the shim points EZRA's cwd there (via $EZRA_PROJECT_DIR,
 *      set by the wiring) or falls back to the payload cwd.
 *   3. OUTPUT SHAPE — EZRA emits
 *      `{hookSpecificOutput:{permissionDecision:'deny',permissionDecisionReason}}`.
 *      Hermes wants `{"decision":"block","reason":...}` (Claude-Code-style,
 *      which shell_hooks._parse_response translates) or the canonical
 *      `{"action":"block","message":...}`. The shim maps deny -> block.
 *
 * DISCIPLINE (matches the native governor + security-guidance):
 *   - FAIL-OPEN: any error, timeout, or missing EZRA repo => emit nothing
 *     (allow). The shim must never wedge a worker.
 *   - READ-ONLY: it only reads the payload + runs EZRA; never mutates state.
 *   - Opt-out: $FACTORY_GOVERNOR_EZRA_DISABLE=1 makes it a no-op.
 *
 * COMPOSITION: this runs ALONGSIDE the native factory-governor plugin. The
 * native GOV-PROTECTED gate and EZRA's SEC/STD checks are complementary — both
 * fire on a write; the first `block` wins (Hermes `get_pre_tool_call_block_message`
 * returns the first block directive). So you get GOV (native) + SEC/STD (EZRA).
 *
 * WIRE (per profile config.yaml, opt-in — NOT enabled by default):
 *   hooks:
 *     - event: pre_tool_call
 *       matcher: "write_file|patch|str_replace_editor|edit_file"
 *       command: "node <engine>/plugins/factory-governor/ezra_shim.js"
 *       timeout: 10
 *   (env EZRA_HOOK / EZRA_PROJECT_DIR resolved below; see defaults.)
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const MAX_STDIN = 1024 * 1024; // 1 MB, same cap EZRA uses

function allowAndExit() {
  // Emit nothing — Hermes treats empty/non-matching stdout as "no directive".
  process.exit(0);
}

function disabled() {
  const v = (process.env.FACTORY_GOVERNOR_EZRA_DISABLE || '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

// Map a Hermes tool name to the Write/Edit verb EZRA gates on. Anything that
// writes file content maps to "Write"; unknown tools return null (skip).
function ezraToolName(hermesTool) {
  if (!hermesTool || typeof hermesTool !== 'string') return null;
  const t = hermesTool.toLowerCase();
  if (t === 'write_file' || t === 'create_file') return 'Write';
  if (t === 'patch' || t === 'edit_file' || t === 'str_replace_editor' ||
      t === 'apply_patch' || t === 'multiedit') return 'Edit';
  // skill_manage carries file_content under a different key; treat as Write.
  if (t === 'skill_manage') return 'Write';
  return null;
}

// Resolve the EZRA hook script to run. Default: ezra-oversight.js in the
// installed EZRA repo. Override with $EZRA_HOOK (absolute path).
function resolveEzraHook() {
  const override = process.env.EZRA_HOOK;
  if (override && fs.existsSync(override)) return override;
  const candidates = [
    'C:\\Dev\\ezra-claude-code\\hooks\\ezra-oversight.js',
    path.join(process.env.USERPROFILE || process.env.HOME || '', 'Dev', 'ezra-claude-code', 'hooks', 'ezra-oversight.js'),
    path.join(process.env.HOME || '', '.claude', 'hooks', 'ezra-oversight.js'),
  ];
  for (const c of candidates) {
    try { if (c && fs.existsSync(c)) return c; } catch { /* ignore */ }
  }
  return null;
}

// Resolve the dir EZRA should treat as the project root (must contain .ezra/).
// Priority: $EZRA_PROJECT_DIR (set by the wiring to the build root workspace
// the native governor seeds) -> $HERMES_KANBAN_WORKSPACE -> payload cwd.
function resolveProjectDir(payloadCwd) {
  const candidates = [
    process.env.EZRA_PROJECT_DIR,
    process.env.HERMES_KANBAN_WORKSPACE,
    payloadCwd,
  ];
  for (const c of candidates) {
    try {
      if (c && fs.existsSync(path.join(c, '.ezra'))) return c;
    } catch { /* ignore */ }
  }
  // No .ezra anywhere — EZRA would no-op. Return the first existing dir so the
  // subprocess still runs cleanly (and exits 0); null means "skip entirely".
  for (const c of candidates) {
    try { if (c && fs.existsSync(c)) return c; } catch { /* ignore */ }
  }
  return null;
}

function main(rawInput) {
  if (disabled()) return allowAndExit();

  let payload;
  try {
    payload = JSON.parse(rawInput);
  } catch {
    return allowAndExit(); // unparseable => allow
  }

  const ezraTool = ezraToolName(payload.tool_name);
  if (!ezraTool) return allowAndExit(); // not a write/edit => nothing to check

  const ti = payload.tool_input && typeof payload.tool_input === 'object'
    ? payload.tool_input : {};
  const filePath = ti.file_path || ti.path || '';
  const content = ti.content || ti.new_string || ti.file_content || ti.patch || '';
  if (!filePath || !content) return allowAndExit();

  const hook = resolveEzraHook();
  if (!hook) return allowAndExit(); // EZRA not installed => allow (Hybrid off)

  const projectDir = resolveProjectDir(payload.cwd || process.cwd());
  if (!projectDir) return allowAndExit();

  // Re-shape the payload into the Claude-Code envelope EZRA expects: a Write/Edit
  // tool_name, file_path + content in tool_input, and cwd = the .ezra project.
  const ezraEvent = {
    hook_event_name: 'PreToolUse',
    tool_name: ezraTool,
    tool_input: { file_path: filePath, content: content },
    session_id: payload.session_id || '',
    cwd: projectDir,
  };

  let res;
  try {
    res = spawnSync(process.execPath, [hook], {
      input: JSON.stringify(ezraEvent),
      encoding: 'utf8',
      timeout: 8000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    });
  } catch {
    return allowAndExit(); // spawn failure => allow
  }

  if (!res || res.status === null /* timed out / killed */) return allowAndExit();

  const out = (res.stdout || '').trim();
  if (!out) return allowAndExit(); // EZRA said nothing => allow

  let ezraOut;
  try {
    ezraOut = JSON.parse(out);
  } catch {
    return allowAndExit();
  }

  const decision = ezraOut?.hookSpecificOutput?.permissionDecision;
  const reason = ezraOut?.hookSpecificOutput?.permissionDecisionReason || 'EZRA oversight blocked this write';

  if (decision === 'deny') {
    // Map to Hermes block. Use Claude-Code shape; shell_hooks normalises it.
    process.stdout.write(JSON.stringify({ decision: 'block', reason: reason }));
    return process.exit(0);
  }

  // allow (incl. monitor/warn levels — EZRA self-logs those to .ezra/oversight)
  return allowAndExit();
}

if (require.main === module) {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => {
    input += chunk;
    if (input.length > MAX_STDIN) { allowAndExit(); }
  });
  process.stdin.on('end', () => {
    try { main(input); }
    catch { allowAndExit(); } // belt-and-suspenders fail-open
  });
}

module.exports = { ezraToolName, resolveEzraHook, resolveProjectDir };
