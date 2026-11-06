'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, readdirSafe, statSafe, findProjectDirs } = require('../utils/fs-safe');
const logger = require('../utils/logger');
const { scanHidden, sanitizeExcerpt } = require('../utils/text');

const SCANNER_ID = 'ai-instructions';
const MAX_FILE_BYTES = 64 * 1024;
const MAX_DIR_FILES = 200;

// kind: 'text' (default) | 'claude-settings' | 'vscode-tasks'; dir entries list files with `exts`.
const PROJECT_FILES = [
  { file: '.cursorrules', tool: 'Cursor' },
  { file: '.cursorignore', tool: 'Cursor' },
  { file: '.cursor/rules', tool: 'Cursor', dir: true, exts: ['.mdc', '.md'] },
  { file: '.windsurfrules', tool: 'Windsurf' },
  { file: '.windsurf/rules', tool: 'Windsurf', dir: true, exts: ['.md'] },
  { file: '.github/copilot-instructions.md', tool: 'GitHub Copilot' },
  { file: '.github/instructions', tool: 'GitHub Copilot', dir: true, exts: ['.md'] },
  { file: '.github/copilot-setup-steps.yml', tool: 'GitHub Copilot' },
  { file: '.copilot-codegeneration-instructions.md', tool: 'GitHub Copilot' },
  { file: '.claude/settings.json', tool: 'Claude Code', kind: 'claude-settings' },
  { file: '.claude/settings.local.json', tool: 'Claude Code', kind: 'claude-settings' },
  { file: '.claude/commands', tool: 'Claude Code', dir: true, exts: ['.md'] },
  { file: '.claude/agents', tool: 'Claude Code', dir: true, exts: ['.md'] },
  { file: 'CLAUDE.md', tool: 'Claude Code' },
  { file: 'claude.md', tool: 'Claude Code' },
  { file: '.mcp.json', tool: 'MCP (project)' },
  { file: '.gemini/settings.json', tool: 'Gemini CLI' },
  { file: 'GEMINI.md', tool: 'Gemini CLI' },
  { file: '.aider.conf.yml', tool: 'Aider' },
  { file: '.aider.model.settings.yml', tool: 'Aider' },
  { file: '.continue/config.json', tool: 'Continue' },
  { file: '.codeiumrc', tool: 'Codeium' },
  { file: '.sourcegraph/cody.json', tool: 'Cody' },
  { file: '.clinerules', tool: 'Cline' },
  { file: '.roomodes', tool: 'Roo Code' },
  { file: '.roorules', tool: 'Roo Code' },
  { file: 'codex.md', tool: 'Codex' },
  { file: 'AGENTS.md', tool: 'Codex' },
  { file: '.vscode/tasks.json', tool: 'VS Code', kind: 'vscode-tasks' },
];

// Per-user configuration, read from each discovered home directory.
const USER_FILES = [
  { file: '.claude/settings.json', tool: 'Claude Code', kind: 'claude-settings' },
  { file: '.claude/CLAUDE.md', tool: 'Claude Code' },
  { file: '.claude/commands', tool: 'Claude Code', dir: true, exts: ['.md'] },
  { file: '.claude/agents', tool: 'Claude Code', dir: true, exts: ['.md'] },
  { file: '.gemini/settings.json', tool: 'Gemini CLI' },
  { file: '.gemini/GEMINI.md', tool: 'Gemini CLI' },
  { file: '.codex/AGENTS.md', tool: 'Codex' },
];

// Natural-language files produce false positives easily, so only unambiguous
// execution primitives are critical; developer-doc staples are medium at most.
// All gaps are bounded so matching stays linear.
const SUSPICIOUS_PATTERNS = [
  { pattern: /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts?)\b/i, label: 'prompt-injection', severity: 'high' },
  { pattern: /\byou\s+are\s+now\s+[^\n.]{0,40}\b(unrestricted|jailbroken|DAN|developer\s+mode|without\s+(any\s+)?restrictions)\b/i, label: 'jailbreak-persona', severity: 'high' },
  { pattern: /\b(send|post|upload|transmit|forward|exfiltrate)\b[^\n]{0,60}(\b(secrets?|tokens?|credentials?|api[\s_-]?keys?|passwords?|private\s+keys?|env(ironment)?\s+variables)\b|\.env\b)[^\n]{0,60}https?:\/\//i, label: 'exfil-instruction', severity: 'high' },
  { pattern: /\bexfiltrat\w*|\bsteal\s+(the\s+)?(credentials|tokens|secrets|keys|passwords|cookies)\b/i, label: 'exfil-keyword', severity: 'high' },
  { pattern: /--dangerously-skip-permissions|--yolo\b|--trust-all-tools/, label: 'ai-cli-permission-bypass', severity: 'high' },
  { pattern: /\bpowershell\b[^\n]{0,200}\s-e(nc(oded(command)?)?)?\s/i, label: 'powershell-encoded', severity: 'critical' },
  { pattern: /\/dev\/tcp\/|\bnc\b[^\n]{0,200}\s-e\s/, label: 'reverse-shell', severity: 'critical' },
  { pattern: /\b(curl|wget)\b[^\n]{0,200}\|\s*(bash|sh|node|python3?)\b/, label: 'pipe-to-shell', severity: 'medium' },
  { pattern: /https?:\/\/(?!(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, label: 'public-ip-url', severity: 'medium' },
  { pattern: /~\/\.(ssh|aws|gnupg)\b|\bid_(rsa|ed25519)\b|\.aws\/credentials|\.npmrc\b|\.netrc\b/, label: 'credential-file-ref', severity: 'medium' },
  { pattern: /\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|disclose|show)\s+(this|these|that|it|anything)?\s*(to\s+)?(the\s+)?user\b/i, label: 'concealment-from-user', severity: 'medium' },
  { pattern: /\bhide\s+(this|these|the)\s+(instructions?|rules?|files?|actions?|changes?)\b/i, label: 'concealment-from-user', severity: 'medium' },
];

// projectDirs: optional [{ dir }] from the shared directory walk.
function scan(platform, opts = {}, projectDirs) {
  const dirs = projectDirs || findProjectDirs(platform.projectRoots || [], { maxDepth: opts.maxDepth || 4 });
  const findings = [];
  const inventory = [];
  const seen = new Set();
  const reportedLinks = new Set();

  const ctx = { findings, inventory, seen, reportedLinks };
  for (const { dir } of dirs) {
    for (const spec of PROJECT_FILES) inspectSpec(spec, dir, dir, ctx, 'project');
  }
  for (const home of (platform.userHomes || [])) {
    for (const spec of USER_FILES) inspectSpec(spec, home, home, ctx, 'user');
  }

  const suspiciousCount = findings.filter(f => f.severity !== 'info').length;
  if (suspiciousCount > 0) {
    logger.warn(SCANNER_ID, `Found ${suspiciousCount} suspicious AI instruction files`);
  } else {
    logger.info(SCANNER_ID, `Inventoried ${inventory.length} AI instruction files across ${dirs.length} projects (none suspicious)`);
  }

  return {
    ecosystem: SCANNER_ID,
    projects_scanned: dirs.length,
    files_found: inventory.length,
    total_findings: findings.length,
    suspicious: suspiciousCount,
    inventory,
    findings,
  };
}

// scope: 'project' (files that arrive with a repository) or 'user' (the user's own config).
function inspectSpec(spec, baseDir, trustedRoot, ctx, scope) {
  const fullPath = path.join(baseDir, spec.file);
  const st = statSafe(fullPath);
  if (!st) return;

  if (spec.dir) {
    if (!st.isDirectory()) return;
    const files = readdirSafe(fullPath).filter(f => spec.exts.some(e => f.endsWith(e))).slice(0, MAX_DIR_FILES);
    for (const f of files) inspectFile({ ...spec, dir: false }, path.join(fullPath, f), baseDir, trustedRoot, ctx, scope);
    return;
  }
  if (st.isFile()) inspectFile(spec, fullPath, baseDir, trustedRoot, ctx, scope);
}

function inspectFile(spec, filePath, project, trustedRoot, ctx, scope) {
  let real;
  try { real = fs.realpathSync.native(filePath); } catch { return; }
  const st = statSafe(real);
  if (!st || !st.isFile()) return;
  // File identity, not path: CLAUDE.md and claude.md are one file on case-insensitive filesystems.
  const identity = st.ino ? `${st.dev}:${st.ino}` : real;
  if (ctx.seen.has(identity)) return;
  const item = { path: filePath, tool: spec.tool, type: path.extname(filePath) || 'text', size: st.size, project };

  let realRoot = trustedRoot;
  try { realRoot = fs.realpathSync.native(trustedRoot); } catch { /* keep as is */ }
  if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
    // The link itself is deduplicated (CLAUDE.md and claude.md are one link on
    // case-insensitive filesystems); its target is not marked as seen.
    const link = fs.lstatSync(filePath, { throwIfNoEntry: false });
    const linkId = link && link.ino ? `${link.dev}:${link.ino}` : filePath;
    if (ctx.reportedLinks.has(linkId)) return;
    ctx.reportedLinks.add(linkId);
    item.symlink_target = real;
    ctx.inventory.push(item);
    ctx.findings.push(makeFinding(spec.tool, filePath, project, [{ label: 'symlink-outside-project', severity: 'medium' }],
      `AI instruction file for ${spec.tool} at ${filePath} is a symlink to ${real}, outside the project`));
    return;
  }
  // Marked only once read, so a link reported above never hides the real file's own scan.
  ctx.seen.add(identity);

  const content = readFileSafe(real, { maxBytes: MAX_FILE_BYTES });
  ctx.inventory.push(item);
  if (content == null) return;

  const extra = [];
  if (spec.kind === 'claude-settings') extra.push(...inspectClaudeSettings(content, item, scope));
  if (spec.kind === 'vscode-tasks') {
    const tasks = autorunTasks(content);
    if (tasks && tasks.length > 0) {
      item.autorun_tasks = tasks;
      extra.push({ label: 'autorun-on-folder-open', severity: 'medium' });
    } else {
      // Ordinary tasks.json is not an agent surface; unparseable ones are still pattern-checked.
      ctx.inventory.pop();
      if (tasks) return;
      const hits = checkText(content);
      if (hits.length === 0) return;
      ctx.inventory.push(item);
    }
  }

  const hits = [...extra, ...checkText(content)];
  if (hits.length > 0) {
    const labels = [...new Set(hits.map(h => h.label))];
    ctx.findings.push(makeFinding(spec.tool, filePath, project, hits,
      `Suspicious AI instruction file for ${spec.tool} at ${filePath}: ${labels.join(', ')}`));
  }
}

function checkText(content) {
  const { cleaned, suspicious, strong } = scanHidden(content);
  // A stray zero-width space or two often comes from copy-paste; bidi overrides,
  // tag characters, or several unexplained characters look deliberate.
  const hits = suspicious === 0 ? [] : [{ label: 'hidden-unicode', severity: strong > 0 || suspicious >= 3 ? 'high' : 'medium' }];
  for (const { pattern, label, severity } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(cleaned)) hits.push({ label, severity });
  }
  return hits;
}

/**
 * Records hook commands for visibility. Flags settings that disable permission prompts,
 * and hooks defined in a repository's own settings: those come from cloned code and run
 * automatically in the user's agent (the ChainDrop/Miasma persistence pattern).
 */
function inspectClaudeSettings(content, item, scope) {
  let data;
  try { data = JSON.parse(stripBom(content)); } catch { return []; }
  const hooks = [];
  for (const [event, groups] of Object.entries((data && data.hooks) || {})) {
    for (const g of (Array.isArray(groups) ? groups : [])) {
      for (const h of ((g && g.hooks) || [])) {
        if (h && typeof h.command === 'string') hooks.push({ event, command: sanitizeExcerpt(h.command, 200) });
      }
    }
  }
  const hits = [];
  if (hooks.length > 0) {
    item.hooks = hooks;
    if (scope === 'project') hits.push({ label: 'project-agent-hooks', severity: 'medium' });
  }
  const mode = data && data.permissions && data.permissions.defaultMode;
  if (mode === 'bypassPermissions') hits.push({ label: 'permission-bypass-mode', severity: 'medium' });
  return hits;
}

// VS Code tasks with runOptions.runOn === "folderOpen" run when the folder is opened.
// Returns null when the file cannot be parsed.
function autorunTasks(content) {
  let data;
  try { data = JSON.parse(stripJsonc(content)); } catch { return null; }
  const tasks = (data && Array.isArray(data.tasks)) ? data.tasks : [];
  return tasks
    .filter(t => t && t.runOptions && t.runOptions.runOn === 'folderOpen')
    .map(t => ({ label: sanitizeExcerpt(t.label || '', 100), command: sanitizeExcerpt([t.command, ...(Array.isArray(t.args) ? t.args : [])].filter(Boolean).join(' '), 300) }));
}

// Strips // and /* */ comments (outside strings) and trailing commas from JSONC.
function stripJsonc(text) {
  const src = stripBom(text);
  let out = '';
  let inStr = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += src[++i] || ''; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && src[i + 1] === '*') { i += 2; while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function stripBom(text) {
  return text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
}

function makeFinding(tool, filePath, project, hits, text) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const severity = hits.reduce((w, h) => ((order[h.severity] ?? 3) < (order[w] ?? 3) ? h.severity : w), 'low');
  return {
    severity,
    type: 'suspicious_ai_instruction',
    tool,
    path: filePath,
    project,
    triggers: [...new Set(hits.map(h => h.label))],
    text,
  };
}

module.exports = { scan, SCANNER_ID, checkText, stripJsonc };
