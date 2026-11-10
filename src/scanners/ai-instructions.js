'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, readdirSafe, statSafe, findProjectDirs } = require('../utils/fs-safe');
const logger = require('../utils/logger');
const { referencedScriptFiles, inspectScriptFile, localImports } = require('../utils/script-inspect');
const { scanHidden, sanitizeExcerpt } = require('../utils/text');
const { stripJsonc, stripBom } = require('../utils/jsonc');
const { inToolCatalog } = require('../utils/ai-roots');

const SCANNER_ID = 'ai-instructions';
const MAX_FILE_BYTES = 64 * 1024;
const MAX_DIR_FILES = 200;

// Generic agent layout inside any dot-folder (~/.gemini, .cursor, a future agent's
// folder...): markdown under these subfolders, and skills/<name>/SKILL.md.
const GENERIC_MD_SUBDIRS = ['rules', 'commands', 'agents', 'prompts', 'instructions'];
const GENERIC_DOT_SKIP = new Set(['.git', '.svn', '.hg', '.cache', '.npm', '.yarn', '.pnpm-store', '.cargo', '.rustup',
  '.m2', '.gradle', '.nuget', '.local', '.venv', '.tox', '.nvm', '.pyenv', '.rbenv', '.conda', '.docker', '.terraform']);

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
  { file: 'AGENTS.md', tool: 'Agents (AGENTS.md)' },
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
  // A tool's own catalog folders (e.g. ~/.tool/plugins/<name>) are not the user's projects.
  const dirs = (projectDirs || findProjectDirs(platform.projectRoots || [], { maxDepth: opts.maxDepth || 4 })).filter(d => !inToolCatalog(d.dir));
  const findings = [];
  const inventory = [];
  const seen = new Set();
  const reportedLinks = new Set();

  const ctx = { findings, inventory, seen, reportedLinks };
  // Most specific first so its label wins (files are deduplicated by identity):
  // user-level entries, project entries, then generic dot-folder discovery.
  // A home folder that also looks like a project (a package.json or .git in ~) is still
  // the user's own configuration, not something that arrived with a repository.
  const homes = platform.userHomes || [];
  const key = (p) => (process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p));
  const homeKeys = new Set(homes.map(key));
  const scopeOf = (dir) => (homeKeys.has(key(dir)) ? 'user' : 'project');
  for (const home of homes) for (const spec of USER_FILES) inspectSpec(spec, home, home, ctx, 'user');
  for (const { dir, cloud } of dirs) for (const spec of PROJECT_FILES) inspectSpec(spec, dir, dir, ctx, scopeOf(dir), !!cloud);
  for (const home of homes) inspectGenericDotDirs(home, ctx, 'user', false);
  for (const { dir, cloud } of dirs) if (scopeOf(dir) === 'project') inspectGenericDotDirs(dir, ctx, 'project', !!cloud);

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
/** Agent files in every dot-folder of baseDir, labelled by folder name (no product list). */
function inspectGenericDotDirs(baseDir, ctx, scope, namesOnly) {
  for (const e of listEntries(baseDir)) {
    if (!e.isDirectory() || e.isSymbolicLink() || !e.name.startsWith('.') || GENERIC_DOT_SKIP.has(e.name.toLowerCase())) continue;
    const dot = path.join(baseDir, e.name);
    const spec = { tool: e.name.slice(1) };
    for (const sub of GENERIC_MD_SUBDIRS) {
      const subDir = path.join(dot, sub);
      for (const f of listEntries(subDir).filter(x => x.isFile() && /\.(md|mdc)$/i.test(x.name)).slice(0, MAX_DIR_FILES)) {
        inspectFile(spec, path.join(subDir, f.name), baseDir, baseDir, ctx, scope, namesOnly);
      }
    }
    const skillsDir = path.join(dot, 'skills');
    for (const skill of listEntries(skillsDir).filter(x => x.isDirectory() && !x.isSymbolicLink()).slice(0, MAX_DIR_FILES)) {
      const skillDir = path.join(skillsDir, skill.name);
      const skillMd = listEntries(skillDir).find(x => x.isFile() && x.name.toLowerCase() === 'skill.md');
      if (skillMd) inspectFile({ ...spec, skillDir }, path.join(skillDir, skillMd.name), baseDir, baseDir, ctx, scope, namesOnly);
    }
  }
}

function listEntries(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
}

// Files bundled with a skill (scripts the agent may run), counted two levels deep.
function countFiles(dir, depth = 0) {
  let n = 0;
  for (const e of listEntries(dir)) {
    if (e.isSymbolicLink()) continue;
    if (e.isFile()) n++;
    else if (e.isDirectory() && depth < 1) n += countFiles(path.join(dir, e.name), depth + 1);
  }
  return n;
}

// namesOnly: cloud-synced folder; inventory files without reading them.
function inspectSpec(spec, baseDir, trustedRoot, ctx, scope, namesOnly = false) {
  if (namesOnly && spec.kind === 'vscode-tasks') return; // relevant only if it auto-runs, which needs a read
  const fullPath = path.join(baseDir, spec.file);
  const st = statSafe(fullPath);
  if (!st) return;

  if (spec.dir) {
    if (!st.isDirectory()) return;
    const files = readdirSafe(fullPath).filter(f => spec.exts.some(e => f.endsWith(e))).slice(0, MAX_DIR_FILES);
    for (const f of files) inspectFile({ ...spec, dir: false }, path.join(fullPath, f), baseDir, trustedRoot, ctx, scope, namesOnly);
    return;
  }
  if (st.isFile()) inspectFile(spec, fullPath, baseDir, trustedRoot, ctx, scope, namesOnly);
}

function inspectFile(spec, filePath, project, trustedRoot, ctx, scope, namesOnly = false) {
  let real;
  try { real = fs.realpathSync.native(filePath); } catch { return; }
  const st = statSafe(real);
  if (!st || !st.isFile()) return;
  // File identity, not path: CLAUDE.md and claude.md are one file on case-insensitive filesystems.
  const identity = st.ino ? `${st.dev}:${st.ino}` : real;
  if (ctx.seen.has(identity)) return;
  const item = { path: filePath, tool: spec.tool, type: path.extname(filePath) || 'text', size: st.size, project };
  if (spec.skillDir) item.skill_files = Math.max(0, countFiles(spec.skillDir) - 1);

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
  if (namesOnly) {
    item.content_not_read = 'cloud-synced';
    ctx.inventory.push(item);
    return;
  }

  const content = readFileSafe(real, { maxBytes: MAX_FILE_BYTES });
  ctx.inventory.push(item);
  if (content == null) return;

  const extra = [];
  if (spec.kind === 'claude-settings') {
    extra.push(...inspectClaudeSettings(content, item, scope));
    extra.push(...commandScriptHits((item.hooks || []).map(h => h._raw), filePath, scope, item));
    for (const h of item.hooks || []) delete h._raw;
  }
  if (spec.kind === 'vscode-tasks') {
    const tasks = autorunTasks(content);
    if (tasks && tasks.length > 0) {
      item.autorun_tasks = tasks;
      extra.push({ label: 'autorun-on-folder-open', severity: 'medium' });
      extra.push(...commandScriptHits(tasks.map(t => t._raw), filePath, scope, item));
      for (const t of tasks) delete t._raw;
    } else {
      // Ordinary tasks.json is not an agent surface; unparseable ones are still pattern-checked.
      ctx.inventory.pop();
      if (tasks) return;
      const hits = checkText(content);
      if (hits.length === 0) return;
      ctx.inventory.push(item);
    }
  }

  const hits = [...extra, ...textHits(content, scope)];
  if (hits.length > 0) {
    const labels = [...new Set(hits.map(h => h.label))];
    ctx.findings.push(makeFinding(spec.tool, filePath, project, hits,
      `Suspicious AI instruction file for ${spec.tool} at ${filePath}: ${labels.join(', ')}`));
  }
}

// Mentioning a permission-bypass flag (--dangerously-skip-permissions, --yolo, …) is how
// people document running an agent headless. In the user's own config that is usually
// their notes, so it is medium; in files that arrive with a repository it stays high.
// Script files that hooks actually run are judged separately and are not affected.
const USER_LEVEL_SEVERITY = { 'ai-cli-permission-bypass': 'medium' };

function textHits(content, scope) {
  const hits = checkText(content);
  if (scope !== 'user') return hits;
  return hits.map(h => (USER_LEVEL_SEVERITY[h.label] ? { ...h, severity: USER_LEVEL_SEVERITY[h.label] } : h));
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
        if (h && typeof h.command === 'string') hooks.push({ event, command: sanitizeExcerpt(h.command, 200), _raw: h.command });
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
    .map(t => {
      const raw = [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter(v => typeof v === 'string').join(' ');
      return { label: sanitizeExcerpt(t.label || '', 100), command: sanitizeExcerpt(raw, 300), _raw: raw };
    });
}

/**
 * Script files run by agent hooks and auto-run tasks (e.g. "node .claude/setup.mjs"),
 * plus their direct local imports, inspected like install-hook files. Paths resolve
 * against the folder holding .claude/ or .vscode/ and must stay inside it.
 */
function commandScriptHits(commands, settingsPath, scope, item) {
  const base = path.dirname(path.dirname(settingsPath));
  const vars = scope === 'user' ? { '~/': base + path.sep, '$HOME': base, '${HOME}': base } : {};
  const hits = [];
  const files = [];
  for (const raw of commands) {
    if (typeof raw !== 'string') continue;
    const cmd = raw.replace(/["']?\$\{?(CLAUDE_PROJECT_DIR|workspaceFolder)\}?["']?/g, base);
    for (const ref of referencedScriptFiles(cmd, base, { vars })) {
      files.push(ref.rel);
      hits.push(...inspectScriptFile(ref.abs, ref.rel));
      for (const imp of localImports(ref.abs, base)) {
        files.push(imp.rel);
        hits.push(...inspectScriptFile(imp.abs, imp.rel));
      }
    }
  }
  if (files.length > 0) item.script_files = [...new Set(files)];
  return hits;
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
