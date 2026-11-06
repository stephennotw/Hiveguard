'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, readdirSafe, existsSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'git-hooks';
const MAX_HOOK_BYTES = 64 * 1024;

// Every hook name git will execute (githooks(5)).
const HOOK_NAMES = new Set([
  'applypatch-msg', 'pre-applypatch', 'post-applypatch',
  'pre-commit', 'pre-merge-commit', 'prepare-commit-msg', 'commit-msg', 'post-commit',
  'pre-rebase', 'post-checkout', 'post-merge',
  'pre-push', 'pre-receive', 'update', 'proc-receive', 'post-receive', 'post-update',
  'reference-transaction', 'push-to-checkout', 'pre-auto-gc', 'post-rewrite',
  'sendemail-validate', 'fsmonitor-watchman', 'post-index-change',
  'p4-changelist', 'p4-prepare-changelist', 'p4-post-changelist', 'p4-pre-submit',
]);

// Bounded gaps keep matching linear on large hook files.
const SUSPICIOUS_PATTERNS = [
  { pattern: /\bcurl\b[^\n]{0,200}\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b[^\n]{0,200}\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\beval\s/, label: 'eval', severity: 'high' },
  { pattern: /\bnc\b[^\n]{0,200}\s-e\b/, label: 'netcat-exec', severity: 'critical' },
  { pattern: /\/dev\/tcp\//, label: 'bash-tcp', severity: 'critical' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /base64\s+(-d|--decode)/, label: 'base64-decode', severity: 'high' },
  { pattern: /\bpython[23]?\s+-c\s/, label: 'python-inline', severity: 'medium' },
  { pattern: /\bnode\s+-e\s/, label: 'node-eval', severity: 'medium' },
  { pattern: /\bchmod\b[^\n]{0,200}\+[xs]/, label: 'permission-change', severity: 'medium' },
  { pattern: /\.(ssh|gnupg|aws|npmrc|netrc)\b/, label: 'credential-access', severity: 'high' },
  { pattern: /\bexfil\b|\bsteal\b|\bkeylog\b/i, label: 'exfil-keyword', severity: 'critical' },
  { pattern: /\bpowershell\b[^\n]{0,200}\s-enc/i, label: 'powershell-encoded', severity: 'critical' },
];

function scan(platform, opts = {}) {
  const projectRoots = platform.projectRoots || [];
  const findings = [];
  const scannedHookDirs = new Set();
  let reposScanned = 0;
  let hooksFound = 0;

  const inspectHooksDir = (hooksDir, repoLabel, origin) => {
    let real;
    try { real = fs.realpathSync(hooksDir); } catch { return; }
    if (scannedHookDirs.has(real)) return;
    scannedHookDirs.add(real);

    for (const entry of readdirSafe(hooksDir)) {
      if (!HOOK_NAMES.has(entry)) continue;
      const hookPath = path.join(hooksDir, entry);
      const stat = statSafe(hookPath);
      if (!stat || !stat.isFile()) continue;
      hooksFound++;
      const content = readFileSafe(hookPath, { maxBytes: MAX_HOOK_BYTES });
      if (content == null) continue;
      findings.push(buildFinding(entry, hookPath, repoLabel, origin, stat, content));
    }
  };

  for (const gitDir of findGitDirs(projectRoots, opts.maxDepth || 4)) {
    reposScanned++;
    const repoPath = gitDir.workTree;
    inspectHooksDir(path.join(gitDir.dir, 'hooks'), repoPath, '.git/hooks');
    const commonDir = readCommonDir(gitDir.dir);
    if (commonDir) inspectHooksDir(path.join(commonDir, 'hooks'), repoPath, '.git/hooks');

    const hooksPath = readHooksPath(path.join(commonDir || gitDir.dir, 'config'));
    if (hooksPath) inspectHooksDir(resolveConfigPath(hooksPath, repoPath, null), repoPath, 'core.hooksPath (repo)');
  }

  // A global core.hooksPath applies to every repo of that user — a persistence point.
  for (const cfg of (platform.gitConfigPaths || [])) {
    if (typeof cfg !== 'string') continue;
    const hooksPath = readHooksPath(cfg);
    if (!hooksPath) continue;
    const home = path.dirname(cfg);
    inspectHooksDir(resolveConfigPath(hooksPath, home, home), `(global ${cfg})`, 'core.hooksPath (global)');
  }

  const suspicious = findings.filter(f => f.severity !== 'info').length;
  if (suspicious > 0) {
    logger.warn(SCANNER_ID, `Found ${suspicious} suspicious git hooks`);
  } else {
    logger.info(SCANNER_ID, `Scanned ${reposScanned} repos, ${hooksFound} custom hooks (none suspicious)`);
  }

  return {
    ecosystem: SCANNER_ID,
    repos_scanned: reposScanned,
    hooks_found: hooksFound,
    total_findings: findings.length,
    suspicious,
    findings,
  };
}

function buildFinding(hookName, hookPath, repo, origin, stat, content) {
  const matched = SUSPICIOUS_PATTERNS.filter(p => p.pattern.test(content));
  const base = {
    hook: hookName,
    path: hookPath,
    repo,
    origin,
    executable: !!(stat.mode & 0o111),
    size: stat.size,
  };
  if (matched.length === 0) {
    return { severity: 'info', type: 'custom_git_hook', ...base, triggers: [], text: `Custom git hook "${hookName}" in ${repo} (${origin})` };
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const severity = matched.reduce((w, m) => ((order[m.severity] ?? 3) < (order[w] ?? 3) ? m.severity : w), 'low');
  const labels = [...new Set(matched.map(m => m.label))];
  return {
    severity,
    type: 'suspicious_git_hook',
    ...base,
    triggers: labels,
    text: `Suspicious git hook "${hookName}" in ${repo} (${origin}): ${labels.join(', ')}`,
  };
}

// Returns core.hooksPath from a git config file, or null.
function readHooksPath(configPath) {
  const raw = readFileSafe(configPath, { maxBytes: 256 * 1024 });
  if (!raw) return null;
  let inCore = false;
  let value = null;
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('[')) {
      inCore = /^\[\s*core\s*\]$/i.test(t);
      continue;
    }
    if (!inCore) continue;
    const m = t.match(/^hookspath\s*=\s*(.*)$/i);
    if (m) value = m[1].replace(/\s+[#;].*$/, '').replace(/^"(.*)"$/, '$1').trim();
  }
  return value || null;
}

function resolveConfigPath(p, baseDir, home) {
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(home || require('os').homedir(), p.slice(2));
  return path.isAbsolute(p) ? p : path.resolve(baseDir, p);
}

// Worktrees keep hooks in the main repo's common dir.
function readCommonDir(gitDir) {
  const raw = readFileSafe(path.join(gitDir, 'commondir'), { maxBytes: 4096 });
  return raw ? path.resolve(gitDir, raw.trim()) : null;
}

// Finds repos under roots. `.git` may be a directory or a file ("gitdir: <path>") for
// worktrees and submodules. Returns [{ dir: <git dir>, workTree: <repo root> }].
function findGitDirs(roots, maxDepth) {
  const results = [];
  const skip = new Set(['node_modules', '.git', '__pycache__', 'dist', 'build', 'target', '.cache', '.local']);

  function walk(dir, depth) {
    if (depth > maxDepth) return;

    const dotGit = path.join(dir, '.git');
    const st = statSafe(dotGit);
    if (st && st.isDirectory()) {
      results.push({ dir: dotGit, workTree: dir });
    } else if (st && st.isFile()) {
      const raw = readFileSafe(dotGit, { maxBytes: 4096 });
      const m = raw && raw.match(/^gitdir:\s*(.+)$/m);
      if (m) results.push({ dir: path.resolve(dir, m[1].trim()), workTree: dir });
    }

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if (skip.has(entry.name.toLowerCase())) continue;
      walk(path.join(dir, entry.name), depth + 1);
    }
  }

  for (const root of roots) {
    if (existsSafe(root)) walk(root, 0);
  }
  return results;
}

module.exports = { scan, SCANNER_ID, readHooksPath };
