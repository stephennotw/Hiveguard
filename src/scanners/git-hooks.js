'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, readdirSafe, statSafe, findProjectDirs } = require('../utils/fs-safe');
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

// projectDirs: optional [{ dir, gitDir }] from the shared directory walk.
function scan(platform, opts = {}, projectDirs) {
  const dirs = projectDirs || findProjectDirs(platform.projectRoots || [], { maxDepth: opts.maxDepth || 4 });
  const findings = [];
  const scannedHookDirs = new Set();
  let reposScanned = 0;
  let hooksFound = 0;

  // trustedRoot: hooks that are symlinks may only be read if they resolve inside it.
  // namesOnly: cloud-synced folder; list hooks but never read their contents.
  const inspectHooksDir = (hooksDir, repoLabel, origin, trustedRoot, namesOnly = false) => {
    let real;
    try { real = fs.realpathSync.native(hooksDir); } catch { return; }
    if (scannedHookDirs.has(real)) return;
    scannedHookDirs.add(real);
    let realRoot = real;
    try { realRoot = fs.realpathSync.native(trustedRoot); } catch { /* keep hooks dir */ }

    for (const entry of readdirSafe(hooksDir)) {
      if (!HOOK_NAMES.has(entry)) continue;
      const hookPath = path.join(hooksDir, entry);
      const stat = statSafe(hookPath);
      if (!stat || !stat.isFile()) continue;
      hooksFound++;

      if (namesOnly) {
        findings.push(unreadFinding(entry, hookPath, repoLabel, origin, stat));
        continue;
      }
      let target;
      try { target = fs.realpathSync.native(hookPath); } catch { continue; }
      if (!isInside(target, realRoot) && !isInside(target, real)) {
        findings.push(symlinkFinding(entry, hookPath, target, repoLabel, origin, stat));
        continue;
      }
      const content = readFileSafe(hookPath, { maxBytes: MAX_HOOK_BYTES });
      if (content == null) continue;
      findings.push(buildFinding(entry, hookPath, repoLabel, origin, stat, content));
    }
  };

  for (const { dir: repoPath, gitDir: hasGit, cloud } of dirs) {
    if (!hasGit) continue;
    if (cloud) {
      // Only a real .git directory can be listed without reading any file.
      const dotGit = path.join(repoPath, '.git');
      const st = statSafe(dotGit);
      if (!st || !st.isDirectory()) continue;
      reposScanned++;
      inspectHooksDir(path.join(dotGit, 'hooks'), repoPath, '.git/hooks', repoPath, true);
      continue;
    }
    const gitDir = resolveGitDir(repoPath);
    if (!gitDir) continue;
    reposScanned++;
    inspectHooksDir(path.join(gitDir, 'hooks'), repoPath, '.git/hooks', repoPath);
    const commonDir = readCommonDir(gitDir);
    if (commonDir) inspectHooksDir(path.join(commonDir, 'hooks'), repoPath, '.git/hooks', repoPath);

    const hooksPath = readHooksPath(path.join(commonDir || gitDir, 'config'));
    if (hooksPath) inspectHooksDir(resolveConfigPath(hooksPath, repoPath, null), repoPath, 'core.hooksPath (repo)', repoPath);
  }

  // A global core.hooksPath applies to every repo of that user — a persistence point.
  for (const cfg of (platform.gitConfigPaths || [])) {
    if (typeof cfg !== 'string') continue;
    const hooksPath = readHooksPath(cfg);
    if (!hooksPath) continue;
    const home = path.dirname(cfg);
    const dir = resolveConfigPath(hooksPath, home, home);
    inspectHooksDir(dir, `(global ${cfg})`, 'core.hooksPath (global)', dir);
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
    executable: executableBit(stat),
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

// .git may be a directory, or a file ("gitdir: <path>") for worktrees and submodules.
function resolveGitDir(workTree) {
  const dotGit = path.join(workTree, '.git');
  const st = statSafe(dotGit);
  if (st && st.isDirectory()) return dotGit;
  if (st && st.isFile()) {
    const raw = readFileSafe(dotGit, { maxBytes: 4096 });
    const m = raw && raw.match(/^gitdir:\s*(.+)$/m);
    if (m) return path.resolve(workTree, m[1].trim());
  }
  return null;
}

function isInside(p, root) {
  return p === root || p.startsWith(root + path.sep);
}

// Permission bits carry no meaning on Windows.
function executableBit(stat) {
  return process.platform === 'win32' ? null : !!(stat.mode & 0o111);
}

function unreadFinding(hookName, hookPath, repo, origin, stat) {
  return {
    severity: 'info',
    type: 'custom_git_hook',
    hook: hookName,
    path: hookPath,
    repo,
    origin,
    executable: executableBit(stat),
    size: stat.size,
    content_not_read: 'cloud-synced',
    triggers: [],
    text: `Custom git hook "${hookName}" in ${repo} (${origin}); in a cloud-synced folder, contents not read`,
  };
}

function symlinkFinding(hookName, hookPath, target, repo, origin, stat) {
  return {
    severity: 'medium',
    type: 'suspicious_git_hook',
    hook: hookName,
    path: hookPath,
    repo,
    origin,
    executable: executableBit(stat),
    size: stat.size,
    symlink_target: target,
    triggers: ['symlink-outside-repo'],
    text: `Git hook "${hookName}" in ${repo} (${origin}) is a symlink to ${target}, outside the repository`,
  };
}

module.exports = { scan, SCANNER_ID, readHooksPath };
