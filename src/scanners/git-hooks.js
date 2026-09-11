'use strict';

const path = require('path');
const { readFileSafe, readdirSafe, existsSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'git-hooks';

const HOOK_NAMES = new Set([
  'applypatch-msg', 'pre-applypatch', 'post-applypatch',
  'pre-commit', 'prepare-commit-msg', 'commit-msg', 'post-commit',
  'pre-rebase', 'post-checkout', 'post-merge',
  'pre-push', 'pre-receive', 'update', 'post-receive', 'post-update',
  'push-to-checkout', 'pre-auto-gc', 'post-rewrite',
  'sendemail-validate', 'fsmonitor-watchman', 'post-index-change',
]);

const SUSPICIOUS_PATTERNS = [
  { pattern: /\bcurl\b.*\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b.*\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\beval\s/, label: 'eval', severity: 'high' },
  { pattern: /\bnc\b.*-e\b/, label: 'netcat-exec', severity: 'critical' },
  { pattern: /\/dev\/tcp\//, label: 'bash-tcp', severity: 'critical' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /base64\s+(-d|--decode)/, label: 'base64-decode', severity: 'high' },
  { pattern: /\bpython[23]?\s+-c\s/, label: 'python-inline', severity: 'medium' },
  { pattern: /\bnode\s+-e\s/, label: 'node-eval', severity: 'medium' },
  { pattern: /\bchmod\b.*\+[xs]/, label: 'permission-change', severity: 'medium' },
  { pattern: /\.(ssh|gnupg|aws|npmrc|netrc)\b/, label: 'credential-access', severity: 'high' },
  { pattern: /\bexfil\b|\bsteal\b|\bkeylog\b/i, label: 'exfil-keyword', severity: 'critical' },
  { pattern: /\bpowershell\b.*-enc/i, label: 'powershell-encoded', severity: 'critical' },
];

function scan(platform, opts = {}) {
  const projectRoots = platform.projectRoots || [];
  const findings = [];
  let reposScanned = 0;
  let hooksFound = 0;

  const gitDirs = findGitDirs(projectRoots, opts.maxDepth || 4);

  for (const gitDir of gitDirs) {
    reposScanned++;
    const hooksDir = path.join(gitDir, 'hooks');
    if (!existsSafe(hooksDir)) continue;

    const entries = readdirSafe(hooksDir);
    for (const entry of entries) {
      if (entry.endsWith('.sample')) continue;

      const hookName = entry;
      if (!HOOK_NAMES.has(hookName)) continue;

      const hookPath = path.join(hooksDir, entry);
      const stat = statSafe(hookPath);
      if (!stat || !stat.isFile()) continue;

      hooksFound++;

      const content = readFileSafe(hookPath, { maxBytes: 8192 });
      if (!content) continue;

      const matched = [];
      for (const { pattern, label, severity } of SUSPICIOUS_PATTERNS) {
        if (pattern.test(content)) {
          matched.push({ label, severity });
        }
      }

      const isExecutable = !!(stat.mode & 0o111);
      const repoPath = path.dirname(gitDir);

      if (matched.length > 0) {
        const worstSeverity = matched.reduce((worst, m) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3 };
          return (order[m.severity] ?? 3) < (order[worst] ?? 3) ? m.severity : worst;
        }, 'low');

        findings.push({
          severity: worstSeverity,
          type: 'suspicious_git_hook',
          hook: hookName,
          path: hookPath,
          repo: repoPath,
          executable: isExecutable,
          triggers: matched.map(m => m.label),
          size: stat.size,
          text: `Suspicious git hook "${hookName}" in ${repoPath}: ${matched.map(m => m.label).join(', ')}`,
        });
      } else {
        findings.push({
          severity: 'info',
          type: 'custom_git_hook',
          hook: hookName,
          path: hookPath,
          repo: repoPath,
          executable: isExecutable,
          triggers: [],
          size: stat.size,
          text: `Custom git hook "${hookName}" in ${repoPath}`,
        });
      }
    }
  }

  if (findings.filter(f => f.severity !== 'info').length > 0) {
    logger.warn(SCANNER_ID, `Found ${findings.filter(f => f.severity !== 'info').length} suspicious git hooks`);
  } else {
    logger.info(SCANNER_ID, `Scanned ${reposScanned} repos, ${hooksFound} custom hooks (none suspicious)`);
  }

  return {
    ecosystem: SCANNER_ID,
    repos_scanned: reposScanned,
    hooks_found: hooksFound,
    total_findings: findings.length,
    suspicious: findings.filter(f => f.severity !== 'info').length,
    findings,
  };
}

function findGitDirs(roots, maxDepth) {
  const results = [];
  const fs = require('fs');

  function walk(dir, depth) {
    if (depth > maxDepth) return;

    const gitDir = path.join(dir, '.git');
    if (existsSafe(gitDir)) {
      const st = statSafe(gitDir);
      if (st && st.isDirectory()) {
        results.push(gitDir);
      }
    }

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.isSymbolicLink()) continue;
      const name = entry.name.toLowerCase();
      if (name === 'node_modules' || name === '.git' || name === '__pycache__'
          || name === 'dist' || name === 'build' || name === 'target'
          || name === '.cache' || name === '.local') continue;
      walk(path.join(dir, entry.name), depth + 1);
    }
  }

  for (const root of roots) {
    if (existsSafe(root)) walk(root, 0);
  }

  return results;
}

module.exports = { scan, SCANNER_ID };
