'use strict';

const path = require('path');
const { readJsonSafe, readdirSafe, existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'lifecycle-scripts';

const LIFECYCLE_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  'prepublish', 'prepare',
];

const SUSPICIOUS_PATTERNS = [
  { pattern: /\bcurl\b.*\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b.*\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\beval\s*\(/, label: 'eval-call', severity: 'high' },
  { pattern: /\bchild_process\b/, label: 'child_process-import', severity: 'high' },
  { pattern: /\bexec\s*\(/, label: 'exec-call', severity: 'high' },
  { pattern: /\bexecSync\b/, label: 'execSync-call', severity: 'high' },
  { pattern: /\bspawn\s*\(/, label: 'spawn-call', severity: 'medium' },
  { pattern: /Buffer\.from\s*\([^)]*,\s*['"]base64['"]/, label: 'base64-decode', severity: 'high' },
  { pattern: /\batob\s*\(/, label: 'base64-decode', severity: 'high' },
  { pattern: /\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}/, label: 'hex-encoded-strings', severity: 'high' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /\bpowershell\b.*\b-e(nc(oded(command)?)?)?/i, label: 'powershell-encoded', severity: 'critical' },
  { pattern: /\bnet\s+user\b/i, label: 'user-creation', severity: 'critical' },
  { pattern: /(\/dev\/tcp|\bnc\b.*-e|\bncat\b.*-e)/, label: 'reverse-shell', severity: 'critical' },
  { pattern: /process\.env\.(HOME|USERPROFILE|APPDATA)/, label: 'home-dir-access', severity: 'medium' },
  { pattern: /\.(ssh|gnupg|aws|npmrc|netrc)\b/, label: 'credential-file-access', severity: 'high' },
  { pattern: /node\s+-e\s+['"]/, label: 'node-eval', severity: 'high' },
];

function scan(platform, opts = {}, npmProjects) {
  const projects = npmProjects || [];
  const findings = [];
  let packagesScanned = 0;

  for (const proj of projects) {
    const projectDir = proj.project_path;
    if (!projectDir) continue;

    const projPkgJson = readJsonSafe(path.join(projectDir, 'package.json'));
    if (projPkgJson && projPkgJson.scripts) {
      const projHits = checkScripts(projPkgJson.scripts, projPkgJson.name || path.basename(projectDir), '(project)', projectDir);
      findings.push(...projHits);
    }

    const nmDir = path.join(projectDir, 'node_modules');
    if (!existsSafe(nmDir)) continue;

    const entries = readdirSafe(nmDir);
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;

      if (entry.startsWith('@')) {
        const scopeDir = path.join(nmDir, entry);
        for (const scopedEntry of readdirSafe(scopeDir)) {
          if (scopedEntry.startsWith('.')) continue;
          const pkgDir = path.join(scopeDir, scopedEntry);
          const pkgName = `${entry}/${scopedEntry}`;
          scanPackageDir(pkgDir, pkgName, proj.project || projectDir, findings);
          packagesScanned++;
        }
        continue;
      }

      const pkgDir = path.join(nmDir, entry);
      scanPackageDir(pkgDir, entry, proj.project || projectDir, findings);
      packagesScanned++;
    }
  }

  if (findings.length > 0) {
    logger.warn(SCANNER_ID, `Found ${findings.length} suspicious lifecycle scripts in ${packagesScanned} packages`);
  } else {
    logger.info(SCANNER_ID, `Scanned ${packagesScanned} packages, no suspicious lifecycle scripts`);
  }

  return {
    ecosystem: SCANNER_ID,
    packages_scanned: packagesScanned,
    total_findings: findings.length,
    findings,
  };
}

function scanPackageDir(pkgDir, pkgName, project, findings) {
  const pkgJson = readJsonSafe(path.join(pkgDir, 'package.json'));
  if (!pkgJson || !pkgJson.scripts) return;

  const hits = checkScripts(pkgJson.scripts, pkgJson.name || pkgName, project, pkgDir);
  findings.push(...hits);
}

function checkScripts(scripts, packageName, project, pkgDir) {
  const hits = [];

  for (const hook of LIFECYCLE_HOOKS) {
    const script = scripts[hook];
    if (!script || typeof script !== 'string') continue;

    const matched = [];
    for (const { pattern, label, severity } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(script)) {
        matched.push({ label, severity });
      }
    }

    if (matched.length > 0) {
      const worstSeverity = matched.reduce((worst, m) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[m.severity] ?? 3) < (order[worst] ?? 3) ? m.severity : worst;
      }, 'low');

      hits.push({
        severity: worstSeverity,
        type: 'suspicious_lifecycle_script',
        ecosystem: 'npm',
        package: packageName,
        project,
        hook,
        script: script.slice(0, 500),
        triggers: matched.map(m => m.label),
        path: pkgDir,
        text: `${packageName} has suspicious "${hook}" script: ${matched.map(m => m.label).join(', ')}`,
      });
    }
  }

  return hits;
}

module.exports = { scan, SCANNER_ID, checkScripts };
