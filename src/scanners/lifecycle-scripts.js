'use strict';

const fs = require('fs');
const path = require('path');
const { readJsonSafe, readFileSafe, statSafe, existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'lifecycle-scripts';

const LIFECYCLE_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  'prepublish', 'prepare',
];

const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_SCRIPT_CHARS = 4096;
const MAX_SCRIPT_FILE_BYTES = 64 * 1024;
const OVERSIZED_SCRIPT_FILE_BYTES = 1024 * 1024;
const MAX_NESTING = 6;

// All gaps are bounded ([^\n]{0,200}) so matching stays linear on hostile input.
const SCRIPT_PATTERNS = [
  { pattern: /\bcurl\b[^\n]{0,200}\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b[^\n]{0,200}\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\beval\s*\(/, label: 'eval-call', severity: 'high' },
  { pattern: /\bchild_process\b/, label: 'child_process-import', severity: 'high' },
  { pattern: /\bexec\s*\(/, label: 'exec-call', severity: 'high' },
  { pattern: /\bexecSync\b/, label: 'execSync-call', severity: 'high' },
  { pattern: /\bspawn\s*\(/, label: 'spawn-call', severity: 'medium' },
  { pattern: /Buffer\.from\s*\([^)]{0,200},\s*['"]base64['"]/, label: 'base64-decode', severity: 'high' },
  { pattern: /\batob\s*\(/, label: 'base64-decode', severity: 'high' },
  { pattern: /\\x[0-9a-fA-F]{2}[^\n]{0,200}\\x[0-9a-fA-F]{2}[^\n]{0,200}\\x[0-9a-fA-F]{2}/, label: 'hex-encoded-strings', severity: 'high' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /\bpowershell\b[^\n]{0,200}\s-e(nc(oded(command)?)?)?\b/i, label: 'powershell-encoded', severity: 'critical' },
  { pattern: /\bnet\s+user\b/i, label: 'user-creation', severity: 'critical' },
  { pattern: /(\/dev\/tcp\/|\bnc\b[^\n]{0,200}\s-e\b|\bncat\b[^\n]{0,200}\s-e\b)/, label: 'reverse-shell', severity: 'critical' },
  { pattern: /process\.env\.(HOME|USERPROFILE|APPDATA)/, label: 'home-dir-access', severity: 'medium' },
  { pattern: /\.(ssh|gnupg|aws|npmrc|netrc)\b/, label: 'credential-file-access', severity: 'high' },
  { pattern: /node\s+-e\s+['"]/, label: 'node-eval', severity: 'high' },
];

// Applied to files an install hook runs. Legit installers (esbuild, node-gyp, prebuild)
// routinely use child_process/https/env, so only high-signal behaviour is flagged here.
const FILE_PATTERNS = [
  { pattern: /\bcurl\b[^\n]{0,200}\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b[^\n]{0,200}\|\s*(bash|sh)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /(\/dev\/tcp\/|\bnc\b[^\n]{0,200}\s-e\b)/, label: 'reverse-shell', severity: 'critical' },
  { pattern: /\bpowershell\b[^\n]{0,200}\s-e(nc(oded(command)?)?)?\b/i, label: 'powershell-encoded', severity: 'critical' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /\beval\s*\(\s*(atob|Buffer\.from)\s*\(/, label: 'eval-decoded-payload', severity: 'high' },
  { pattern: /process\.env\.(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/, label: 'token-env-harvest', severity: 'high' },
  { pattern: /\btrufflehog\b/i, label: 'secret-scanner-download', severity: 'high' },
  { pattern: /--dangerously-skip-permissions|--yolo\b|--trust-all-tools/, label: 'ai-cli-permission-bypass', severity: 'critical' },
  { pattern: /\.(ssh|aws)[\\/]|\bid_rsa\b|\.npmrc\b/, label: 'credential-file-access', severity: 'medium' },
];

// Install-hook payload filenames from Shai-Hulud / Mini Shai-Hulud style worms
const KNOWN_IOC_FILES = new Set(['setup_bun.js', 'bun_environment.js', 'router_runtime.js']);

const SCRIPT_FILE_REF = /\b(?:node|bun|deno|sh|bash)\s+(?:-{1,2}[\w-]+(?:=\S+)?\s+)*["']?([\w./@-]+\.(?:c?js|mjs|ts|sh))\b/g;

function scan(platform, opts = {}, npmProjects) {
  const projects = npmProjects || [];
  const findings = [];
  const stats = { packagesScanned: 0 };

  for (const proj of projects) {
    const projectDir = proj.project_path;
    if (!projectDir) continue;
    const project = proj.project || projectDir;

    const projPkgJson = readJsonSafe(path.join(projectDir, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
    if (projPkgJson && projPkgJson.scripts) {
      findings.push(...checkScripts(projPkgJson.scripts, projPkgJson.name || path.basename(projectDir), project, projectDir));
    }
    scanNodeModules(path.join(projectDir, 'node_modules'), project, findings, stats, 0);
  }

  for (const nmDir of globalNodeModulesDirs(platform)) {
    scanNodeModules(nmDir, '(global)', findings, stats, 0);
  }

  if (findings.length > 0) {
    logger.warn(SCANNER_ID, `Found ${findings.length} suspicious lifecycle scripts in ${stats.packagesScanned} packages`);
  } else {
    logger.info(SCANNER_ID, `Scanned ${stats.packagesScanned} packages, no suspicious lifecycle scripts`);
  }

  return {
    ecosystem: SCANNER_ID,
    packages_scanned: stats.packagesScanned,
    total_findings: findings.length,
    findings,
  };
}

function globalNodeModulesDirs(platform) {
  const dirs = new Set();
  for (const dir of (platform.npmGlobalDirs || [])) {
    if (typeof dir !== 'string') continue;
    const candidates = path.basename(dir) === 'node_modules'
      ? [dir]
      : [path.join(dir, 'lib', 'node_modules'), path.join(dir, 'node_modules')];
    for (const c of candidates) if (existsSafe(c)) dirs.add(c);
  }
  return [...dirs];
}

// Walks node_modules including scoped and nested node_modules; never follows symlinks.
function scanNodeModules(nmDir, project, findings, stats, depth) {
  if (depth > MAX_NESTING) return;
  for (const entry of readDirEntries(nmDir)) {
    if (entry.name.startsWith('.') || !entry.isDirectory()) continue;
    const entryPath = path.join(nmDir, entry.name);

    if (entry.name.startsWith('@')) {
      for (const scoped of readDirEntries(entryPath)) {
        if (scoped.name.startsWith('.') || !scoped.isDirectory()) continue;
        scanPackageDir(path.join(entryPath, scoped.name), `${entry.name}/${scoped.name}`, project, findings, stats, depth);
      }
      continue;
    }
    scanPackageDir(entryPath, entry.name, project, findings, stats, depth);
  }
}

function scanPackageDir(pkgDir, pkgName, project, findings, stats, depth) {
  stats.packagesScanned++;
  const pkgJson = readJsonSafe(path.join(pkgDir, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
  if (pkgJson && pkgJson.scripts) {
    findings.push(...checkScripts(pkgJson.scripts, pkgJson.name || pkgName, project, pkgDir));
  }
  scanNodeModules(path.join(pkgDir, 'node_modules'), project, findings, stats, depth + 1);
}

function readDirEntries(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true }).filter(e => !e.isSymbolicLink());
  } catch {
    return [];
  }
}

function checkScripts(scripts, packageName, project, pkgDir) {
  const hits = [];

  for (const hook of LIFECYCLE_HOOKS) {
    const script = scripts[hook];
    if (!script || typeof script !== 'string') continue;

    const text = script.slice(0, MAX_SCRIPT_CHARS);
    const matched = matchPatterns(SCRIPT_PATTERNS, text);
    const scriptFiles = [];

    for (const ref of referencedScriptFiles(text, pkgDir)) {
      const fileHits = inspectScriptFile(ref.abs, ref.rel);
      if (fileHits.length > 0) {
        matched.push(...fileHits);
        scriptFiles.push(ref.rel);
      }
    }

    if (matched.length === 0) continue;
    const labels = [...new Set(matched.map(m => m.label))];
    hits.push({
      severity: worstSeverity(matched),
      type: 'suspicious_lifecycle_script',
      ecosystem: 'npm',
      package: packageName,
      project,
      hook,
      script: script.slice(0, 500),
      script_files: scriptFiles,
      triggers: labels,
      path: pkgDir,
      text: `${packageName} has suspicious "${hook}" script: ${labels.join(', ')}`,
    });
  }

  return hits;
}

// Files referenced as `node x.js`, `sh ./install.sh`, ... resolved inside pkgDir only.
function referencedScriptFiles(script, pkgDir) {
  const refs = [];
  if (!pkgDir) return refs;
  const root = path.resolve(pkgDir);
  for (const m of script.matchAll(SCRIPT_FILE_REF)) {
    const abs = path.resolve(root, m[1]);
    if (abs !== root && !abs.startsWith(root + path.sep)) continue;
    if (!refs.some(r => r.abs === abs)) refs.push({ abs, rel: path.relative(root, abs) });
  }
  return refs;
}

function inspectScriptFile(absPath, relPath) {
  const hits = [];
  if (KNOWN_IOC_FILES.has(path.basename(relPath))) {
    hits.push({ label: 'known-worm-filename', severity: 'critical' });
  }

  const st = statSafe(absPath);
  if (!st || !st.isFile()) return hits;
  if (st.size > OVERSIZED_SCRIPT_FILE_BYTES) {
    hits.push({ label: 'oversized-install-script', severity: 'medium' });
  }

  const content = readFileSafe(absPath, { maxBytes: MAX_SCRIPT_FILE_BYTES });
  if (content) hits.push(...matchPatterns(FILE_PATTERNS, content));
  return hits;
}

function matchPatterns(patterns, text) {
  const matched = [];
  for (const { pattern, label, severity } of patterns) {
    if (pattern.test(text)) matched.push({ label, severity });
  }
  return matched;
}

function worstSeverity(matched) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return matched.reduce((worst, m) => ((order[m.severity] ?? 3) < (order[worst] ?? 3) ? m.severity : worst), 'low');
}

module.exports = { scan, SCANNER_ID, checkScripts };
