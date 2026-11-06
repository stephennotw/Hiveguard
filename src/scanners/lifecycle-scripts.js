'use strict';

const fs = require('fs');
const path = require('path');
const { readJsonSafe, readFileSafe, statSafe, existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');
const { sanitizeExcerpt } = require('../utils/text');

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

// core-js/es5-ext/msw style: node -e "try{require('./postinstall')}catch(e){}". The eval
// only loads a local file, so the file is inspected instead of flagging the eval.
const LOCAL_REQUIRE_EVAL = /^\s*node\s+-e\s+(["'])\s*try\s*\{\s*require\(\s*(["'])(\.\/[\w./-]+)\2\s*\)\s*;?\s*\}\s*catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}\s*\1\s*$/;

const SCRIPT_FILE_REF = /\b(?:node|bun|deno|sh|bash)\s+(?:-{1,2}[\w-]+(?:=\S+)?\s+)*["']?([\w./@-]+\.(?:c?js|mjs|ts|sh))\b/g;

function scan(platform, opts = {}, npmProjects) {
  const projects = npmProjects || [];
  const findings = [];
  const stats = { packagesScanned: 0, seen: new Set() };

  for (const proj of projects) {
    const projectDir = proj.project_path;
    if (!projectDir) continue;
    const project = proj.project || projectDir;

    const projPkgJson = readJsonSafe(path.join(projectDir, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
    if (projPkgJson && projPkgJson.scripts) {
      findings.push(...checkScripts(projPkgJson.scripts, projPkgJson.name || path.basename(projectDir), project, projectDir));
    }
    scanNodeModules(path.join(projectDir, 'node_modules'), { project, root: realpathOr(projectDir), findings, stats }, 0);
  }

  for (const nmDir of globalNodeModulesDirs(platform)) {
    scanNodeModules(nmDir, { project: '(global)', root: realpathOr(nmDir), findings, stats }, 0);
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

/**
 * Walks node_modules: scoped, nested, and pnpm's .pnpm store. Symlinked packages
 * (pnpm, npm/yarn workspaces) are followed only when they resolve inside ctx.root,
 * and each real package directory is scanned once.
 */
function scanNodeModules(nmDir, ctx, depth) {
  if (depth > MAX_NESTING) return;
  for (const entry of readDirEntries(nmDir)) {
    const entryPath = path.join(nmDir, entry.name);

    if (entry.name === '.pnpm') {
      for (const store of readDirEntries(entryPath)) {
        const storeDir = resolveDir(path.join(entryPath, store.name), store, ctx);
        if (storeDir) scanNodeModules(path.join(storeDir, 'node_modules'), ctx, depth + 1);
      }
      continue;
    }
    if (entry.name.startsWith('.')) continue;

    if (entry.name.startsWith('@')) {
      const scopeDir = resolveDir(entryPath, entry, ctx);
      if (!scopeDir) continue;
      for (const scoped of readDirEntries(scopeDir)) {
        if (scoped.name.startsWith('.')) continue;
        scanPackageDir(path.join(entryPath, scoped.name), scoped, `${entry.name}/${scoped.name}`, ctx, depth);
      }
      continue;
    }
    scanPackageDir(entryPath, entry, entry.name, ctx, depth);
  }
}

function scanPackageDir(pkgPath, dirent, pkgName, ctx, depth) {
  const dir = resolveDir(pkgPath, dirent, ctx);
  if (!dir) return;
  const real = realpathOr(dir);
  if (ctx.stats.seen.has(real)) return;
  ctx.stats.seen.add(real);

  ctx.stats.packagesScanned++;
  const pkgJson = readJsonSafe(path.join(pkgPath, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
  if (pkgJson && pkgJson.scripts) {
    ctx.findings.push(...checkScripts(pkgJson.scripts, pkgJson.name || pkgName, ctx.project, pkgPath));
  }
  scanNodeModules(path.join(pkgPath, 'node_modules'), ctx, depth + 1);
}

// Directory path for a dirent: real directories as-is, symlinks only if they resolve
// to a directory inside ctx.root.
function resolveDir(p, dirent, ctx) {
  if (dirent.isDirectory()) return p;
  if (!dirent.isSymbolicLink()) return null;
  let real;
  try { real = fs.realpathSync(p); } catch { return null; }
  if (real !== ctx.root && !real.startsWith(ctx.root + path.sep)) return null;
  const st = statSafe(real);
  return st && st.isDirectory() ? p : null;
}

// Script paths are reported as npm scripts write them, identically on every OS.
function toPosix(p) {
  return p.split(path.sep).join('/');
}

function realpathOr(p) {
  try { return fs.realpathSync(p); } catch { return path.resolve(p); }
}

function readDirEntries(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
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
    const localRequire = text.match(LOCAL_REQUIRE_EVAL);
    const matched = localRequire ? [] : matchPatterns(SCRIPT_PATTERNS, text);
    const scriptFiles = [];
    const refs = localRequire ? resolveRequire(localRequire[3], pkgDir) : referencedScriptFiles(text, pkgDir);

    for (const ref of refs) {
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
      script: sanitizeExcerpt(script, 500),
      script_files: scriptFiles,
      triggers: labels,
      path: pkgDir,
      text: `${packageName} has suspicious "${hook}" script: ${labels.join(', ')}`,
    });
  }

  return hits;
}

// Node's resolution for a local require: exact file, known extensions, then index files.
function resolveRequire(spec, pkgDir) {
  if (!pkgDir) return [];
  const root = path.resolve(pkgDir);
  const base = path.resolve(root, spec);
  if (base !== root && !base.startsWith(root + path.sep)) return [];
  const candidates = [base, ...['.js', '.cjs', '.mjs'].map(e => base + e), ...['index.js', 'index.cjs'].map(i => path.join(base, i))];
  const found = candidates.find(c => { const st = statSafe(c); return st && st.isFile(); });
  return found ? [{ abs: found, rel: toPosix(path.relative(root, found)) }] : [];
}

// Files referenced as `node x.js`, `sh ./install.sh`, ... resolved inside pkgDir only.
function referencedScriptFiles(script, pkgDir) {
  const refs = [];
  if (!pkgDir) return refs;
  const root = path.resolve(pkgDir);
  for (const m of script.matchAll(SCRIPT_FILE_REF)) {
    const abs = path.resolve(root, m[1]);
    if (abs !== root && !abs.startsWith(root + path.sep)) continue;
    if (!refs.some(r => r.abs === abs)) refs.push({ abs, rel: toPosix(path.relative(root, abs)) });
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
