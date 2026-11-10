'use strict';

const fs = require('fs');
const path = require('path');
const { readJsonSafe, readFileSafe, statSafe, existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');
const { sanitizeExcerpt } = require('../utils/text');
const {
  COMMAND_PATTERNS, LOCAL_REQUIRE_EVAL, resolveRequire, referencedScriptFiles,
  inspectScriptFile, matchPatterns, worstSeverity,
} = require('../utils/script-inspect');

const SCANNER_ID = 'lifecycle-scripts';

const LIFECYCLE_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  'prepublish', 'prepare',
];

const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_SCRIPT_CHARS = 4096;
const MAX_GYP_BYTES = 256 * 1024;
const MAX_NESTING = 6;

// package.json files read at the same time. On Windows most of a read is the antivirus scan
// of the opened file, and those scans overlap; 8 keeps the burst small.
const READ_CONCURRENCY = 8;

/**
 * Two phases: a synchronous walk decides which package folders to check (cheap: directory
 * listings only), then their package.json files are read in parallel and checked.
 */
async function scan(platform, opts = {}, npmProjects) {
  const projects = npmProjects || [];
  const findings = [];
  const stats = {
    packagesScanned: 0, linksResolved: 0, packageJsonReads: 0, hiddenLockfiles: 0, viaHidden: 0, viaWalk: 0,
    pnpmStores: 0, pnpmRecords: 0, viaPnpmRecord: 0, seen: new Set(), queue: [],
  };
  timing.reset();
  const pnpmOverrides = pnpmAllowAllConfigured(platform);

  for (const proj of projects) {
    const projectDir = proj.project_path;
    if (!projectDir) continue;
    const project = proj.project || projectDir;

    const projPkgJson = readJsonSafe(path.join(projectDir, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
    if (projPkgJson && projPkgJson.scripts) {
      findings.push(...checkScripts(projPkgJson.scripts, projPkgJson.name || path.basename(projectDir), project, projectDir));
    }
    if (projPkgJson) findings.push(...urlDependencies(projPkgJson, projPkgJson.name || path.basename(projectDir), project, projectDir, true));
    const root = realpathOr(projectDir);
    scanNodeModulesRoot(path.join(projectDir, 'node_modules'), { project, root, findings, stats, pnpmOverrides }, path.join(root, 'node_modules'));
  }

  for (const nmDir of globalNodeModulesDirs(platform)) {
    const root = realpathOr(nmDir);
    scanNodeModulesRoot(nmDir, { project: '(global)', root, findings, stats, pnpmOverrides }, root);
  }

  const t0 = process.hrtime.bigint();
  await processQueue(stats.queue, findings, stats);
  timing.totals.read_package_json += Number(process.hrtime.bigint() - t0) / 1e6;

  if (findings.length > 0) {
    logger.warn(SCANNER_ID, `Found ${findings.length} suspicious lifecycle scripts in ${stats.packagesScanned} packages`);
  } else {
    logger.info(SCANNER_ID, `Scanned ${stats.packagesScanned} packages, no suspicious lifecycle scripts`);
  }

  return {
    ecosystem: SCANNER_ID,
    packages_scanned: stats.packagesScanned,
    projects_scanned: projects.length,
    links_resolved: stats.linksResolved,
    package_json_reads: stats.packageJsonReads,
    hidden_lockfiles_used: stats.hiddenLockfiles,
    packages_via_hidden_lockfile: stats.viaHidden,
    packages_via_walk: stats.viaWalk,
    pnpm_stores_walked: stats.pnpmStores,
    pnpm_build_records_used: stats.pnpmRecords,
    packages_via_pnpm_record: stats.viaPnpmRecord,
    read_concurrency: READ_CONCURRENCY,
    // Where the time went, for diagnosing slow endpoints (milliseconds).
    timing_ms: timing.snapshot(),
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

const MAX_HIDDEN_LOCKFILE_BYTES = 64 * 1024 * 1024;

/**
 * npm (7+) writes node_modules/.package-lock.json on every install, from the packages it
 * actually installed, marking those with install scripts (hasInstallScript). When it is
 * present and not older than node_modules, only those packages' package.json files need
 * reading — on Windows endpoints each file open costs ~25 ms of antivirus scanning, so this
 * is the difference between seconds and minutes. The committed package-lock.json is not
 * used for this: a repository could ship one without the flags.
 * Falls back to walking node_modules (yarn, pnpm, older npm, or a stale hidden lockfile).
 */
function scanNodeModulesRoot(nmDir, ctx, realNm) {
  const hidden = path.join(nmDir, '.package-lock.json');
  const hiddenStat = statSafe(hidden);
  const nmStat = hiddenStat && statSafe(nmDir);
  if (hiddenStat && nmStat && hiddenStat.mtimeMs + 1000 >= nmStat.mtimeMs) {
    const data = readJsonSafe(hidden, { maxBytes: MAX_HIDDEN_LOCKFILE_BYTES });
    if (data && data.packages && typeof data.packages === 'object') {
      ctx.stats.hiddenLockfiles++;
      scanFromHiddenLockfile(data.packages, path.dirname(nmDir), ctx);
      return;
    }
  }
  if (!ctx.pnpmOverrides && scanFromPnpmRecord(nmDir, ctx)) return;
  scanNodeModules(nmDir, ctx, 0, realNm);
}

function scanFromHiddenLockfile(packages, baseDir, ctx) {
  const base = path.resolve(baseDir);
  for (const [rel, info] of Object.entries(packages)) {
    if (!rel || !info || typeof info !== 'object' || info.link) continue; // a link's target has its own entry
    const pkgPath = path.resolve(base, ...rel.split('/'));
    if (!pkgPath.startsWith(base + path.sep)) continue;
    if (ctx.stats.seen.has(pkgPath)) continue;
    ctx.stats.seen.add(pkgPath);
    ctx.stats.packagesScanned++;
    ctx.stats.viaHidden++;
    const name = info.name || rel.split('node_modules/').pop();
    const remote = remoteTarball(info.resolved);
    if (remote) ctx.findings.push(urlFinding(name, ctx.project, pkgPath, 'resolved', info.resolved, remote));
    if (!info.hasInstallScript) continue;
    ctx.stats.queue.push({ pkgPath, name, project: ctx.project, urlDeps: false });
  }
}

/**
 * pnpm 10+ blocks dependency install scripts unless allowed, and records the packages it
 * blocked in node_modules/.modules.yaml ("ignoredBuilds"; JSON despite the name). Together
 * with the allowed list (onlyBuiltDependencies in package.json or pnpm-workspace.yaml) that
 * is every package with an install script or binding.gyp, so only those are read instead of
 * every package in the .pnpm store. Like npm's hidden lockfile it is written locally by the
 * package manager, not shipped by the repository.
 *
 * Not used (full walk instead) when the record is missing, older than node_modules, from
 * pnpm < 10 or another layout, when "allow all builds" / neverBuiltDependencies is set, or
 * when a recorded package cannot be located.
 */
const MAX_PNPM_RECORD_BYTES = 8 * 1024 * 1024;

function scanFromPnpmRecord(nmDir, ctx) {
  const recordPath = path.join(nmDir, '.modules.yaml');
  const st = statSafe(recordPath);
  if (!st || !st.isFile() || st.size > MAX_PNPM_RECORD_BYTES) return false;
  const nmStat = statSafe(nmDir);
  if (!nmStat || st.mtimeMs + 1000 < nmStat.mtimeMs) return false;
  let record;
  try { record = JSON.parse(readFileSafe(recordPath, { maxBytes: MAX_PNPM_RECORD_BYTES }) || ''); } catch { return false; }
  const major = parseInt((String(record && record.packageManager || '').match(/^pnpm@(\d+)/) || [])[1], 10);
  if (!(major >= 10) || !Array.isArray(record.ignoredBuilds)) return false;
  if ((record.nodeLinker && record.nodeLinker !== 'isolated') || (record.virtualStoreDir && record.virtualStoreDir !== '.pnpm')) return false;

  const projectDir = path.dirname(nmDir);
  const allowed = pnpmAllowedBuilds(projectDir);
  if (allowed == null) return false; // allow-all configured for this project

  const storeDir = path.join(nmDir, '.pnpm');
  const entries = readDirEntries(storeDir).filter(e => e.isDirectory() && e.name !== 'node_modules');
  const storeName = (name) => name.replace(/\//g, '+');
  const queued = [];
  for (const spec of record.ignoredBuilds) {
    const at = String(spec).lastIndexOf('@');
    if (at <= 0) return false;
    const name = spec.slice(0, at);
    const prefix = storeName(spec);
    const hits = entries.filter(e => e.name === prefix || e.name.startsWith(prefix + '_') || e.name.startsWith(prefix + '('));
    if (hits.length === 0) return false; // e.g. a hashed long name: walk instead
    for (const e of hits) queued.push({ pkgPath: path.join(storeDir, e.name, 'node_modules', ...name.split('/')), name });
  }
  for (const name of allowed) {
    const prefix = storeName(name) + '@';
    for (const e of entries.filter(x => x.name.startsWith(prefix))) {
      queued.push({ pkgPath: path.join(storeDir, e.name, 'node_modules', ...name.split('/')), name });
    }
  }

  ctx.stats.pnpmRecords++;
  ctx.stats.packagesScanned += entries.length;
  for (const q of queued) {
    if (ctx.stats.seen.has(q.pkgPath)) continue;
    ctx.stats.seen.add(q.pkgPath);
    ctx.stats.viaPnpmRecord++;
    ctx.stats.queue.push({ ...q, project: ctx.project, urlDeps: false });
  }
  // Dependencies fetched from a URL (not read from package.json on this path)
  const lock = readFileSafe(path.join(storeDir, 'lock.yaml'), { maxBytes: 64 * 1024 * 1024, skipLarger: true });
  for (const m of (lock || '').matchAll(/^ {2}'?([^\s'][^\n]*?)'?:\s*\n\s+resolution:\s*\{[^}\n]*\btarball:\s*([^,}\s]+)/gm)) {
    const info = remoteTarball(m[2]);
    if (!info) continue;
    const key = m[1];
    const name = key.slice(0, key.indexOf('@', 1)) || key;
    ctx.findings.push(urlFinding(name, ctx.project, storeDir, 'resolved', m[2], info));
  }
  return true;
}

// Names pnpm is allowed to build for this project, or null when all builds are allowed.
function pnpmAllowedBuilds(projectDir) {
  const names = new Set();
  const pkg = readJsonSafe(path.join(projectDir, 'package.json'), { maxBytes: MAX_PACKAGE_JSON_BYTES });
  const cfg = (pkg && pkg.pnpm) || {};
  if (cfg.dangerouslyAllowAllBuilds === true || cfg.neverBuiltDependencies) return null;
  for (const n of Array.isArray(cfg.onlyBuiltDependencies) ? cfg.onlyBuiltDependencies : []) if (typeof n === 'string') names.add(n);
  for (const [n, v] of Object.entries(cfg.allowBuilds || {})) if (v === true) names.add(n);

  const ws = readFileSafe(path.join(projectDir, 'pnpm-workspace.yaml'), { maxBytes: 1024 * 1024 });
  if (ws) {
    if (/^dangerouslyAllowAllBuilds:\s*true\b/m.test(ws) || /^neverBuiltDependencies:/m.test(ws)) return null;
    let section = null;
    for (const line of ws.split(/\r?\n/)) {
      if (/^\S/.test(line)) { section = (line.match(/^(onlyBuiltDependencies|allowBuilds):/) || [])[1] || null; continue; }
      if (section === 'onlyBuiltDependencies') {
        const m = line.match(/^\s+-\s+['"]?([^'"\s#]+)/);
        if (m) names.add(m[1]);
      } else if (section === 'allowBuilds') {
        const m = line.match(/^\s+['"]?([^'":\s#]+)['"]?\s*:\s*true\b/);
        if (m) names.add(m[1]);
      }
    }
  }
  const rc = readFileSafe(path.join(projectDir, '.npmrc'), { maxBytes: 256 * 1024 });
  if (rc && /^\s*(dangerously-allow-all-builds\s*=\s*true|never-built-dependencies\s*=)/m.test(rc)) return null;
  return names;
}

// "Allow all builds" set in a user's global npm/pnpm config disables the pnpm shortcut.
function pnpmAllowAllConfigured(platform) {
  for (const home of platform.userHomes || []) {
    for (const rel of [['.npmrc'], ['AppData', 'Local', 'pnpm', 'config', 'rc'], ['.config', 'pnpm', 'rc'], ['Library', 'Preferences', 'pnpm', 'rc']]) {
      const text = readFileSafe(path.join(home, ...rel), { maxBytes: 256 * 1024 });
      if (text && /^\s*(dangerously-allow-all-builds\s*=\s*true|never-built-dependencies\s*=)/m.test(text)) return true;
    }
  }
  return false;
}

/** Reads each queued package.json (READ_CONCURRENCY at a time) and runs the checks in queue order. */
async function processQueue(queue, findings, stats) {
  const results = new Array(queue.length);
  let next = 0;
  const worker = async () => {
    while (next < queue.length) {
      const i = next++;
      const item = queue[i];
      const [pkgJson, hasGyp] = await Promise.all([
        readJsonAsync(path.join(item.pkgPath, 'package.json')),
        isFileAsync(path.join(item.pkgPath, 'binding.gyp')),
      ]);
      results[i] = { pkgJson, hasGyp };
    }
  };
  await Promise.all(Array.from({ length: Math.min(READ_CONCURRENCY, queue.length) }, worker));
  stats.packageJsonReads += queue.length;

  for (let i = 0; i < queue.length; i++) {
    const { pkgPath, name, project, urlDeps } = queue[i];
    const { pkgJson, hasGyp } = results[i];
    const pkgName = (pkgJson && pkgJson.name) || name;
    if (pkgJson && pkgJson.scripts) findings.push(...checkScripts(pkgJson.scripts, pkgName, project, pkgPath));
    if (pkgJson && urlDeps) findings.push(...urlDependencies(pkgJson, pkgName, project, pkgPath, false));
    if (hasGyp) findings.push(...checkBindingGyp(pkgPath, pkgJson, pkgName, { project }));
  }
}

// readJsonSafe semantics (regular files only, size cap, null on any error), asynchronously.
async function readJsonAsync(file) {
  let fh;
  try {
    fh = await fs.promises.open(file, 'r');
    const st = await fh.stat();
    if (!st.isFile() || st.size > MAX_PACKAGE_JSON_BYTES) return null;
    const text = (await fh.readFile({ encoding: 'utf8' }));
    return JSON.parse(text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text);
  } catch {
    return null;
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

async function isFileAsync(file) {
  try { return (await fs.promises.stat(file)).isFile(); } catch { return false; }
}

/**
 * Walks node_modules: scoped, nested, and pnpm's .pnpm store. Symlinked packages
 * (pnpm, npm/yarn workspaces) are followed only when they resolve inside ctx.root,
 * and each real package directory is scanned once.
 *
 * Real paths are built by joining names onto the parent's real path; only links are
 * resolved (once, natively). Resolving every directory was the dominant cost on
 * Windows, where each path component costs an antivirus-scanned filesystem call.
 */
function scanNodeModules(nmDir, ctx, depth, realNm) {
  if (depth > MAX_NESTING) return;
  for (const entry of readDirEntries(nmDir)) {
    const entryPath = path.join(nmDir, entry.name);
    const entryReal = path.join(realNm, entry.name);

    if (entry.name === '.pnpm') {
      ctx.stats.pnpmStores++;
      for (const store of readDirEntries(entryPath)) {
        const r = resolveDir(path.join(entryPath, store.name), store, ctx, path.join(entryReal, store.name));
        if (r) scanNodeModules(path.join(r.path, 'node_modules'), ctx, depth + 1, path.join(r.real, 'node_modules'));
      }
      continue;
    }
    if (entry.name.startsWith('.')) continue;

    if (entry.name.startsWith('@')) {
      const scope = resolveDir(entryPath, entry, ctx, entryReal);
      if (!scope) continue;
      for (const scoped of readDirEntries(scope.path)) {
        if (scoped.name.startsWith('.')) continue;
        scanPackageDir(path.join(entryPath, scoped.name), scoped, `${entry.name}/${scoped.name}`, ctx, depth, path.join(scope.real, scoped.name));
      }
      continue;
    }
    scanPackageDir(entryPath, entry, entry.name, ctx, depth, entryReal);
  }
}

function scanPackageDir(pkgPath, dirent, pkgName, ctx, depth, realGuess) {
  const r = resolveDir(pkgPath, dirent, ctx, realGuess);
  if (!r) return;
  if (ctx.stats.seen.has(r.real)) return;
  ctx.stats.seen.add(r.real);

  ctx.stats.packagesScanned++;
  ctx.stats.viaWalk++;
  ctx.stats.queue.push({ pkgPath, name: pkgName, project: ctx.project, urlDeps: true });
  scanNodeModules(path.join(pkgPath, 'node_modules'), ctx, depth + 1, path.join(r.real, 'node_modules'));
}

// { path, real } for a dirent: real directories keep their computed real path; symlinks
// are resolved and followed only if they land on a directory inside ctx.root.
function resolveDir(p, dirent, ctx, realGuess) {
  if (dirent.isDirectory()) return { path: p, real: realGuess };
  if (!dirent.isSymbolicLink()) return null;
  ctx.stats.linksResolved++;
  let real;
  try { real = timing.measure('resolve_links', () => fs.realpathSync.native(p)); } catch { return null; }
  if (real !== ctx.root && !real.startsWith(ctx.root + path.sep)) return null;
  const st = statSafe(real);
  return st && st.isDirectory() ? { path: p, real } : null;
}

function realpathOr(p) {
  try { return fs.realpathSync.native(p); } catch { return path.resolve(p); }
}

function readDirEntries(dir) {
  return timing.measure('list_dirs', () => {
    try {
      return fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return [];
    }
  });
}

// Cumulative time per filesystem activity within one scan.
const timing = {
  totals: {},
  reset() { this.totals = { list_dirs: 0, read_package_json: 0, resolve_links: 0, read_script_files: 0, binding_gyp: 0 }; },
  measure(key, fn) {
    const t = process.hrtime.bigint();
    try { return fn(); } finally { this.totals[key] += Number(process.hrtime.bigint() - t) / 1e6; }
  },
  snapshot() { return Object.fromEntries(Object.entries(this.totals).map(([k, v]) => [k, Math.round(v)])); },
};
timing.reset();

function checkScripts(scripts, packageName, project, pkgDir) {
  const hits = [];

  for (const hook of LIFECYCLE_HOOKS) {
    const script = scripts[hook];
    if (!script || typeof script !== 'string') continue;

    const text = script.slice(0, MAX_SCRIPT_CHARS);
    const localRequire = text.match(LOCAL_REQUIRE_EVAL);
    const matched = localRequire ? [] : matchPatterns(COMMAND_PATTERNS, text);
    const scriptFiles = [];
    const refs = localRequire ? resolveRequire(localRequire[3], pkgDir) : referencedScriptFiles(text, pkgDir);

    for (const ref of refs) {
      const fileHits = timing.measure('read_script_files', () => inspectScriptFile(ref.abs, ref.rel));
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

/**
 * PhantomRaven-style "remote dynamic dependencies": a dependency given as an http(s) URL
 * is fetched from that server at install time, outside the registry and its malware
 * scanning. Registry tarballs (any host, including private registries) have the
 * "/<name>/-/<name>-<version>.tgz" shape; git and GitHub shorthands are not flagged.
 */
const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];

function remoteTarball(spec) {
  if (typeof spec !== 'string' || !/^https?:\/\//i.test(spec)) return null;
  let u;
  try { u = new URL(spec); } catch { return null; }
  if (/\/-\/[^/]+\.tgz$/i.test(u.pathname)) return null;
  if (/^(codeload\.github\.com|github\.com|gitlab\.com|bitbucket\.org)$/i.test(u.hostname)) return null;
  const ip = /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname);
  return { host: u.hostname, plaintext: u.protocol === 'http:', ip };
}

function urlFinding(pkgName, project, pkgPath, dep, spec, info) {
  const triggers = ['url-dependency', ...(info.plaintext ? ['plaintext-http'] : []), ...(info.ip ? ['ip-address-url'] : [])];
  return {
    severity: info.plaintext || info.ip ? 'high' : 'medium',
    type: 'remote_url_dependency',
    ecosystem: 'npm',
    package: pkgName,
    project,
    dependency: dep,
    url: sanitizeExcerpt(spec, 300),
    triggers,
    path: pkgPath,
    text: dep === 'resolved'
      ? `${pkgName} was installed from ${info.host}, outside a package registry (${triggers.join(', ')})`
      : `${pkgName} depends on "${dep}" fetched from ${info.host}, outside a package registry (${triggers.join(', ')})`,
  };
}

function urlDependencies(pkgJson, pkgName, project, pkgPath, includeDev) {
  const out = [];
  for (const field of includeDev ? [...DEP_FIELDS, 'devDependencies'] : DEP_FIELDS) {
    const deps = pkgJson[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [dep, spec] of Object.entries(deps)) {
      const info = remoteTarball(spec);
      if (info) out.push(urlFinding(pkgName, project, pkgPath, dep, spec, info));
    }
  }
  return out;
}

/**
 * binding.gyp "<!(cmd)" / "<!@(cmd)" expansions run commands when node-gyp configures the
 * package, with no install script in package.json (Phantom Gyp). Common legit forms,
 * node -p "require('node-addon-api').include", pkg-config and similar, are left alone;
 * flagged are network fetches and other high-signal commands, and commands that run a
 * script file (which is then inspected).
 */
const GYP_COMMAND_PATTERNS = [
  { pattern: /\b(curl|wget|Invoke-WebRequest|iwr|Invoke-Expression|iex)\b/i, label: 'gyp-network-or-eval', severity: 'critical' },
  { pattern: /\bpowershell\b[^\n]{0,200}\s-e(nc(oded(command)?)?)?\b/i, label: 'powershell-encoded', severity: 'critical' },
  { pattern: /https?:\/\//, label: 'gyp-url', severity: 'high' },
  { pattern: /base64\s+(-d|--decode)|\batob\s*\(|Buffer\.from\s*\(/, label: 'base64-decode', severity: 'high' },
  { pattern: /(\/dev\/tcp\/|\bnc\b[^\n]{0,200}\s-e\b)/, label: 'reverse-shell', severity: 'critical' },
];

function gypCommands(text) {
  const cmds = [];
  const re = /<!@?\(/g;
  let m;
  while ((m = re.exec(text)) && cmds.length < 50) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    for (; i < text.length && i - start < 1000 && depth > 0; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') depth--;
    }
    if (depth === 0) cmds.push(text.slice(start, i - 1));
  }
  return cmds;
}

function checkBindingGyp(pkgPath, pkgJson, pkgName, ctx) {
  const gypPath = path.join(pkgPath, 'binding.gyp');
  const text = timing.measure('binding_gyp', () => {
    const st = statSafe(gypPath);
    return st && st.isFile() ? readFileSafe(gypPath, { maxBytes: MAX_GYP_BYTES }) : null;
  });
  if (!text) return [];
  const matched = [];
  const files = [];
  const commands = [];
  const main = pkgJson && typeof pkgJson.main === 'string' ? path.resolve(pkgPath, pkgJson.main) : null;
  for (const cmd of gypCommands(text)) {
    const hits = matchPatterns(GYP_COMMAND_PATTERNS, cmd);
    for (const ref of referencedScriptFiles(cmd, pkgPath)) {
      const entry = ref.abs === main || /^index\.[cm]?js$/i.test(path.basename(ref.abs));
      hits.push({ label: entry ? 'gyp-runs-package-entry' : 'gyp-runs-script', severity: entry ? 'high' : 'medium' });
      const fileHits = timing.measure('read_script_files', () => inspectScriptFile(ref.abs, ref.rel));
      hits.push(...fileHits);
      files.push(ref.rel);
    }
    if (hits.length > 0) { matched.push(...hits); commands.push(cmd); }
  }
  if (matched.length === 0) return [];
  const labels = [...new Set(matched.map(m => m.label))];
  return [{
    severity: worstSeverity(matched),
    type: 'suspicious_lifecycle_script',
    ecosystem: 'npm',
    package: pkgName,
    project: ctx.project,
    hook: 'binding.gyp',
    script: sanitizeExcerpt(commands.map(c => `<!(${c})`).join(' '), 500),
    script_files: [...new Set(files)],
    triggers: labels,
    path: pkgPath,
    text: `${pkgName} runs commands from binding.gyp at build time: ${labels.join(', ')}`,
  }];
}

module.exports = { scan, SCANNER_ID, checkScripts, checkBindingGyp, remoteTarball, gypCommands };
