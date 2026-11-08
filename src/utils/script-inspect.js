'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { readFileSafe, statSafe } = require('./fs-safe');

/**
 * Shared inspection of commands and the script files they run: npm install hooks,
 * binding.gyp command expansions, AI-agent hook commands, auto-run tasks and autostart
 * entries. Files are only read, never executed.
 */

const MAX_SCRIPT_FILE_BYTES = 64 * 1024;
const OVERSIZED_SCRIPT_FILE_BYTES = 1024 * 1024;
const MAX_HASH_BYTES = 8 * 1024 * 1024;

// Applied to a command line. All gaps are bounded ([^\n]{0,200}) so matching stays
// linear on hostile input.
const COMMAND_PATTERNS = [
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

// Applied to files a command runs. Legit installers (esbuild, node-gyp, prebuild)
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

// A "curl ... | sh" pipeline needs a shell. In JavaScript the text only matters if it
// flows into a shell call; bun's install.js, for example, keeps its installer command in a
// variable used only in an Error message, while also spawning powershell for an unrelated
// CPU check. Without data-flow analysis, two cheap checks: a shell call close to the text,
// or the variable the text is assigned to appearing in a shell call's arguments.
const SHELL_SINKS = [
  /(^|[^.\w])exec\s*\(|\.execSync\s*\(|(^|[^.\w])execSync\s*\(|\b(child_?process|childProcess|cp|import_child_process(\.default)?)\.exec\s*\(/gi,
  /\bshell\s*:\s*(true|['"])/g,
  /\b(spawn|spawnSync|execFile|execFileSync)\s*\(\s*['"`]((ba|z)?sh|cmd(\.exe)?|powershell(\.exe)?|pwsh)['"`]/g,
  /\beval\s*\(|\bnew\s+Function\s*\(/g,
];
const PIPE_TO_SHELL = /\b(curl|wget)\b[^\n]{0,200}\|\s*(bash|sh)\b/g;
const SINK_WINDOW_BEFORE = 400;
const SINK_WINDOW_AFTER = 200;
const SHELL_PIPE_LABELS = new Set(['pipe-to-shell']);

function usesIdentifier(text, identifier) {
  const escaped = identifier.replace(/[$]/g, '\\$');
  return new RegExp('(^|[^\\w$])' + escaped + '($|[^\\w$])').test(text);
}

function shellPipeReachesShell(content) {
  const sinks = [];
  for (const re of SHELL_SINKS) for (const m of content.matchAll(re)) sinks.push(m.index);
  if (sinks.length === 0) return false;
  for (const m of content.matchAll(PIPE_TO_SHELL)) {
    const start = m.index;
    const end = start + m[0].length;
    if (sinks.some(i => i >= start - SINK_WINDOW_BEFORE && i <= end + SINK_WINDOW_AFTER)) return true;
    const lineStart = content.lastIndexOf('\n', start) + 1;
    const assigned = content.slice(lineStart, start).match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=|\b([A-Za-z_$][\w$]*)\s*=\s*[^=]/);
    const name = assigned && (assigned[1] || assigned[2]);
    if (name && sinks.some(i => usesIdentifier(content.slice(i, i + 300).split(';')[0], name))) return true;
  }
  return false;
}

/**
 * Indicators of compromise. Built-in worm payload names, extended at runtime from the
 * loaded threat-intel catalogs (see src/threat-intel/iocs.js).
 */
const BUILTIN_IOC_FILES = ['setup_bun.js', 'bun_environment.js', 'router_runtime.js'];
const iocs = { filenames: new Set(BUILTIN_IOC_FILES), sha256: new Map(), strings: new Map() };

function configureIocs({ filenames = [], sha256 = [], strings = [] } = {}) {
  iocs.filenames = new Set([...BUILTIN_IOC_FILES, ...filenames.map(f => f.name || f).map(s => s.toLowerCase())]);
  iocs.sha256 = new Map(sha256.map(h => [h.value.toLowerCase(), h.source]));
  iocs.strings = new Map(strings.map(s => [s.value, s.source]));
}

function isIocFilename(name) {
  return iocs.filenames.has(String(name).toLowerCase());
}

// core-js/es5-ext/msw style: node -e "try{require('./postinstall')}catch(e){}". The eval
// only loads a local file, so the file is inspected instead of flagging the eval.
const LOCAL_REQUIRE_EVAL = /^\s*node\s+-e\s+(["'])\s*try\s*\{\s*require\(\s*(["'])(\.\/[\w./-]+)\2\s*\)\s*;?\s*\}\s*catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}\s*\1\s*$/;

const INTERPRETERS = 'node|bun|deno|sh|bash|zsh|python3?|ruby|perl|pwsh|powershell(?:\\.exe)?|cscript|wscript|osascript';
const SCRIPT_EXT = 'c?js|mjs|ts|sh|py|rb|pl|ps1|vbs|bat|cmd';
const SCRIPT_FILE_REF = new RegExp(`(?:^|[\\s;&|("'\`])(?:${INTERPRETERS})(?:\\.exe)?\\s+(?:-{1,2}[\\w-]+(?:=\\S+)?\\s+)*["']?([\\w./\\\\@~$:{}-]+\\.(?:${SCRIPT_EXT}))\\b`, 'gi');

const toPosix = (p) => p.split(path.sep).join('/');

// Node's resolution for a local require: exact file, known extensions, then index files.
function resolveRequire(spec, baseDir) {
  if (!baseDir) return [];
  const root = path.resolve(baseDir);
  const base = path.resolve(root, spec);
  if (base !== root && !base.startsWith(root + path.sep)) return [];
  const candidates = [base, ...['.js', '.cjs', '.mjs'].map(e => base + e), ...['index.js', 'index.cjs'].map(i => path.join(base, i))];
  const found = candidates.find(c => { const st = statSafe(c); return st && st.isFile(); });
  return found ? [{ abs: found, rel: toPosix(path.relative(root, found)) }] : [];
}

/**
 * Files a command runs (`node x.js`, `sh ./install.sh`, `python3 ~/.x/cat.py`).
 * Relative paths resolve against baseDir and must stay inside it unless opts.allowOutside;
 * opts.vars maps placeholders such as $HOME or ${workspaceFolder} to directories.
 */
function referencedScriptFiles(command, baseDir, opts = {}) {
  const refs = [];
  if (!baseDir && !opts.allowOutside) return refs;
  const root = baseDir ? path.resolve(baseDir) : null;
  for (const m of String(command).matchAll(SCRIPT_FILE_REF)) {
    let spec = m[1];
    for (const [k, v] of Object.entries(opts.vars || {})) spec = spec.split(k).join(v);
    if (/[$%{}]/.test(spec)) continue; // unresolved variable
    const isAbs = path.isAbsolute(spec) || /^[A-Za-z]:[\\/]/.test(spec);
    if (!isAbs && !root) continue;
    const abs = isAbs ? path.resolve(spec) : path.resolve(root, spec);
    const inside = root && (abs === root || abs.startsWith(root + path.sep));
    if (!inside && !opts.allowOutside) continue;
    if (!refs.some(r => r.abs === abs)) refs.push({ abs, rel: inside ? toPosix(path.relative(root, abs)) : abs });
  }
  return refs;
}

// Relative ES imports and requires of a script file, resolved inside root (one level).
const LOCAL_IMPORT = /\bimport\s+(?:[^'"\n;]*?\sfrom\s+)?["'](\.{1,2}\/[^"'\n]+)["']|\b(?:require|import)\(\s*["'](\.{1,2}\/[^"'\n]+)["']\s*\)/g;
function localImports(absPath, root) {
  const content = readFileSafe(absPath, { maxBytes: MAX_SCRIPT_FILE_BYTES });
  if (!content) return [];
  const out = [];
  for (const m of content.matchAll(LOCAL_IMPORT)) {
    for (const r of resolveRequire(path.relative(root, path.resolve(path.dirname(absPath), m[1] || m[2])).split(path.sep).join('/').replace(/^(?!\.)/, './'), root)) {
      if (r.abs !== absPath && !out.some(o => o.abs === r.abs)) out.push(r);
    }
    if (out.length >= 10) break;
  }
  return out;
}

/** Findings ([{label, severity}]) for one script file, plus its sha256 when it was hashed. */
function inspectScriptFile(absPath, relPath = absPath) {
  const hits = [];
  if (isIocFilename(path.basename(relPath))) hits.push({ label: 'known-worm-filename', severity: 'critical' });

  const st = statSafe(absPath);
  if (!st || !st.isFile()) return hits;
  if (st.size > OVERSIZED_SCRIPT_FILE_BYTES) hits.push({ label: 'oversized-install-script', severity: 'medium' });

  if (iocs.sha256.size > 0 && st.size <= MAX_HASH_BYTES) {
    const digest = sha256File(absPath);
    if (digest && iocs.sha256.has(digest)) hits.push({ label: 'known-malicious-hash', severity: 'critical', ioc: iocs.sha256.get(digest) });
  }

  const content = readFileSafe(absPath, { maxBytes: MAX_SCRIPT_FILE_BYTES });
  if (!content) return hits;
  hits.push(...contentHits(content, absPath));
  return hits;
}

function contentHits(content, fileName = '') {
  let hits = matchPatterns(FILE_PATTERNS, content);
  if (/\.(c?js|mjs|ts)$/i.test(fileName) && !shellPipeReachesShell(content)) {
    hits = hits.filter(h => !SHELL_PIPE_LABELS.has(h.label));
  }
  for (const [value, source] of iocs.strings) {
    if (content.includes(value)) { hits.push({ label: 'known-ioc-string', severity: 'critical', ioc: source }); break; }
  }
  return hits;
}

function sha256File(p) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); } catch { return null; }
}

function matchPatterns(patterns, text) {
  const matched = [];
  for (const { pattern, label, severity } of patterns) {
    if (pattern.test(text)) matched.push({ label, severity });
  }
  return matched;
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function worstSeverity(matched) {
  return matched.reduce((worst, m) => ((SEV_ORDER[m.severity] ?? 4) < (SEV_ORDER[worst] ?? 4) ? m.severity : worst), 'low');
}

module.exports = {
  COMMAND_PATTERNS, FILE_PATTERNS, LOCAL_REQUIRE_EVAL,
  configureIocs, isIocFilename, shellPipeReachesShell,
  resolveRequire, referencedScriptFiles, inspectScriptFile, contentHits, localImports,
  matchPatterns, worstSeverity, toPosix,
};
