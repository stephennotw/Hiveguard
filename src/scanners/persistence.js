'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, statSafe } = require('../utils/fs-safe');
const { sanitizeExcerpt } = require('../utils/text');
const logger = require('../utils/logger');
const {
  FILE_PATTERNS, referencedScriptFiles, inspectScriptFile, matchPatterns, worstSeverity, isIocFilename,
} = require('../utils/script-inspect');

const SCANNER_ID = 'persistence';
const MAX_ENTRY_BYTES = 256 * 1024;
const MAX_ENTRIES_PER_DIR = 500;
const MAX_TASK_FILES = 2000;

/**
 * Programs set to start on their own: per-user autostart locations on every OS, plus
 * the system ones that are readable (Windows scheduled task XML when run elevated, cron
 * tables when run as root). Files only: nothing is executed and no registry is read.
 *
 * Every entry is inventoried; findings are raised when the command is a script
 * interpreter running a file from a temporary, hidden or node_modules directory, when
 * the command or that file shows high-signal behaviour (download-and-run, encoded
 * PowerShell, reverse shell), or when it matches a catalog indicator. Known persistence
 * files named by catalogs (iocPaths) are checked by existence.
 */
function scan(platform, opts = {}, iocPaths = []) {
  const entries = [];
  const findings = [];
  const unreadable = [];
  const homes = platform.userHomes || [];

  for (const home of homes) {
    const vars = homeVars(home);
    for (const loc of userLocations(home)) {
      for (const file of listFiles(loc.dir)) {
        const entry = readEntry(file, loc.kind, vars);
        if (entry) entries.push(entry);
      }
    }
  }

  if (!platform.usersRoot) {
    if (platform.id === 'windows') {
      const tasksDir = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'Tasks');
      const files = walkFiles(tasksDir, MAX_TASK_FILES);
      if (files == null) unreadable.push('scheduled-tasks');
      for (const file of files || []) {
        const entry = readEntry(file, 'scheduled-task', {});
        if (entry) entries.push(entry);
      }
    } else {
      for (const dir of ['/var/spool/cron/crontabs', '/var/spool/cron', '/usr/lib/cron/tabs']) {
        for (const file of listFiles(dir)) {
          const entry = readEntry(file, 'crontab', {});
          if (entry) entries.push(entry);
        }
      }
    }
  }

  for (const e of entries) {
    const f = judge(e);
    if (f) findings.push(f);
  }

  // Catalog persistence files (~/... per profile, absolute paths once)
  const iocHits = [];
  for (const ioc of iocPaths) {
    const spec = ioc.value;
    const targets = spec.startsWith('~/')
      ? homes.map(h => path.join(h, ...spec.slice(2).split('/')))
      : platform.usersRoot ? [] : [spec];
    for (const t of targets) {
      for (const hit of globExisting(t)) iocHits.push({ path: hit, ioc });
    }
  }
  for (const { path: p, ioc } of iocHits) {
    findings.push({
      severity: 'critical',
      type: 'known_ioc_file',
      ecosystem: SCANNER_ID,
      path: p,
      ioc: ioc.source,
      triggers: ['known-persistence-file'],
      text: `File named by a threat-intel catalog is present (${ioc.source})`,
    });
  }

  logger.info(SCANNER_ID, `${entries.length} autostart entries, ${findings.length} findings`);
  return {
    ecosystem: SCANNER_ID,
    entries,
    total: entries.length,
    unreadable,
    findings,
  };
}

function homeVars(home) {
  const v = {
    '~/': home + '/', '$HOME': home, '${HOME}': home, '%USERPROFILE%': home, '%HOMEPATH%': home,
    '%APPDATA%': path.join(home, 'AppData', 'Roaming'), '%LOCALAPPDATA%': path.join(home, 'AppData', 'Local'),
    '%TEMP%': path.join(home, 'AppData', 'Local', 'Temp'), '%TMP%': path.join(home, 'AppData', 'Local', 'Temp'),
  };
  return v;
}

function userLocations(home) {
  return [
    { kind: 'launch-agent', dir: path.join(home, 'Library', 'LaunchAgents') },
    { kind: 'xdg-autostart', dir: path.join(home, '.config', 'autostart') },
    { kind: 'systemd-user', dir: path.join(home, '.config', 'systemd', 'user') },
    { kind: 'startup-folder', dir: path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') },
  ];
}

function listFiles(dir) {
  let names;
  try { names = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  return names
    .filter(e => e.isFile() || e.isSymbolicLink())
    .slice(0, MAX_ENTRIES_PER_DIR)
    .map(e => path.join(dir, e.name));
}

function walkFiles(dir, max) {
  const out = [];
  const queue = [dir];
  let first = true;
  while (queue.length > 0 && out.length < max) {
    const d = queue.shift();
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { if (first) return null; continue; }
    first = false;
    for (const e of ents) {
      if (e.isDirectory()) queue.push(path.join(d, e.name));
      else if (e.isFile()) out.push(path.join(d, e.name));
    }
  }
  return out;
}

// "dir/prefix-*" style globs in the last segment only.
function globExisting(p) {
  const base = path.basename(p);
  if (!base.includes('*')) return statSafe(p) ? [p] : [];
  const re = new RegExp('^' + base.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
  try {
    return fs.readdirSync(path.dirname(p)).filter(n => re.test(n)).slice(0, 20).map(n => path.join(path.dirname(p), n));
  } catch {
    return [];
  }
}

/** { kind, name, path, command, script_files, vars } or null. */
function readEntry(file, kind, vars) {
  const st = statSafe(file);
  if (!st || !st.isFile()) return null;
  const name = path.basename(file);
  const entry = { kind, name, path: file, command: null };
  entry._vars = vars;
  if (st.size > MAX_ENTRY_BYTES) return entry;
  const buf = readBuffer(file);
  if (!buf) return entry;
  entry.command = commandOf(kind, name, buf);
  return entry;
}

function readBuffer(file) {
  try { return fs.readFileSync(file); } catch { return null; }
}

const unxml = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

function commandOf(kind, name, buf) {
  const lower = name.toLowerCase();
  if (lower.endsWith('.lnk')) return lnkStrings(buf);
  let text = buf.toString(buf[0] === 0xFF && buf[1] === 0xFE ? 'utf16le' : 'utf8');
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  if (text.startsWith('bplist')) return null; // binary plist: listed by name only

  if (kind === 'launch-agent' || lower.endsWith('.plist')) {
    const args = text.match(/<key>\s*ProgramArguments\s*<\/key>\s*<array>([\s\S]*?)<\/array>/);
    if (args) return [...args[1].matchAll(/<string>([\s\S]*?)<\/string>/g)].map(m => unxml(m[1].trim())).join(' ');
    const prog = text.match(/<key>\s*Program\s*<\/key>\s*<string>([\s\S]*?)<\/string>/);
    return prog ? unxml(prog[1].trim()) : null;
  }
  if (kind === 'xdg-autostart' || lower.endsWith('.desktop')) {
    const m = text.match(/^Exec\s*=\s*(.+)$/m);
    return m ? m[1].trim() : null;
  }
  if (kind === 'systemd-user' || /\.(service|timer)$/.test(lower)) {
    const lines = [...text.matchAll(/^Exec(?:Start|StartPre|StartPost)\s*=\s*[-@+!:]*(.+)$/gm)].map(m => m[1].trim());
    return lines.length ? lines.join(' ; ') : null;
  }
  if (kind === 'scheduled-task') {
    const execs = [...text.matchAll(/<Exec>([\s\S]*?)<\/Exec>/g)].map(m => {
      const cmd = (m[1].match(/<Command>([\s\S]*?)<\/Command>/) || [])[1] || '';
      const args = (m[1].match(/<Arguments>([\s\S]*?)<\/Arguments>/) || [])[1] || '';
      return unxml(`${cmd.trim()} ${args.trim()}`.trim());
    }).filter(Boolean);
    return execs.length ? execs.join(' ; ') : null;
  }
  if (kind === 'crontab') {
    return text.split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !/^\w+\s*=/.test(l))
      .map(l => (l.startsWith('@') ? l.replace(/^@\S+\s+/, '') : l.split(/\s+/).slice(5).join(' ')))
      .filter(Boolean)
      .join(' ; ') || null;
  }
  // Startup folder scripts (.bat, .cmd, .vbs, .ps1, .js): the file is the command.
  return text.slice(0, 4096);
}

// Windows shortcuts are binary; the target and arguments appear as UTF-16LE or ANSI strings.
function lnkStrings(buf) {
  const strs = new Set();
  const u16 = buf.toString('utf16le');
  for (const m of u16.matchAll(/[\x20-\x7e]{6,}/g)) strs.add(m[0]);
  for (const m of buf.toString('latin1').matchAll(/[\x20-\x7e]{6,}/g)) strs.add(m[0]);
  const useful = [...strs].filter(s => /[\\/]|\.\w{2,4}\b|\s-\w/.test(s));
  return useful.length ? useful.join(' ').slice(0, 4096) : null;
}

const INTERPRETER = /(^|[\\/\s"'])(node|bun|deno|python3?|pythonw|ruby|perl|osascript|sh|bash|zsh|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?["']?(\s|$)/i;
const RISKY_DIR = /([\\/](tmp|temp|var[\\/]tmp)[\\/])|([\\/]node_modules[\\/])|([\\/]AppData[\\/]Local[\\/]Temp[\\/])|([\\/]\.(?!config[\\/]|local[\\/]bin[\\/])[\w-]+[\\/])/i;
const AUTOSTART_PATTERNS = [
  ...FILE_PATTERNS.filter(p => !['credential-file-access', 'token-env-harvest'].includes(p.label)),
  { pattern: /base64\s+(-d|--decode)|FromBase64String/i, label: 'base64-decode', severity: 'high' },
  { pattern: /\b(Invoke-Expression|iex)\b[^\n]{0,200}\b(Invoke-WebRequest|iwr|DownloadString|Net\.WebClient)\b|\b(DownloadString|Invoke-WebRequest|iwr)\b[^\n]{0,200}\|\s*(iex|Invoke-Expression)\b/i, label: 'download-and-run', severity: 'critical' },
  { pattern: /\bmshta\b[^\n]{0,200}https?:/i, label: 'mshta-remote', severity: 'critical' },
  // Hidden window plus inline code; -File with a hidden window is how many legit agents run.
  { pattern: /-w(indowstyle)?\s+hidden\b[^\n]{0,200}(\s-c(ommand)?\s|\biex\b)|(\s-c(ommand)?\s|\biex\b)[^\n]{0,200}-w(indowstyle)?\s+hidden\b/i, label: 'hidden-powershell', severity: 'high' },
];

function judge(entry) {
  const hits = [];
  const files = [];
  const cmd = entry.command || '';
  if (isIocFilename(entry.name)) hits.push({ label: 'known-worm-filename', severity: 'critical' });
  if (cmd) {
    hits.push(...matchPatterns(AUTOSTART_PATTERNS, cmd));
    const runsInterpreter = INTERPRETER.test(cmd);
    for (const ref of referencedScriptFiles(cmd, null, { allowOutside: true, vars: entry._vars })) {
      files.push(ref.abs);
      if (runsInterpreter && RISKY_DIR.test(ref.abs)) hits.push({ label: 'script-in-hidden-or-temp-dir', severity: 'high' });
      hits.push(...inspectScriptFile(ref.abs, ref.abs));
    }
    if (runsInterpreter && files.length === 0 && RISKY_DIR.test(cmd) && /\.(c?js|mjs|py|sh|ps1|vbs|rb|pl)\b/i.test(cmd)) {
      hits.push({ label: 'script-in-hidden-or-temp-dir', severity: 'high' });
    }
  }
  entry.command = cmd ? sanitizeExcerpt(cmd, 500) : null;
  entry.script_files = files;
  delete entry._vars;
  if (hits.length === 0) return null;
  const labels = [...new Set(hits.map(h => h.label))];
  const ioc = hits.find(h => h.ioc);
  return {
    severity: worstSeverity(hits),
    type: 'suspicious_autostart',
    ecosystem: SCANNER_ID,
    autostart_kind: entry.kind,
    name: entry.name,
    command: entry.command,
    script_files: files,
    triggers: labels,
    path: entry.path,
    ...(ioc ? { ioc: ioc.ioc } : {}),
    text: `${entry.kind} "${entry.name}" starts automatically: ${labels.join(', ')}`,
  };
}

module.exports = { scan, SCANNER_ID, commandOf, judge };
