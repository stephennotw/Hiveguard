'use strict';

const fs = require('fs');
const { normalizeVersion } = require('./matcher');

/**
 * Indicators given with --ioc / --ioc-file, classified by shape:
 *   sha256 hex                         -> file hash
 *   eco:name[@version]                 -> package (npm, pypi, go, cargo, composer, rubygems/gem, vscode)
 *   name@version, @scope/name[@version] -> npm package (unscoped names need npm:)
 *   ~/path, /path, C:\path, %VAR%\path -> file path (a * glob is allowed in the last segment)
 *   name.ext (no slash)                -> file name
 *   anything else (domain, URL, text)  -> string searched in script files HiveGuard reads
 */
const ECO_ALIASES = { gem: 'rubygems', vscode: 'editor-extension', 'editor-extension': 'editor-extension', npm: 'npm', pypi: 'pypi', go: 'go', cargo: 'cargo', composer: 'composer', rubygems: 'rubygems' };
const FILE_EXT = /\.(c?js|mjs|ts|sh|py|rb|pl|ps1|psm1|vbs|bat|cmd|plist|desktop|service|exe|dll|so|dylib|node|jar|lnk|scr)$/i;

function parseIoc(input) {
  const raw = String(input).trim();
  if (!raw || raw.startsWith('#')) return null;
  const source = `command line: ${raw}`;
  if (/^[a-f0-9]{64}$/i.test(raw)) return { raw, source, kind: 'sha256', value: raw.toLowerCase() };
  const eco = raw.match(/^([a-z-]+):(.+)$/i);
  if (eco && ECO_ALIASES[eco[1].toLowerCase()]) return pkg(raw, source, ECO_ALIASES[eco[1].toLowerCase()], eco[2]);
  if (/^(~[\\/]|\/|[A-Za-z]:[\\/]|%\w+%[\\/])/.test(raw)) return { raw, source, kind: 'path', value: raw.replace(/^~\\/, '~/') };
  if (/^(@[\w.-]+\/)?[\w.-]+@v?\d[\w.+-]*$/.test(raw)) return pkg(raw, source, 'npm', raw);
  if (/^@[\w.-]+\/[\w.-]+$/.test(raw)) return pkg(raw, source, 'npm', raw); // scoped npm name, any version
  if (!/[\\/\s]/.test(raw) && FILE_EXT.test(raw)) return { raw, source, kind: 'filename', value: raw };
  if (raw.length < 6) return { raw, source, kind: 'invalid', value: raw, error: 'too short to search for' };
  let value = raw;
  if (/^https?:\/\//i.test(raw)) {
    try { value = new URL(raw).hostname; } catch { /* keep as text */ }
  }
  return { raw, source, kind: 'string', value };
}

function pkg(raw, source, ecosystem, spec) {
  const at = spec.lastIndexOf('@');
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? normalizeVersion(spec.slice(at + 1)) : null;
  return { raw, source, kind: 'package', ecosystem, name, version, value: version ? `${name}@${version}` : name };
}

function parseIocs(values = [], file = null) {
  const items = [...values];
  if (file) items.push(...fs.readFileSync(file, 'utf8').split(/\r?\n/));
  const seen = new Set();
  const out = [];
  for (const v of items) {
    const ioc = parseIoc(v);
    if (!ioc || seen.has(ioc.source)) continue;
    seen.add(ioc.source);
    out.push(ioc);
  }
  return out;
}

/** Inventoried packages matching a package IOC (name case-insensitive; any version when none given). */
function matchPackageIoc(ioc, packages) {
  const name = ioc.name.toLowerCase();
  return packages.filter(p => p.ecosystem === ioc.ecosystem
    && String(p.name).toLowerCase() === name
    && (!ioc.version || normalizeVersion(p.version || '') === ioc.version));
}

module.exports = { parseIoc, parseIocs, matchPackageIoc };
