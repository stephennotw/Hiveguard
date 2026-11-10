'use strict';

/**
 * File-level indicators of compromise taken from the loaded catalogs' free-form
 * _indicators blocks, by key name and value shape:
 *   - sha256: any 64-hex string value
 *   - filenames: string values of keys ending in "filename"
 *   - paths: entries of keys like persistence_files / *_paths (may start with ~/, may
 *     end in a * glob)
 *   - strings: values of keys ending in "marker", and hosts from keys ending in
 *     "endpoint", "host" or "domain", searched for in script files HiveGuard reads anyway
 * Each item keeps its source ("catalog.json: key") for the finding.
 */
const GENERIC_HOSTS = new Set([
  'github.com', 'api.github.com', 'raw.githubusercontent.com', 'gist.github.com', 'objects.githubusercontent.com',
  'registry.npmjs.org', 'npmjs.com', 'www.npmjs.com', 'pypi.org', 'files.pythonhosted.org', 'rubygems.org',
  'crates.io', 'packagist.org', 'proxy.golang.org', 'bun.sh', 'nodejs.org', 'localhost', '127.0.0.1',
]);

function extractIocs(catalogs) {
  const out = { sha256: [], filenames: [], paths: [], strings: [] };
  const seen = new Set();
  const add = (kind, value, source) => {
    const key = `${kind}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out[kind].push({ value, source });
  };
  for (const cat of catalogs || []) {
    const visit = (node, keyPath) => {
      if (typeof node === 'string') {
        const key = keyPath[keyPath.length - 1] || '';
        const listKey = keyPath.find(k => /persistence|_paths?$|_files$/i.test(k)) || '';
        const source = `${cat.file}: ${keyPath.filter(k => !/^\d+$/.test(k)).join('.')}`;
        if (/^[a-f0-9]{64}$/i.test(node)) add('sha256', node.toLowerCase(), source);
        else if (/filename$/i.test(key) && /^[\w.-]{3,100}$/.test(node)) add('filenames', node, source);
        else if (listKey && /^(~\/|\/|[A-Za-z]:\\|%\w+%)/.test(node)) add('paths', node, source);
        else if (/marker$/i.test(key) && node.length >= 12) add('strings', node, source);
        else if (/(endpoint|host|domain)$/i.test(key)) {
          const host = hostOf(node);
          if (host && !GENERIC_HOSTS.has(host)) add('strings', host, source);
        }
        return;
      }
      if (Array.isArray(node)) node.forEach((v, i) => visit(v, [...keyPath, String(i)]));
      else if (node && typeof node === 'object') for (const [k, v] of Object.entries(node)) if (!k.startsWith('_')) visit(v, [...keyPath, k]);
    };
    visit(cat.indicators || {}, []);
  }
  return out;
}

function hostOf(value) {
  const s = String(value).trim();
  try {
    return new URL(/^[a-z]+:\/\//i.test(s) ? s : `https://${s}`).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

module.exports = { extractIocs };
