'use strict';

const fs = require('fs');
const path = require('path');
const { readJsonSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'ai-apps';
const DEFAULT_CATALOG = path.resolve(__dirname, '..', '..', 'data', 'ai-apps.json');

/**
 * Presence of common AI apps from a small data file (data/ai-apps.json). This covers apps
 * with no structural footprint (e.g. ChatGPT desktop); everything else is found by
 * structure elsewhere. Only checks whether locations exist; never reads app data.
 */
function scan(platform, opts = {}) {
  const catalog = readJsonSafe(opts.catalogPath || DEFAULT_CATALOG) || { apps: [] };
  const osKey = platform.id === 'windows' ? 'windows' : platform.id === 'darwin' ? 'darwin' : 'linux';
  const found = [];

  for (const app of (catalog.apps || [])) {
    const patterns = [...(app.all || []), ...(app[osKey] || [])];
    for (const home of (platform.userHomes || [])) {
      const evidence = [];
      for (const pattern of patterns) {
        const expanded = expand(pattern, home, platform);
        if (expanded) evidence.push(...matchPath(expanded));
      }
      if (evidence.length > 0) {
        found.push({ id: app.id, name: app.name, vendor: app.vendor, kind: app.kind, user: path.basename(home), evidence: [...new Set(evidence)] });
      }
    }
  }

  // System-wide installs (e.g. /Applications) are attributed once, not per user.
  const seen = new Set();
  const apps = found.filter(a => {
    const key = `${a.id}:${a.evidence.join('|')}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  logger.info(SCANNER_ID, `Known AI apps present: ${[...new Set(apps.map(a => a.id))].length}`);
  return { ecosystem: SCANNER_ID, catalog_reviewed: catalog.last_reviewed || null, apps };
}

// Pattern -> absolute path for this home, or null when it does not apply.
function expand(pattern, home, platform) {
  if (pattern.startsWith('~/')) return path.join(home, ...pattern.slice(2).split('/'));
  if (pattern.startsWith('%APPDATA%/')) return path.join(home, 'AppData', 'Roaming', ...pattern.slice(10).split('/'));
  if (pattern.startsWith('%LOCALAPPDATA%/')) return path.join(home, 'AppData', 'Local', ...pattern.slice(15).split('/'));
  if (pattern.startsWith('/')) return platform.usersRoot ? null : pattern;
  return null;
}

// Existing paths matching an absolute pattern; '*' is allowed in the last segment only.
function matchPath(p) {
  const dir = path.dirname(p);
  const last = path.basename(p);
  if (!last.includes('*')) {
    if (statSafe(p)) return [p];
    // Case-insensitive fallback for case-sensitive filesystems.
    return listNames(dir).filter(n => n.toLowerCase() === last.toLowerCase()).map(n => path.join(dir, n));
  }
  const re = new RegExp(`^${last.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i');
  return listNames(dir).filter(n => re.test(n)).map(n => path.join(dir, n));
}

function listNames(dir) {
  try { return fs.readdirSync(dir); } catch { return []; }
}

module.exports = { scan, SCANNER_ID, expand, matchPath };
