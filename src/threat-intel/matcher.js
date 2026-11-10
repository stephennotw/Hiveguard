'use strict';

const logger = require('../utils/logger');

/**
 * Build a threat index from an in-memory catalog Map.
 * Accepts: Map<filename, parsedJSON> from loadThreatIntel()
 * Returns: { catalogs[], threatIndex Map, totalEntries, totalVersions }
 */
function buildIndex(inMemoryCatalogs) {
  const catalogs = [];
  const threatIndex = new Map();
  let totalEntries = 0;
  let totalVersions = 0;

  if (!inMemoryCatalogs || inMemoryCatalogs.size === 0) {
    logger.warn('matcher', 'No threat intel catalogs available');
    return { catalogs, threatIndex, totalEntries, totalVersions };
  }

  for (const [file, cat] of inMemoryCatalogs) {
    try {
      const campaignName = (cat._comment || file).replace(/\.json$/, '').replace(/[-_]/g, ' ');
      const sourceTag = cat._source || 'unknown';
      const catalog = {
        file,
        campaignName,
        comment: cat._comment || '',
        indicators: cat._indicators || {},
        entries: cat.entries || [],
        source: sourceTag,
      };
      catalogs.push(catalog);

      for (const entry of (cat.entries || [])) {
        totalEntries++;
        for (const ver of (entry.versions || [])) {
          totalVersions++;
          const key = buildKey(entry.ecosystem, entry.package, ver);
          if (!threatIndex.has(key)) threatIndex.set(key, []);
          threatIndex.get(key).push({
            catalog: file,
            campaignName,
            attackType: entry.name || campaignName,
            source: entry.source || '',
            indicators: cat._indicators || {},
            catalogSource: sourceTag,
            entry,
          });
        }
      }
    } catch (e) {
      logger.error('matcher', `Failed to index catalog ${file}: ${e.message}`);
    }
  }

  logger.info('matcher', `Indexed ${catalogs.length} catalogs, ${totalEntries} entries, ${totalVersions} known-bad versions`);
  return { catalogs, threatIndex, totalEntries, totalVersions };
}

/**
 * Match a flat list of packages against the threat index.
 * Each package must have: { ecosystem, name, version }
 * Returns array of matches with full threat context.
 */
function matchPackages(packages, threatIndex) {
  const matches = [];

  for (const pkg of packages) {
    const key = buildKey(pkg.ecosystem, pkg.name, pkg.version);
    const threats = threatIndex.get(key);
    if (threats && threats.length > 0) {
      matches.push({
        ...pkg,
        threats: threats.map(t => ({
          attackType: t.attackType,
          campaignName: t.campaignName,
          catalog: t.catalog,
          source: t.source,
          indicators: t.indicators,
          entryName: t.entry?.name || '',
        })),
      });
    }
  }

  if (matches.length > 0) {
    logger.warn('matcher', `THREAT MATCHES FOUND: ${matches.length} compromised packages!`);
  } else {
    logger.info('matcher', `No threat matches among ${packages.length} packages`);
  }

  return matches;
}

function normalizeVersion(version) {
  if (!version) return '';
  return version.replace(/^v/, '');
}

// True for an installed version like "1.2.3" or "v0.17.0-rc1"; false for specs like ">=1.0", "^2", "*", "".
function isConcreteVersion(version) {
  return typeof version === 'string' && /^v?\d[0-9A-Za-z.+_!-]*$/.test(version);
}

/**
 * Merge additional source matches (OSV, GHSA) into target in place.
 * Identity is the specific inventoried package (ecosystem, name, version, project, source),
 * so the same name@version in two projects stays two entries. Threats already present
 * (same catalog + campaign) are not duplicated.
 */
function mergeThreatMatches(target, extra) {
  const keyOf = (m) => [
    (m.ecosystem || '').toLowerCase(), (m.name || '').toLowerCase(), normalizeVersion(m.version),
    m.project || '', m.source || '',
  ].join('\0');
  const threatKey = (t) => `${t.catalog}\0${t.campaignName}`;

  const index = new Map(target.map(m => [keyOf(m), m]));
  for (const m of (extra || [])) {
    const existing = index.get(keyOf(m));
    if (!existing) {
      target.push(m);
      index.set(keyOf(m), m);
      continue;
    }
    const have = new Set(existing.threats.map(threatKey));
    for (const t of m.threats) {
      if (!have.has(threatKey(t))) {
        existing.threats.push(t);
        have.add(threatKey(t));
      }
    }
  }
  return target;
}

function buildKey(ecosystem, packageName, version) {
  // Some published catalogs write scoped names with a doubled '@' ("@@antv/x").
  const name = (packageName || '').toLowerCase().replace(/^@@+/, '@');
  return `${(ecosystem || '').toLowerCase()}:${name}:${normalizeVersion(version)}`;
}

module.exports = { buildIndex, matchPackages, mergeThreatMatches, isConcreteVersion, normalizeVersion };
