'use strict';

const logger = require('../utils/logger');
const http = require('./http');
const { isConcreteVersion } = require('./matcher');

const GHSA_API = 'https://api.github.com/advisories';
const MAX_PER_CHUNK = 100;
const MAX_AFFECTS_CHARS = 4000;
const MAX_PAGES_PER_CHUNK = 10;
const MAX_REQUESTS = 200;

const ECOSYSTEM_MAP = {
  npm: 'npm',
  pypi: 'pip',
  go: 'go',
  rubygems: 'rubygems',
  cargo: 'rust',
  composer: 'composer',
  nuget: 'nuget',
  maven: 'maven',
};

/**
 * Check packages against GitHub Advisory Database malware advisories.
 *
 * Uses GET /advisories?type=malware&affects=name@version,... so GitHub evaluates
 * version ranges server-side. Each chunk holds a package name at most once, so any
 * advisory returned for a name maps to exactly one name@version.
 *
 * Requires GITHUB_TOKEN/GH_TOKEN: the unauthenticated limit (60 req/hr, shared per IP)
 * cannot cover a real endpoint, and OSV's OpenSSF data overlaps heavily.
 *
 * Returns { matches, status, queried, error } with status 'ok' | 'partial' | 'failed' | 'skipped'.
 */
async function queryGhsa(packages, opts = {}) {
  const { timeout = 20000, token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN } = opts;
  const result = { matches: [], status: 'skipped', queried: 0, error: null };
  if (!packages || packages.length === 0) return result;

  // ecosystem -> Map(lower(name)@version -> { name, version, indices })
  const byEco = new Map();
  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const eco = ECOSYSTEM_MAP[(pkg.ecosystem || '').toLowerCase()];
    if (!eco || !pkg.name || !isConcreteVersion(pkg.version)) continue;
    if (!byEco.has(eco)) byEco.set(eco, new Map());
    const key = `${pkg.name.toLowerCase()}@${pkg.version}`;
    const m = byEco.get(eco);
    if (!m.has(key)) m.set(key, { name: pkg.name, version: pkg.version, indices: [] });
    m.get(key).indices.push(i);
  }
  if (byEco.size === 0) return result;

  if (!token) {
    result.error = 'GITHUB_TOKEN not set';
    logger.info('ghsa', 'Skipping GitHub Advisory DB (set GITHUB_TOKEN to enable)');
    return result;
  }

  let requests = 0;
  let failedChunks = 0;
  let chunks = 0;

  for (const [eco, entries] of byEco) {
    result.queried += entries.size;
    for (const chunk of buildAffectsChunks([...entries.values()])) {
      chunks++;
      if (requests >= MAX_REQUESTS) {
        failedChunks++;
        result.error = `request budget (${MAX_REQUESTS}) exhausted`;
        continue;
      }
      const byName = new Map(chunk.map(e => [e.name.toLowerCase(), e]));
      const affects = chunk.map(e => `${e.name}@${e.version}`).join(',');
      let url = `${GHSA_API}?type=malware&ecosystem=${encodeURIComponent(eco)}&per_page=100&affects=${encodeURIComponent(affects)}`;

      try {
        for (let page = 0; url && page < MAX_PAGES_PER_CHUNK; page++) {
          requests++;
          const res = await http.request(url, { timeout, headers: githubHeaders(token) });
          if (res.status !== 200) throw new Error(`GHSA API ${res.status}: ${res.body.replace(/\s+/g, " ").slice(0, 200)}`);
          const advisories = JSON.parse(res.body);
          if (!Array.isArray(advisories)) throw new Error('GHSA API returned a non-array');

          for (const adv of advisories) {
            for (const vuln of (adv.vulnerabilities || [])) {
              const pkgName = vuln.package && vuln.package.name;
              const ecoMatches = vuln.package && (vuln.package.ecosystem || '').toLowerCase() === eco;
              const entry = pkgName && ecoMatches && byName.get(pkgName.toLowerCase());
              if (!entry) continue;
              entry.advisories = entry.advisories || new Map();
              entry.advisories.set(adv.ghsa_id, adv);
            }
          }
          url = nextLink(res.headers.link);
        }
      } catch (e) {
        failedChunks++;
        result.error = e.message;
        logger.warn('ghsa', `Query failed for ${eco}: ${e.message}`);
      }
    }

    for (const entry of entries.values()) {
      if (!entry.advisories) continue;
      const threats = [...entry.advisories.values()].map(toThreat);
      for (const i of entry.indices) {
        result.matches.push({ ...packages[i], threats: threats.map(t => ({ ...t })) });
      }
    }
  }

  result.status = failedChunks === 0 ? 'ok' : failedChunks === chunks ? 'failed' : 'partial';
  if (result.matches.length > 0) {
    logger.warn('ghsa', `GHSA MATCHES: ${result.matches.length} malicious package entries found!`);
  } else if (result.status === 'ok') {
    logger.info('ghsa', `No GHSA malware matches among ${result.queried} unique packages`);
  }
  return result;
}

/**
 * Split entries into chunks where each package name appears at most once and the
 * affects list stays within URL-length limits.
 */
function buildAffectsChunks(entries) {
  const chunks = [];
  for (const e of entries) {
    const item = `${e.name}@${e.version}`;
    const lname = e.name.toLowerCase();
    let target = chunks.find(c => !c.names.has(lname) && c.items.length < MAX_PER_CHUNK && c.chars + item.length + 1 <= MAX_AFFECTS_CHARS);
    if (!target) {
      target = { items: [], names: new Set(), chars: 0 };
      chunks.push(target);
    }
    target.items.push(e);
    target.names.add(lname);
    target.chars += item.length + 1;
  }
  return chunks.map(c => c.items);
}

function githubHeaders(token) {
  return {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Authorization': `Bearer ${token}`,
  };
}

function nextLink(linkHeader) {
  if (!linkHeader) return null;
  const m = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  return m && m[1].startsWith(GHSA_API) ? m[1] : null;
}

function toThreat(adv) {
  return {
    attackType: adv.summary || 'Malicious package (GitHub Advisory)',
    campaignName: adv.ghsa_id,
    catalog: 'github-advisory-db',
    source: adv.html_url || `https://github.com/advisories/${adv.ghsa_id}`,
    indicators: { publishedAt: adv.published_at || '' },
    entryName: adv.ghsa_id,
    ghsaId: adv.ghsa_id,
    details: (adv.description || adv.summary || '').slice(0, 500),
  };
}

module.exports = { queryGhsa, buildAffectsChunks };
