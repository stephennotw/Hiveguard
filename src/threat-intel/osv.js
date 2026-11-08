'use strict';

const logger = require('../utils/logger');
const http = require('./http');
const { isConcreteVersion } = require('./matcher');

const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const MAX_PAGE_FOLLOWS = 5;
const MAX_DETAIL_FETCHES = 500;
const DETAIL_CONCURRENCY = 8;

const ECOSYSTEM_MAP = {
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go',
  rubygems: 'RubyGems',
  cargo: 'crates.io',
  composer: 'Packagist',
  nuget: 'NuGet',
  maven: 'Maven',
  // VS Code-family extensions (Marketplace / Open VSX ids, "<publisher>.<name>", lowercase on OSV)
  'editor-extension': 'VSCode',
};
const LOWERCASE_NAMES = new Set(['VSCode']);

/**
 * Check packages against OpenSSF malicious-package advisories (MAL-*) on OSV.dev.
 *
 * querybatch only returns { id, modified } per vuln, so each distinct MAL id is
 * then fetched once from /v1/vulns/{id} for summary, details, and indicators.
 * Identical name@version entries (same package in many projects) are queried once.
 *
 * Returns { matches, status, queried, error } where status is
 * 'ok' | 'partial' | 'failed' | 'skipped'. Matches use the Bumblebee match shape.
 */
async function queryOsv(packages, opts = {}) {
  const { timeout = 20000 } = opts;
  const result = { matches: [], status: 'skipped', queried: 0, error: null };
  if (!packages || packages.length === 0) return result;

  // Unique (ecosystem, name, version) -> indices into packages
  const unique = new Map();
  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const eco = ECOSYSTEM_MAP[(pkg.ecosystem || '').toLowerCase()];
    if (!eco || !pkg.name || !isConcreteVersion(pkg.version)) continue;
    const name = LOWERCASE_NAMES.has(eco) ? pkg.name.toLowerCase() : pkg.name;
    const key = `${eco}\0${name}\0${pkg.version}`;
    if (!unique.has(key)) unique.set(key, { query: { package: { name, ecosystem: eco }, version: pkg.version }, indices: [], malIds: new Set() });
    unique.get(key).indices.push(i);
  }
  if (unique.size === 0) return result;

  const entries = [...unique.values()];
  result.queried = entries.length;
  logger.info('osv', `Checking ${entries.length} unique packages against OSV.dev...`);

  let batches = 0;
  let failedBatches = 0;
  for (let offset = 0; offset < entries.length; offset += BATCH_SIZE) {
    const batch = entries.slice(offset, offset + BATCH_SIZE);
    batches++;
    try {
      const results = await postBatch(batch.map(e => e.query), timeout);
      for (let j = 0; j < batch.length; j++) {
        collectMalIds(results[j], batch[j]);
        let token = results[j] && results[j].next_page_token;
        for (let follow = 0; token && follow < MAX_PAGE_FOLLOWS; follow++) {
          const [page] = await postBatch([{ ...batch[j].query, page_token: token }], timeout);
          collectMalIds(page, batch[j]);
          token = page && page.next_page_token;
        }
      }
    } catch (e) {
      failedBatches++;
      result.error = e.message;
      logger.warn('osv', `Batch query failed (offset ${offset}): ${e.message}`);
    }
  }
  result.status = failedBatches === 0 ? 'ok' : failedBatches === batches ? 'failed' : 'partial';

  const allIds = new Set();
  for (const e of entries) for (const id of e.malIds) allIds.add(id);
  const details = await fetchDetails([...allIds], timeout);

  for (const e of entries) {
    if (e.malIds.size === 0) continue;
    const threats = [...e.malIds].map(id => toThreat(id, details.get(id)));
    for (const i of e.indices) {
      result.matches.push({ ...packages[i], threats: threats.map(t => ({ ...t })) });
    }
  }

  if (result.matches.length > 0) {
    logger.warn('osv', `OSV MATCHES: ${result.matches.length} malicious package entries found!`);
  } else if (result.status === 'ok') {
    logger.info('osv', `No OSV malware matches among ${entries.length} unique packages`);
  }
  return result;
}

async function postBatch(queries, timeout) {
  const res = await http.request(`${OSV_API}/querybatch`, { method: 'POST', body: { queries }, timeout });
  if (res.status !== 200) throw new Error(`OSV API ${res.status}: ${res.body.replace(/\s+/g, " ").slice(0, 200)}`);
  const parsed = JSON.parse(res.body);
  if (!parsed || !Array.isArray(parsed.results)) throw new Error('OSV API returned no results array');
  return parsed.results;
}

function collectMalIds(result, entry) {
  for (const v of ((result && result.vulns) || [])) {
    if (v.id && v.id.startsWith('MAL-')) entry.malIds.add(v.id);
  }
}

// Fetch full advisory records; failures fall back to id-only threats.
async function fetchDetails(ids, timeout) {
  const details = new Map();
  const todo = ids.slice(0, MAX_DETAIL_FETCHES);
  if (ids.length > todo.length) logger.warn('osv', `Fetching details for first ${todo.length} of ${ids.length} advisories`);

  let next = 0;
  async function worker() {
    while (next < todo.length) {
      const id = todo[next++];
      try {
        const res = await http.request(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { timeout });
        if (res.status === 200) details.set(id, JSON.parse(res.body));
      } catch (e) {
        logger.debug('osv', `Detail fetch failed for ${id}: ${e.message}`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, todo.length) }, worker));
  return details;
}

function toThreat(id, vuln) {
  const v = vuln || {};
  return {
    attackType: v.summary || 'Malicious package (OpenSSF)',
    campaignName: id,
    catalog: 'osv.dev',
    source: `https://osv.dev/vulnerability/${id}`,
    indicators: extractIndicators(v),
    entryName: id,
    osvId: id,
    aliases: v.aliases || [],
    details: (v.details || '').slice(0, 500),
  };
}

function extractIndicators(vuln) {
  const indicators = {};
  const origins = vuln.database_specific && vuln.database_specific['malicious-packages-origins'];
  if (Array.isArray(origins)) {
    const sources = origins.map(o => o.source).filter(Boolean);
    if (sources.length > 0) indicators.sources = [...new Set(sources)];
    const hashes = origins.map(o => o.sha256).filter(Boolean);
    if (hashes.length > 0) indicators.sha256 = hashes;
  }
  return indicators;
}

module.exports = { queryOsv, extractIndicators };
