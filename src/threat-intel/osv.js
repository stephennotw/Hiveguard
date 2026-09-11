'use strict';

const https = require('https');
const logger = require('../utils/logger');

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;

/**
 * Query OSV.dev for malicious package advisories (MAL-* only).
 * Accepts a flat package list [{ ecosystem, name, version }].
 * Returns matches in the same shape as Bumblebee threat matches so
 * they merge seamlessly into the existing threat match results.
 *
 * Only MAL-prefixed advisories are returned — CVEs and GHSAs are
 * filtered out to keep HiveGuard focused on supply chain malware.
 */
async function queryOsv(packages, opts = {}) {
  const { timeout = 20000 } = opts;
  if (!packages || packages.length === 0) return [];

  const ecosystemMap = {
    npm: 'npm',
    pypi: 'PyPI',
    go: 'Go',
    rubygems: 'RubyGems',
    cargo: 'crates.io',
    composer: 'Packagist',
    nuget: 'NuGet',
    maven: 'Maven',
  };

  const queries = [];
  const queryIndexMap = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const osvEcosystem = ecosystemMap[(pkg.ecosystem || '').toLowerCase()];
    if (!osvEcosystem) continue;

    queries.push({
      package: { name: pkg.name, ecosystem: osvEcosystem },
      version: pkg.version,
    });
    queryIndexMap.push(i);
  }

  if (queries.length === 0) return [];

  logger.info('osv', `Checking ${queries.length} packages against OSV.dev...`);

  const allMatches = [];

  for (let offset = 0; offset < queries.length; offset += BATCH_SIZE) {
    const batch = queries.slice(offset, offset + BATCH_SIZE);
    const batchIndices = queryIndexMap.slice(offset, offset + BATCH_SIZE);

    try {
      const response = await httpsPost(OSV_BATCH_URL, { queries: batch }, timeout);
      const parsed = JSON.parse(response);

      if (!parsed.results || !Array.isArray(parsed.results)) continue;

      for (let j = 0; j < parsed.results.length; j++) {
        const result = parsed.results[j];
        if (!result.vulns || result.vulns.length === 0) continue;

        const malVulns = result.vulns.filter(v => v.id && v.id.startsWith('MAL-'));
        if (malVulns.length === 0) continue;

        const pkgIndex = batchIndices[j];
        const pkg = packages[pkgIndex];

        allMatches.push({
          ...pkg,
          threats: malVulns.map(v => ({
            attackType: v.summary || 'Malicious package (OpenSSF)',
            campaignName: v.id,
            catalog: 'osv.dev',
            source: 'openssf',
            indicators: extractIndicators(v),
            entryName: v.id,
            osvId: v.id,
            aliases: v.aliases || [],
            details: (v.details || '').slice(0, 500),
          })),
        });
      }
    } catch (e) {
      logger.warn('osv', `Batch query failed (offset ${offset}): ${e.message}`);
    }
  }

  if (allMatches.length > 0) {
    logger.warn('osv', `OSV MATCHES: ${allMatches.length} malicious packages found!`);
  } else {
    logger.info('osv', `No OSV malware matches among ${queries.length} packages`);
  }

  return allMatches;
}

function extractIndicators(vuln) {
  const indicators = {};
  const dbSpecific = vuln.database_specific;
  if (dbSpecific && dbSpecific['malicious-packages-origins']) {
    const origins = dbSpecific['malicious-packages-origins'];
    indicators.sources = origins.map(o => o.source).filter(Boolean);
    const hashes = origins.map(o => o.sha256).filter(Boolean);
    if (hashes.length > 0) indicators.sha256 = hashes;
  }
  return indicators;
}

function httpsPost(url, body, timeout = 20000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = JSON.stringify(body);
    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'User-Agent': 'hiveguard/1.0',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout,
    };
    const req = https.request(opts, (res) => {
      if (res.statusCode !== 200) {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => reject(new Error(`OSV API ${res.statusCode}: ${data.slice(0, 200)}`)));
        return;
      }
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('OSV request timed out')); });
    req.write(payload);
    req.end();
  });
}

module.exports = { queryOsv };
