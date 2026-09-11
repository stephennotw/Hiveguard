'use strict';

const https = require('https');
const logger = require('../utils/logger');

const GHSA_API = 'https://api.github.com/advisories';
const MAX_PAGES = 5;

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
 * Query GitHub Advisory Database for malware-type advisories.
 * Fetches per-ecosystem, then matches against the provided package list.
 * Returns matches in the same shape as OSV/Bumblebee threat matches.
 *
 * Supports GITHUB_TOKEN env var for higher rate limits (5000/hr vs 60/hr).
 */
async function queryGhsa(packages, opts = {}) {
  const { timeout = 20000 } = opts;
  if (!packages || packages.length === 0) return [];

  const ecosystemsInUse = new Set();
  const pkgLookup = new Map();

  for (const pkg of packages) {
    const ghEco = ECOSYSTEM_MAP[(pkg.ecosystem || '').toLowerCase()];
    if (!ghEco) continue;
    ecosystemsInUse.add(ghEco);
    const key = `${ghEco}:${(pkg.name || '').toLowerCase()}`;
    if (!pkgLookup.has(key)) pkgLookup.set(key, []);
    pkgLookup.get(key).push(pkg);
  }

  if (ecosystemsInUse.size === 0) return [];

  logger.info('ghsa', `Checking ${ecosystemsInUse.size} ecosystem(s) against GitHub Advisory Database...`);

  const advisoryIndex = new Map();

  for (const ecosystem of ecosystemsInUse) {
    try {
      const advisories = await fetchMalwareAdvisories(ecosystem, timeout);
      for (const adv of advisories) {
        for (const vuln of (adv.vulnerabilities || [])) {
          if (!vuln.package || !vuln.package.name) continue;
          const key = `${ecosystem}:${vuln.package.name.toLowerCase()}`;
          if (!advisoryIndex.has(key)) advisoryIndex.set(key, []);
          advisoryIndex.get(key).push({
            ghsaId: adv.ghsa_id,
            summary: adv.summary || '',
            severity: adv.severity || 'unknown',
            versionRange: vuln.vulnerable_version_range || '',
            publishedAt: adv.published_at || '',
            url: adv.html_url || '',
          });
        }
      }
    } catch (e) {
      logger.warn('ghsa', `Failed to fetch ${ecosystem} advisories: ${e.message}`);
    }
  }

  if (advisoryIndex.size === 0) {
    logger.info('ghsa', 'No GitHub malware advisories fetched');
    return [];
  }

  logger.info('ghsa', `Indexed ${advisoryIndex.size} advisory-affected packages`);

  const matches = [];
  const seen = new Set();

  for (const [key, pkgs] of pkgLookup) {
    const advisories = advisoryIndex.get(key);
    if (!advisories || advisories.length === 0) continue;

    for (const pkg of pkgs) {
      const dedupKey = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const matchingAdvisories = advisories.filter(a => versionInRange(pkg.version, a.versionRange));
      if (matchingAdvisories.length === 0) continue;

      matches.push({
        ...pkg,
        threats: matchingAdvisories.map(a => ({
          attackType: a.summary || 'Malicious package (GitHub Advisory)',
          campaignName: a.ghsaId,
          catalog: 'github-advisory-db',
          source: 'github',
          indicators: { url: a.url, publishedAt: a.publishedAt },
          entryName: a.ghsaId,
          ghsaId: a.ghsaId,
          details: a.summary.slice(0, 500),
        })),
      });
    }
  }

  if (matches.length > 0) {
    logger.warn('ghsa', `GHSA MATCHES: ${matches.length} malicious packages found!`);
  } else {
    logger.info('ghsa', `No GHSA malware matches among scanned packages`);
  }

  return matches;
}

async function fetchMalwareAdvisories(ecosystem, timeout) {
  const all = [];
  let url = `${GHSA_API}?type=malware&ecosystem=${ecosystem}&per_page=100`;

  for (let page = 0; page < MAX_PAGES; page++) {
    const { body, linkNext } = await httpsGet(url, timeout);
    const parsed = JSON.parse(body);
    if (!Array.isArray(parsed)) break;
    all.push(...parsed);

    if (!linkNext || parsed.length < 100) break;
    url = linkNext;
  }

  return all;
}

/**
 * Simple semver-range check for GitHub advisory version ranges.
 * Handles common patterns: "<= X.Y.Z", ">= X, <= Y", "= X.Y.Z", "< X.Y.Z"
 * Returns true if version falls in the vulnerable range (or range is unparseable — assume affected).
 */
function versionInRange(version, range) {
  if (!range || !version) return true;

  const v = normalizeVersion(version);

  const constraints = range.split(',').map(s => s.trim());
  for (const c of constraints) {
    const match = c.match(/^([<>=!]+)\s*(.+)$/);
    if (!match) return true;

    const op = match[1].trim();
    const target = normalizeVersion(match[2].trim());
    const cmp = compareVersions(v, target);

    switch (op) {
      case '=': case '==': if (cmp !== 0) return false; break;
      case '<': if (cmp >= 0) return false; break;
      case '<=': if (cmp > 0) return false; break;
      case '>': if (cmp <= 0) return false; break;
      case '>=': if (cmp < 0) return false; break;
      case '!=': if (cmp === 0) return false; break;
      default: return true;
    }
  }

  return true;
}

function normalizeVersion(v) {
  return (v || '').replace(/^v/, '');
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

function httpsGet(url, timeout = 20000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const headers = {
      'User-Agent': 'hiveguard/1.0',
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };

    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers,
      timeout,
    };

    const req = https.request(opts, (res) => {
      if (res.statusCode === 304) {
        resolve({ body: '[]', linkNext: null });
        return;
      }
      if (res.statusCode !== 200) {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => reject(new Error(`GHSA API ${res.statusCode}: ${data.slice(0, 200)}`)));
        return;
      }
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        let linkNext = null;
        const linkHeader = res.headers['link'];
        if (linkHeader) {
          const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
          if (nextMatch) linkNext = nextMatch[1];
        }
        resolve({ body: data, linkNext });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('GHSA request timed out')); });
    req.end();
  });
}

module.exports = { queryGhsa, versionInRange, compareVersions };
