'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const logger = require('../utils/logger');

const GITHUB_API = 'https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel';
const RAW_BASE = 'https://raw.githubusercontent.com/perplexityai/bumblebee/main/threat_intel/';
const BASELINE_DIR = path.resolve(__dirname, '..', '..', 'data', 'baseline-catalogs');
const CONVENTION_DIR = path.join(os.homedir(), '.hiveguard', 'custom-catalogs');

/**
 * Load all threat intel catalogs into memory using a tiered fallback chain:
 *
 *   1. Live fetch from Bumblebee GitHub (catalogs held in memory)
 *   2. Bundled baseline catalogs (shipped with HiveGuard)
 *   3. Custom catalogs (--custom-intel dir + ~/.hiveguard/custom-catalogs/)
 *
 * Custom catalogs are always additive — they merge on top of everything else.
 * Returns: { inMemoryCatalogs: Map<filename, object>, source, lastSync, ... }
 */
async function loadThreatIntel(opts = {}) {
  const { offline = false, timeout = 15000, customIntelDirs = [] } = opts;

  // Phase 1: Primary source — live fetch or baseline fallback
  let primaryCatalogs = new Map();  // filename -> parsed JSON
  let source = 'none';
  let lastSync = null;
  let newCampaigns = [];
  let updatedCampaigns = [];

  if (!offline) {
    // Try live fetch into memory
    const liveResult = await fetchLiveCatalogs(timeout);
    if (liveResult.success) {
      primaryCatalogs = liveResult.catalogs;
      source = 'live';
      lastSync = new Date().toISOString();
      newCampaigns = liveResult.newCampaigns || [];
      updatedCampaigns = liveResult.updatedCampaigns || [];
      logger.info('threat-intel', `Live fetch: ${primaryCatalogs.size} catalogs loaded into memory`);
    } else {
      logger.warn('threat-intel', `Live fetch failed: ${liveResult.error} — falling back to baseline`);
    }
  } else {
    logger.info('threat-intel', 'Offline mode — skipping live fetch');
  }

  // Phase 2: If live failed or offline, load bundled baseline
  if (primaryCatalogs.size === 0) {
    primaryCatalogs = loadCatalogsFromDir(BASELINE_DIR, 'baseline');
    if (primaryCatalogs.size > 0) {
      source = 'baseline';
      logger.info('threat-intel', `Baseline fallback: ${primaryCatalogs.size} bundled catalogs loaded`);
    } else {
      logger.warn('threat-intel', 'No baseline catalogs found — threat intel unavailable');
    }
  }

  // Phase 3: Merge custom catalogs (always additive, custom wins on conflict)
  const customSources = [];

  // Convention directory: ~/.hiveguard/custom-catalogs/
  if (fs.existsSync(CONVENTION_DIR)) {
    customSources.push(CONVENTION_DIR);
  }

  // CLI-provided directories
  for (const dir of customIntelDirs) {
    if (fs.existsSync(dir) && !customSources.includes(dir)) {
      customSources.push(dir);
    }
  }

  let customCount = 0;
  for (const dir of customSources) {
    const custom = loadCatalogsFromDir(dir, 'custom');
    for (const [name, data] of custom) {
      // Tag as custom source
      data._source = 'custom';
      data._sourceDir = dir;
      primaryCatalogs.set(name, data); // overwrites if same filename — custom wins
      customCount++;
    }
  }

  if (customCount > 0) {
    logger.info('threat-intel', `Custom catalogs: ${customCount} loaded from ${customSources.length} dir(s)`);
    if (source === 'none') source = 'custom';
    else source += '+custom';
  }

  if (primaryCatalogs.size === 0) {
    source = 'none';
  }

  return {
    inMemoryCatalogs: primaryCatalogs,
    source,
    lastSync,
    catalogCount: primaryCatalogs.size,
    newCampaigns,
    updatedCampaigns,
    customDirs: customSources,
    customCount,
  };
}

/**
 * Fetch catalogs live from GitHub into memory (not to disk).
 */
async function fetchLiveCatalogs(timeout) {
  let listing;
  try {
    logger.info('threat-intel', 'Fetching catalog listing from GitHub...');
    const raw = await httpsGet(GITHUB_API, timeout);
    listing = JSON.parse(raw);
  } catch (e) {
    return { success: false, error: e.message, catalogs: new Map() };
  }

  const remoteCatalogs = listing.filter(f => f.name.endsWith('.json') && !f.name.startsWith('_'));
  const catalogs = new Map();
  const newCampaigns = [];
  const updatedCampaigns = [];

  for (const file of remoteCatalogs) {
    try {
      const url = file.download_url || (RAW_BASE + file.name);
      const raw = await httpsGet(url, timeout);
      const data = JSON.parse(raw);

      // Validate structure
      if (!data.entries || !Array.isArray(data.entries)) {
        logger.warn('threat-intel', `Skipping ${file.name} — no entries array`);
        continue;
      }

      data._source = 'live';
      data._sha = file.sha;
      data._fetched_at = new Date().toISOString();
      catalogs.set(file.name, data);

      const entryCount = data.entries.length;
      let verCount = 0;
      for (const e of data.entries) verCount += (e.versions || []).length;

      logger.info('threat-intel', `Fetched: ${file.name} (${entryCount} packages, ${verCount} versions)`);
      newCampaigns.push(file.name);
    } catch (e) {
      logger.error('threat-intel', `Failed to fetch ${file.name}: ${e.message}`);
    }
  }

  return { success: catalogs.size > 0, catalogs, newCampaigns, updatedCampaigns };
}

/**
 * Load all .json catalogs from a directory into a Map<filename, parsedJSON>.
 */
function loadCatalogsFromDir(dir, sourceTag) {
  const catalogs = new Map();
  if (!fs.existsSync(dir)) return catalogs;

  let files;
  try {
    files = fs.readdirSync(dir).filter(f => f.endsWith('.json') && !f.startsWith('_'));
  } catch (e) {
    logger.error('threat-intel', `Cannot read directory ${dir}: ${e.message}`);
    return catalogs;
  }

  for (const file of files) {
    try {
      const raw = fs.readFileSync(path.join(dir, file), 'utf8');
      const data = JSON.parse(raw);
      if (data.entries && Array.isArray(data.entries)) {
        data._source = sourceTag;
        catalogs.set(file, data);
      }
    } catch (e) {
      logger.debug('threat-intel', `Skipping ${file} in ${dir}: ${e.message}`);
    }
  }

  return catalogs;
}

// ── HTTP helpers ──

function httpsGet(url, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      headers: { 'User-Agent': 'hiveguard/1.0' },
      timeout,
    };
    const req = https.get(opts, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpsGet(res.headers.location, timeout).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`)));
        return;
      }
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
  });
}

module.exports = { loadThreatIntel };
