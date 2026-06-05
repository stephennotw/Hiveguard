'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const { existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

/**
 * Detect and return the platform-specific config.
 * Enumerates all user profiles so scans work even when running as SYSTEM.
 * Supports custom scan directories via CLI --scan-dirs flag.
 */
function getPlatform(customScanDirs) {
  const platformId = os.platform();
  let getConfig;

  switch (platformId) {
    case 'win32':
      getConfig = require('./windows');
      break;
    case 'darwin':
      getConfig = require('./darwin');
      break;
    case 'linux':
      getConfig = require('./linux');
      break;
    default:
      logger.warn('platform', `Unsupported platform: ${platformId}, falling back to linux paths`);
      getConfig = require('./linux');
      break;
  }

  // Enumerate all real user home directories
  const userHomes = enumerateUserHomes(platformId);
  logger.info('platform', `Discovered ${userHomes.length} user profile(s): ${userHomes.map(h => path.basename(h)).join(', ')}`);

  // Generate config for each user home and merge them
  const configs = userHomes.map(home => getConfig(home));
  let config = mergeConfigs(configs);

  // Expose discovered user homes for username extraction in findings
  config.userHomes = userHomes;

  // Override project roots if custom scan dirs provided
  if (customScanDirs && customScanDirs.length > 0) {
    config = { ...config, projectRoots: customScanDirs, userHomes };
    logger.info('platform', `Using custom scan directories: ${customScanDirs.join(', ')}`);
  }

  // Resolve glob-like paths (e.g., C:\Python* -> actual dirs)
  config.projectRoots = resolveGlobRoots(config.projectRoots);

  // Prune: remove non-existent roots and subdirs already covered by a parent root
  config.projectRoots = pruneRoots(config.projectRoots);
  if (Array.isArray(config.envSearchRoots)) config.envSearchRoots = pruneRoots(config.envSearchRoots);
  if (Array.isArray(config.pythonRoots)) config.pythonRoots = pruneRoots(config.pythonRoots);
  logger.info('platform', `Pruned to ${config.projectRoots.length} project root(s), ${(config.envSearchRoots || []).length} env root(s)`);

  logger.info('platform', `Detected platform: ${config.id} (${os.arch()})`);
  return config;
}

/**
 * Enumerate all real user home directories on the system.
 * Filters out system/service accounts.
 */
function enumerateUserHomes(platformId) {
  const homes = [];
  const skipNames = new Set([
    'default', 'default user', 'defaultuser0', 'public', 'all users',
    'defaultaccount', 'guest', 'defaultapppool', 'networkservice',
    'localservice', 'systemprofile', '.net v4.5', '.net v4.5 classic',
  ]);

  let usersBase;
  if (platformId === 'win32') {
    usersBase = process.env.SystemDrive ? path.join(process.env.SystemDrive, 'Users') : 'C:\\Users';
  } else if (platformId === 'darwin') {
    usersBase = '/Users';
  } else {
    usersBase = '/home';
  }

  try {
    if (!fs.existsSync(usersBase)) return [os.homedir()];
    const entries = fs.readdirSync(usersBase, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const name = entry.name.toLowerCase();
      if (name.startsWith('.') || skipNames.has(name)) continue;
      const homePath = path.join(usersBase, entry.name);
      homes.push(homePath);
    }
  } catch (e) {
    logger.warn('platform', `Could not enumerate user profiles: ${e.message}`);
  }

  // Fallback: always include current user's home if nothing found
  if (homes.length === 0) {
    homes.push(os.homedir());
  }

  return homes;
}

/**
 * Merge multiple per-user platform configs into one unified config.
 * Arrays are concatenated (deduplicated). Objects have their values merged into arrays.
 */
function mergeConfigs(configs) {
  if (configs.length === 0) return {};
  if (configs.length === 1) return configs[0];

  const merged = {};

  for (const cfg of configs) {
    for (const [key, value] of Object.entries(cfg)) {
      if (key === 'id') {
        merged.id = value;
      } else if (Array.isArray(value)) {
        if (!merged[key]) merged[key] = [];
        for (const item of value) {
          if (!merged[key].includes(item)) merged[key].push(item);
        }
      } else if (typeof value === 'object' && value !== null) {
        // Objects like editorExtensionDirs, browserExtensionDirs
        // Each value is already an array — merge per sub-key
        if (!merged[key]) merged[key] = {};
        for (const [subKey, subVal] of Object.entries(value)) {
          if (!merged[key][subKey]) merged[key][subKey] = [];
          const arr = Array.isArray(subVal) ? subVal : [subVal];
          for (const item of arr) {
            if (!merged[key][subKey].includes(item)) merged[key][subKey].push(item);
          }
        }
      } else if (typeof value === 'string') {
        // String properties like goModCache, cargoRegistry, composerGlobalDir
        // Convert to arrays for multi-user
        if (!merged[key]) merged[key] = [value];
        else if (Array.isArray(merged[key])) {
          if (!merged[key].includes(value)) merged[key].push(value);
        }
      }
    }
  }

  return merged;
}

/**
 * Prune project roots: remove non-existent dirs and subdirectories
 * already covered by a shallower root (since scanners walk to depth 6).
 */
function pruneRoots(roots) {
  // 1. Filter to only existing directories
  const existing = roots.filter(r => existsSafe(r));

  // 2. Normalize paths for comparison
  const normalized = existing.map(r => path.resolve(r));

  // 3. Sort shortest first so parents come before children
  normalized.sort((a, b) => a.length - b.length);

  // 4. Remove subdirs already covered by a parent root
  const kept = [];
  for (const dir of normalized) {
    const isChild = kept.some(parent => dir.startsWith(parent + path.sep));
    if (!isChild) {
      kept.push(dir);
    }
  }

  return kept;
}

/**
 * Expand simple wildcard paths to actual directories.
 * Only supports trailing * for directory name expansion.
 */
function resolveGlobRoots(roots) {
  const fs = require('fs');
  const expanded = [];

  for (const root of roots) {
    if (root.includes('*')) {
      const dir = path.dirname(root);
      const pattern = path.basename(root);
      if (!existsSafe(dir)) continue;
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        for (const entry of entries) {
          if (entry.isDirectory() && regex.test(entry.name)) {
            expanded.push(path.join(dir, entry.name));
          }
        }
      } catch { /* skip unreadable */ }
    } else {
      expanded.push(root);
    }
  }

  return expanded;
}

/**
 * Get system metadata for the scan report.
 */
function getSystemInfo() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    username: os.userInfo().username,
    homedir: os.homedir(),
    nodeVersion: process.version,
    cpus: os.cpus().length,
    totalMemoryMB: Math.round(os.totalmem() / 1048576),
    uptime: Math.round(os.uptime()),
  };
}

module.exports = { getPlatform, getSystemInfo };
