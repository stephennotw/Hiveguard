'use strict';

const os = require('os');
const path = require('path');
const { existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

/**
 * Detect and return the platform-specific config.
 * Supports custom scan directories via CLI --scan-dirs flag.
 */
function getPlatform(customScanDirs) {
  const platform = os.platform();
  let config;

  switch (platform) {
    case 'win32':
      config = require('./windows');
      break;
    case 'darwin':
      config = require('./darwin');
      break;
    case 'linux':
      config = require('./linux');
      break;
    default:
      logger.warn('platform', `Unsupported platform: ${platform}, falling back to linux paths`);
      config = require('./linux');
      break;
  }

  // Override project roots if custom scan dirs provided
  if (customScanDirs && customScanDirs.length > 0) {
    config = { ...config, projectRoots: customScanDirs };
    logger.info('platform', `Using custom scan directories: ${customScanDirs.join(', ')}`);
  }

  // Resolve glob-like paths (e.g., C:\Python* -> actual dirs)
  config.projectRoots = resolveGlobRoots(config.projectRoots);

  logger.info('platform', `Detected platform: ${config.id} (${os.arch()})`);
  return config;
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
