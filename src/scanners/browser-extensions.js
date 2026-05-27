'use strict';

const path = require('path');
const { readJsonSafe, existsSafe, readdirSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'browser-extensions';

/**
 * Scan browser extensions for Chromium-based browsers.
 * Extension dir structure: Extensions/<extension_id>/<version>/manifest.json
 */
function scan(platform) {
  const results = {};

  for (const [browser, extDir] of Object.entries(platform.browserExtensionDirs || {})) {
    // Skip Firefox profiles (handled separately)
    if (browser === 'firefox_profiles' || browser === 'safari_extensions') continue;

    if (!existsSafe(extDir)) {
      logger.debug(SCANNER_ID, `${browser} extensions dir not found`);
      continue;
    }

    const extensions = [];

    for (const extId of readdirSafe(extDir)) {
      if (extId.startsWith('.') || extId === 'Temp') continue;
      const extIdDir = path.join(extDir, extId);

      // Find latest version directory
      const versions = readdirSafe(extIdDir).filter(v => !v.startsWith('.'));
      if (versions.length === 0) continue;

      // Sort versions, pick latest
      const latestVer = versions.sort().pop();
      const manifestPath = path.join(extIdDir, latestVer, 'manifest.json');
      const manifest = readJsonSafe(manifestPath);
      if (!manifest) continue;

      let name = manifest.name || extId;
      // Resolve __MSG_ references (can't fully resolve without _locales)
      if (name.startsWith('__MSG_')) {
        const localeName = tryResolveLocale(path.join(extIdDir, latestVer), name);
        name = localeName || `(${extId.slice(0, 20)})`;
      }

      extensions.push({
        extension_id: extId,
        name,
        version: manifest.version || latestVer,
        manifest_version: manifest.manifest_version || 2,
        description: (manifest.description || '').slice(0, 200),
        permissions: manifest.permissions || [],
        optional_permissions: manifest.optional_permissions || [],
        host_permissions: manifest.host_permissions || [],
        content_scripts: (manifest.content_scripts || []).length,
        background: manifest.background ? true : false,
      });
    }

    if (extensions.length > 0) {
      results[browser] = extensions;
      logger.info(SCANNER_ID, `${browser}: ${extensions.length} extensions`);
    }
  }

  return { ecosystem: SCANNER_ID, browsers: results, total: Object.values(results).reduce((s, e) => s + e.length, 0) };
}

function tryResolveLocale(extDir, msgKey) {
  const key = msgKey.replace('__MSG_', '').replace('__', '');
  for (const locale of ['en', 'en_US', 'en_GB']) {
    const messagesPath = path.join(extDir, '_locales', locale, 'messages.json');
    const messages = readJsonSafe(messagesPath);
    if (messages) {
      const entry = messages[key] || messages[key.toLowerCase()];
      if (entry && entry.message) return entry.message;
    }
  }
  return null;
}

module.exports = { scan, SCANNER_ID };
