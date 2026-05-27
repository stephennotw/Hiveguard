'use strict';

const path = require('path');
const { readJsonSafe, existsSafe, readdirSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'editor-extensions';

/**
 * Scan editor extensions for VS Code, Windsurf, Cursor, VSCodium.
 * Reads package.json from each extension directory.
 */
function scan(platform) {
  const results = {};

  for (const [editor, extDir] of Object.entries(platform.editorExtensionDirs || {})) {
    if (!existsSafe(extDir)) {
      logger.debug(SCANNER_ID, `${editor} extensions dir not found: ${extDir}`);
      continue;
    }

    const extensions = [];
    for (const entry of readdirSafe(extDir)) {
      if (entry.startsWith('.')) continue;
      const extPath = path.join(extDir, entry);

      // Extension package.json
      const pkgJson = readJsonSafe(path.join(extPath, 'package.json'));
      if (!pkgJson) continue;

      extensions.push({
        id: entry,
        name: pkgJson.name || entry,
        displayName: pkgJson.displayName || pkgJson.name || entry,
        publisher: pkgJson.publisher || 'unknown',
        version: pkgJson.version || 'unknown',
        description: pkgJson.description || '',
        engines: pkgJson.engines?.vscode || null,
        categories: pkgJson.categories || [],
        extensionKind: pkgJson.extensionKind || null,
        activationEvents: (pkgJson.activationEvents || []).length,
        hasExtensionDeps: (pkgJson.extensionDependencies || []).length > 0,
      });
    }

    if (extensions.length > 0) {
      results[editor] = extensions;
      logger.info(SCANNER_ID, `${editor}: ${extensions.length} extensions`);
    }
  }

  return { ecosystem: SCANNER_ID, editors: results, total: Object.values(results).reduce((s, e) => s + e.length, 0) };
}

module.exports = { scan, SCANNER_ID };
