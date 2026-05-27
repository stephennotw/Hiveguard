'use strict';

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Read-only filesystem helpers. Never writes, never executes.
 */

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    logger.debug('fs-safe', `Cannot read ${filePath}: ${e.code || e.message}`);
    return null;
  }
}

function readJsonSafe(filePath) {
  const raw = readFileSafe(filePath);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    logger.debug('fs-safe', `Invalid JSON in ${filePath}: ${e.message}`);
    return null;
  }
}

function existsSafe(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function readdirSafe(dirPath) {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

function statSafe(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

/**
 * Walk directories up to maxDepth, yielding files matching a filter.
 * Respects symlink safety and skips unreadable dirs.
 */
function walkSync(dir, opts = {}) {
  const { maxDepth = 10, filter = null, skipDirs = [] } = opts;
  const results = [];

  function walk(currentDir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (skipDirs.includes(lower)) continue;
        if (lower === 'node_modules' || lower === '.git' || lower === '__pycache__') continue;
        walk(fullPath, depth + 1);
      } else if (entry.isFile()) {
        if (!filter || filter(entry.name, fullPath)) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dir, 0);
  return results;
}

/**
 * Find files by name pattern in multiple root directories.
 */
function findFiles(roots, fileName, opts = {}) {
  const results = [];
  for (const root of roots) {
    if (!existsSafe(root)) continue;
    const found = walkSync(root, {
      ...opts,
      filter: (name) => name === fileName
    });
    results.push(...found);
  }
  return results;
}


module.exports = {
  readFileSafe,
  readJsonSafe,
  existsSafe,
  readdirSafe,
  statSafe,
  walkSync,
  findFiles,
};
