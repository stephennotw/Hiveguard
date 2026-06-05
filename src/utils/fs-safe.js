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
 * Directories that are always skipped during recursive walks.
 * These are heavy/irrelevant dirs that never contain project lockfiles.
 * Scanners that need data from these dirs (e.g. browser exts in AppData)
 * access them via direct paths in the platform config, not via walkSync.
 */
const BUILTIN_SKIP = new Set([
  // VCS / build
  'node_modules', '.git', '__pycache__', '.svn', '.hg',
  'dist', 'build', 'out', 'target', '.next', '.output',
  // Windows heavy dirs
  'appdata', '.nuget', '.dotnet', '.android', '.gradle',
  'downloads', 'music', 'videos', 'pictures', 'saved games',
  'contacts', 'favorites', 'links', 'searches', '3d objects',
  'scoop', 'chocolatey',
  // Package manager caches
  '.npm', '.yarn', '.pnpm-store', '.cache', '.local',
  '.m2', '.ivy2', '.sbt', '.cargo', '.rustup',
  '.conda', '.virtualenvs', '.pyenv', '.rbenv', '.nvm',
  '.sdkman', '.jabba',
  // Cloud sync (onedrive variants handled by prefix check below)
  'dropbox', 'google drive', 'icloud drive',
  // IDE / editor state
  '.vscode-server', '.cursor-server', '.idea', '.vs',
  // Containers / VMs
  '.docker', '.minikube', '.vagrant',
  // macOS / Linux
  'library', '.trash', 'trash',
  // Infra
  '.terraform', '.serverless',
  // Test / temp
  '.tox', '.nox', '.eggs', '__pypackages__', '.pytest_cache',
  'coverage', '.nyc_output',
]);

/**
 * Walk directories up to maxDepth, yielding files matching a filter.
 * Respects symlink safety and skips unreadable dirs.
 * Uses a built-in skip set plus caller-supplied extras for O(1) lookups.
 */
function walkSync(dir, opts = {}) {
  const { maxDepth = 10, filter = null, skipDirs = [] } = opts;
  const results = [];
  const extraSkip = skipDirs.length > 0 ? new Set(skipDirs) : null;

  function walk(currentDir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (BUILTIN_SKIP.has(lower)) continue;
        if (lower.startsWith('onedrive')) continue;
        if (extraSkip && extraSkip.has(lower)) continue;
        walk(path.join(currentDir, entry.name), depth + 1);
      } else if (entry.isFile()) {
        if (!filter || filter(entry.name, path.join(currentDir, entry.name))) {
          results.push(path.join(currentDir, entry.name));
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

/**
 * Walk directories once, collecting files that match ANY of the given filenames.
 * Returns a Map<filename, filepath[]> — far faster than calling findFiles N times.
 */
function findMultipleFiles(roots, fileNames, opts = {}) {
  const nameSet = new Set(fileNames);
  const resultMap = new Map();
  for (const fn of fileNames) resultMap.set(fn, []);

  for (const root of roots) {
    if (!existsSafe(root)) continue;
    const found = walkSync(root, {
      ...opts,
      filter: (name) => nameSet.has(name)
    });
    for (const fp of found) {
      const base = path.basename(fp);
      resultMap.get(base).push(fp);
    }
  }
  return resultMap;
}


module.exports = {
  readFileSafe,
  readJsonSafe,
  existsSafe,
  readdirSafe,
  statSafe,
  walkSync,
  findFiles,
  findMultipleFiles,
};
