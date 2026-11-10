'use strict';

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Read-only filesystem helpers. Never writes, never executes.
 */

// Only regular files are read: opening a FIFO or device would block or never end.
function readFileSafe(filePath, opts = {}) {
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile()) {
      logger.debug('fs-safe', `Not a regular file, skipping ${filePath}`);
      return null;
    }
    if (opts.skipLarger && opts.maxBytes && st.size > opts.maxBytes) {
      logger.debug('fs-safe', `Skipping oversized file ${filePath} (${st.size} bytes)`);
      return null;
    }
    if (opts.maxBytes && st.size > opts.maxBytes) {
      const fd = fs.openSync(filePath, 'r');
      try {
        const buf = Buffer.alloc(opts.maxBytes);
        const bytesRead = fs.readSync(fd, buf, 0, opts.maxBytes, 0);
        return buf.subarray(0, bytesRead).toString('utf8');
      } finally {
        fs.closeSync(fd);
      }
    }
    return fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    logger.debug('fs-safe', `Cannot read ${filePath}: ${e.code || e.message}`);
    return null;
  }
}

// opts.maxBytes: skip (return null) files larger than this, and anything that isn't a regular file.
function readJsonSafe(filePath, opts = {}) {
  const raw = readFileSafe(filePath, opts.maxBytes ? { maxBytes: opts.maxBytes, skipLarger: true } : {});
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
 * Directories never entered when collecting project directories (onDir). Repos can
 * live in Downloads, OneDrive, Dropbox etc., so those stay walkable for discovery;
 * these are build output, VCS internals and package caches that never hold one.
 */
const DISCOVERY_SKIP = new Set([
  'node_modules', '.git', '.svn', '.hg', '__pycache__',
  'dist', 'build', 'target', '.next', '.output', 'vendor',
  '.cache', '.local',
  '.npm', '.yarn', '.pnpm-store', '.m2', '.ivy2', '.sbt', '.gradle', '.nuget',
  '.cargo', '.rustup', '.conda', '.virtualenvs', '.pyenv', '.rbenv', '.nvm', '.sdkman', '.jabba',
  '.tox', '.nox', '.eggs', '__pypackages__', '.pytest_cache', '.terraform',
]);

/**
 * Cloud-sync folders. Files there may be online-only placeholders that the OS downloads
 * when read, so scanners only look at names inside them, never contents.
 */
function isCloudSyncedName(name) {
  const lower = name.toLowerCase();
  return lower.startsWith('onedrive') || lower === 'dropbox' || lower === 'google drive'
    || lower === 'icloud drive' || lower === 'cloudstorage' || lower === 'mobile documents';
}

function isCloudSyncedPath(p) {
  return path.resolve(p).split(path.sep).some(isCloudSyncedName);
}

/**
 * Walk directories up to maxDepth, yielding files matching a filter.
 * Respects symlink safety and skips unreadable dirs.
 * Uses a built-in skip set plus caller-supplied extras for O(1) lookups.
 *
 * opts.onDir(dirPath, dirents, { cloud }) is called for every directory visited
 * (cloud: inside a cloud-sync folder, see isCloudSyncedName). When it is
 * set, directories in the built-in skip set are still entered for onDir (unless in
 * DISCOVERY_SKIP), but no files are matched inside them, so file results are
 * unchanged by passing onDir.
 */
function walkSync(dir, opts = {}) {
  const { maxDepth = 10, filter = null, skipDirs = [], onDir = null } = opts;
  const results = [];
  const extraSkip = skipDirs.length > 0 ? new Set(skipDirs) : null;

  function walk(currentDir, depth, filesSuppressed, cloud) {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    if (onDir) onDir(currentDir, entries, { cloud });

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (extraSkip && extraSkip.has(lower)) continue;
        const skipped = BUILTIN_SKIP.has(lower) || lower.startsWith('onedrive');
        const childCloud = cloud || isCloudSyncedName(entry.name);
        if (!skipped) {
          walk(path.join(currentDir, entry.name), depth + 1, filesSuppressed, childCloud);
        } else if (onDir && !DISCOVERY_SKIP.has(lower)) {
          walk(path.join(currentDir, entry.name), depth + 1, true, childCloud);
        }
      } else if (entry.isFile() && !filesSuppressed) {
        if (!filter || filter(entry.name, path.join(currentDir, entry.name))) {
          results.push(path.join(currentDir, entry.name));
        }
      }
    }
  }

  walk(dir, 0, false, onDir ? isCloudSyncedPath(dir) : false);
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

// Entries that mark a directory as a project (or an AI-assistant workspace) worth inspecting.
const PROJECT_MARKERS = new Set([
  'package.json', 'go.mod', 'Cargo.toml', 'composer.json', 'Gemfile', 'pyproject.toml',
  'setup.py', 'pom.xml', 'build.gradle', 'build.gradle.kts',
  '.cursorrules', '.windsurfrules', '.clinerules', 'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.mcp.json',
]);

/**
 * Returns an onDir callback for walkSync that records project directories into `out`
 * as { dir, gitDir, packageJson, cloud } — gitDir: holds a .git dir or file; packageJson:
 * holds a package.json (an npm/pnpm/yarn project, installed or not); cloud: inside a
 * cloud-sync folder, so only names may be inspected.
 */
function projectDirCollector(out) {
  return (dir, entries, info = {}) => {
    let isProject = false;
    let gitDir = false;
    let packageJson = false;
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.name === '.git' && (e.isDirectory() || e.isFile())) gitDir = true;
      else if (PROJECT_MARKERS.has(e.name)) {
        isProject = true;
        if (e.name === 'package.json' && e.isFile()) packageJson = true;
      }
    }
    if (isProject || gitDir) out.push({ dir, gitDir, packageJson, cloud: !!info.cloud });
  };
}

/** Walk roots once and return project directories (see projectDirCollector). */
function findProjectDirs(roots, opts = {}) {
  const out = [];
  const onDir = projectDirCollector(out);
  for (const root of roots) {
    if (existsSafe(root)) walkSync(root, { ...opts, filter: () => false, onDir });
  }
  return out;
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
  findProjectDirs,
  projectDirCollector,
  isCloudSyncedName,
  isCloudSyncedPath,
};
