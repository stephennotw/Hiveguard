'use strict';

const path = require('path');
const { readJsonSafe, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'npm';

/**
 * Scan for npm projects by finding package-lock.json files.
 * Parses lockfile v2/v3 (packages) and v1 (dependencies).
 */
function scan(platform, opts = {}) {
  const maxDepth = opts.maxDepth || 6;
  const roots = platform.projectRoots;

  logger.info(SCANNER_ID, `Searching for package-lock.json in ${roots.length} root dirs...`);
  const lockfiles = findFiles(roots, 'package-lock.json', { maxDepth });
  logger.info(SCANNER_ID, `Found ${lockfiles.length} lockfiles`);

  const projects = [];

  for (const lockfile of lockfiles) {
    const data = readJsonSafe(lockfile);
    if (!data) continue;

    const projectDir = path.dirname(lockfile);
    const projectName = data.name || path.basename(projectDir);
    const dependencies = [];

    if (data.packages && typeof data.packages === 'object') {
      // Lockfile v2/v3
      for (const [pkgPath, info] of Object.entries(data.packages)) {
        if (pkgPath === '') continue; // root package
        if (!info.version) continue;

        const name = pkgPath.startsWith('node_modules/')
          ? pkgPath.replace(/^node_modules\//, '')
          : pkgPath;

        // Skip nested node_modules (transitive-of-transitive)
        const parts = name.split('node_modules/');
        const finalName = parts[parts.length - 1];

        dependencies.push({
          name: finalName,
          version: info.version,
          resolved: info.resolved || null,
          integrity: info.integrity || null,
          dev: !!info.dev,
          optional: !!info.optional,
        });
      }
    } else if (data.dependencies && typeof data.dependencies === 'object') {
      // Lockfile v1
      parseDepsV1(data.dependencies, dependencies);
    }

    projects.push({
      project: projectName,
      project_path: projectDir,
      lockfile,
      lockfile_version: data.lockfileVersion || 1,
      total_dependencies: dependencies.length,
      dependencies,
    });

    logger.debug(SCANNER_ID, `${projectName}: ${dependencies.length} deps`);
  }

  return { ecosystem: SCANNER_ID, projects, total_projects: projects.length };
}

function parseDepsV1(deps, results, prefix = '') {
  for (const [name, info] of Object.entries(deps)) {
    if (!info.version) continue;
    results.push({
      name,
      version: info.version,
      resolved: info.resolved || null,
      integrity: info.integrity || null,
      dev: !!info.dev,
      optional: !!info.optional,
    });
    if (info.dependencies) {
      parseDepsV1(info.dependencies, results, name + '/');
    }
  }
}

/**
 * Scan global npm packages.
 */
function scanGlobal(platform) {
  const results = [];
  for (const globalDir of (platform.npmGlobalDirs || [])) {
    const pkgJson = path.join(globalDir, 'package.json');
    const data = readJsonSafe(pkgJson);
    if (data && data.dependencies) {
      for (const [name, version] of Object.entries(data.dependencies)) {
        results.push({ name, version: String(version).replace(/^\^|~/, ''), global: true });
      }
    }
    // Also check node_modules directly
    const { readdirSafe } = require('../utils/fs-safe');
    const nmDir = path.join(globalDir, 'node_modules');
    for (const entry of readdirSafe(nmDir)) {
      if (entry.startsWith('.') || entry.startsWith('@')) continue;
      const epkg = readJsonSafe(path.join(nmDir, entry, 'package.json'));
      if (epkg && epkg.version) {
        if (!results.find(r => r.name === epkg.name)) {
          results.push({ name: epkg.name || entry, version: epkg.version, global: true });
        }
      }
    }
  }

  logger.info(SCANNER_ID, `Found ${results.length} global npm packages`);
  return results;
}

module.exports = { scan, scanGlobal, SCANNER_ID };
