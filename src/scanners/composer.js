'use strict';

const path = require('path');
const { readJsonSafe, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'composer';

/**
 * Scan PHP Composer packages by finding composer.lock files.
 */
function scan(platform, opts = {}, preFoundFiles) {
  const lockfiles = preFoundFiles || findFiles(platform.projectRoots, 'composer.lock', { maxDepth: opts.maxDepth || 4 });
  logger.info(SCANNER_ID, `Found ${lockfiles.length} composer.lock files`);

  const projects = [];

  for (const lockfile of lockfiles) {
    const data = readJsonSafe(lockfile);
    if (!data) continue;

    const projectDir = path.dirname(lockfile);
    const projectName = path.basename(projectDir);
    const dependencies = [];

    for (const pkg of (data.packages || [])) {
      dependencies.push({
        name: pkg.name,
        version: (pkg.version || '').replace(/^v/, ''),
        source: pkg.source?.url || null,
        type: pkg.type || null,
        license: Array.isArray(pkg.license) ? pkg.license.join(', ') : (pkg.license || null),
        dev: false,
      });
    }

    for (const pkg of (data['packages-dev'] || [])) {
      dependencies.push({
        name: pkg.name,
        version: (pkg.version || '').replace(/^v/, ''),
        source: pkg.source?.url || null,
        type: pkg.type || null,
        license: Array.isArray(pkg.license) ? pkg.license.join(', ') : (pkg.license || null),
        dev: true,
      });
    }

    projects.push({
      project: projectName,
      project_path: projectDir,
      lockfile,
      total_dependencies: dependencies.length,
      dependencies,
    });

    logger.debug(SCANNER_ID, `${projectName}: ${dependencies.length} deps`);
  }

  return { ecosystem: SCANNER_ID, projects, total_projects: projects.length };
}

module.exports = { scan, SCANNER_ID };
