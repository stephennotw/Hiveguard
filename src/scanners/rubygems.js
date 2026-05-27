'use strict';

const path = require('path');
const { readFileSafe, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'rubygems';

/**
 * Scan Ruby dependencies by finding Gemfile.lock files.
 */
function scan(platform, opts = {}) {
  const maxDepth = opts.maxDepth || 6;
  const roots = platform.projectRoots;

  logger.info(SCANNER_ID, `Searching for Gemfile.lock...`);
  const lockfiles = findFiles(roots, 'Gemfile.lock', { maxDepth });
  logger.info(SCANNER_ID, `Found ${lockfiles.length} Gemfile.lock files`);

  const projects = [];

  for (const lockfile of lockfiles) {
    const raw = readFileSafe(lockfile);
    if (!raw) continue;

    const projectDir = path.dirname(lockfile);
    const projectName = path.basename(projectDir);
    const dependencies = [];

    // Parse GEM section -> specs
    let inSpecs = false;
    for (const line of raw.split('\n')) {
      const trimmed = line.trimEnd();

      if (trimmed === '    specs:' || trimmed === '  specs:') {
        inSpecs = true;
        continue;
      }

      // End of specs when we hit a non-indented line or different section
      if (inSpecs && (trimmed === '' || (!trimmed.startsWith('    ') && !trimmed.startsWith('      ')))) {
        if (!trimmed.startsWith('      ')) inSpecs = false;
        if (!inSpecs) continue;
      }

      if (inSpecs) {
        // Gem entries are indented 4 spaces: "    gemname (version)"
        const match = trimmed.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          dependencies.push({
            name: match[1],
            version: match[2],
          });
        }
      }
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
