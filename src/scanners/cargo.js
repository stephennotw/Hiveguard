'use strict';

const path = require('path');
const { readFileSafe, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'cargo';

/**
 * Scan Rust dependencies by finding Cargo.lock files.
 */
function scan(platform, opts = {}) {
  const maxDepth = opts.maxDepth || 6;
  const roots = platform.projectRoots;

  logger.info(SCANNER_ID, `Searching for Cargo.lock...`);
  const lockfiles = findFiles(roots, 'Cargo.lock', { maxDepth });
  logger.info(SCANNER_ID, `Found ${lockfiles.length} Cargo.lock files`);

  const projects = [];

  for (const lockfile of lockfiles) {
    const raw = readFileSafe(lockfile);
    if (!raw) continue;

    const projectDir = path.dirname(lockfile);
    const projectName = path.basename(projectDir);
    const dependencies = [];

    // Parse TOML-like [[package]] blocks
    let current = null;
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();

      if (trimmed === '[[package]]') {
        if (current && current.name && current.version) {
          dependencies.push(current);
        }
        current = {};
        continue;
      }

      if (current) {
        const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) { current.name = nameMatch[1]; continue; }

        const verMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
        if (verMatch) { current.version = verMatch[1]; continue; }

        const srcMatch = trimmed.match(/^source\s*=\s*"([^"]+)"/);
        if (srcMatch) { current.source = srcMatch[1]; continue; }

        const csMatch = trimmed.match(/^checksum\s*=\s*"([^"]+)"/);
        if (csMatch) { current.checksum = csMatch[1]; continue; }
      }
    }
    // Push last package
    if (current && current.name && current.version) {
      dependencies.push(current);
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
