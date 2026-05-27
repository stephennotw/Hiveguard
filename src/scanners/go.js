'use strict';

const path = require('path');
const { readFileSafe, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'go';

/**
 * Scan Go modules by finding go.sum files.
 * Each line: module version hash
 */
function scan(platform, opts = {}) {
  const maxDepth = opts.maxDepth || 6;
  const roots = platform.projectRoots;

  logger.info(SCANNER_ID, `Searching for go.sum in ${roots.length} root dirs...`);
  const goSumFiles = findFiles(roots, 'go.sum', { maxDepth });
  logger.info(SCANNER_ID, `Found ${goSumFiles.length} go.sum files`);

  const projects = [];

  for (const sumFile of goSumFiles) {
    const raw = readFileSafe(sumFile);
    if (!raw) continue;

    const projectDir = path.dirname(sumFile);
    const projectName = path.basename(projectDir);
    const dependencies = [];
    const seen = new Set();

    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      // Format: module version hash
      // Also: module version/go.mod hash
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) continue;

      const mod = parts[0];
      let version = parts[1];

      // Skip /go.mod entries (duplicates)
      if (version.endsWith('/go.mod')) continue;

      // Normalize version
      version = version.replace(/^v/, '');

      const key = `${mod}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      dependencies.push({
        name: mod,
        version,
        integrity: parts[2] || null,
      });
    }

    // Also try parsing go.mod for direct dependencies
    const goModPath = path.join(projectDir, 'go.mod');
    const goModRaw = readFileSafe(goModPath);
    const directDeps = new Set();
    if (goModRaw) {
      let inRequire = false;
      for (const line of goModRaw.split('\n')) {
        const t = line.trim();
        if (t === 'require (') { inRequire = true; continue; }
        if (t === ')') { inRequire = false; continue; }
        if (inRequire) {
          const match = t.match(/^(\S+)\s+v?(\S+)/);
          if (match) directDeps.add(match[1]);
        }
        // Single-line require
        const single = t.match(/^require\s+(\S+)\s+v?(\S+)/);
        if (single) directDeps.add(single[1]);
      }
    }

    // Mark direct vs transitive
    for (const dep of dependencies) {
      dep.direct = directDeps.has(dep.name);
    }

    projects.push({
      project: projectName,
      project_path: projectDir,
      sum_file: sumFile,
      total_dependencies: dependencies.length,
      direct_dependencies: directDeps.size,
      dependencies,
    });

    logger.debug(SCANNER_ID, `${projectName}: ${dependencies.length} deps (${directDeps.size} direct)`);
  }

  return { ecosystem: SCANNER_ID, projects, total_projects: projects.length };
}

module.exports = { scan, SCANNER_ID };
