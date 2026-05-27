'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, readJsonSafe, existsSafe, readdirSafe, walkSync, findFiles } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'pypi';

/**
 * Scan Python packages by:
 * 1. Finding venvs and reading dist-info/METADATA
 * 2. Finding requirements.txt files
 * 3. Checking global/user site-packages
 */
function scan(platform, opts = {}) {
  const maxDepth = opts.maxDepth || 6;
  const roots = platform.projectRoots;
  const packages = [];
  const seenKeys = new Set();

  // Strategy 1: Find virtualenvs (pyvenv.cfg marks a venv)
  const venvConfigs = findFiles(roots, 'pyvenv.cfg', { maxDepth: maxDepth });
  logger.info(SCANNER_ID, `Found ${venvConfigs.length} Python virtual environments`);

  for (const cfg of venvConfigs) {
    const venvDir = path.dirname(cfg);
    const sitePackages = findSitePackages(venvDir);
    if (sitePackages) {
      const pkgs = parseSitePackages(sitePackages, venvDir);
      for (const pkg of pkgs) {
        const key = `${pkg.name}:${pkg.version}:${pkg.source_dir}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          packages.push(pkg);
        }
      }
    }
  }

  // Strategy 2: Find requirements.txt
  const reqFiles = findFiles(roots, 'requirements.txt', { maxDepth });
  logger.info(SCANNER_ID, `Found ${reqFiles.length} requirements.txt files`);

  for (const reqFile of reqFiles) {
    const pkgs = parseRequirementsTxt(reqFile);
    for (const pkg of pkgs) {
      const key = `req:${pkg.name}:${pkg.version}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        packages.push(pkg);
      }
    }
  }

  // Strategy 3: Check global/user site-packages
  const globalPkgs = scanGlobalPython(platform);
  for (const pkg of globalPkgs) {
    const key = `global:${pkg.name}:${pkg.version}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      packages.push(pkg);
    }
  }

  logger.info(SCANNER_ID, `Total Python packages found: ${packages.length}`);
  return { ecosystem: SCANNER_ID, packages, total: packages.length };
}

function findSitePackages(venvDir) {
  // Windows: Lib/site-packages, Unix: lib/python*/site-packages
  const winPath = path.join(venvDir, 'Lib', 'site-packages');
  if (existsSafe(winPath)) return winPath;

  const libDir = path.join(venvDir, 'lib');
  for (const entry of readdirSafe(libDir)) {
    if (entry.startsWith('python')) {
      const sp = path.join(libDir, entry, 'site-packages');
      if (existsSafe(sp)) return sp;
    }
  }
  return null;
}

function parseSitePackages(siteDir, source) {
  const packages = [];
  for (const entry of readdirSafe(siteDir)) {
    if (!entry.endsWith('.dist-info')) continue;
    const metadataPath = path.join(siteDir, entry, 'METADATA');
    const raw = readFileSafe(metadataPath);
    if (!raw) continue;

    const pkg = parseMetadata(raw);
    if (pkg.name && pkg.version) {
      pkg.source_dir = source;
      pkg.source_type = 'venv';

      // Check installer
      const installerPath = path.join(siteDir, entry, 'INSTALLER');
      const installer = readFileSafe(installerPath);
      if (installer) pkg.installer = installer.trim();

      packages.push(pkg);
    }
  }
  return packages;
}

function parseMetadata(raw) {
  const pkg = {};
  for (const line of raw.split('\n')) {
    if (line.startsWith('Name: ')) pkg.name = line.slice(6).trim();
    else if (line.startsWith('Version: ')) pkg.version = line.slice(9).trim();
    else if (line.startsWith('Summary: ')) pkg.summary = line.slice(9).trim();
    else if (line.startsWith('License: ')) pkg.license = line.slice(9).trim();
    else if (line.startsWith('Author: ')) pkg.author = line.slice(8).trim();
    if (pkg.name && pkg.version) break; // Early exit for speed
  }
  return pkg;
}

function parseRequirementsTxt(filePath) {
  const raw = readFileSafe(filePath);
  if (!raw) return [];
  const packages = [];

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

    // Parse: package==version, package>=version, package~=version
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*[=~><!]+\s*([a-zA-Z0-9_.*+-]+)/);
    if (match) {
      packages.push({
        name: match[1],
        version: match[2],
        source_dir: filePath,
        source_type: 'requirements.txt',
        confidence: 'medium', // version spec, not exact installed
      });
    }
  }
  return packages;
}

function scanGlobalPython(platform) {
  const packages = [];
  const patterns = platform.pythonSitePackages || [];

  for (const pattern of patterns) {
    // Resolve glob patterns
    const dir = path.dirname(pattern);
    if (!existsSafe(dir)) continue;

    try {
      const dirs = resolveGlob(pattern);
      for (const spDir of dirs) {
        const pkgs = parseSitePackages(spDir, 'global');
        for (const p of pkgs) {
          p.source_type = 'global';
          packages.push(p);
        }
      }
    } catch { /* skip */ }
  }

  return packages;
}

function resolveGlob(pattern) {
  const parts = pattern.split(path.sep);
  let current = [parts[0] === '' ? path.sep : parts[0]];

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const next = [];
    for (const dir of current) {
      if (part.includes('*')) {
        const regex = new RegExp('^' + part.replace(/\*/g, '.*') + '$');
        for (const entry of readdirSafe(dir)) {
          if (regex.test(entry)) {
            const full = path.join(dir, entry);
            if (existsSafe(full)) next.push(full);
          }
        }
      } else {
        const full = path.join(dir, part);
        if (existsSafe(full)) next.push(full);
      }
    }
    current = next;
  }
  return current;
}

module.exports = { scan, SCANNER_ID };
