#!/usr/bin/env node
'use strict';

// Parallel file reads (install-script scan) run on libuv's thread pool, 4 threads by
// default. Must be set before the pool is first used.
if (!process.env.UV_THREADPOOL_SIZE) process.env.UV_THREADPOOL_SIZE = '8';

/**
 * HiveGuard — Cross-platform endpoint supply chain scanner
 * 
 * Usage:
 *   node hiveguard.js [options]
 * 
 * Options:
 *   --output <dir>      Output directory for results (default: ./hiveguard-results)
 *   --json              Output JSON to stdout (quiet mode for automation)
 *   --offline            Skip threat intel sync (use cached catalogs only)
 *   --scan-dirs <dirs>  Comma-separated list of directories to scan
 *   --users-root <dir>  Scan user profiles under <dir> only (skips system-wide paths)
 *   --no-report         Skip HTML report generation
 *   --no-secrets        Skip secrets hygiene scan
 *   --max-depth <n>     Max directory depth for lockfile search (default: 4)
 *   --verbose           Enable debug logging
 *   --help              Show this help message
 * 
 * Exit codes:
 *   0 — Clean (no threats, no critical findings)
 *   1 — Findings present (medium/high CVEs, advisories)
 *   2 — Critical (supply chain compromise detected via threat intel)
 */

const path = require('path');
const fs = require('fs');

// Resolve source root for both direct and bundled execution
const SRC_ROOT = path.resolve(__dirname, '..', 'src');

const logger = require(path.join(SRC_ROOT, 'utils', 'logger'));
const { getPlatform, getSystemInfo } = require(path.join(SRC_ROOT, 'platform'));
const output = require(path.join(SRC_ROOT, 'utils', 'output'));
const { findMultipleFiles, projectDirCollector } = require(path.join(SRC_ROOT, 'utils', 'fs-safe'));
const VERSION = require(path.join(SRC_ROOT, 'version'));

// Scanners
const npmScanner = require(path.join(SRC_ROOT, 'scanners', 'npm'));
const pypiScanner = require(path.join(SRC_ROOT, 'scanners', 'pypi'));
const goScanner = require(path.join(SRC_ROOT, 'scanners', 'go'));
const composerScanner = require(path.join(SRC_ROOT, 'scanners', 'composer'));
const rubygemsScanner = require(path.join(SRC_ROOT, 'scanners', 'rubygems'));
const cargoScanner = require(path.join(SRC_ROOT, 'scanners', 'cargo'));
const lockfilesScanner = require(path.join(SRC_ROOT, 'scanners', 'lockfiles'));
const persistenceScanner = require(path.join(SRC_ROOT, 'scanners', 'persistence'));
const { configureIocs } = require(path.join(SRC_ROOT, 'utils', 'script-inspect'));
const { extractIocs } = require(path.join(SRC_ROOT, 'threat-intel', 'iocs'));
const { parseIocs, matchPackageIoc } = require(path.join(SRC_ROOT, 'threat-intel', 'cli-iocs'));
const exportsFmt = require(path.join(SRC_ROOT, 'report', 'exports'));
const { iocHits } = require(path.join(SRC_ROOT, 'utils', 'script-inspect'));
const editorExtScanner = require(path.join(SRC_ROOT, 'scanners', 'editor-extensions'));
const browserExtScanner = require(path.join(SRC_ROOT, 'scanners', 'browser-extensions'));
const mcpScanner = require(path.join(SRC_ROOT, 'scanners', 'mcp-configs'));
const secretsScanner = require(path.join(SRC_ROOT, 'scanners', 'secrets-hygiene'));
const lifecycleScanner = require(path.join(SRC_ROOT, 'scanners', 'lifecycle-scripts'));
const gitHooksScanner = require(path.join(SRC_ROOT, 'scanners', 'git-hooks'));
const aiInstructionsScanner = require(path.join(SRC_ROOT, 'scanners', 'ai-instructions'));
const aiModelsScanner = require(path.join(SRC_ROOT, 'scanners', 'ai-models'));
const aiUsageScanner = require(path.join(SRC_ROOT, 'scanners', 'ai-usage'));
const aiAppsScanner = require(path.join(SRC_ROOT, 'scanners', 'ai-apps'));
const { agentRoots, mcpCandidates, editorForks } = require(path.join(SRC_ROOT, 'utils', 'ai-roots'));

// Threat intel
const { loadThreatIntel } = require(path.join(SRC_ROOT, 'threat-intel', 'sync'));
const { buildIndex, matchPackages, mergeThreatMatches } = require(path.join(SRC_ROOT, 'threat-intel', 'matcher'));
const { queryOsv } = require(path.join(SRC_ROOT, 'threat-intel', 'osv'));
const { queryGhsa } = require(path.join(SRC_ROOT, 'threat-intel', 'ghsa'));

// CVE
const { checkKnownVulns } = require(path.join(SRC_ROOT, 'cve', 'known-vulns'));

// Report
const { generateReport } = require(path.join(SRC_ROOT, 'report', 'html-report'));

const EXPORT_FORMATS = ['sarif', 'cyclonedx', 'ndjson'];

// ── Parse CLI arguments ──
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    outputDir: './hiveguard-results',
    json: false,
    offline: false,
    scanDirs: null,
    customIntelDirs: [],
    usersRoot: null,
    normalPriority: false,
    noReport: false,
    noSecrets: false,
    maxDepth: 4,
    formats: [],
    iocs: [],
    iocFile: null,
    verbose: false,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--output': case '-o':
        opts.outputDir = args[++i] || opts.outputDir;
        break;
      case '--json':
        opts.json = true;
        break;
      case '--offline':
        opts.offline = true;
        break;
      case '--normal-priority':
        opts.normalPriority = true;
        break;
      case '--users-root':
        opts.usersRoot = args[++i] || null;
        break;
      case '--scan-dirs':
        opts.scanDirs = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
        break;
      case '--custom-intel':
        opts.customIntelDirs.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--no-report':
        opts.noReport = true;
        break;
      case '--no-secrets':
        opts.noSecrets = true;
        break;
      case '--max-depth':
        opts.maxDepth = parseInt(args[++i]) || 4;
        break;
      case '--format': case '--formats': {
        const list = (args[++i] || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        opts.formats.push(...(list.includes('all') ? EXPORT_FORMATS : list));
        break;
      }
      case '--ioc':
        opts.iocs.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--ioc-file':
        opts.iocFile = args[++i] || null;
        break;
      case '--verbose': case '-v':
        opts.verbose = true;
        break;
      case '--help': case '-h':
        opts.help = true;
        break;
    }
  }

  return opts;
}

function showHelp() {
  const help = `
  🐝 HiveGuard — Cross-platform Endpoint Supply Chain Scanner

  Usage:  node hiveguard.js [options]

  Options:
    --output <dir>       Output directory (default: ./hiveguard-results)
    --json               Output JSON to stdout (quiet mode)
    --offline            No network: bundled and custom threat intel only
    --scan-dirs <dirs>   Comma-separated scan directories
    --users-root <dir>   Scan user profiles under <dir> only (e.g. a mounted disk image)
    --normal-priority    Run at normal CPU priority (default: below normal)
    --custom-intel <dir> Dir(s) with custom threat intel JSON catalogs
    --no-report          Skip HTML report generation
    --no-secrets         Skip secrets hygiene scan
    --max-depth <n>      Max directory depth (default: 4)
    --format <list>      Also write sarif, cyclonedx (SBOM), ndjson (SIEM events), or all
    --ioc <values>       Look for indicators: name@version, eco:name, sha256, file name,
                         path (~/..., /..., C:\\...), domain or text; comma-separated, repeatable
    --ioc-file <file>    Indicators, one per line (# comments allowed)
    --verbose, -v        Debug logging
    --help, -h           Show this message

  Exit codes:
    0  Clean
    1  Critical or high findings
    2  Known-compromised package installed, or an --ioc indicator found
    3  Could not run

  Documentation: README.md and docs/ (HOW-TO.md, RESULTS-GUIDE.md, DEPLOYMENT.md)

  Examples:
    node hiveguard.js
    node hiveguard.js --output ./results --verbose
    node hiveguard.js --json --offline > results.json
    node hiveguard.js --scan-dirs /home/user/projects,/opt/apps
    node hiveguard.js --format sarif,cyclonedx
    node hiveguard.js --ioc "@antv/a8@0.1.1,~/.local/share/kitty/cat.py,t.m-kosche.com"
  `;
  console.log(help);
}

/**
 * Extract username from a file path by matching against discovered user home dirs.
 */
function resolveUser(filePath, userHomes) {
  if (!filePath || !userHomes || userHomes.length === 0) return null;
  const normalized = path.normalize(filePath);
  for (const home of userHomes) {
    if (normalized.startsWith(home + path.sep) || normalized === home) {
      return path.basename(home);
    }
  }
  return null;
}

// ── Main ──
async function main() {
  const opts = parseArgs();

  if (opts.help) {
    showHelp();
    process.exit(0);
  }

  if (opts.verbose) logger.setLevel('debug');
  if (opts.json) logger.setLevel('silent');

  const startTime = Date.now();

  // Stay out of the way of the user's own work on shared workstations.
  if (!opts.normalPriority) {
    try {
      require('os').setPriority(0, require('os').constants.priority.PRIORITY_BELOW_NORMAL);
    } catch (e) {
      logger.debug('core', `Could not lower process priority: ${e.message}`);
    }
  }

  if (!opts.json) {
    process.stderr.write('\n');
    process.stderr.write('  ╔═══════════════════════════════════════════════════╗\n');
    process.stderr.write(`  ║   🐝 HiveGuard — Supply Chain Scanner v${VERSION.padEnd(10)}║\n`);
    process.stderr.write('  ╚═══════════════════════════════════════════════════╝\n');
    process.stderr.write('\n');
  }

  // Step 1: System info
  const systemInfo = getSystemInfo();
  logger.info('core', `Host: ${systemInfo.hostname} | OS: ${systemInfo.platform}/${systemInfo.arch} | User: ${systemInfo.username}`);

  // Step 2: Platform detection
  const platform = getPlatform(opts.scanDirs, { usersRoot: opts.usersRoot });

  // Step 3: Threat intel — load into memory (live → baseline → custom)
  const intelResult = await loadThreatIntel({
    offline: opts.offline,
    customIntelDirs: opts.customIntelDirs,
  });
  const { catalogs, threatIndex, totalEntries, totalVersions } = buildIndex(intelResult.inMemoryCatalogs);

  // File-level indicators (payload names, hashes, markers, persistence paths) from the catalogs
  const iocs = extractIocs(catalogs);
  let cliIocs = [];
  try {
    cliIocs = parseIocs(opts.iocs, opts.iocFile);
  } catch (e) {
    process.stderr.write(`  Could not read --ioc-file: ${e.message}\n`);
    process.exit(3);
  }
  const ofKind = (k) => cliIocs.filter(i => i.kind === k).map(i => ({ value: i.value, source: i.source }));
  // Command-line indicators go last so their source wins when a value is also in a catalog.
  iocs.filenames.push(...ofKind('filename'));
  iocs.sha256.push(...ofKind('sha256'));
  iocs.strings.push(...ofKind('string'));
  iocs.paths.push(...ofKind('path'));
  configureIocs({ filenames: iocs.filenames, sha256: iocs.sha256, strings: iocs.strings });
  const iocNames = new Map(iocs.filenames.map(i => [i.value.toLowerCase(), i.source]));
  const walkIocFiles = [];

  // Step 4: Single-pass directory walk for all lockfile types
  logger.info('core', 'Starting scanners...');
  const scanOpts = { maxDepth: opts.maxDepth };

  const lockfileNames = [
    'package-lock.json', 'pyvenv.cfg', 'requirements.txt',
    'go.sum', 'composer.lock', 'Gemfile.lock', 'Cargo.lock',
    ...lockfilesScanner.LOCKFILE_NAMES,
  ];

  let t0 = Date.now();
  // The same walk records project directories for the git-hook and AI-file scanners
  const projectDirs = [];
  const modelCandidates = [];
  const envFiles = [];
  const collectEnvFiles = aiUsageScanner.envFileCollector(envFiles);
  const collectProject = projectDirCollector(projectDirs);
  const collectModels = aiModelsScanner.modelCandidateCollector(modelCandidates);
  const foundFiles = findMultipleFiles(platform.projectRoots, lockfileNames, {
    ...scanOpts,
    onDir: (dir, entries, info) => {
      collectProject(dir, entries, info); collectModels(dir, entries, info); collectEnvFiles(dir, entries, info);
      // Payload file names from catalogs and --ioc, matched on names the walk lists anyway
      if (iocNames.size > 0) {
        for (const e of entries) {
          const src = e.isFile() && iocNames.get(e.name.toLowerCase());
          if (src && walkIocFiles.length < 1000) walkIocFiles.push({ path: path.join(dir, e.name), source: src });
        }
      }
    },
  });
  logger.info('core', `Directory walk completed in ${Date.now() - t0}ms`);

  // Pass pre-found files to each scanner (avoids redundant walks)
  const timedScan = (label, fn) => { t0 = Date.now(); const r = fn(); logger.info('core', `  ${label}: ${Date.now() - t0}ms`); return r; };

  const scanResults = {};
  scanResults.npm = timedScan('npm', () => npmScanner.scan(platform, scanOpts, foundFiles.get('package-lock.json')));
  scanResults.npm_global = timedScan('npm-global', () => npmScanner.scanGlobal(platform));
  scanResults.pypi = timedScan('pypi', () => pypiScanner.scan(platform, scanOpts, {
    venvConfigs: foundFiles.get('pyvenv.cfg'),
    reqFiles: foundFiles.get('requirements.txt'),
  }));
  // pnpm / yarn / bun / poetry / uv / pipenv lockfiles feed the npm and pypi inventories.
  // A directory that already has a package-lock.json keeps that (richer) source.
  const extraLocks = timedScan('lockfiles', () => lockfilesScanner.scan(foundFiles));
  const npmDirs = new Set((scanResults.npm.projects || []).map(p => path.resolve(p.project_path)));
  for (const proj of extraLocks.projects) {
    if (proj.ecosystem === 'npm') {
      if (npmDirs.has(path.resolve(proj.project_path))) continue;
      const { ecosystem, ...rest } = proj;
      scanResults.npm.projects.push(rest);
    } else {
      const seenPy = new Set(scanResults.pypi.packages.map(p => `${p.name}@${p.version}@${p.source_dir}`));
      for (const d of proj.dependencies) {
        const key = `${d.name}@${d.version}@${proj.project_path}`;
        if (seenPy.has(key)) continue;
        seenPy.add(key);
        scanResults.pypi.packages.push({
          name: d.name, version: d.version, source_dir: proj.project_path,
          source_type: proj.lockfile_type, installer: proj.lockfile_type, confidence: 'high',
        });
      }
    }
  }
  scanResults.npm.total_projects = scanResults.npm.projects.length;
  scanResults.pypi.total = scanResults.pypi.packages.length;
  scanResults.lockfiles = {
    parsed: extraLocks.projects.map(p => ({ lockfile: p.lockfile, type: p.lockfile_type, ecosystem: p.ecosystem, dependencies: p.total_dependencies })),
    unparsed: extraLocks.unparsed,
  };
  scanResults.go = timedScan('go', () => goScanner.scan(platform, scanOpts, foundFiles.get('go.sum')));
  scanResults.composer = timedScan('composer', () => composerScanner.scan(platform, scanOpts, foundFiles.get('composer.lock')));
  scanResults.rubygems = timedScan('rubygems', () => rubygemsScanner.scan(platform, scanOpts, foundFiles.get('Gemfile.lock')));
  scanResults.cargo = timedScan('cargo', () => cargoScanner.scan(platform, scanOpts, foundFiles.get('Cargo.lock')));
  // AI tool locations by structure, not product name (see src/utils/ai-roots.js)
  const aiRoots = timedScan('ai-roots', () => agentRoots(platform));
  const knownExtDirs = new Set(Object.values(platform.editorExtensionDirs || {}).flat().map(p => path.resolve(p)));
  const discoveredEditors = [];
  for (const [label, dirs] of Object.entries(editorForks(platform, aiRoots))) {
    const fresh = dirs.filter(d => !knownExtDirs.has(path.resolve(d)));
    if (fresh.length === 0) continue;
    platform.editorExtensionDirs = platform.editorExtensionDirs || {};
    platform.editorExtensionDirs[label] = [...(platform.editorExtensionDirs[label] || []), ...fresh];
    discoveredEditors.push(label);
  }
  t0 = Date.now();
  scanResults.editor_extensions = await editorExtScanner.scan(platform);
  logger.info('core', `  editor-ext: ${Date.now() - t0}ms`);
  scanResults.editor_extensions.discovered_editors = discoveredEditors;
  scanResults.browser_extensions = timedScan('browser-ext', () => browserExtScanner.scan(platform));
  const mcpDiscovery = {};
  scanResults.mcp_configs = timedScan('mcp', () => mcpScanner.scan(platform, scanOpts, mcpCandidates(platform, aiRoots, mcpDiscovery)));
  scanResults.mcp_configs.discovery = mcpDiscovery;

  if (!opts.noSecrets) {
    scanResults.secrets_hygiene = timedScan('secrets', () => secretsScanner.scan(platform, scanOpts));
  }

  // Install scripts: lockfile projects plus every package.json directory, so pnpm/yarn
  // projects and freshly cloned repos (before npm install) are covered too.
  const lifecycleProjects = [...(scanResults.npm.projects || [])];
  const lifecyclePaths = new Set(lifecycleProjects.map(p => path.resolve(p.project_path)));
  for (const d of projectDirs) {
    if (d.packageJson && !d.cloud && !lifecyclePaths.has(path.resolve(d.dir))) {
      lifecyclePaths.add(path.resolve(d.dir));
      lifecycleProjects.push({ project: path.basename(d.dir), project_path: d.dir });
    }
  }
  t0 = Date.now();
  scanResults.lifecycle_scripts = await lifecycleScanner.scan(platform, scanOpts, lifecycleProjects);
  logger.info('core', `  lifecycle: ${Date.now() - t0}ms`);
  scanResults.git_hooks = timedScan('git-hooks', () => gitHooksScanner.scan(platform, scanOpts, projectDirs));
  scanResults.ai_instructions = timedScan('ai-instruct', () => aiInstructionsScanner.scan(platform, scanOpts, projectDirs));
  scanResults.ai_models = timedScan('ai-models', () => aiModelsScanner.scan(platform, scanOpts, modelCandidates));
  scanResults.ai_apps = timedScan('ai-apps', () => aiAppsScanner.scan(platform, scanOpts));
  scanResults.persistence = timedScan('persistence', () => persistenceScanner.scan(platform, scanOpts, iocs.paths));

  // Discovered user profiles for attributing findings
  const userHomes = platform.userHomes || [];

  // Step 4b: Enrich scanner results with user attribution
  for (const proj of (scanResults.npm?.projects || [])) {
    proj.user = resolveUser(proj.lockfile || proj.project_path, userHomes);
  }
  for (const pkg of (scanResults.pypi?.packages || [])) {
    pkg.user = resolveUser(pkg.source_dir || pkg.venv_path, userHomes);
  }
  for (const proj of (scanResults.go?.projects || [])) {
    proj.user = resolveUser(proj.sum_file || proj.project_path, userHomes);
  }
  for (const proj of (scanResults.composer?.projects || [])) {
    proj.user = resolveUser(proj.lockfile || proj.project_path, userHomes);
  }
  for (const proj of (scanResults.rubygems?.projects || [])) {
    proj.user = resolveUser(proj.lockfile || proj.project_path, userHomes);
  }
  for (const proj of (scanResults.cargo?.projects || [])) {
    proj.user = resolveUser(proj.lockfile || proj.project_path, userHomes);
  }
  for (const [, exts] of Object.entries(scanResults.editor_extensions?.editors || {})) {
    for (const ext of exts) ext.user = resolveUser(ext.path, userHomes);
  }
  for (const [, exts] of Object.entries(scanResults.browser_extensions?.browsers || {})) {
    for (const ext of exts) ext.user = resolveUser(ext.path, userHomes);
  }
  for (const cfg of (scanResults.mcp_configs?.configs || [])) {
    cfg.user = resolveUser(cfg.config_path, userHomes);
  }
  for (const e of (scanResults.persistence?.entries || [])) {
    e.user = resolveUser(e.path, userHomes);
  }

  // Step 5: Build flat package list for threat matching + CVE checking
  const flatPackages = buildFlatPackageList(scanResults, userHomes);
  scanResults.ai_usage = timedScan('ai-usage', () => aiUsageScanner.scan(platform, scanOpts, {
    envFiles, mcpConfigs: scanResults.mcp_configs.configs || [], packages: flatPackages,
  }));
  logger.info('core', `Total components inventoried: ${flatPackages.length}`);

  // Step 6: Threat intel matching (Bumblebee catalogs)
  const threatMatches = matchPackages(flatPackages, threatIndex);

  // Step 6b/6c: OpenSSF (OSV.dev) and GitHub Advisory DB malware checks.
  // Each reports its own status so an unreachable source is never read as 'clean'.
  const offlineSource = { matches: [], status: 'skipped', queried: 0, error: 'offline mode' };
  const runSource = async (label, fn) => {
    if (opts.offline) return offlineSource;
    try {
      return await fn(flatPackages, { timeout: 20000 });
    } catch (e) {
      logger.warn('core', `${label} query failed (non-fatal): ${e.message}`);
      return { matches: [], status: 'failed', queried: 0, error: e.message };
    }
  };
  const osvResult = await runSource('OSV.dev', queryOsv);
  const ghsaResult = await runSource('GitHub Advisory DB', queryGhsa);
  const osvMatches = osvResult.matches;
  const ghsaMatches = ghsaResult.matches;
  mergeThreatMatches(threatMatches, osvMatches);
  mergeThreatMatches(threatMatches, ghsaMatches);

  // Step 7: Known CVE checks
  const cveFindings = checkKnownVulns(flatPackages);

  // Step 8: Aggregate findings
  const allFindings = [];
  for (const match of threatMatches) {
    for (const t of match.threats) {
      allFindings.push({
        severity: 'critical',
        type: 'supply_chain_compromise',
        user: resolveUser(match.source || match.project, userHomes),
        location: match.source || null,
        ecosystem: match.ecosystem,
        package: match.name,
        version: match.version,
        project: match.project || '',
        attackType: t.attackType,
        campaignName: t.campaignName,
        catalog: t.catalog,
        source: t.source,
        indicators: t.indicators,
        text: `${match.name}@${match.version} — SUPPLY CHAIN COMPROMISE: ${t.attackType}`,
      });
    }
  }

  // CVE findings (deduplicate by package+version+cve, aggregate project locations)
  const cveMap = new Map();
  for (const f of cveFindings) {
    const key = `${f.package}@${f.version}:${f.cve || f.text}`;
    if (cveMap.has(key)) {
      const existing = cveMap.get(key);
      if (f.project && !existing.project.includes(f.project)) {
        existing.project += ', ' + f.project;
      }
    } else {
      cveMap.set(key, { type: 'known_cve', user: resolveUser(f.source || f.project, userHomes), ...f });
    }
  }
  for (const f of cveMap.values()) {
    allFindings.push(f);
  }

  // MCP server findings (unpinned package runners)
  for (const f of (scanResults.mcp_configs.findings || [])) {
    allFindings.push({ user: resolveUser(f.path, userHomes), version: '', ...f });
  }

  // Secrets findings
  if (scanResults.secrets_hygiene) {
    const sh = scanResults.secrets_hygiene;
    for (const f of [...sh.envFiles.findings, ...sh.gitCredentials.findings, ...sh.sshKeys.findings]) {
      allFindings.push({
        type: 'secrets_hygiene',
        user: resolveUser(f.path, userHomes),
        ecosystem: 'secrets',
        package: f.type || 'secrets-hygiene',
        version: '',
        text: f.message || f.text || '',
        ...f,
      });
    }
  }

  // Lifecycle script findings
  if (scanResults.lifecycle_scripts) {
    for (const f of scanResults.lifecycle_scripts.findings) {
      allFindings.push({
        type: 'suspicious_lifecycle_script',
        user: resolveUser(f.path, userHomes),
        ecosystem: f.ecosystem || 'npm',
        package: f.package,
        version: '',
        ...f,
      });
    }
  }

  // Git hook findings (only suspicious, not info-level)
  if (scanResults.git_hooks) {
    for (const f of scanResults.git_hooks.findings) {
      if (f.severity === 'info') continue;
      allFindings.push({
        type: 'suspicious_git_hook',
        user: resolveUser(f.path, userHomes),
        ecosystem: 'git',
        package: f.hook,
        version: '',
        ...f,
      });
    }
  }

  // AI instruction file findings
  if (scanResults.ai_instructions) {
    for (const f of scanResults.ai_instructions.findings) {
      allFindings.push({
        type: 'suspicious_ai_instruction',
        user: resolveUser(f.path, userHomes),
        ecosystem: 'ai-tools',
        package: f.tool,
        version: '',
        ...f,
      });
    }
  }

  // Editor extensions hiding code in invisible Unicode (GlassWorm)
  for (const f of (scanResults.editor_extensions.findings || [])) {
    allFindings.push({ user: resolveUser(f.path, userHomes), ...f });
  }

  // Autostart entries and catalog persistence files
  for (const f of (scanResults.persistence.findings || [])) {
    allFindings.push({ user: resolveUser(f.path, userHomes), package: f.name || path.basename(f.path), version: '', ...f });
  }

  // Payload file names seen during the directory walk
  const reportedIocFiles = new Set((scanResults.persistence.findings || []).map(f => f.path));
  for (const hit of walkIocFiles) {
    if (reportedIocFiles.has(hit.path)) continue;
    reportedIocFiles.add(hit.path);
    allFindings.push({
      severity: 'critical', type: 'known_ioc_file', user: resolveUser(hit.path, userHomes), ecosystem: 'persistence',
      package: path.basename(hit.path), version: '', path: hit.path, ioc: hit.source, triggers: ['known-payload-filename'],
      text: `File with a known payload name is present (${hit.source})`,
    });
  }

  // --ioc: packages, plus everything recorded by the file-level checks
  const iocSearch = cliIocs.map(ioc => {
    if (ioc.kind === 'invalid') return { ioc: ioc.raw, kind: ioc.kind, found: false, error: ioc.error, locations: [] };
    let locations = [];
    if (ioc.kind === 'package') {
      locations = matchPackageIoc(ioc, flatPackages).map(p => `${p.name}@${p.version} in ${p.source || p.project}`);
    } else {
      const fromFiles = iocHits().filter(h => h.source === ioc.source).map(h => h.file);
      const fromFindings = allFindings.filter(f => f.ioc === ioc.source).map(f => f.path);
      locations = [...new Set([...fromFiles, ...fromFindings].filter(Boolean))];
    }
    if (ioc.kind === 'package') {
      for (const loc of locations) {
        allFindings.push({
          severity: 'critical', type: 'ioc_match', ecosystem: ioc.ecosystem, package: ioc.name, version: ioc.version || '',
          ioc: ioc.source, location: loc, triggers: ['cli-ioc-package'], text: `Indicator ${ioc.raw} found: ${loc}`,
        });
      }
    }
    return { ioc: ioc.raw, kind: ioc.kind, value: ioc.value, found: locations.length > 0, locations: locations.slice(0, 200) };
  });

  // Sort by severity
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  // Step 9: Build final result
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  const result = {
    meta: {
      tool: 'hiveguard',
      version: VERSION,
      scan_time: new Date().toISOString(),
      elapsed_seconds: parseFloat(elapsed),
      users_scanned: userHomes.map(h => path.basename(h)),
      ...systemInfo,
    },
    threat_intel: {
      catalogs_loaded: catalogs.length,
      total_known_bad_entries: totalEntries,
      total_known_bad_versions: totalVersions,
      source: intelResult.source,
      last_sync: intelResult.lastSync,
      custom_catalogs: intelResult.customCount,
      custom_dirs: intelResult.customDirs,
      osv_matches: osvMatches.length,
      ghsa_matches: ghsaMatches.length,
      sources: {
        bumblebee: intelResult.liveStatus,
        osv: { status: osvResult.status, queried: osvResult.queried, error: osvResult.error },
        ghsa: { status: ghsaResult.status, queried: ghsaResult.queried, error: ghsaResult.error },
      },
      matches: threatMatches.length,
    },
    summary: {
      total_components: flatPackages.length,
      threat_matches: threatMatches.length,
      findings_critical: allFindings.filter(f => f.severity === 'critical').length,
      findings_high: allFindings.filter(f => f.severity === 'high').length,
      findings_medium: allFindings.filter(f => f.severity === 'medium').length,
      findings_low: allFindings.filter(f => f.severity === 'low').length,
      findings_total: allFindings.length,
      ecosystems: {
        npm_projects: scanResults.npm.total_projects,
        npm_global_packages: scanResults.npm_global.length,
        pypi_packages: scanResults.pypi.total,
        go_projects: scanResults.go.total_projects,
        composer_projects: scanResults.composer.total_projects,
        rubygems_projects: scanResults.rubygems.total_projects,
        cargo_projects: scanResults.cargo.total_projects,
        extra_lockfiles: scanResults.lockfiles.parsed.length,
        lockfiles_unparsed: scanResults.lockfiles.unparsed.length,
        editor_extensions: scanResults.editor_extensions.total,
        browser_extensions: scanResults.browser_extensions.total,
        mcp_servers: scanResults.mcp_configs.total_servers,
        lifecycle_scripts_scanned: scanResults.lifecycle_scripts.packages_scanned,
        lifecycle_scripts_findings: scanResults.lifecycle_scripts.total_findings,
        git_hooks_repos: scanResults.git_hooks.repos_scanned,
        git_hooks_suspicious: scanResults.git_hooks.suspicious,
        ai_instruction_files: scanResults.ai_instructions.files_found,
        ai_instruction_suspicious: scanResults.ai_instructions.suspicious,
        ai_models: scanResults.ai_models.total,
        ai_models_pickle: scanResults.ai_models.pickle_count,
        ai_provider_credentials: scanResults.ai_usage.providers.length,
        ai_sdks: scanResults.ai_usage.sdks.length,
        editors_discovered: (scanResults.editor_extensions.discovered_editors || []).length,
        ai_apps_known: new Set(scanResults.ai_apps.apps.map(a => a.id)).size,
        autostart_entries: scanResults.persistence.total,
        threat_intel_iocs: iocs.sha256.length + iocs.filenames.length + iocs.paths.length + iocs.strings.length,
      },
    },
    findings: allFindings,
    ecosystems: scanResults,
    packages: flatPackages,
    threat_matches: threatMatches,
    ...(cliIocs.length ? { ioc_search: iocSearch } : {}),
    catalogs: catalogs.map(c => ({
      file: c.file,
      campaignName: c.campaignName,
      entries: c.entries.length,
      comment: (c.comment || '').slice(0, 300),
    })),
  };

  // Step 10: Output
  fs.mkdirSync(opts.outputDir, { recursive: true });

  // Always write JSON file to disk
  const outStamp = Date.now();
  const jsonPath = path.join(opts.outputDir, `hiveguard-${systemInfo.hostname}-${outStamp}.json`);
  output.writeJson(jsonPath, result);

  // Always write HTML report (unless --no-report)
  if (!opts.noReport) {
    const htmlPath = path.join(opts.outputDir, `hiveguard-report-${systemInfo.hostname}.html`);
    const html = generateReport(result);
    output.writeHtml(htmlPath, html);
  }

  // Extra machine-readable formats (--format)
  const stem = path.join(opts.outputDir, `hiveguard-${systemInfo.hostname}-${outStamp}`);
  for (const fmt of new Set(opts.formats)) {
    const writers = {
      sarif: () => fs.writeFileSync(`${stem}.sarif`, JSON.stringify(exportsFmt.toSarif(result), null, 2)),
      cyclonedx: () => fs.writeFileSync(`${stem}.cdx.json`, JSON.stringify(exportsFmt.toCycloneDx(result), null, 2)),
      ndjson: () => fs.writeFileSync(`${stem}.ndjson`, exportsFmt.toNdjson(result)),
    };
    if (!writers[fmt]) { logger.warn('output', `Unknown --format "${fmt}" (use ${EXPORT_FORMATS.join(', ')} or all)`); continue; }
    try { writers[fmt](); } catch (e) { logger.error('output', `Failed to write ${fmt}: ${e.message}`); }
  }

  // If --json, also print to stdout
  if (opts.json) {
    await output.writeStdout(result);
  }

  // Summary to stderr
  process.stderr.write('\n');
  process.stderr.write('  ────────────────────────────────────────────\n');
  process.stderr.write(`  ✅ Scan complete in ${elapsed}s\n`);
  process.stderr.write(`     📦 ${flatPackages.length} components inventoried\n`);
  process.stderr.write(`     🛡️  ${catalogs.length} threat catalogs (${totalVersions} known-bad versions)${osvMatches.length > 0 ? ` + ${osvMatches.length} OSV` : ''}\n`);
  process.stderr.write(`     ${threatMatches.length > 0 ? '🚨' : '✅'} ${threatMatches.length} threat matches\n`);
  for (const [label, r] of [['Bumblebee live feed', intelResult.liveStatus], ['OSV.dev', osvResult], ['GitHub Advisory DB', ghsaResult]]) {
    if (r.status === 'failed' || r.status === 'partial') {
      process.stderr.write(`     ⚠️  ${label} ${r.status} (${r.error}) — threat matches may be incomplete\n`);
    }
  }
  process.stderr.write(`     ⚠️  ${allFindings.length} findings (${allFindings.filter(f => f.severity === 'critical').length} critical, ${allFindings.filter(f => f.severity === 'high').length} high)\n`);
  if (iocSearch.length > 0) {
    process.stderr.write(`     🔎 Indicators: ${iocSearch.filter(r => r.found).length} of ${iocSearch.length} found\n`);
    for (const r of iocSearch) {
      process.stderr.write(`        ${r.found ? 'FOUND    ' : r.error ? 'SKIPPED  ' : 'not found'}  ${r.ioc} (${r.kind})${r.error ? ` — ${r.error}` : ''}\n`);
      for (const loc of r.locations.slice(0, 5)) process.stderr.write(`                   ${loc}\n`);
      if (r.locations.length > 5) process.stderr.write(`                   …and ${r.locations.length - 5} more\n`);
    }
    if (iocSearch.some(r => ['sha256', 'string'].includes(r.kind))) {
      process.stderr.write('        (hashes and text are compared against script files HiveGuard inspects, not every file on disk)\n');
    }
  }
  process.stderr.write(`     📁 Results: ${opts.outputDir}\n`);
  process.stderr.write('  ────────────────────────────────────────────\n\n');

  // Exit code
  if (threatMatches.length > 0 || iocSearch.some(r => r.found)) process.exit(2);
  if (allFindings.some(f => f.severity === 'critical' || f.severity === 'high')) process.exit(1);
  process.exit(0);
}

/**
 * Flatten all scan results into a unified package list for matching.
 */
function buildFlatPackageList(scanResults, userHomes) {
  const packages = [];

  // npm projects
  for (const proj of (scanResults.npm.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'npm', name: dep.name, version: dep.version,
        user: resolveUser(proj.lockfile, userHomes),
        project: proj.project, source: proj.lockfile,
        resolved: dep.resolved, confidence: 'high',
      });
    }
  }

  // npm global
  for (const pkg of (scanResults.npm_global || [])) {
    packages.push({
      ecosystem: 'npm', name: pkg.name, version: pkg.version,
      user: null,
      project: '(global)', source: 'npm-global',
      confidence: 'high',
    });
  }

  // pypi
  for (const pkg of (scanResults.pypi.packages || [])) {
    // Derive a short project name from the source_dir path
    const srcDir = pkg.source_dir || '';
    const shortProject = srcDir.split(/[/\\]/).filter(Boolean).slice(-2).join('/') || pkg.source_type || 'pypi';
    packages.push({
      ecosystem: 'pypi', name: pkg.name, version: pkg.version,
      user: resolveUser(srcDir, userHomes),
      project: shortProject, source: srcDir,
      sourceType: pkg.source_type,
      installer: pkg.installer, confidence: pkg.confidence || 'high',
    });
  }

  // go
  for (const proj of (scanResults.go.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'go', name: dep.name, version: dep.version,
        user: resolveUser(proj.sum_file, userHomes),
        project: proj.project, source: proj.sum_file,
        confidence: 'high',
      });
    }
  }

  // composer
  for (const proj of (scanResults.composer.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'composer', name: dep.name, version: dep.version,
        user: resolveUser(proj.lockfile, userHomes),
        project: proj.project, source: proj.lockfile,
        confidence: 'high',
      });
    }
  }

  // rubygems
  for (const proj of (scanResults.rubygems.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'rubygems', name: dep.name, version: dep.version,
        user: resolveUser(proj.lockfile, userHomes),
        project: proj.project, source: proj.lockfile,
        confidence: 'high',
      });
    }
  }

  // cargo
  for (const proj of (scanResults.cargo.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'cargo', name: dep.name, version: dep.version,
        user: resolveUser(proj.lockfile, userHomes),
        project: proj.project, source: proj.lockfile,
        confidence: 'high',
      });
    }
  }

  // editor extensions
  for (const [editor, exts] of Object.entries(scanResults.editor_extensions.editors || {})) {
    for (const ext of exts) {
      packages.push({
        ecosystem: 'editor-extension',
        name: `${ext.publisher}.${ext.name}`,
        displayName: ext.displayName,
        version: ext.version,
        user: resolveUser(ext.path, userHomes),
        project: editor, source: ext.id,
        confidence: 'high',
      });
    }
  }

  // MCP servers started from a pinned package version can be threat-matched like any dependency
  for (const cfg of (scanResults.mcp_configs.configs || [])) {
    for (const srv of (cfg.servers || [])) {
      if (!srv.active || !srv.package || !srv.package_version) continue;
      packages.push({
        ecosystem: srv.package_ecosystem, name: srv.package, version: srv.package_version,
        user: resolveUser(cfg.config_path, userHomes),
        project: `MCP: ${srv.name} (${cfg.app || cfg.config_name})`, source: cfg.config_path,
        confidence: 'high',
      });
    }
  }

  // browser extensions
  for (const [browser, exts] of Object.entries(scanResults.browser_extensions.browsers || {})) {
    for (const ext of exts) {
      packages.push({
        ecosystem: 'browser-extension',
        name: ext.name, version: ext.version,
        user: resolveUser(ext.path, userHomes),
        project: browser, source: ext.extension_id,
        permissions: ext.permissions,
        confidence: 'medium',
      });
    }
  }

  return packages;
}

main().catch(e => {
  logger.error('core', `Fatal: ${e.message}`);
  if (e.stack) logger.debug('core', e.stack);
  process.exit(3);
});
