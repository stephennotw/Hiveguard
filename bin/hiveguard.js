#!/usr/bin/env node
'use strict';

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
 *   --no-report         Skip HTML report generation
 *   --no-secrets        Skip secrets hygiene scan
 *   --max-depth <n>     Max directory depth for lockfile search (default: 6)
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

// Scanners
const npmScanner = require(path.join(SRC_ROOT, 'scanners', 'npm'));
const pypiScanner = require(path.join(SRC_ROOT, 'scanners', 'pypi'));
const goScanner = require(path.join(SRC_ROOT, 'scanners', 'go'));
const composerScanner = require(path.join(SRC_ROOT, 'scanners', 'composer'));
const rubygemsScanner = require(path.join(SRC_ROOT, 'scanners', 'rubygems'));
const cargoScanner = require(path.join(SRC_ROOT, 'scanners', 'cargo'));
const editorExtScanner = require(path.join(SRC_ROOT, 'scanners', 'editor-extensions'));
const browserExtScanner = require(path.join(SRC_ROOT, 'scanners', 'browser-extensions'));
const mcpScanner = require(path.join(SRC_ROOT, 'scanners', 'mcp-configs'));
const secretsScanner = require(path.join(SRC_ROOT, 'scanners', 'secrets-hygiene'));

// Threat intel
const { loadThreatIntel } = require(path.join(SRC_ROOT, 'threat-intel', 'sync'));
const { buildIndex, matchPackages } = require(path.join(SRC_ROOT, 'threat-intel', 'matcher'));

// CVE
const { checkKnownVulns } = require(path.join(SRC_ROOT, 'cve', 'known-vulns'));

// Report
const { generateReport } = require(path.join(SRC_ROOT, 'report', 'html-report'));

// ── Parse CLI arguments ──
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    outputDir: './hiveguard-results',
    json: false,
    offline: false,
    scanDirs: null,
    customIntelDirs: [],
    noReport: false,
    noSecrets: false,
    maxDepth: 6,
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
        opts.maxDepth = parseInt(args[++i]) || 6;
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
    --offline            Use bundled baseline catalogs only (no GitHub sync)
    --scan-dirs <dirs>   Comma-separated scan directories
    --custom-intel <dir> Dir(s) with custom threat intel JSON catalogs
    --no-report          Skip HTML report generation
    --no-secrets         Skip secrets hygiene scan
    --max-depth <n>      Max directory depth (default: 6)
    --verbose, -v        Debug logging
    --help, -h           Show this message

  Exit codes:
    0  Clean
    1  Findings (CVEs, advisories)
    2  Critical (supply chain compromise)

  Examples:
    node hiveguard.js
    node hiveguard.js --output ./results --verbose
    node hiveguard.js --json --offline > results.json
    node hiveguard.js --scan-dirs /home/user/projects,/opt/apps
  `;
  console.log(help);
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

  if (!opts.json) {
    process.stderr.write('\n');
    process.stderr.write('  ╔═══════════════════════════════════════════════════╗\n');
    process.stderr.write('  ║   🐝 HiveGuard — Supply Chain Scanner v1.0.0     ║\n');
    process.stderr.write('  ╚═══════════════════════════════════════════════════╝\n');
    process.stderr.write('\n');
  }

  // Step 1: System info
  const systemInfo = getSystemInfo();
  logger.info('core', `Host: ${systemInfo.hostname} | OS: ${systemInfo.platform}/${systemInfo.arch} | User: ${systemInfo.username}`);

  // Step 2: Platform detection
  const platform = getPlatform(opts.scanDirs);

  // Step 3: Threat intel — load into memory (live → baseline → custom)
  const intelResult = await loadThreatIntel({
    offline: opts.offline,
    customIntelDirs: opts.customIntelDirs,
  });
  const { catalogs, threatIndex, totalEntries, totalVersions } = buildIndex(intelResult.inMemoryCatalogs);

  // Step 4: Run all scanners
  logger.info('core', 'Starting scanners...');
  const scanOpts = { maxDepth: opts.maxDepth };

  const scanResults = {
    npm: npmScanner.scan(platform, scanOpts),
    npm_global: npmScanner.scanGlobal(platform),
    pypi: pypiScanner.scan(platform, scanOpts),
    go: goScanner.scan(platform, scanOpts),
    composer: composerScanner.scan(platform, scanOpts),
    rubygems: rubygemsScanner.scan(platform, scanOpts),
    cargo: cargoScanner.scan(platform, scanOpts),
    editor_extensions: editorExtScanner.scan(platform),
    browser_extensions: browserExtScanner.scan(platform),
    mcp_configs: mcpScanner.scan(platform),
  };

  if (!opts.noSecrets) {
    scanResults.secrets_hygiene = secretsScanner.scan(platform);
  }

  // Step 5: Build flat package list for threat matching + CVE checking
  const flatPackages = buildFlatPackageList(scanResults);
  logger.info('core', `Total components inventoried: ${flatPackages.length}`);

  // Step 6: Threat intel matching
  const threatMatches = matchPackages(flatPackages, threatIndex);

  // Step 7: Known CVE checks
  const cveFindings = checkKnownVulns(flatPackages);

  // Step 8: Aggregate findings
  const allFindings = [];

  // Threat matches are critical
  for (const match of threatMatches) {
    for (const t of match.threats) {
      allFindings.push({
        severity: 'critical',
        type: 'supply_chain_compromise',
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
      cveMap.set(key, { type: 'known_cve', ...f });
    }
  }
  for (const f of cveMap.values()) {
    allFindings.push(f);
  }

  // Secrets findings
  if (scanResults.secrets_hygiene) {
    const sh = scanResults.secrets_hygiene;
    for (const f of [...sh.envFiles.findings, ...sh.gitCredentials.findings, ...sh.sshKeys.findings]) {
      allFindings.push({
        type: 'secrets_hygiene',
        ecosystem: 'secrets',
        package: f.type || 'secrets-hygiene',
        version: '',
        text: f.message || f.text || '',
        ...f,
      });
    }
  }

  // Sort by severity
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  // Step 9: Build final result
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  const result = {
    meta: {
      tool: 'hiveguard',
      version: '1.0.0',
      scan_time: new Date().toISOString(),
      elapsed_seconds: parseFloat(elapsed),
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
        editor_extensions: scanResults.editor_extensions.total,
        browser_extensions: scanResults.browser_extensions.total,
        mcp_servers: scanResults.mcp_configs.total_servers,
      },
    },
    findings: allFindings,
    ecosystems: scanResults,
    packages: flatPackages,
    threat_matches: threatMatches,
    catalogs: catalogs.map(c => ({
      file: c.file,
      campaignName: c.campaignName,
      entries: c.entries.length,
      comment: (c.comment || '').slice(0, 300),
    })),
  };

  // Step 10: Output
  fs.mkdirSync(opts.outputDir, { recursive: true });

  if (opts.json) {
    output.writeStdout(result);
  } else {
    // Write JSON
    const jsonPath = path.join(opts.outputDir, `hiveguard-${systemInfo.hostname}-${Date.now()}.json`);
    output.writeJson(jsonPath, result);

    // Write HTML report
    if (!opts.noReport) {
      const htmlPath = path.join(opts.outputDir, `hiveguard-report-${systemInfo.hostname}.html`);
      const html = generateReport(result);
      output.writeHtml(htmlPath, html);
    }

    // Summary
    process.stderr.write('\n');
    process.stderr.write('  ────────────────────────────────────────────\n');
    process.stderr.write(`  ✅ Scan complete in ${elapsed}s\n`);
    process.stderr.write(`     📦 ${flatPackages.length} components inventoried\n`);
    process.stderr.write(`     🛡️  ${catalogs.length} threat catalogs (${totalVersions} known-bad versions)\n`);
    process.stderr.write(`     ${threatMatches.length > 0 ? '🚨' : '✅'} ${threatMatches.length} threat matches\n`);
    process.stderr.write(`     ⚠️  ${allFindings.length} findings (${allFindings.filter(f => f.severity === 'critical').length} critical, ${allFindings.filter(f => f.severity === 'high').length} high)\n`);
    process.stderr.write(`     📁 Results: ${opts.outputDir}\n`);
    process.stderr.write('  ────────────────────────────────────────────\n\n');
  }

  // Exit code
  if (threatMatches.length > 0) process.exit(2);
  if (allFindings.some(f => f.severity === 'critical' || f.severity === 'high')) process.exit(1);
  process.exit(0);
}

/**
 * Flatten all scan results into a unified package list for matching.
 */
function buildFlatPackageList(scanResults) {
  const packages = [];

  // npm projects
  for (const proj of (scanResults.npm.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'npm', name: dep.name, version: dep.version,
        project: proj.project, source: proj.lockfile,
        resolved: dep.resolved, confidence: 'high',
      });
    }
  }

  // npm global
  for (const pkg of (scanResults.npm_global || [])) {
    packages.push({
      ecosystem: 'npm', name: pkg.name, version: pkg.version,
      project: '(global)', source: 'npm-global',
      confidence: 'high',
    });
  }

  // pypi
  for (const pkg of (scanResults.pypi.packages || [])) {
    packages.push({
      ecosystem: 'pypi', name: pkg.name, version: pkg.version,
      project: pkg.source_dir || '', source: pkg.source_type || 'venv',
      installer: pkg.installer, confidence: pkg.confidence || 'high',
    });
  }

  // go
  for (const proj of (scanResults.go.projects || [])) {
    for (const dep of (proj.dependencies || [])) {
      packages.push({
        ecosystem: 'go', name: dep.name, version: dep.version,
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
        project: editor, source: ext.id,
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
