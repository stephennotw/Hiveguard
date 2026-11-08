#!/usr/bin/env node
'use strict';

/**
 * HiveGuard self-check: runs a normal scan on this machine and prints a summary that
 * is safe to share — counts, timings and finding categories only. No file paths,
 * usernames, hostnames or package names are included in the summary.
 *
 * The full report (JSON + HTML, which DO contain paths) is kept locally for your own
 * review and is never uploaded.
 *
 *   node tools/self-check.js            # offline scan (no network access)
 *   node tools/self-check.js --online   # also query OSV.dev / Bumblebee / GitHub
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const BIN = path.resolve(__dirname, '..', 'bin', 'hiveguard.js');
const online = process.argv.includes('--online');
const outDir = path.join(os.tmpdir(), `hiveguard-selfcheck-${Date.now()}`);

if (+process.versions.node.split('.')[0] < 18) {
  console.error(`Node.js 18 or newer is required (found ${process.version}).`);
  process.exit(1);
}

console.error(`Running HiveGuard ${online ? '(online)' : '(offline)'} — this can take a few minutes on a large profile...`);

// Run the CLI in a child that reports its own peak memory on exit.
const runner = [
  `process.on('exit', () => process.stderr.write('\\nHG_SELFCHECK_MAXRSS_KB=' + process.resourceUsage().maxRSS + '\\n'));`,
  `process.argv.splice(1, 0, 'hiveguard');`,
  `require(${JSON.stringify(BIN)});`,
].join('\n');
const args = ['--output', outDir, ...(online ? [] : ['--offline'])];
const started = Date.now();
const child = spawnSync(process.execPath, ['-e', runner, '--', ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
const wallMs = Date.now() - started;
const stderr = (child.stderr || '').replace(/\x1b\[[0-9;]*m/g, '');

const jsonFile = fs.existsSync(outDir) && fs.readdirSync(outDir).find(f => f.endsWith('.json'));
if (!jsonFile) {
  console.error(`HiveGuard did not produce a result (exit ${child.status}). Last output:\n${stderr.split('\n').slice(-25).join('\n')}`);
  process.exit(1);
}
const result = JSON.parse(fs.readFileSync(path.join(outDir, jsonFile), 'utf8'));

const lines = [];
const add = (s = '') => lines.push(s);
const count = (items, keyFn) => {
  const m = new Map();
  for (const it of items) { const k = keyFn(it); m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
};
const triggers = (f) => [...(f.triggers || [])].sort().join(', ') || '-';
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

add('HiveGuard self-check summary (safe to share: no paths, usernames or package names)');
add('='.repeat(80));
add(`HiveGuard ${result.meta.version} | ${os.platform()} ${os.release()} ${os.arch()} | Node ${process.version} | ${os.cpus().length} CPUs | ${Math.round(os.totalmem() / 1073741824)} GB RAM`);
add(`Mode: ${online ? 'online' : 'offline'} | exit code ${child.status} | wall time ${(wallMs / 1000).toFixed(1)} s | peak memory ${Math.round((+(stderr.match(/HG_SELFCHECK_MAXRSS_KB=(\d+)/) || [])[1] || 0) / 1024)} MB`);
add(`User profiles scanned: ${(result.meta.users_scanned || []).length}`);

add();
add('Timings');
const walk = stderr.match(/Directory walk completed in (\d+)ms/);
if (walk) add(`  directory walk       ${walk[1].padStart(7)} ms`);
for (const m of stderr.matchAll(/\[core\]\s+([\w-]+): (\d+)ms/g)) add(`  ${m[1].padEnd(20)} ${m[2].padStart(7)} ms`);

add();
add('Inventory');
const e = result.summary.ecosystems || {};
add(`  components total: ${result.summary.total_components}`);
for (const [k, v] of Object.entries(e)) add(`  ${k.padEnd(28)} ${v}`);
const locks = (result.ecosystems && result.ecosystems.lockfiles) || {};
for (const [k, v] of count(locks.parsed || [], l => l.type)) add(`    ${String(v).padStart(4)} x ${k} lockfile (${(locks.parsed || []).filter(l => l.type === k).reduce((s, l) => s + l.dependencies, 0)} deps)`);
for (const [k, v] of count(locks.unparsed || [], u => `${path.basename(u.lockfile)}: ${/^parse error/.test(u.reason) ? 'parse error' : 'not parsed'}`)) add(`    ${String(v).padStart(4)} x ${k}`);
const ai = (result.ecosystems && result.ecosystems.ai_instructions) || {};
add(`  directories checked for AI files: ${ai.projects_scanned || 0}`);
for (const [k, v] of count(ai.inventory || [], i => `${i.tool}: ${path.basename(i.path)}${i.hooks ? ' (has hooks)' : ''}${i.autorun_tasks ? ' (auto-run tasks)' : ''}${i.symlink_target ? ' (symlink)' : ''}`)) {
  add(`    ${String(v).padStart(4)} x ${k}`);
}

add();
add('AI on this machine (tool folder names, provider and SDK names only)');
const ecos = result.ecosystems || {};
const mcpCfgs = (ecos.mcp_configs && ecos.mcp_configs.configs) || [];
const allServers = mcpCfgs.flatMap(c => c.servers.map(s => ({ app: c.app || c.config_name, state: c.state, dir: (c.relative_dir || '').split('/')[0], ...s })));
const servers = allServers.filter(s => s.active !== false);
const knownApps = (ecos.ai_apps && ecos.ai_apps.apps) || [];
add(`  known AI apps present: ${new Set(knownApps.map(a => a.id)).size}`);
for (const [k, v] of count(knownApps, a => `${a.name} [${a.kind}]`)) add(`    ${String(v).padStart(4)} x ${k}`);
add(`  MCP servers configured: ${servers.length} (${servers.filter(s => s.unpinned).length} unpinned, ${servers.filter(s => s.wrapped_by).length} behind a wrapper); not counted: ${allServers.filter(s => s.state === 'available').length} available in catalogs, ${allServers.filter(s => s.disabled).length} disabled`);
for (const [k, v] of count(servers.filter(s => s.wrapped_by), s => s.wrapped_by)) add(`    wrapper ${k}: ${v} server(s)`);
const byApp = new Map();
for (const c of mcpCfgs.filter(x => x.state !== 'available')) {
  if (!c.server_count) continue;
  const app = c.app || c.config_name;
  const e = byApp.get(app) || { configs: 0, servers: 0, names: new Set(), files: new Set() };
  e.configs++;
  e.servers += c.server_count;
  for (const srv of c.servers) e.names.add(srv.name);
  e.files.add(path.basename(c.config_path));
  byApp.set(app, e);
}
for (const [app, e] of [...byApp.entries()].sort((a, b) => b[1].servers - a[1].servers)) {
  add(`    ${String(e.servers).padStart(4)} x ${app} (${e.configs} config file(s): ${[...e.files].join(', ')}; ${e.names.size} distinct server names)`);
}
const editorsFound = (ecos.editor_extensions && ecos.editor_extensions.discovered_editors) || [];
if (editorsFound.length) for (const [k, v] of count(allServers.filter(s => s.state === 'available'), s => `${s.app} under ${s.dir || '(top)'}/`)) add(`    available (catalog): ${String(v).padStart(3)} x ${k}`);
add(`  editors found by structure: ${editorsFound.join(', ')}`);
const am = ecos.ai_models || {};
add(`  local models: ${am.total || 0} (${((am.total_size || 0) / 1073741824).toFixed(1)} GB, ${am.pickle_count || 0} pickle-format)`);
for (const [k, v] of count(am.models || [], m => `${m.store || 'loose file'}: ${m.format}`)) add(`    ${String(v).padStart(4)} x ${k}`);
const au = ecos.ai_usage || {};
add(`  AI provider credentials in plain text: ${(au.providers || []).length}`);
for (const [k, v] of count(au.providers || [], p => `${p.provider} (${p.source})`)) add(`    ${String(v).padStart(4)} x ${k}`);
add(`  AI SDKs in dependencies: ${(au.sdks || []).length}`);
for (const sdk of (au.sdks || []).slice(0, 15)) add(`    ${sdk.ecosystem}:${sdk.name} in ${sdk.projects} project(s)`);

const ps = (result.ecosystems && result.ecosystems.persistence) || {};
add(`  autostart entries: ${ps.total || 0}${(ps.unreadable || []).length ? ` (not readable without elevation: ${ps.unreadable.join(', ')})` : ''}`);
for (const [k, v] of count(ps.entries || [], x => `${x.kind}${x.command ? '' : ' (command not read)'}`)) add(`    ${String(v).padStart(4)} x ${k}`);

add();
add('Threat intel');
const ti = result.threat_intel || {};
add(`  catalogs ${ti.catalogs_loaded} (${ti.source}) | known-bad versions ${ti.total_known_bad_versions} | matches ${ti.matches}`);
for (const [k, v] of Object.entries(ti.sources || {})) add(`  source ${k}: ${v.status}${v.error ? ` (${v.error})` : ''}`);
for (const [k, v] of count((result.findings || []).filter(f => f.type === 'supply_chain_compromise'), f => f.catalog)) add(`    ${String(v).padStart(4)} x match in ${k}`);

add();
add('Findings by severity');
for (const [k, v] of count(result.findings || [], f => f.severity).sort((a, b) => (sevOrder[a[0]] ?? 9) - (sevOrder[b[0]] ?? 9))) add(`  ${k.padEnd(10)} ${v}`);

add();
add('Findings by kind (count x severity | category | triggers)');
const describe = (f) => {
  switch (f.type) {
    case 'suspicious_lifecycle_script': return `install script "${f.hook}"${(f.script_files || []).length ? ' (via script file)' : ''}${f.project === '(global)' ? ' [global]' : ''}`;
    case 'suspicious_git_hook': return `git hook "${f.hook}" (${f.origin || '.git/hooks'})`;
    case 'suspicious_ai_instruction': return `AI file ${f.tool}: ${path.basename(f.path || '')}`;
    case 'supply_chain_compromise': return `threat-intel match (${f.ecosystem})`;
    case 'suspicious_autostart': return `autostart entry (${f.autostart_kind})`;
    case 'known_ioc_file': return 'catalog persistence file present';
    case 'remote_url_dependency': return `npm dependency from URL${f.dependency === 'resolved' ? ' (installed)' : ''}`;
    case 'known_cve': return `known CVE (${f.ecosystem}) ${f.cve || ''}`.trim();
    default: return f.ecosystem === 'secrets' ? `secrets hygiene: ${f.type}` : f.type;
  }
};
const kinds = count(result.findings || [], f => `${f.severity} | ${describe(f)} | ${f.type === 'supply_chain_compromise' || f.type === 'known_cve' ? '-' : triggers(f)}`)
  .sort((a, b) => (sevOrder[a[0].split(' ')[0]] ?? 9) - (sevOrder[b[0].split(' ')[0]] ?? 9) || b[1] - a[1]);
if (kinds.length === 0) add('  none');
for (const [k, v] of kinds) add(`  ${String(v).padStart(4)} x ${k}`);

const gh = (result.ecosystems && result.ecosystems.git_hooks) || {};
const customHooks = (gh.findings || []).filter(f => f.severity === 'info');
if (customHooks.length) {
  add();
  add('Custom git hooks not flagged (info)');
  for (const [k, v] of count(customHooks, f => `"${f.hook}" (${f.origin})`)) add(`  ${String(v).padStart(4)} x ${k}`);
}

add();
add('Diagnostics');
const lcs = (result.ecosystems && result.ecosystems.lifecycle_scripts) || {};
add(`  install scripts: ${lcs.projects_scanned || 0} project dirs, ${lcs.packages_scanned || 0} packages, ${lcs.links_resolved || 0} links resolved`);
add(`    package.json reads: ${lcs.package_json_reads || 0}; via npm hidden lockfile: ${lcs.packages_via_hidden_lockfile || 0} packages (${lcs.hidden_lockfiles_used || 0} lockfiles); via full walk: ${lcs.packages_via_walk || 0} packages (${lcs.pnpm_stores_walked || 0} pnpm stores)`);
if (lcs.timing_ms) add(`    time (ms): ${Object.entries(lcs.timing_ms).map(([k, v]) => `${k} ${v}`).join(', ')}`);
const disc = (ecos.mcp_configs && ecos.mcp_configs.discovery) || {};
const io = (ecos.mcp_configs && ecos.mcp_configs.io) || {};
add(`  MCP discovery: ${disc.roots || 0} app/dot folders, ${disc.dirs_visited || 0} dirs visited, ${(disc.roots_over_budget || []).length} over budget`);
add(`    config reads: ${io.files_read || 0} files, ${Math.round((io.bytes_read || 0) / 1048576)} MB (largest ${Math.round((io.largest_file_bytes || 0) / 1048576)} MB), ${io.read_parse_ms || 0} ms read+parse`);

const summary = lines.join('\n') + '\n';
const summaryFile = path.join(outDir, 'selfcheck-summary.txt');
fs.writeFileSync(summaryFile, summary);

process.stdout.write('\n' + summary);
console.error(`\nSummary saved to: ${summaryFile}`);
console.error(`Full report (contains paths — for your eyes only): ${outDir}`);
