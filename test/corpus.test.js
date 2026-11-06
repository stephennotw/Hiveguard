'use strict';

// Corpus test: builds synthetic endpoints (test/corpus/machines.js), scans each with
// the real CLI in isolation (--users-root, --offline), and compares a normalised
// summary with test/corpus/expected/<machine>.json.
//
// After an intentional behaviour change, regenerate and REVIEW the expectations:
//   HIVEGUARD_UPDATE_CORPUS=1 node --test test/corpus.test.js

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const machines = require('./corpus/machines');

const BIN = path.resolve(__dirname, '..', 'bin', 'hiveguard.js');
const EXPECTED_DIR = path.join(__dirname, 'corpus', 'expected');
const UPDATE = process.env.HIVEGUARD_UPDATE_CORPUS === '1';
const IS_WINDOWS = process.platform === 'win32';

function builder(root) {
  const abs = (rel) => path.join(root, ...rel.split('/'));
  const file = (rel, content) => {
    fs.mkdirSync(path.dirname(abs(rel)), { recursive: true });
    fs.writeFileSync(abs(rel), content);
  };
  return {
    file,
    json: (rel, obj) => file(rel, JSON.stringify(obj, null, 2)),
    // Directory links work unprivileged on Windows as junctions.
    dirSymlink: (targetRel, linkRel) => {
      fs.mkdirSync(path.dirname(abs(linkRel)), { recursive: true });
      fs.symlinkSync(abs(targetRel), abs(linkRel), IS_WINDOWS ? 'junction' : 'dir');
    },
    // File symlinks need elevated rights on Windows; those fixtures are POSIX-only.
    fileSymlink: (targetRel, linkRel) => {
      if (IS_WINDOWS) return;
      fs.mkdirSync(path.dirname(abs(linkRel)), { recursive: true });
      fs.symlinkSync(abs(targetRel), abs(linkRel));
    },
  };
}

function scanMachine(machine) {
  const tmp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `hg-corpus-${machine.name}-`)));
  const usersRoot = path.join(tmp, 'Users');
  fs.mkdirSync(usersRoot);
  machine.build(builder(usersRoot));

  const r = spawnSync(process.execPath, [BIN, '--offline', '--no-secrets', '--json', '--users-root', usersRoot, '--output', path.join(tmp, 'out')], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    // Isolate from the developer's own ~/.hiveguard custom catalogs.
    env: { ...process.env, HOME: tmp, USERPROFILE: tmp },
  });
  try {
    if (r.stdout === '') throw new Error(`no output (exit ${r.status}): ${r.stderr.slice(-2000)}`);
    return summarize(JSON.parse(r.stdout), r.status, usersRoot);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function summarize(result, exitCode, usersRoot) {
  const roots = [...new Set([usersRoot, fs.realpathSync(usersRoot)])];
  const rel = (p) => {
    if (!p) return '';
    for (const root of roots) {
      if (p === root || p.startsWith(root + path.sep)) return path.relative(root, p).split(path.sep).join('/');
    }
    return p;
  };
  const triggers = (f) => `[${[...(f.triggers || [])].sort().join(',')}]`;
  const eco = result.ecosystems || {};

  const findings = (result.findings || []).map((f) => {
    if (f.type === 'supply_chain_compromise') return `${f.severity} ${f.type} ${f.ecosystem}:${f.package}@${f.version} (${f.catalog})`;
    if (f.type === 'known_cve') return `${f.severity} ${f.type} ${f.package}@${f.version} ${f.cve || ''}`.trim();
    return `${f.severity} ${f.type} ${rel(f.path)} ${triggers(f)}`;
  });

  return {
    exit_code: exitCode,
    counts: {
      components: result.summary.total_components,
      git_repos: eco.git_hooks.repos_scanned,
      lifecycle_packages: eco.lifecycle_scripts.packages_scanned,
    },
    threat_matches: (result.threat_matches || []).map(m => `${m.ecosystem}:${m.name}@${m.version}`),
    findings,
    git_hooks: eco.git_hooks.findings.map(f => `${f.severity} ${rel(f.path)} (${f.origin}) ${triggers(f)}`),
    ai_files: eco.ai_instructions.inventory.map(i => [
      `${i.tool}: ${rel(i.path)}`,
      i.hooks ? ` hooks=${i.hooks.length}` : '',
      i.autorun_tasks ? ` autorun=${i.autorun_tasks.length}` : '',
      i.symlink_target ? ' symlink' : '',
    ].join('')),
  };
}

const LIST_KEYS = ['threat_matches', 'findings', 'git_hooks', 'ai_files'];

function forPlatform(expected, machine) {
  if (!IS_WINDOWS || !machine.posixOnly) return expected;
  const out = { ...expected };
  for (const key of LIST_KEYS) out[key] = expected[key].filter(line => !machine.posixOnly.some(p => line.includes(p)));
  return out;
}

function diffLists(actual, expected) {
  const missing = expected.filter(x => !actual.includes(x));
  const unexpected = actual.filter(x => !expected.includes(x));
  return [...missing.map(x => `  - missing:    ${x}`), ...unexpected.map(x => `  + unexpected: ${x}`)].join('\n');
}

describe('corpus: synthetic endpoints', () => {
  for (const machine of machines) {
    it(machine.name, () => {
      const actual = scanMachine(machine);
      for (const key of LIST_KEYS) actual[key].sort();
      const file = path.join(EXPECTED_DIR, `${machine.name}.json`);

      if (UPDATE) {
        fs.mkdirSync(EXPECTED_DIR, { recursive: true });
        const doc = { machine: machine.name, description: machine.description, known_gaps: machine.knownGaps || [], ...actual };
        fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
        return;
      }

      const expected = forPlatform(JSON.parse(fs.readFileSync(file, 'utf8')), machine);
      const problems = [];
      for (const key of LIST_KEYS) {
        const d = diffLists(actual[key], [...expected[key]].sort());
        if (d) problems.push(`${key}:\n${d}`);
      }
      if (actual.exit_code !== expected.exit_code) problems.push(`exit_code: expected ${expected.exit_code}, got ${actual.exit_code}`);
      for (const [k, v] of Object.entries(expected.counts)) {
        if (actual.counts[k] !== v) problems.push(`counts.${k}: expected ${v}, got ${actual.counts[k]}`);
      }
      assert.ok(problems.length === 0, `${machine.name} differs from test/corpus/expected/${machine.name}.json:\n${problems.join('\n')}`);
    });
  }
});
