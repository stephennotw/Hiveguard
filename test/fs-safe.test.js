'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { readFileSafe, readJsonSafe, existsSafe, statSafe, walkSync, findProjectDirs } = require('../src/utils/fs-safe');

const TMP = path.join(os.tmpdir(), 'hiveguard-test-' + process.pid);

before(() => {
  fs.mkdirSync(TMP, { recursive: true });
});

after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
});

describe('readFileSafe', () => {
  it('reads a normal file', () => {
    const fp = path.join(TMP, 'normal.txt');
    fs.writeFileSync(fp, 'hello world');
    assert.equal(readFileSafe(fp), 'hello world');
  });

  it('returns null for missing file', () => {
    assert.equal(readFileSafe(path.join(TMP, 'nope.txt')), null);
  });

  it('respects maxBytes option', () => {
    const fp = path.join(TMP, 'big.txt');
    fs.writeFileSync(fp, 'A'.repeat(1000));
    const result = readFileSafe(fp, { maxBytes: 128 });
    assert.equal(result.length, 128);
  });

  it('maxBytes larger than file returns full content', () => {
    const fp = path.join(TMP, 'small.txt');
    fs.writeFileSync(fp, 'tiny');
    const result = readFileSafe(fp, { maxBytes: 1024 });
    assert.equal(result, 'tiny');
  });

  it('maxBytes 0 or omitted reads full file', () => {
    const fp = path.join(TMP, 'full.txt');
    fs.writeFileSync(fp, 'X'.repeat(500));
    assert.equal(readFileSafe(fp).length, 500);
    assert.equal(readFileSafe(fp, {}).length, 500);
  });
});

describe('readJsonSafe', () => {
  it('parses valid JSON', () => {
    const fp = path.join(TMP, 'valid.json');
    fs.writeFileSync(fp, '{"a":1}');
    assert.deepEqual(readJsonSafe(fp), { a: 1 });
  });

  it('returns null for invalid JSON', () => {
    const fp = path.join(TMP, 'bad.json');
    fs.writeFileSync(fp, '{broken');
    assert.equal(readJsonSafe(fp), null);
  });
});

describe('existsSafe / statSafe', () => {
  it('existsSafe returns true for existing path', () => {
    assert.equal(existsSafe(TMP), true);
  });

  it('existsSafe returns false for missing path', () => {
    assert.equal(existsSafe(path.join(TMP, 'no-such')), false);
  });

  it('statSafe returns stat for existing file', () => {
    const fp = path.join(TMP, 'stat.txt');
    fs.writeFileSync(fp, 'x');
    const s = statSafe(fp);
    assert.ok(s);
    assert.ok(s.isFile());
  });

  it('statSafe returns null for missing path', () => {
    assert.equal(statSafe(path.join(TMP, 'no-stat')), null);
  });
});

describe('walkSync', () => {
  it('finds files matching a filter', () => {
    const dir = path.join(TMP, 'walk');
    fs.mkdirSync(path.join(dir, 'sub'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'a.txt'), '');
    fs.writeFileSync(path.join(dir, 'b.json'), '');
    fs.writeFileSync(path.join(dir, 'sub', 'c.txt'), '');

    const results = walkSync(dir, { filter: (name) => name.endsWith('.txt') });
    assert.equal(results.length, 2);
    assert.ok(results.some(r => r.endsWith('a.txt')));
    assert.ok(results.some(r => r.endsWith('c.txt')));
  });

  it('respects maxDepth', () => {
    const dir = path.join(TMP, 'depth');
    fs.mkdirSync(path.join(dir, 'a', 'b', 'c'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'a', 'b', 'c', 'deep.txt'), '');
    fs.writeFileSync(path.join(dir, 'a', 'shallow.txt'), '');

    const results = walkSync(dir, { maxDepth: 2 });
    assert.ok(results.some(r => r.endsWith('shallow.txt')));
    assert.ok(!results.some(r => r.endsWith('deep.txt')));
  });

  it('skips node_modules by default', () => {
    const dir = path.join(TMP, 'skip');
    fs.mkdirSync(path.join(dir, 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'node_modules', 'pkg.json'), '');
    fs.writeFileSync(path.join(dir, 'top.txt'), '');

    const results = walkSync(dir);
    assert.equal(results.length, 1);
    assert.ok(results[0].endsWith('top.txt'));
  });
});

describe('non-regular files and project discovery', () => {
  const { spawnSync } = require('child_process');
  let tmp;
  before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-fs2-')); });
  after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('does not block on a FIFO named like a manifest', { skip: process.platform === 'win32' }, (t) => {
    const fifo = path.join(tmp, 'package.json');
    if (spawnSync('mkfifo', [fifo]).status !== 0) return t.skip('mkfifo unavailable');
    assert.equal(readFileSafe(fifo), null);
    assert.equal(readJsonSafe(fifo), null);
    assert.equal(readFileSafe(fifo, { maxBytes: 10 }), null);
  });

  it('returns null for a directory', () => {
    assert.equal(readFileSafe(tmp), null);
  });

  it('findProjectDirs finds manifests, AI files and .git, and skips node_modules', () => {
    const mk = (p, c = '') => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); };
    const root = path.join(tmp, 'tree');
    mk(path.join(root, 'app', 'package.json'), '{}');
    mk(path.join(root, 'notes', 'CLAUDE.md'));
    mk(path.join(root, 'repo', '.git', 'HEAD'));
    mk(path.join(root, 'app', 'node_modules', 'dep', 'package.json'), '{}');
    mk(path.join(root, 'plain', 'readme.txt'));
    const found = findProjectDirs([root], { maxDepth: 4 }).map(d => [path.relative(root, d.dir), d.gitDir]).sort();
    assert.deepEqual(found, [['app', false], ['notes', false], ['repo', true]]);
  });
});

describe('project discovery inside lockfile-skipped folders', () => {
  let tmp;
  before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-fs3-')); });
  after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const mk = (p, c = '') => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); };

  it('finds repos under Downloads, OneDrive and Library but not in caches or node_modules', () => {
    const home = path.join(tmp, 'home');
    for (const rel of ['Downloads/interview-task', 'OneDrive - Corp/Documents/GitHub/app', 'Library/dev/tool', 'Dropbox/x', 'projects/ok']) {
      mk(path.join(home, rel, '.git', 'HEAD'));
    }
    mk(path.join(home, '.cargo', 'registry', 'src', 'crate', 'Cargo.toml'));
    mk(path.join(home, '.npm', '_npx', 'abc', 'package.json'), '{}');
    mk(path.join(home, 'projects', 'ok', 'node_modules', 'dep', 'package.json'), '{}');
    const found = findProjectDirs([home], { maxDepth: 5 }).map(d => path.relative(home, d.dir).split(path.sep).join('/')).sort();
    assert.deepEqual(found, ['Downloads/interview-task', 'Dropbox/x', 'Library/dev/tool', 'OneDrive - Corp/Documents/GitHub/app', 'projects/ok']);
  });

  it('still does not collect lockfiles inside skipped folders when onDir is set', () => {
    const { findMultipleFiles, projectDirCollector } = require('../src/utils/fs-safe');
    const home = path.join(tmp, 'home2');
    mk(path.join(home, 'Downloads', 'x', 'package-lock.json'), '{}');
    mk(path.join(home, 'projects', 'y', 'package-lock.json'), '{}');
    const dirs = [];
    const files = findMultipleFiles([home], ['package-lock.json'], { maxDepth: 4, onDir: projectDirCollector(dirs) });
    assert.deepEqual(files.get('package-lock.json').map(p => path.relative(home, p).split(path.sep).join('/')), ['projects/y/package-lock.json']);
  });
});
