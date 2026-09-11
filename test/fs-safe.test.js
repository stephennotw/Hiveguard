'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { readFileSafe, readJsonSafe, existsSafe, statSafe, walkSync } = require('../src/utils/fs-safe');

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
