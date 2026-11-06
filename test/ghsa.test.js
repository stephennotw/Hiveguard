'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('../src/threat-intel/http');
const { queryGhsa, buildAffectsChunks } = require('../src/threat-intel/ghsa');

// Fake GitHub advisories endpoint: returns advisories whose package@version is in `affects`.
function fakeGithub(advisories, { status = 200 } = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, headers: opts.headers });
    if (status !== 200) return { status, headers: {}, body: '{"message":"rate limited"}' };
    const u = new URL(url);
    const affects = new Set(u.searchParams.get('affects').split(','));
    const eco = u.searchParams.get('ecosystem');
    const hits = advisories.filter(a => a.vulnerabilities.some(v =>
      v.package.ecosystem === eco && [...affects].some(x => x === `${v.package.name}@${v._version}`)));
    return { status: 200, headers: {}, body: JSON.stringify(hits) };
  };
  return { fn, calls };
}

const EVIL_ADVISORY = {
  ghsa_id: 'GHSA-evil-0001',
  summary: 'Malware in evil-pkg',
  html_url: 'https://github.com/advisories/GHSA-evil-0001',
  vulnerabilities: [{ package: { ecosystem: 'npm', name: 'evil-pkg' }, _version: '1.0.0' }],
};

describe('ghsa module', () => {
  let original;
  beforeEach(() => { original = http.request; });
  afterEach(() => { http.request = original; });

  it('returns skipped for empty or null input', async () => {
    for (const input of [[], null]) {
      const r = await queryGhsa(input, { token: 't' });
      assert.equal(r.status, 'skipped');
      assert.deepEqual(r.matches, []);
    }
  });

  it('skips without a token and makes no requests', async () => {
    const fake = fakeGithub([EVIL_ADVISORY]);
    http.request = fake.fn;
    const r = await queryGhsa([{ ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' }], { token: '' });
    assert.equal(r.status, 'skipped');
    assert.match(r.error, /GITHUB_TOKEN/);
    assert.equal(fake.calls.length, 0);
  });

  it('matches only the affected version and reports every project that has it', async () => {
    const fake = fakeGithub([EVIL_ADVISORY]);
    http.request = fake.fn;
    const r = await queryGhsa([
      { ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0', project: 'A' },
      { ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0', project: 'B' },
      { ecosystem: 'npm', name: 'evil-pkg', version: '2.0.0', project: 'C' },
      { ecosystem: 'npm', name: 'express', version: '4.21.0', project: 'A' },
    ], { token: 't' });
    assert.equal(r.status, 'ok');
    assert.deepEqual(r.matches.map(m => m.project).sort(), ['A', 'B']);
    assert.equal(r.matches[0].threats[0].ghsaId, 'GHSA-evil-0001');
    assert.equal(fake.calls[0].headers.Authorization, 'Bearer t');
    assert.match(fake.calls[0].url, /type=malware/);
  });

  it('never sends non-concrete versions', async () => {
    const fake = fakeGithub([]);
    http.request = fake.fn;
    const r = await queryGhsa([
      { ecosystem: 'pypi', name: 'requests', version: '>=2.0' },
      { ecosystem: 'pypi', name: 'flask', version: '' },
    ], { token: 't' });
    assert.equal(fake.calls.length, 0);
    assert.equal(r.status, 'skipped');
  });

  it('reports failed status when GitHub rejects the request', async () => {
    http.request = fakeGithub([], { status: 403 }).fn;
    const r = await queryGhsa([{ ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' }], { token: 't' });
    assert.equal(r.status, 'failed');
    assert.match(r.error, /403/);
  });

  describe('buildAffectsChunks', () => {
    it('never puts the same package name twice in one chunk', () => {
      const chunks = buildAffectsChunks([
        { name: 'lodash', version: '1.0.0' },
        { name: 'Lodash', version: '2.0.0' },
        { name: 'express', version: '4.0.0' },
      ]);
      for (const c of chunks) {
        const names = c.map(e => e.name.toLowerCase());
        assert.equal(new Set(names).size, names.length);
      }
      assert.equal(chunks.flat().length, 3);
    });

    it('caps chunk size at 100 entries', () => {
      const entries = Array.from({ length: 250 }, (_, i) => ({ name: `p${i}`, version: '1.0.0' }));
      const chunks = buildAffectsChunks(entries);
      assert.ok(chunks.every(c => c.length <= 100));
      assert.equal(chunks.flat().length, 250);
    });
  });
});
