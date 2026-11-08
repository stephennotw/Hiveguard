'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('../src/threat-intel/http');
const { queryOsv } = require('../src/threat-intel/osv');

// Fake OSV.dev: querybatch returns { id, modified } only (as the real API does);
// full records come from /v1/vulns/{id}.
function fakeOsv({ malByPkg = {}, records = {}, failBatch = false, failDetails = false, pageTokens = {} } = {}) {
  const calls = { batch: [], details: [] };
  const fn = async (url, opts) => {
    if (url.endsWith('/querybatch')) {
      calls.batch.push(opts.body.queries);
      if (failBatch) return { status: 403, headers: {}, body: 'Host not in allowlist' };
      const results = opts.body.queries.map(q => {
        const key = `${q.package.name}@${q.version}`;
        if (q.page_token) return { vulns: (pageTokens[key] || {}).page || [] };
        const r = { vulns: (malByPkg[key] || []).map(id => ({ id, modified: '2026-01-01T00:00:00Z' })) };
        if (pageTokens[key]) r.next_page_token = pageTokens[key].token;
        return r;
      });
      return { status: 200, headers: {}, body: JSON.stringify({ results }) };
    }
    const id = decodeURIComponent(url.split('/vulns/')[1]);
    calls.details.push(id);
    if (failDetails || !records[id]) return { status: 404, headers: {}, body: '' };
    return { status: 200, headers: {}, body: JSON.stringify(records[id]) };
  };
  return { fn, calls };
}

describe('osv module', () => {
  let original;
  beforeEach(() => { original = http.request; });
  afterEach(() => { http.request = original; });

  it('returns skipped with no matches for empty or null input', async () => {
    for (const input of [[], null]) {
      const r = await queryOsv(input);
      assert.deepEqual(r.matches, []);
      assert.equal(r.status, 'skipped');
    }
  });

  it('queries editor extensions in the VSCode ecosystem with lowercase ids', async () => {
    const { fn, calls } = fakeOsv({
      malByPkg: { 'nrwl.angular-console@18.95.0': ['MAL-2026-5161'] },
      records: { 'MAL-2026-5161': { id: 'MAL-2026-5161', summary: 'Malicious code in nrwl.angular-console (VSCode)' } },
    });
    http.request = fn;
    const r = await queryOsv([{ ecosystem: 'editor-extension', name: 'Nrwl.Angular-Console', version: '18.95.0', project: 'vscode' }]);
    assert.deepEqual(calls.batch[0].map(q => q.package), [{ name: 'nrwl.angular-console', ecosystem: 'VSCode' }]);
    assert.equal(r.matches.length, 1);
    assert.equal(r.matches[0].name, 'Nrwl.Angular-Console');
  });

  it('skips unknown ecosystems and non-concrete versions without calling the API', async () => {
    const fake = fakeOsv();
    http.request = fake.fn;
    const r = await queryOsv([
      { ecosystem: 'unknown-eco', name: 'x', version: '1.0.0' },
      { ecosystem: 'pypi', name: 'requests', version: '>=2.0' },
      { ecosystem: 'npm', name: 'lodash', version: '^4.17.0' },
      { ecosystem: 'pypi', name: 'flask', version: '' },
    ]);
    assert.equal(r.status, 'skipped');
    assert.equal(fake.calls.batch.length, 0);
  });

  it('queries each name@version once and reports every project that has it', async () => {
    const fake = fakeOsv({
      malByPkg: { 'evil@1.0.0': ['MAL-2026-1'] },
      records: { 'MAL-2026-1': { id: 'MAL-2026-1', summary: 'Malicious code in evil (npm)' } },
    });
    http.request = fake.fn;
    const r = await queryOsv([
      { ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A' },
      { ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'B' },
      { ecosystem: 'npm', name: 'express', version: '4.21.0', project: 'A' },
    ]);
    assert.equal(fake.calls.batch[0].length, 2);
    assert.equal(r.status, 'ok');
    assert.deepEqual(r.matches.map(m => m.project).sort(), ['A', 'B']);
  });

  it('fetches each MAL record once and fills summary and indicators; ignores non-MAL ids', async () => {
    const fake = fakeOsv({
      malByPkg: { 'evil@1.0.0': ['MAL-2026-1', 'GHSA-xxxx'], 'evil2@2.0.0': ['MAL-2026-1'] },
      records: {
        'MAL-2026-1': {
          id: 'MAL-2026-1',
          summary: 'Malicious code in evil (npm)',
          details: 'Steals tokens',
          aliases: ['GHSA-abcd'],
          database_specific: { 'malicious-packages-origins': [{ source: 'ghsa-malware', sha256: 'deadbeef' }, { source: 'ghsa-malware' }] },
        },
      },
    });
    http.request = fake.fn;
    const r = await queryOsv([
      { ecosystem: 'npm', name: 'evil', version: '1.0.0' },
      { ecosystem: 'npm', name: 'evil2', version: '2.0.0' },
    ]);
    assert.deepEqual(fake.calls.details, ['MAL-2026-1']);
    const t = r.matches[0].threats;
    assert.equal(t.length, 1);
    assert.equal(t[0].attackType, 'Malicious code in evil (npm)');
    assert.equal(t[0].details, 'Steals tokens');
    assert.deepEqual(t[0].aliases, ['GHSA-abcd']);
    assert.deepEqual(t[0].indicators, { sources: ['ghsa-malware'], sha256: ['deadbeef'] });
    assert.equal(t[0].source, 'https://osv.dev/vulnerability/MAL-2026-1');
  });

  it('follows next_page_token', async () => {
    const fake = fakeOsv({
      malByPkg: { 'evil@1.0.0': [] },
      pageTokens: { 'evil@1.0.0': { token: 'p2', page: [{ id: 'MAL-2026-9' }] } },
    });
    http.request = fake.fn;
    const r = await queryOsv([{ ecosystem: 'npm', name: 'evil', version: '1.0.0' }]);
    assert.equal(r.matches.length, 1);
    assert.equal(r.matches[0].threats[0].osvId, 'MAL-2026-9');
  });

  it('falls back to an id-only threat when the detail fetch fails', async () => {
    const fake = fakeOsv({ malByPkg: { 'evil@1.0.0': ['MAL-2026-1'] }, failDetails: true });
    http.request = fake.fn;
    const r = await queryOsv([{ ecosystem: 'npm', name: 'evil', version: '1.0.0' }]);
    assert.equal(r.status, 'ok');
    assert.equal(r.matches[0].threats[0].attackType, 'Malicious package (OpenSSF)');
  });

  it('reports failed status (not clean) when the API is unreachable', async () => {
    http.request = fakeOsv({ failBatch: true }).fn;
    const r = await queryOsv([{ ecosystem: 'npm', name: 'evil', version: '1.0.0' }]);
    assert.equal(r.status, 'failed');
    assert.match(r.error, /403/);
    assert.deepEqual(r.matches, []);
  });
});
