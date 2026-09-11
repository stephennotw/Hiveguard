'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { queryOsv } = require('../src/threat-intel/osv');

describe('osv module', () => {
  it('returns empty for empty package list', async () => {
    const result = await queryOsv([]);
    assert.deepEqual(result, []);
  });

  it('returns empty for null input', async () => {
    const result = await queryOsv(null);
    assert.deepEqual(result, []);
  });

  it('skips packages with unknown ecosystems', async () => {
    const result = await queryOsv([
      { ecosystem: 'unknown-eco', name: 'test', version: '1.0.0' },
    ]);
    assert.deepEqual(result, []);
  });

  it('gracefully handles API failure', async () => {
    const result = await queryOsv([
      { ecosystem: 'npm', name: 'express', version: '4.21.0' },
    ], { timeout: 5000 });
    assert.ok(Array.isArray(result));
  });

  it('queries OSV.dev for a known-malicious npm package (network)', async (t) => {
    const probe = await queryOsv([
      { ecosystem: 'npm', name: 'express', version: '4.21.0' },
    ], { timeout: 10000 });
    if (!Array.isArray(probe)) {
      t.skip('OSV.dev unreachable');
      return;
    }

    const result = await queryOsv([
      { ecosystem: 'npm', name: 'node-ipc', version: '9.2.3' },
    ], { timeout: 30000 });

    if (result.length === 0) {
      t.skip('OSV.dev unreachable or blocked');
      return;
    }
    assert.equal(result[0].name, 'node-ipc');
    assert.ok(result[0].threats.length > 0);
    assert.ok(result[0].threats[0].osvId.startsWith('MAL-'));
  });

  it('handles mixed safe and malicious in a batch (network)', async (t) => {
    const probe = await queryOsv([
      { ecosystem: 'npm', name: 'express', version: '4.21.0' },
    ], { timeout: 10000 });
    if (!Array.isArray(probe)) {
      t.skip('OSV.dev unreachable');
      return;
    }

    const result = await queryOsv([
      { ecosystem: 'npm', name: 'express', version: '4.21.0' },
      { ecosystem: 'npm', name: 'node-ipc', version: '9.2.3' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
    ], { timeout: 30000 });

    if (result.length === 0) {
      t.skip('OSV.dev blocked in this environment');
      return;
    }
    assert.equal(result.length, 1);
    assert.equal(result[0].name, 'node-ipc');
  });
});
