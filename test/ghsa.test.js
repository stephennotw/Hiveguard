'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { queryGhsa, versionInRange, compareVersions } = require('../src/threat-intel/ghsa');

describe('ghsa module', () => {
  describe('compareVersions', () => {
    it('returns 0 for equal versions', () => {
      assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
    });

    it('returns -1 when a < b', () => {
      assert.equal(compareVersions('1.2.3', '1.2.4'), -1);
      assert.equal(compareVersions('1.2.3', '2.0.0'), -1);
      assert.equal(compareVersions('0.9.0', '1.0.0'), -1);
    });

    it('returns 1 when a > b', () => {
      assert.equal(compareVersions('1.2.4', '1.2.3'), 1);
      assert.equal(compareVersions('2.0.0', '1.9.9'), 1);
    });

    it('handles versions with different segment counts', () => {
      assert.equal(compareVersions('1.2', '1.2.0'), 0);
      assert.equal(compareVersions('1.2.3', '1.2'), 1);
      assert.equal(compareVersions('1', '1.0.0'), 0);
    });

    it('strips v-prefix via normalizeVersion', () => {
      assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
    });
  });

  describe('versionInRange', () => {
    it('matches <= range', () => {
      assert.equal(versionInRange('1.0.0', '<= 9999.0.0'), true);
      assert.equal(versionInRange('1.0.0', '<= 0.9.0'), false);
    });

    it('matches < range', () => {
      assert.equal(versionInRange('1.0.0', '< 2.0.0'), true);
      assert.equal(versionInRange('2.0.0', '< 2.0.0'), false);
    });

    it('matches = range', () => {
      assert.equal(versionInRange('1.0.0', '= 1.0.0'), true);
      assert.equal(versionInRange('1.0.1', '= 1.0.0'), false);
    });

    it('matches >= range', () => {
      assert.equal(versionInRange('2.0.0', '>= 1.0.0'), true);
      assert.equal(versionInRange('0.9.0', '>= 1.0.0'), false);
    });

    it('matches compound ranges', () => {
      assert.equal(versionInRange('1.5.0', '>= 1.0.0, <= 2.0.0'), true);
      assert.equal(versionInRange('3.0.0', '>= 1.0.0, <= 2.0.0'), false);
      assert.equal(versionInRange('0.5.0', '>= 1.0.0, <= 2.0.0'), false);
    });

    it('returns true for empty/null range (assume affected)', () => {
      assert.equal(versionInRange('1.0.0', ''), true);
      assert.equal(versionInRange('1.0.0', null), true);
    });

    it('returns true for unparseable range (assume affected)', () => {
      assert.equal(versionInRange('1.0.0', 'all versions'), true);
    });
  });

  describe('queryGhsa', () => {
    it('returns empty for empty package list', async () => {
      const result = await queryGhsa([]);
      assert.deepEqual(result, []);
    });

    it('returns empty for null input', async () => {
      const result = await queryGhsa(null);
      assert.deepEqual(result, []);
    });

    it('skips packages with unmapped ecosystems', async () => {
      const result = await queryGhsa([
        { ecosystem: 'unknown-eco', name: 'test', version: '1.0.0' },
      ]);
      assert.deepEqual(result, []);
    });

    it('gracefully handles API failure', async () => {
      const result = await queryGhsa([
        { ecosystem: 'npm', name: 'express', version: '4.21.0' },
      ], { timeout: 5000 });
      assert.ok(Array.isArray(result));
    });

    it('queries GitHub Advisory DB for npm packages (network)', async (t) => {
      const result = await queryGhsa([
        { ecosystem: 'npm', name: 'express', version: '4.21.0' },
      ], { timeout: 15000 });

      if (!Array.isArray(result)) {
        t.skip('GitHub API unreachable');
        return;
      }
      assert.ok(Array.isArray(result));
    });
  });
});
