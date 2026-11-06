'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { buildIndex, matchPackages } = require('../src/threat-intel/matcher');

describe('threat-intel matcher', () => {
  const sampleCatalogs = new Map([
    ['test-campaign.json', {
      _comment: 'Test Campaign',
      _source: 'test',
      _indicators: { c2_domains: ['evil.example.com'] },
      entries: [
        {
          ecosystem: 'npm',
          package: 'event-stream',
          name: 'flatmap-stream attack',
          source: 'unit test',
          versions: ['3.3.6'],
        },
        {
          ecosystem: 'pypi',
          package: 'jeilyfish',
          name: 'typosquat',
          source: 'unit test',
          versions: ['0.7.0', '0.8.0'],
        },
      ],
    }],
  ]);

  describe('buildIndex', () => {
    it('builds a threat index from catalogs', () => {
      const { catalogs, threatIndex, totalEntries, totalVersions } = buildIndex(sampleCatalogs);
      assert.equal(catalogs.length, 1);
      assert.equal(totalEntries, 2);
      assert.equal(totalVersions, 3);
      assert.ok(threatIndex.has('npm:event-stream:3.3.6'));
      assert.ok(threatIndex.has('pypi:jeilyfish:0.7.0'));
      assert.ok(threatIndex.has('pypi:jeilyfish:0.8.0'));
    });

    it('returns empty index for null input', () => {
      const { threatIndex, totalEntries } = buildIndex(null);
      assert.equal(threatIndex.size, 0);
      assert.equal(totalEntries, 0);
    });

    it('returns empty index for empty map', () => {
      const { threatIndex } = buildIndex(new Map());
      assert.equal(threatIndex.size, 0);
    });

    it('key lookup is case-insensitive for ecosystem and package', () => {
      const mixed = new Map([
        ['mixed.json', {
          entries: [{
            ecosystem: 'NPM',
            package: 'Evil-Pkg',
            versions: ['1.0.0'],
          }],
        }],
      ]);
      const { threatIndex } = buildIndex(mixed);
      assert.ok(threatIndex.has('npm:evil-pkg:1.0.0'));
    });
  });

  describe('matchPackages', () => {
    it('finds exact matches', () => {
      const { threatIndex } = buildIndex(sampleCatalogs);
      const matches = matchPackages([
        { ecosystem: 'npm', name: 'event-stream', version: '3.3.6' },
      ], threatIndex);
      assert.equal(matches.length, 1);
      assert.equal(matches[0].threats[0].attackType, 'flatmap-stream attack');
    });

    it('returns empty for safe packages', () => {
      const { threatIndex } = buildIndex(sampleCatalogs);
      const matches = matchPackages([
        { ecosystem: 'npm', name: 'event-stream', version: '4.0.0' },
        { ecosystem: 'npm', name: 'express', version: '4.20.0' },
      ], threatIndex);
      assert.equal(matches.length, 0);
    });

    it('matches are case-insensitive', () => {
      const { threatIndex } = buildIndex(sampleCatalogs);
      const matches = matchPackages([
        { ecosystem: 'NPM', name: 'Event-Stream', version: '3.3.6' },
      ], threatIndex);
      assert.equal(matches.length, 1);
    });

    it('handles empty package list', () => {
      const { threatIndex } = buildIndex(sampleCatalogs);
      const matches = matchPackages([], threatIndex);
      assert.equal(matches.length, 0);
    });

    it('matches versions with v-prefix against catalog without v-prefix', () => {
      const goCatalogs = new Map([
        ['go-malware.json', {
          _comment: 'Go Malware',
          entries: [{
            ecosystem: 'go',
            package: 'github.com/evil/pkg',
            name: 'go backdoor',
            versions: ['0.17.0'],
          }],
        }],
      ]);
      const { threatIndex } = buildIndex(goCatalogs);
      const matches = matchPackages([
        { ecosystem: 'go', name: 'github.com/evil/pkg', version: 'v0.17.0' },
      ], threatIndex);
      assert.equal(matches.length, 1);
    });

    it('matches catalog entries with v-prefix against scanned packages without', () => {
      const goCatalogs = new Map([
        ['go-malware.json', {
          entries: [{
            ecosystem: 'go',
            package: 'github.com/evil/pkg',
            versions: ['v1.2.3'],
          }],
        }],
      ]);
      const { threatIndex } = buildIndex(goCatalogs);
      const matches = matchPackages([
        { ecosystem: 'go', name: 'github.com/evil/pkg', version: '1.2.3' },
      ], threatIndex);
      assert.equal(matches.length, 1);
    });

    it('still matches exact versions without v-prefix', () => {
      const { threatIndex } = buildIndex(sampleCatalogs);
      const matches = matchPackages([
        { ecosystem: 'npm', name: 'event-stream', version: '3.3.6' },
      ], threatIndex);
      assert.equal(matches.length, 1);
    });
  });
});

describe('mergeThreatMatches', () => {
  const { mergeThreatMatches, isConcreteVersion } = require('../src/threat-intel/matcher');
  const threat = (campaign) => ({ catalog: 'osv.dev', campaignName: campaign });

  it('keeps the same name@version in different projects as separate matches', () => {
    const target = [{ ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A', source: 'a/lock', threats: [threat('bb')] }];
    mergeThreatMatches(target, [
      { ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A', source: 'a/lock', threats: [threat('MAL-1')] },
      { ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'B', source: 'b/lock', threats: [threat('MAL-1')] },
    ]);
    assert.equal(target.length, 2);
    assert.deepEqual(target[0].threats.map(t => t.campaignName), ['bb', 'MAL-1']);
    assert.deepEqual(target[1].threats.map(t => t.campaignName), ['MAL-1']);
  });

  it('does not duplicate a threat already present', () => {
    const target = [{ ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A', threats: [threat('MAL-1')] }];
    mergeThreatMatches(target, [{ ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A', threats: [threat('MAL-1')] }]);
    mergeThreatMatches(target, [{ ecosystem: 'npm', name: 'evil', version: '1.0.0', project: 'A', threats: [threat('MAL-1')] }]);
    assert.equal(target[0].threats.length, 1);
  });

  it('treats v-prefixed and bare versions as the same package', () => {
    const target = [{ ecosystem: 'go', name: 'm', version: 'v1.2.3', project: 'A', threats: [threat('x')] }];
    mergeThreatMatches(target, [{ ecosystem: 'go', name: 'm', version: '1.2.3', project: 'A', threats: [threat('y')] }]);
    assert.equal(target.length, 1);
    assert.equal(target[0].threats.length, 2);
  });

  it('isConcreteVersion accepts installed versions and rejects specs', () => {
    for (const v of ['1.2.3', 'v0.17.0', '2.0.0rc1', '1.0.0-beta.1+build', '1!2.0']) assert.ok(isConcreteVersion(v), v);
    for (const v of ['', '>=1.0', '^4.17.0', '~1.2', '*', 'latest', '1.0 - 2.0', null]) assert.ok(!isConcreteVersion(v), String(v));
  });
});
