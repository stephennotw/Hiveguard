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
  });
});
