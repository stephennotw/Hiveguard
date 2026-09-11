'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkKnownVulns, RULES } = require('../src/cve/known-vulns');

describe('known-vulns version checks', () => {
  // ── parseVersion robustness (tested indirectly through rules) ──

  it('handles pre-release suffixes without NaN', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '4.18.2-beta.1' },
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].cve, 'CVE-2024-29041');
  });

  it('handles versions with extra segments', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.20.0' },
    ]);
    assert.equal(result.length, 1);
  });

  // ── Express: v0-3 now caught ──

  it('flags express v3.x as vulnerable', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '3.21.2' },
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].cve, 'CVE-2024-29041');
  });

  it('flags express v0.x as vulnerable', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '0.1.0' },
    ]);
    assert.equal(result.length, 1);
  });

  it('flags express 4.19.x as vulnerable', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '4.19.2' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears express 4.20.0', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '4.20.0' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── urllib3 operator precedence ──

  it('flags urllib3 1.25.x (v1 branch)', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'urllib3', version: '1.25.11' },
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].cve, 'CVE-2023-45803');
  });

  it('flags urllib3 1.26.17 (just below patch)', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'urllib3', version: '1.26.17' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears urllib3 1.26.18', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'urllib3', version: '1.26.18' },
    ]);
    assert.equal(result.length, 0);
  });

  it('flags urllib3 2.0.6 (v2 branch)', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'urllib3', version: '2.0.6' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears urllib3 2.0.7', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'urllib3', version: '2.0.7' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── postcss operator precedence ──

  it('flags postcss 8.3.0', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'postcss', version: '8.3.0' },
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].cve, 'CVE-2023-44270');
  });

  it('flags postcss 8.4.30', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'postcss', version: '8.4.30' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears postcss 8.4.31', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'postcss', version: '8.4.31' },
    ]);
    assert.equal(result.length, 0);
  });

  it('does not flag postcss 7.x (different major)', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'postcss', version: '7.0.39' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── semver boundary ──

  it('flags semver 7.5.1', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'semver', version: '7.5.1' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears semver 7.5.2', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'semver', version: '7.5.2' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── jinja2 boundary ──

  it('flags jinja2 3.1.3', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'jinja2', version: '3.1.3' },
    ]);
    assert.equal(result.length, 1);
  });

  it('clears jinja2 3.1.4', () => {
    const result = checkKnownVulns([
      { ecosystem: 'pypi', name: 'jinja2', version: '3.1.4' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── Unknown packages return nothing ──

  it('returns empty for unknown packages', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'some-unknown-package', version: '1.0.0' },
    ]);
    assert.equal(result.length, 0);
  });

  // ── Batch check ──

  it('handles mixed ecosystems in a single batch', () => {
    const result = checkKnownVulns([
      { ecosystem: 'npm', name: 'express', version: '4.18.0' },
      { ecosystem: 'pypi', name: 'requests', version: '2.31.0' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
      { ecosystem: 'go', name: 'golang.org/x/net', version: '0.22.0' },
    ]);
    assert.equal(result.length, 3);
    const names = result.map(r => r.package);
    assert.ok(names.includes('express'));
    assert.ok(names.includes('requests'));
    assert.ok(names.includes('golang.org/x/net'));
  });
});
