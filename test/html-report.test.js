'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { generateReport } = require('../src/report/html-report');

describe('html-report XSS escaping', () => {
  const minimalResult = {
    meta: { scanId: 'test', platform: 'linux', hostname: 'test', timestamp: new Date().toISOString(), duration: '1s' },
    threat_intel: { source: 'none', catalogCount: 0, matches: [] },
    summary: { totalPackages: 0, ecosystems: {}, totalFindings: 0, findings: [] },
    scanners: {},
    cve: { findings: [] },
  };

  it('generates valid HTML', () => {
    const html = generateReport(minimalResult);
    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('</html>'));
  });

  it('escapes all dangerous characters in metadata', () => {
    const xssResult = {
      ...minimalResult,
      meta: {
        ...minimalResult.meta,
        hostname: '<script>alert("xss")</script>',
        platform: "test'platform",
      },
    };
    const html = generateReport(xssResult);
    assert.ok(!html.includes('<script>alert'));
    assert.ok(html.includes('&lt;script&gt;'));
    assert.ok(!html.includes("test'platform"));
    assert.ok(html.includes('test&#39;platform'));
  });

  it('escapes single quotes in attribute contexts', () => {
    const html = generateReport({
      ...minimalResult,
      meta: { ...minimalResult.meta, scanId: "id'with'quotes" },
    });
    assert.ok(!html.includes("id'with'quotes"));
  });
});
