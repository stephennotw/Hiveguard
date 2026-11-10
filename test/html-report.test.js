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

  it('escapes single quotes in rendered values', () => {
    const html = generateReport({
      ...minimalResult,
      meta: { ...minimalResult.meta, hostname: "host'with'quotes" },
    });
    assert.ok(html.includes('host&#39;with&#39;quotes'));
    assert.ok(!html.includes("host'with'quotes"));
  });
});

describe('html-report script and URL contexts', () => {
  const base = {
    meta: { hostname: 'h', platform: 'linux', scan_time: new Date().toISOString() },
    threat_intel: {}, summary: { ecosystems: {} }, findings: [], ecosystems: {},
  };

  it('does not let a package name break out of the embedded <script>', () => {
    const html = generateReport({ ...base, packages: [{ ecosystem: 'npm', name: 'x</script><script>alert(1)</script>', version: '1.0.0' }] });
    assert.ok(!html.includes('</script><script>alert(1)'));
    assert.ok(html.includes('x\\u003c/script>'));
  });

  it('only links http(s) catalog sources', () => {
    const html = generateReport({
      ...base,
      packages: [],
      threat_matches: [{ ecosystem: 'npm', name: 'e', version: '1', project: 'p', threats: [{ attackType: 'a', catalog: 'c', source: 'javascript:alert(1)' }] }],
    });
    assert.ok(!html.includes('href="javascript:'));
  });
});

describe('html-report scripts, hooks and AI panel', () => {
  const base = {
    meta: { hostname: 'h', platform: 'linux', scan_time: new Date().toISOString() },
    summary: { ecosystems: {} }, findings: [], packages: [],
  };

  it('renders new scanner results escaped, and source status', () => {
    const html = generateReport({
      ...base,
      threat_intel: { sources: { osv: { status: 'failed', error: 'OSV API 403' }, ghsa: { status: 'skipped', error: 'GITHUB_TOKEN not set' } } },
      ecosystems: {
        lifecycle_scripts: { packages_scanned: 3, total_findings: 1, findings: [{ severity: 'critical', package: 'evil<b>', hook: 'postinstall', triggers: ['pipe-to-shell'], script: 'curl x | bash', path: '/p' }] },
        git_hooks: { repos_scanned: 1, hooks_found: 1, suspicious: 0, findings: [{ severity: 'info', hook: 'pre-commit', repo: '/r', origin: '.git/hooks', triggers: [] }] },
        ai_instructions: { files_found: 1, suspicious: 1, inventory: [{ path: '/r/.claude/settings.json', tool: 'Claude Code', hooks: [{ event: 'SessionStart', command: 'node <x>' }] }],
          findings: [{ severity: 'medium', path: '/r/.claude/settings.json', triggers: ['permission-bypass-mode'] }] },
      },
    });
    assert.ok(html.includes('id="panel-hygiene"'));
    assert.ok(html.includes('evil&lt;b&gt;'));
    assert.ok(html.includes('node &lt;x&gt;'));
    assert.ok(html.includes('pre-commit'));
    assert.ok(html.includes('permission-bypass-mode'));
    assert.ok(html.includes('OSV.dev (OpenSSF): failed (OSV API 403)'));
  });
});
