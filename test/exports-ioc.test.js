'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { toSarif, toCycloneDx, toNdjson, purl } = require('../src/report/exports');
const { parseIoc, matchPackageIoc } = require('../src/threat-intel/cli-iocs');

const result = {
  meta: { version: '9.9.9', scan_time: '2026-11-08T00:00:00.000Z', hostname: 'host1', platform: 'linux' },
  summary: { total_components: 3, findings_total: 3 },
  threat_intel: { source: 'baseline' },
  packages: [
    { ecosystem: 'npm', name: '@antv/a8', version: '0.1.1', source: '/w/charts/yarn.lock' },
    { ecosystem: 'npm', name: '@antv/a8', version: '0.1.1', source: '/w/other/pnpm-lock.yaml' },
    { ecosystem: 'pypi', name: 'Charset_Normalizer', version: '3.5.2', source: '/w/api' },
    { ecosystem: 'editor-extension', name: 'nrwl.angular-console', version: '18.95.0', source: 'nrwl.angular-console-18.95.0' },
  ],
  findings: [
    { severity: 'critical', type: 'supply_chain_compromise', ecosystem: 'npm', package: '@antv/a8', version: '0.1.1', catalog: 'antv.json', source: 'https://socket.dev/x', location: '/w/charts/yarn.lock', indicators: { a: 1 }, text: 'compromised' },
    { severity: 'medium', type: 'mcp_server_risk', ecosystem: 'npm', package: 'x', path: '/h/.agent/mcp.json', triggers: ['mcp-unpinned-package'], text: 'unpinned' },
    { severity: 'high', type: 'suspicious_autostart', ecosystem: 'persistence', path: '/h/Library/LaunchAgents/a.plist', triggers: ['script-in-hidden-or-temp-dir'], text: 'autostart' },
  ],
};

test('SARIF: one rule per finding type, levels, locations and stable fingerprints', () => {
  const s = toSarif(result);
  assert.strictEqual(s.version, '2.1.0');
  const run = s.runs[0];
  assert.deepStrictEqual(run.tool.driver.rules.map(r => r.id), ['supply_chain_compromise', 'mcp_server_risk', 'suspicious_autostart']);
  assert.deepStrictEqual(run.results.map(r => r.level), ['error', 'warning', 'error']);
  assert.strictEqual(run.results[0].locations[0].physicalLocation.artifactLocation.uri, require('url').pathToFileURL('/w/charts/yarn.lock').href);
  assert.strictEqual(run.results[0].properties['security-severity'], '9.5');
  assert.deepStrictEqual(toSarif(result).runs[0].results.map(r => r.partialFingerprints.hiveguard), run.results.map(r => r.partialFingerprints.hiveguard));
});

test('CycloneDX: deduplicated components with purls and linked vulnerabilities', () => {
  const bom = toCycloneDx(result);
  assert.strictEqual(bom.specVersion, '1.5');
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.deepStrictEqual(bom.components.map(c => c.purl || null), ['pkg:npm/%40antv/a8@0.1.1', 'pkg:pypi/charset-normalizer@3.5.2', null]);
  assert.deepStrictEqual(bom.components[0].properties.filter(p => p.name === 'hiveguard:location').map(p => p.value), ['/w/charts/yarn.lock', '/w/other/pnpm-lock.yaml']);
  assert.deepStrictEqual(bom.vulnerabilities.map(v => [v.id, v.affects[0].ref, v.source.url]), [['antv.json', 'npm:@antv/a8@0.1.1', 'https://socket.dev/x']]);
});

test('NDJSON: a summary event then one compact event per finding', () => {
  const lines = toNdjson(result).trim().split('\n').map(JSON.parse);
  assert.deepStrictEqual(lines.map(l => l.event), ['hiveguard_scan_summary', 'hiveguard_finding', 'hiveguard_finding', 'hiveguard_finding']);
  assert.strictEqual(lines[1].host, 'host1');
  assert.strictEqual(lines[1].location, '/w/charts/yarn.lock');
  assert.strictEqual(lines[1].indicators, undefined);
});

test('purl covers each ecosystem with a standard type', () => {
  assert.strictEqual(purl({ ecosystem: 'go', name: 'github.com/a/b', version: 'v1.2.3' }), 'pkg:golang/github.com/a/b@v1.2.3');
  assert.strictEqual(purl({ ecosystem: 'composer', name: 'laravel/framework', version: '11.0.0' }), 'pkg:composer/laravel/framework@11.0.0');
  assert.strictEqual(purl({ ecosystem: 'rubygems', name: 'rails', version: '7.1.0' }), 'pkg:gem/rails@7.1.0');
  assert.strictEqual(purl({ ecosystem: 'cargo', name: 'serde', version: '1.0.0' }), 'pkg:cargo/serde@1.0.0');
});

test('--ioc values are classified by shape', () => {
  const kind = (v) => { const r = parseIoc(v); return r && [r.kind, r.ecosystem || null, r.value]; };
  assert.deepStrictEqual(kind('@antv/a8@0.1.1'), ['package', 'npm', '@antv/a8@0.1.1']);
  assert.deepStrictEqual(kind('@antv/a8'), ['package', 'npm', '@antv/a8']);
  assert.deepStrictEqual(kind('left-pad@v1.3.0'), ['package', 'npm', 'left-pad@1.3.0']);
  assert.deepStrictEqual(kind('pypi:requests==2.31.0'.replace('==', '@')), ['package', 'pypi', 'requests@2.31.0']);
  assert.deepStrictEqual(kind('vscode:nrwl.angular-console@18.95.0'), ['package', 'editor-extension', 'nrwl.angular-console@18.95.0']);
  assert.deepStrictEqual(kind('A'.repeat(64)), ['sha256', null, 'a'.repeat(64)]);
  assert.deepStrictEqual(kind('~\\.local\\share\\kitty\\cat.py'), ['path', null, '~/.local\\share\\kitty\\cat.py']);
  assert.deepStrictEqual(kind('C:\\Users\\Public\\x.exe'), ['path', null, 'C:\\Users\\Public\\x.exe']);
  assert.deepStrictEqual(kind('setup_bun.js'), ['filename', null, 'setup_bun.js']);
  assert.deepStrictEqual(kind('https://t.m-kosche.com:443/api'), ['string', null, 't.m-kosche.com']);
  assert.deepStrictEqual(kind('Shai-Hulud: Here We Go Again'), ['string', null, 'Shai-Hulud: Here We Go Again']);
  assert.strictEqual(parseIoc('abc').kind, 'invalid');
  assert.strictEqual(parseIoc('# comment'), null);
});

test('package indicators match by ecosystem and name, with or without a version', () => {
  const pkgs = result.packages;
  assert.strictEqual(matchPackageIoc(parseIoc('@antv/a8'), pkgs).length, 2);
  assert.strictEqual(matchPackageIoc(parseIoc('@antv/a8@0.1.2'), pkgs).length, 0);
  assert.strictEqual(matchPackageIoc(parseIoc('pypi:charset_normalizer@3.5.2'), pkgs).length, 1);
  assert.strictEqual(matchPackageIoc(parseIoc('npm:charset_normalizer'), pkgs).length, 0);
});
