'use strict';

const crypto = require('crypto');
const { pathToFileURL } = require('url');

/**
 * Machine-readable exports of a scan result, for tools that already speak these formats:
 *   SARIF 2.1.0      findings, for code-scanning / vulnerability dashboards
 *   CycloneDX 1.5    inventory (SBOM) plus threat-intel and CVE matches as vulnerabilities
 *   NDJSON           one event per line (summary + each finding), for SIEM ingestion
 * Derived only from the result object; nothing is read from disk here.
 */

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '7.5', medium: '5.0', low: '2.0', info: '0.0' };

function findingLocation(f) {
  return f.path || f.location || f.config_path || (typeof f.source === 'string' && !/^https?:/i.test(f.source) ? f.source : null);
}

function fileUri(p) {
  try { return pathToFileURL(p).href; } catch { return null; }
}

function ruleId(f) {
  return f.type || 'finding';
}

function toSarif(result) {
  const findings = result.findings || [];
  const rules = new Map();
  for (const f of findings) {
    const id = ruleId(f);
    if (rules.has(id)) continue;
    rules.set(id, {
      id,
      name: id.split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(''),
      shortDescription: { text: RULE_TEXT[id] || id.replace(/_/g, ' ') },
      properties: { tags: ['security', 'supply-chain'] },
    });
  }
  const ruleIndex = new Map([...rules.keys()].map((k, i) => [k, i]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HiveGuard',
          version: result.meta.version,
          informationUri: 'https://github.com/stephennotw/hiveguard',
          rules: [...rules.values()],
        },
      },
      invocations: [{
        executionSuccessful: true,
        endTimeUtc: result.meta.scan_time,
        machine: result.meta.hostname,
      }],
      results: findings.map(f => {
        const loc = findingLocation(f);
        const uri = loc && fileUri(loc);
        const r = {
          ruleId: ruleId(f),
          ruleIndex: ruleIndex.get(ruleId(f)),
          level: LEVEL[f.severity] || 'warning',
          message: { text: f.text || ruleId(f) },
          properties: {
            severity: f.severity,
            'security-severity': SECURITY_SEVERITY[f.severity] || '5.0',
            ...pick(f, ['ecosystem', 'package', 'version', 'user', 'project', 'cve', 'catalog', 'campaignName', 'hook', 'tool', 'ioc']),
            ...(Array.isArray(f.triggers) && f.triggers.length ? { triggers: f.triggers } : {}),
          },
          partialFingerprints: { hiveguard: fingerprint(f) },
        };
        if (uri) r.locations = [{ physicalLocation: { artifactLocation: { uri } } }];
        return r;
      }),
    }],
  };
}

const RULE_TEXT = {
  supply_chain_compromise: 'Installed package version is listed in a threat-intel catalog as compromised or malicious',
  known_cve: 'Installed package version has a known vulnerability',
  suspicious_lifecycle_script: 'Install-time code (npm hook or binding.gyp) shows suspicious behaviour',
  remote_url_dependency: 'Dependency fetched from a URL outside any package registry',
  suspicious_git_hook: 'Git hook shows suspicious behaviour',
  suspicious_ai_instruction: 'AI assistant instruction or config file shows suspicious content',
  suspicious_autostart: 'Program set to start automatically shows suspicious behaviour',
  suspicious_extension: 'Editor extension hides code in invisible Unicode',
  known_ioc_file: 'File named by a threat-intel indicator is present',
  mcp_server_risk: 'MCP server runs an unpinned package',
  secrets_hygiene: 'Secret material stored insecurely',
  ioc_match: 'Indicator of compromise given on the command line was found',
};

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') out[k] = obj[k];
  return out;
}

function fingerprint(f) {
  return crypto.createHash('sha256')
    .update([f.type, f.ecosystem, f.package, f.version, findingLocation(f), (f.triggers || []).join(',')].map(v => v || '').join('\0'))
    .digest('hex').slice(0, 32);
}

/** Package URL (purl) for an inventoried package, or null when there is no standard type. */
function purl(p) {
  const v = p.version ? `@${encodeURIComponent(p.version)}` : '';
  const enc = (s) => encodeURIComponent(s);
  switch (p.ecosystem) {
    case 'npm': {
      const m = p.name.match(/^@([^/]+)\/(.+)$/);
      return m ? `pkg:npm/%40${enc(m[1])}/${enc(m[2])}${v}` : `pkg:npm/${enc(p.name)}${v}`;
    }
    case 'pypi': return `pkg:pypi/${enc(p.name.toLowerCase().replace(/[-_.]+/g, '-'))}${v}`;
    case 'go': return `pkg:golang/${p.name.split('/').map(enc).join('/')}${v}`;
    case 'composer': return `pkg:composer/${p.name.split('/').map(enc).join('/')}${v}`;
    case 'rubygems': return `pkg:gem/${enc(p.name)}${v}`;
    case 'cargo': return `pkg:cargo/${enc(p.name)}${v}`;
    default: return null;
  }
}

function toCycloneDx(result) {
  const components = new Map();
  for (const p of result.packages || []) {
    if (!p.name) continue;
    const ref = `${p.ecosystem}:${p.name}@${p.version || ''}`;
    let c = components.get(ref);
    if (!c) {
      const id = purl(p);
      c = {
        type: p.ecosystem === 'editor-extension' ? 'application' : 'library',
        'bom-ref': ref,
        name: p.name,
        ...(p.version ? { version: p.version } : {}),
        ...(id ? { purl: id } : {}),
        properties: [{ name: 'hiveguard:ecosystem', value: p.ecosystem }],
      };
      components.set(ref, c);
    }
    const where = p.source || p.project;
    if (where && c.properties.length < 51 && !c.properties.some(x => x.value === where)) {
      c.properties.push({ name: 'hiveguard:location', value: String(where) });
    }
  }

  const vulnerabilities = [];
  for (const f of result.findings || []) {
    if (f.type !== 'supply_chain_compromise' && f.type !== 'known_cve') continue;
    const ref = `${f.ecosystem}:${f.package}@${f.version || ''}`;
    if (!components.has(ref)) continue;
    const id = f.cve || f.advisory_id || f.catalog || f.type;
    let v = vulnerabilities.find(x => x.id === id && x.description === f.text);
    if (!v) {
      v = {
        id,
        ...(f.source && /^https?:/i.test(f.source) ? { source: { url: f.source } } : {}),
        ratings: [{ severity: f.severity === 'info' ? 'info' : f.severity }],
        description: f.text,
        affects: [],
      };
      vulnerabilities.push(v);
    }
    if (!v.affects.some(a => a.ref === ref)) v.affects.push({ ref });
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: result.meta.scan_time,
      tools: { components: [{ type: 'application', name: 'HiveGuard', version: result.meta.version }] },
      component: { type: 'device', 'bom-ref': 'endpoint', name: result.meta.hostname },
    },
    components: [...components.values()],
    ...(vulnerabilities.length ? { vulnerabilities } : {}),
  };
}

function toNdjson(result) {
  const base = {
    host: result.meta.hostname,
    scan_time: result.meta.scan_time,
    hiveguard_version: result.meta.version,
    platform: result.meta.platform,
  };
  const lines = [JSON.stringify({ event: 'hiveguard_scan_summary', ...base, ...result.summary, threat_intel_source: result.threat_intel && result.threat_intel.source })];
  for (const f of result.findings || []) {
    const { indicators, ...rest } = f; // catalog indicators are repeated per finding; keep events small
    lines.push(JSON.stringify({ event: 'hiveguard_finding', ...base, location: findingLocation(f), ...rest }));
  }
  return lines.join('\n') + '\n';
}

module.exports = { toSarif, toCycloneDx, toNdjson, purl };
