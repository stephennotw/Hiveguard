'use strict';

const logger = require('../utils/logger');

/**
 * Static known-vulnerability rules for common packages.
 * These are well-known CVEs that can be detected by version comparison
 * without requiring an external API call.
 *
 * Format: { ecosystem, package, check(version) -> finding|null }
 */
const RULES = [
  // ── Python / PyPI ──
  {
    ecosystem: 'pypi', package: 'pip',
    check(v) {
      if (majorInt(v) < 23) return {
        severity: 'high', cve: 'CVE-2023-5752',
        text: `pip ${v} — arbitrary command injection via wheel file names. Upgrade to ≥23.3.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'setuptools',
    check(v) {
      if (majorInt(v) < 70) return {
        severity: 'high', cve: 'CVE-2024-6345',
        text: `setuptools ${v} — path traversal / RCE via crafted packages. Upgrade to ≥70.0.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'idna',
    check(v) {
      if (v === '3.6') return {
        severity: 'medium', cve: 'CVE-2024-3651',
        text: `idna 3.6 — ReDoS vulnerability. Upgrade to ≥3.7.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'jinja2',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 3 && parts[1] === 1 && (parts[2] || 0) < 4) return {
        severity: 'medium', cve: 'CVE-2024-34064',
        text: `Jinja2 ${v} — XSS via xmlattr filter. Upgrade to ≥3.1.4.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'pyyaml',
    check(v) {
      if (v === '6.0.1' || v === '6.0') return {
        severity: 'medium', cve: 'CVE-2024-6156',
        text: `PyYAML ${v} — arbitrary code execution via untrusted YAML. Use safe_load().`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'requests',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 2 && parts[1] < 32) return {
        severity: 'medium', cve: 'CVE-2024-35195',
        text: `requests ${v} — session cookies leak on cross-origin redirects. Upgrade to ≥2.32.0.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'urllib3',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 2 && parts[1] === 0 && (parts[2] || 0) < 7) return {
        severity: 'medium', cve: 'CVE-2023-45803',
        text: `urllib3 ${v} — request body leak on redirect. Upgrade to ≥2.0.7.`,
      };
      if (parts[0] === 1 && parts[1] < 26 || (parts[1] === 26 && (parts[2] || 0) < 18)) return {
        severity: 'medium', cve: 'CVE-2023-45803',
        text: `urllib3 ${v} — request body leak on redirect. Upgrade to ≥1.26.18 or 2.0.7.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'cryptography',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 42) return {
        severity: 'high', cve: 'CVE-2024-26130',
        text: `cryptography ${v} — NULL pointer dereference in PKCS12 parsing. Upgrade to ≥42.0.4.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'pypi', package: 'certifi',
    check(v) {
      // certifi uses date-based versions like 2024.2.2
      const year = parseInt(v);
      if (year < 2024) return {
        severity: 'low', cve: '',
        text: `certifi ${v} — outdated CA bundle. Update to latest for current root certificates.`,
      };
      return null;
    }
  },

  // ── npm ──
  {
    ecosystem: 'npm', package: 'express',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 4 && parts[1] < 20) return {
        severity: 'medium', cve: 'CVE-2024-29041',
        text: `express ${v} — open redirect vulnerability. Upgrade to ≥4.20.0.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'axios',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 1 && parts[1] < 7) return {
        severity: 'high', cve: 'CVE-2024-39338',
        text: `axios ${v} — SSRF via unexpected protocol in server-side requests. Upgrade to ≥1.7.4.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'jsonwebtoken',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 9) return {
        severity: 'high', cve: 'CVE-2022-23529',
        text: `jsonwebtoken ${v} — insecure key handling allows forgery. Upgrade to ≥9.0.0.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'semver',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 7 || (parts[0] === 7 && parts[1] < 5) || (parts[0] === 7 && parts[1] === 5 && (parts[2]||0) < 2)) return {
        severity: 'medium', cve: 'CVE-2022-25883',
        text: `semver ${v} — ReDoS via crafted version strings. Upgrade to ≥7.5.2.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'lodash',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 4 || (parts[0] === 4 && parts[1] < 17) || (parts[0] === 4 && parts[1] === 17 && (parts[2]||0) < 21)) return {
        severity: 'high', cve: 'CVE-2021-23337',
        text: `lodash ${v} — command injection via template(). Upgrade to ≥4.17.21.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'tar',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 6 || (parts[0] === 6 && parts[1] < 2)) return {
        severity: 'high', cve: 'CVE-2024-28863',
        text: `tar ${v} — denial of service via crafted tar files. Upgrade to ≥6.2.1.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'npm', package: 'postcss',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 8 && parts[1] < 4 || (parts[1] === 4 && (parts[2]||0) < 31)) return {
        severity: 'medium', cve: 'CVE-2023-44270',
        text: `postcss ${v} — line return parsing issue. Upgrade to ≥8.4.31.`,
      };
      return null;
    }
  },

  // ── Go ──
  {
    ecosystem: 'go', package: 'golang.org/x/crypto',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 0 && parts[1] < 17) return {
        severity: 'high', cve: 'CVE-2023-48795',
        text: `x/crypto ${v} — Terrapin SSH prefix truncation attack. Upgrade to ≥0.17.0.`,
      };
      return null;
    }
  },
  {
    ecosystem: 'go', package: 'golang.org/x/net',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 0 && parts[1] < 23) return {
        severity: 'high', cve: 'CVE-2023-45288',
        text: `x/net ${v} — HTTP/2 rapid reset DoS. Upgrade to ≥0.23.0.`,
      };
      return null;
    }
  },

  // ── Ruby ──
  {
    ecosystem: 'rubygems', package: 'rack',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] < 3 || (parts[0] === 3 && parts[1] === 0 && (parts[2]||0) < 10)) return {
        severity: 'medium', cve: 'CVE-2024-26146',
        text: `rack ${v} — ReDoS in header parsing. Upgrade to ≥3.0.10.`,
      };
      return null;
    }
  },

  // ── Composer / PHP ──
  {
    ecosystem: 'composer', package: 'guzzlehttp/guzzle',
    check(v) {
      const parts = v.split('.').map(Number);
      if (parts[0] === 7 && parts[1] < 8) return {
        severity: 'high', cve: 'CVE-2023-29197',
        text: `guzzle ${v} — HTTP header injection. Upgrade to ≥7.8.0.`,
      };
      return null;
    }
  },
];

function majorInt(v) {
  return parseInt(String(v).split('.')[0]) || 0;
}

/**
 * Run known-vuln checks against a flat package list.
 * Each package: { ecosystem, name, version }
 */
function checkKnownVulns(packages) {
  const findings = [];

  for (const pkg of packages) {
    const normalizedName = (pkg.name || '').toLowerCase();
    const normalizedEco = (pkg.ecosystem || '').toLowerCase();

    for (const rule of RULES) {
      if (rule.ecosystem !== normalizedEco) continue;
      if (rule.package !== normalizedName) continue;

      const result = rule.check(pkg.version);
      if (result) {
        findings.push({
          ecosystem: pkg.ecosystem,
          package: pkg.name,
          version: pkg.version,
          project: pkg.project || '',
          ...result,
        });
      }
    }
  }

  logger.info('known-vulns', `Checked ${packages.length} packages, ${findings.length} known vulnerabilities found`);
  return findings;
}

module.exports = { checkKnownVulns, RULES };
