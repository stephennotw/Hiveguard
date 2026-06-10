# HiveGuard Results Guide

Complete reference for understanding HiveGuard scan output — findings, scoring, dependencies, ecosystems, and how to interpret every field.

---

## Table of Contents

1. [Scan Pipeline Overview](#scan-pipeline-overview)
2. [Output Files](#output-files)
3. [Exit Codes](#exit-codes)
4. [JSON Structure](#json-structure)
5. [Findings — What Are They?](#findings--what-are-they)
6. [Finding Types](#finding-types)
7. [Severity Scoring](#severity-scoring)
8. [Threat Intelligence](#threat-intelligence)
9. [Known CVE Checks](#known-cve-checks)
10. [Secrets Hygiene](#secrets-hygiene)
11. [Ecosystems & Dependencies](#ecosystems--dependencies)
12. [Packages (Flat List)](#packages-flat-list)
13. [HTML Report](#html-report)
14. [Field Reference](#field-reference)
15. [Examples](#examples)

---

## Scan Pipeline Overview

HiveGuard runs a 10-step pipeline on every endpoint:

```
Step 1:  Parse CLI arguments
Step 2:  Detect platform (Win/Mac/Linux), enumerate user profiles
Step 3:  Load threat intelligence (live → baseline → custom)
Step 4:  Run ecosystem scanners (npm, PyPI, Go, etc.)
Step 4b: Enrich scanner results with user attribution
Step 5:  Build flat package list from all ecosystems
Step 6:  Match packages against threat intel catalogs
Step 7:  Check packages against known CVE rules
Step 8:  Aggregate all findings (threats + CVEs + secrets)
Step 9:  Build final result object
Step 10: Write JSON + HTML to disk; optionally print JSON to stdout
```

### Dependency Discovery

HiveGuard discovers dependencies by **reading lockfiles and metadata on disk**. It never executes package managers, never installs anything, and never modifies files. This makes it safe to run on production endpoints.

| Ecosystem | Discovery Method |
|---|---|
| npm | Parses `package-lock.json` for exact resolved versions |
| PyPI | Reads `.dist-info/METADATA` in venvs, parses `requirements.txt` |
| Go | Parses `go.sum` for cryptographic hashes of module versions (Go SDK internal files under `/usr/local/go/` and `~/sdk/` are excluded) |
| Composer | Parses `composer.lock` for PHP dependencies |
| RubyGems | Parses `Gemfile.lock` for Ruby gem versions |
| Cargo | Parses `Cargo.lock` for Rust crate versions |
| Editor Extensions | Reads `package.json` from VS Code/Windsurf/Cursor/VSCodium extension dirs |
| Browser Extensions | Reads `manifest.json` from Chrome/Edge/Brave profile dirs |
| MCP Configs | Reads Claude/Cursor/Windsurf MCP configuration JSON files |
| Secrets Hygiene | Detects `.env` files, git credential configs, SSH keys (metadata only) |

---

## Output Files

Every scan produces two files in the output directory (`./hiveguard-results/` by default):

| File | Format | Contents |
|---|---|---|
| `hiveguard-<hostname>-<timestamp>.json` | JSON | Full machine-readable scan results |
| `hiveguard-report-<hostname>.html` | HTML | Interactive single-file report (no server needed) |

When `--json` is passed, the JSON is **also** printed to stdout (in addition to being written to disk).

---

## Exit Codes

Exit codes allow automation tools (Tanium, Jamf, Ansible) to take action based on scan results:

| Code | Meaning | When |
|---|---|---|
| **0** | **Clean** | No threat matches AND no critical/high findings |
| **1** | **Findings** | Medium or high CVEs/advisories present, but no supply chain compromise |
| **2** | **Critical** | At least one package matched a known supply chain compromise in threat intel |
| **3** | **Fatal error** | Script/bootstrap failure (e.g., Node.js download failed, missing files) |

### Decision Logic

```
if (threat_matches > 0)     → exit 2  (Critical)
if (any critical/high CVE)  → exit 1  (Findings)
else                        → exit 0  (Clean)
```

---

## JSON Structure

Top-level keys in the JSON output:

```json
{
  "meta":           {},    // Scan metadata (host, OS, timing, users)
  "threat_intel":   {},    // Catalog stats and match count
  "summary":        {},    // Counts for quick triage
  "findings":       [],    // ALL findings (threats + CVEs + secrets), sorted by severity
  "ecosystems":     {},    // Raw scanner output per ecosystem
  "packages":       [],    // Flat list of every component found
  "threat_matches": [],    // Packages that matched threat intel
  "catalogs":       []     // Loaded threat intel catalog metadata
}
```

### `meta`

```json
{
  "tool": "hiveguard",
  "version": "1.0.0",
  "scan_time": "2026-06-09T13:20:41.764Z",
  "elapsed_seconds": 3.4,
  "users_scanned": ["jdoe", "tech"],
  "hostname": "host-a1b2c",
  "platform": "darwin",
  "arch": "arm64",
  "username": "root",
  "nodeVersion": "v22.15.0"
}
```

| Field | Description |
|---|---|
| `scan_time` | UTC timestamp of scan completion |
| `elapsed_seconds` | Total wall-clock time for the scan |
| `users_scanned` | Real user profiles whose home directories were scanned (system dirs like `Library`, `Shared`, `Public` are automatically excluded) |
| `hostname` | Machine hostname (used in filenames) |
| `platform` | `win32`, `darwin`, or `linux` |
| `username` | OS user that ran the scan (often `root` or `SYSTEM` for Tanium) |

### `summary`

Quick triage numbers — read these first:

```json
{
  "total_components": 542,
  "threat_matches": 0,
  "findings_critical": 0,
  "findings_high": 2,
  "findings_medium": 5,
  "findings_low": 3,
  "findings_total": 10,
  "ecosystems": {
    "npm_projects": 3,
    "pypi_packages": 45,
    "go_projects": 1,
    "browser_extensions": 5,
    "mcp_servers": 2
  }
}
```

| Field | What to Look For |
|---|---|
| `threat_matches` | **> 0 = CRITICAL.** A known-compromised package is installed. Escalate immediately. |
| `findings_critical` | Supply chain compromises. Always 0 if `threat_matches` is 0. |
| `findings_high` | Known CVEs with serious impact (RCE, injection, credential leak). Patch urgently. |
| `findings_medium` | Known CVEs with moderate impact (ReDoS, XSS, redirect). Plan patching. |
| `findings_low` | Informational (outdated CA bundles, old SSH keys). Low urgency. |
| `total_components` | Total dependencies/extensions/configs inventoried across all ecosystems. |

---

## Findings — What Are They?

A **finding** is an actionable security observation about a specific component on the endpoint. Findings are generated from three sources:

```
┌──────────────────────┐
│   THREAT INTEL       │  → severity: critical
│   (supply chain      │     Exact match: ecosystem + package + version
│    compromise)       │     against known-malicious catalog entries
└──────────┬───────────┘
           │
┌──────────┴───────────┐
│   KNOWN CVE RULES    │  → severity: high / medium / low
│   (version-based     │     Static rules check version ranges
│    vulnerability     │     for well-known CVEs (express, lodash,
│    checks)           │     axios, pip, cryptography, etc.)
└──────────┬───────────┘
           │
┌──────────┴───────────┐
│   SECRETS HYGIENE    │  → severity: high / medium / low / info
│   (credential        │     Detects .env files with secret keys,
│    exposure risks)   │     plaintext git credentials, weak/old SSH keys
└──────────────────────┘
```

### Finding Object Structure

Every finding in the `findings[]` array has:

```json
{
  "severity": "high",
  "type": "known_cve",
  "user": "jdoe",
  "ecosystem": "npm",
  "package": "express",
  "version": "4.17.1",
  "project": "my-app",
  "cve": "CVE-2024-29041",
  "text": "express 4.17.1 — open redirect vulnerability. Upgrade to ≥4.20.0."
}
```

| Field | Description |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `type` | Finding source: `supply_chain_compromise`, `known_cve`, or `secrets_hygiene` |
| `user` | Which user profile the affected component belongs to |
| `ecosystem` | `npm`, `pypi`, `go`, `composer`, `rubygems`, `cargo`, `secrets` |
| `package` | Package/gem/module name |
| `version` | Installed version |
| `project` | Project directory where this dependency was found |
| `cve` | CVE identifier (if applicable) |
| `text` | Human-readable description with remediation advice |

---

## Finding Types

### 1. `supply_chain_compromise` (severity: **critical**)

**What:** An exact match of `(ecosystem, package, version)` against a known-malicious entry in a threat intel catalog. This means a package on this machine was published as part of an active supply chain attack.

**How it matches:** The threat intel matcher builds an index of every `ecosystem:package:version` triple from all loaded catalogs. Every inventoried package is checked against this index. A match means the exact compromised version is installed.

**Additional fields:**
```json
{
  "attackType": "Mini Shai Hulud npm worm",
  "campaignName": "AntV / Mini Shai-Hulud npm worm wave",
  "catalog": "antv-mini-shai-hulud.json",
  "source": "socket",
  "indicators": {
    "c2_domain": "...",
    "reference": "..."
  }
}
```

**Action:** Immediately isolate the endpoint. Remove the compromised package. Check for lateral movement. Rotate all credentials on the affected machine.

### 2. `known_cve` (severity: **high** / **medium** / **low**)

**What:** A package version falls within a known-vulnerable range for a well-documented CVE. These are static rules compiled into HiveGuard covering the most common packages across all ecosystems.

**Currently covered packages:**

| Ecosystem | Package | CVE | Severity |
|---|---|---|---|
| npm | express < 4.20 | CVE-2024-29041 | medium |
| npm | axios < 1.7 | CVE-2024-39338 | high |
| npm | jsonwebtoken < 9.0 | CVE-2022-23529 | high |
| npm | semver < 7.5.2 | CVE-2022-25883 | medium |
| npm | lodash < 4.17.21 | CVE-2021-23337 | high |
| npm | tar < 6.2 | CVE-2024-28863 | high |
| npm | postcss < 8.4.31 | CVE-2023-44270 | medium |
| pypi | pip < 23 | CVE-2023-5752 | high |
| pypi | setuptools < 70 | CVE-2024-6345 | high |
| pypi | idna 3.6 | CVE-2024-3651 | medium |
| pypi | jinja2 < 3.1.4 | CVE-2024-34064 | medium |
| pypi | pyyaml 6.0/6.0.1 | CVE-2024-6156 | medium |
| pypi | requests < 2.32 | CVE-2024-35195 | medium |
| pypi | urllib3 < 2.0.7 | CVE-2023-45803 | medium |
| pypi | cryptography < 42 | CVE-2024-26130 | high |
| pypi | certifi < 2024 | (outdated CA) | low |
| go | x/crypto < 0.17 | CVE-2023-48795 | high |
| go | x/net < 0.23 | CVE-2023-45288 | high |
| ruby | rack < 3.0.10 | CVE-2024-26146 | medium |
| composer | guzzle < 7.8 | CVE-2023-29197 | high |

**How it works:** Each rule defines a version comparison function. The package's installed version is checked against the vulnerable range. Findings are deduplicated — if the same `package@version:CVE` appears in multiple projects, they're merged with all project locations listed.

**Action:** Update the affected package to the version noted in the finding text. Prioritize `high` severity first.

### 3. `secrets_hygiene` (severity: **high** / **medium** / **low** / **info**)

**What:** Credential exposure risks detected on the endpoint. HiveGuard **never reads secret values** — it only detects file presence and key name patterns.

**Sub-types:**

| Type | Severity | What It Detects |
|---|---|---|
| `env_secrets_detected` | medium | `.env` files containing keys matching patterns like `API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AWS_ACCESS`, `STRIPE_`, `DATABASE_URL`, etc. |
| `git_plaintext_credentials` | high | Git config with `credential.helper = store` — passwords saved in plaintext |
| `git_hardcoded_token` | high | Git remote URLs containing embedded `user:token@` credentials |
| `git_credentials_file` | medium | Existence of `~/.git-credentials` file (plaintext credential store) |
| `ssh_weak_key` | high | DSA SSH keys — deprecated and cryptographically weak |
| `ssh_rsa_key` | low | RSA SSH keys — functional but Ed25519 is recommended |
| `ssh_old_key` | low | SSH keys older than 365 days — consider annual rotation |
| `ssh_authorized_keys` | info | `authorized_keys` file exists — review for unexpected entries |

**Action:** For `high` findings, immediately remediate (switch git credential helpers, remove hardcoded tokens, replace weak keys). For `medium`/`low`, plan remediation in your next maintenance window.

---

## Severity Scoring

HiveGuard uses a 5-level severity scale:

| Severity | Color | Meaning | Exit Code Impact |
|---|---|---|---|
| **critical** | Red | Active supply chain compromise. Known-malicious package installed. | Triggers exit code **2** |
| **high** | Orange | Serious CVE or credential exposure. Exploitable with significant impact. | Triggers exit code **1** |
| **medium** | Yellow | Moderate CVE. Exploitable under specific conditions (ReDoS, XSS, redirects). | Does NOT change exit code |
| **low** | Blue | Informational. Outdated but not immediately exploitable. | Does NOT change exit code |
| **info** | Gray | Awareness only. Review recommended but no immediate risk. | Does NOT change exit code |

### How Severity Is Assigned

- **Threat intel matches** are always `critical` — presence of a known-compromised package version is a confirmed incident.
- **CVE findings** are scored per-rule based on the CVE's impact (RCE/injection = `high`, ReDoS/redirect = `medium`, outdated = `low`).
- **Secrets findings** are scored by risk: plaintext credentials = `high`, .env with secrets = `medium`, old keys = `low`.

### Finding Sort Order

All findings in the `findings[]` array are sorted by severity:
```
critical → high → medium → low → info
```

---

## Threat Intelligence

### How It Works

HiveGuard maintains a catalog of known-malicious packages from active supply chain campaigns. At scan time:

1. **Live fetch** (default): Downloads the latest catalogs from [Bumblebee](https://github.com/perplexityai/bumblebee) on GitHub. Catalogs are held in memory only — nothing written to disk.
2. **Baseline fallback**: If live fetch fails (no internet, firewall), falls back to bundled snapshot in `data/baseline-catalogs/`.
3. **Custom catalogs**: Always merged on top. Place in `~/.hiveguard/custom-catalogs/` or pass via `--custom-intel <dir>`.

### What's In a Catalog

Each catalog represents a specific supply chain attack campaign:

```json
{
  "_comment": "Mini Shai-Hulud npm worm...",
  "_indicators": {
    "c2_domain": "...",
    "primary_source": "https://socket.dev/blog/..."
  },
  "entries": [
    {
      "name": "Backdoored package description",
      "ecosystem": "npm",
      "package": "@tanstack/query-core",
      "source": "socket",
      "versions": ["5.62.9", "5.62.10"]
    }
  ]
}
```

### Matching Algorithm

The matcher builds a hash index of `ecosystem:package:version` keys. For each inventoried package, it does an O(1) lookup. A match means: **the exact compromised version of a known-malicious package is installed on this machine**.

This is NOT a fuzzy match. It is NOT a "similar name" check. It is an exact `(ecosystem, package_name, version)` triple match against confirmed-malicious releases.

### Currently Tracked Campaigns

Catalogs are updated continuously. See the live list at:

> **[github.com/perplexityai/bumblebee/tree/main/threat_intel](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)**

Your scan output also includes catalog metadata — check `catalogs[]` in the JSON or the "Threat Intel" panel in the HTML report to see exactly which catalogs were loaded and how many entries each contains.

### `threat_intel` Object

```json
{
  "catalogs_loaded": 10,
  "total_known_bad_entries": 931,
  "total_known_bad_versions": 2769,
  "source": "live",
  "last_sync": "2026-06-09T13:20:41.640Z",
  "custom_catalogs": 0,
  "matches": 0
}
```

| Field | Meaning |
|---|---|
| `catalogs_loaded` | Number of threat intel catalogs loaded |
| `total_known_bad_entries` | Unique malicious packages tracked (across all catalogs) |
| `total_known_bad_versions` | Total specific version strings tracked |
| `source` | `live` = fetched from GitHub, `baseline` = bundled snapshot, `custom` = user-provided, `live+custom` = both |
| `last_sync` | When live catalogs were fetched (null if baseline/offline) |
| `matches` | **Number of packages on this machine that matched known-malicious entries** |

---

## Known CVE Checks

HiveGuard includes a static rule engine (`src/cve/known-vulns.js`) with version-comparison rules for commonly vulnerable packages. These run **offline** — no API calls needed.

### How It Works

For each inventoried package, the engine checks if the `(ecosystem, package_name)` pair has a rule. If so, the rule's version check function determines if the installed version falls in the vulnerable range.

### Example Rule

```javascript
// express < 4.20 → CVE-2024-29041 (open redirect)
{
  ecosystem: 'npm', package: 'express',
  check(v) {
    const parts = v.split('.').map(Number);
    if (parts[0] === 4 && parts[1] < 20) return {
      severity: 'medium', cve: 'CVE-2024-29041',
      text: 'express 4.17.1 — open redirect vulnerability. Upgrade to ≥4.20.0.',
    };
    return null;
  }
}
```

### Deduplication

If the same `package@version:CVE` appears in multiple projects (e.g., `lodash@4.17.20` in 3 different npm projects), the finding is reported once with all project locations combined:

```json
{
  "package": "lodash",
  "version": "4.17.20",
  "cve": "CVE-2021-23337",
  "project": "app-a, app-b, app-c"
}
```

---

## Secrets Hygiene

The secrets scanner audits three categories of credential exposure risk. It **never reads actual secret values** — only detects file presence, key name patterns, and metadata.

### 1. `.env` File Detection

- Walks project directories looking for files matching `.env`, `.env.local`, `.env.production`, etc.
- Scans key names (left side of `=`) for patterns: `API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AUTH`, `CREDENTIAL`, `PRIVATE_KEY`, `DATABASE_URL`, `MONGO_URI`, `REDIS_URL`, `AWS_ACCESS`, `STRIPE_`, `SENDGRID_`, `TWILIO_`
- Reports the **key names** found (up to 10), never the values

### 2. Git Credential Audit

- Checks `.gitconfig` for `credential.helper = store` (plaintext storage)
- Checks remote URLs for embedded `user:token@host` patterns
- Checks for existence of `.git-credentials` file

### 3. SSH Key Audit

- Enumerates `~/.ssh/` directory
- Identifies key types by reading only the first line (header detection)
- Flags: DSA keys (weak), RSA keys (recommend Ed25519), keys > 365 days old, unexpected `authorized_keys`

---

## Ecosystems & Dependencies

The `ecosystems` object contains the **raw scanner output** per ecosystem. This is the detailed view — every project, every dependency, every extension.

### npm

```json
{
  "ecosystem": "npm",
  "projects": [
    {
      "project": "my-app",
      "project_path": "/Users/jdoe/projects/my-app",
      "lockfile": "/Users/jdoe/projects/my-app/package-lock.json",
      "user": "jdoe",
      "total_dependencies": 537,
      "dependencies": [
        { "name": "express", "version": "4.18.2", "resolved": "https://registry.npmjs.org/..." },
        { "name": "lodash", "version": "4.17.21" }
      ]
    }
  ],
  "total_projects": 1
}
```

### PyPI

```json
{
  "ecosystem": "pypi",
  "packages": [
    {
      "name": "requests",
      "version": "2.31.0",
      "source_type": "venv",
      "source_dir": "/Users/jdoe/.venv/lib/python3.11/site-packages",
      "user": "jdoe"
    }
  ],
  "total": 45
}
```

### Go

```json
{
  "ecosystem": "go",
  "projects": [
    {
      "project": "my-service",
      "sum_file": "/Users/jdoe/go/my-service/go.sum",
      "user": "jdoe",
      "total_dependencies": 120,
      "dependencies": [
        { "name": "golang.org/x/net", "version": "0.24.0" }
      ]
    }
  ]
}
```

### Browser Extensions

```json
{
  "ecosystem": "browser-extensions",
  "browsers": {
    "chrome": [
      {
        "extension_id": "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
        "name": "Google Docs Offline",
        "version": "1.106.1",
        "manifest_version": 3,
        "permissions": ["alarms", "storage"],
        "host_permissions": ["https://docs.google.com/*"],
        "content_scripts": 0,
        "background": true,
        "user": "jdoe",
        "path": "/Users/jdoe/Library/Application Support/Google/Chrome/Default/Extensions"
      }
    ]
  }
}
```

### Editor Extensions

```json
{
  "ecosystem": "editor-extensions",
  "editors": {
    "windsurf": [
      {
        "publisher": "ms-python",
        "displayName": "Python",
        "version": "2024.6.0",
        "user": "jdoe",
        "path": "/Users/jdoe/.windsurf/extensions/ms-python.python-2024.6.0"
      }
    ]
  }
}
```

### MCP Configs

```json
{
  "ecosystem": "mcp-configs",
  "configs": [
    {
      "config_name": "claude_desktop_config.json",
      "config_path": "/Users/jdoe/.config/Claude/claude_desktop_config.json",
      "user": "jdoe",
      "server_count": 3,
      "servers": [
        {
          "name": "filesystem",
          "transport": "stdio",
          "command": "npx",
          "env_keys": ["ANTHROPIC_API_KEY"]
        }
      ]
    }
  ]
}
```

---

## Packages (Flat List)

The `packages[]` array is a **unified flat list** of every component found across all ecosystems. This is what the "All Packages" table in the HTML report shows.

```json
{
  "ecosystem": "npm",
  "name": "express",
  "version": "4.18.2",
  "user": "jdoe",
  "project": "my-app",
  "source": "/Users/jdoe/projects/my-app/package-lock.json",
  "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
  "confidence": "high"
}
```

| Field | Description |
|---|---|
| `ecosystem` | `npm`, `pypi`, `go`, `composer`, `rubygems`, `cargo`, `editor-extension`, `browser-extension`, `mcp-config` |
| `name` | Package/module/extension name |
| `version` | Installed version string |
| `user` | User profile this component belongs to |
| `project` | Short readable project/location name (e.g., `my-app` for npm, `vik/.dataScience` for PyPI venvs, `mod/go-micro.dev@v1.18.0` for Go modules) |
| `source` | Full path to lockfile, venv directory, or extension ID — distinguishes duplicates |
| `sourceType` | (PyPI only) `venv` or `requirements.txt` |
| `confidence` | `high` (from lockfile with exact version), `medium` (from metadata/manifest) |

### Apparent Duplicates

The same `(ecosystem, name, version)` triple can appear multiple times when it exists in multiple locations. For example, `pip@21.2.4` might appear 3 times if it's installed in 3 separate venvs. Each row's `project` and `source` fields indicate the distinct location. This is intentional — if a compromised version were found, you need to know *every* location to remediate.

### Confidence Levels

| Level | Meaning | Source |
|---|---|---|
| **high** | Exact version confirmed from lockfile hash | `package-lock.json`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock` |
| **medium** | Version from metadata or manifest (no cryptographic hash) | `.dist-info/METADATA`, `requirements.txt`, extension `package.json`/`manifest.json` |

---

## HTML Report

The interactive HTML report is a single self-contained file. No web server needed — open directly in a browser.

### Panels

| Panel | What It Shows |
|---|---|
| **Overview** | Scan metadata, host info, users scanned, timing |
| **All Packages** | Searchable/filterable table of every component with User, Project, and threat status |
| **Findings** | All findings sorted by severity, with CVE links and user attribution |
| **npm** | Per-project cards showing lockfile dependencies, with user in header |
| **Python** | Table of all PyPI packages with User and Source columns |
| **Go** | Per-project cards showing Go module dependencies |
| **Extensions** | Editor and browser extensions with User column |
| **MCP** | MCP server configurations with user attribution |

### Features

- **Search:** Type in the search box to filter across package name, version, ecosystem, project, and user
- **Ecosystem filter:** Click sidebar items to filter by ecosystem
- **Detail modal:** Click any package row to see full details
- **CSV export:** Export visible (filtered) results to CSV
- **Findings panel:** Click any finding to see CVE details with NVD links

---

## Field Reference

### Quick Triage Checklist

When reviewing a scan result, check these fields in order:

| # | Check | Where | Action |
|---|---|---|---|
| 1 | `summary.threat_matches > 0` | `summary` | **ESCALATE IMMEDIATELY.** Known-compromised package on endpoint. |
| 2 | `summary.findings_critical > 0` | `summary` | Same as above — supply chain compromise confirmed. |
| 3 | `summary.findings_high > 0` | `summary` | Review `findings[]` for high-severity CVEs and credential exposures. Patch/remediate urgently. |
| 4 | `summary.findings_medium > 0` | `summary` | Plan patching for medium CVEs in next maintenance window. |
| 5 | `threat_intel.source` | `threat_intel` | Verify catalogs are `live` (current). `baseline` means the endpoint couldn't reach GitHub — catalogs may be stale. |
| 6 | `meta.users_scanned` | `meta` | Verify expected user profiles were scanned. |
| 7 | `summary.total_components` | `summary` | Sanity check — if 0 on a developer machine, scanner may not have had access to user directories. |

---

## Examples

### Clean Scan (Exit Code 0)

```json
{
  "summary": {
    "total_components": 542,
    "threat_matches": 0,
    "findings_critical": 0,
    "findings_high": 0,
    "findings_medium": 3,
    "findings_low": 1,
    "findings_total": 4
  }
}
```

**Interpretation:** No supply chain threats. 3 medium CVEs to patch when convenient. No urgent action needed.

### Findings Present (Exit Code 1)

```json
{
  "summary": {
    "threat_matches": 0,
    "findings_high": 2,
    "findings_total": 7
  },
  "findings": [
    {
      "severity": "high",
      "type": "known_cve",
      "package": "axios",
      "version": "1.5.0",
      "cve": "CVE-2024-39338",
      "text": "axios 1.5.0 — SSRF via unexpected protocol. Upgrade to ≥1.7.4."
    },
    {
      "severity": "high",
      "type": "secrets_hygiene",
      "package": "git_plaintext_credentials",
      "text": "Git credential helper is set to 'store' — credentials saved in plaintext"
    }
  ]
}
```

**Interpretation:** No active compromise, but 2 high-severity issues: a known SSRF vulnerability in axios and plaintext git credentials. Update axios and switch git credential helper to a secure option (e.g., `osxkeychain` on macOS, `wincred` on Windows).

### Critical — Supply Chain Compromise (Exit Code 2)

```json
{
  "summary": {
    "threat_matches": 1,
    "findings_critical": 1,
    "findings_total": 1
  },
  "findings": [
    {
      "severity": "critical",
      "type": "supply_chain_compromise",
      "ecosystem": "npm",
      "package": "@tanstack/query-core",
      "version": "5.62.9",
      "user": "dev-user",
      "attackType": "Mini Shai Hulud npm worm",
      "campaignName": "Mini Shai-Hulud npm worm wave",
      "catalog": "mini-shai-hulud.json",
      "text": "@tanstack/query-core@5.62.9 — SUPPLY CHAIN COMPROMISE: Mini Shai Hulud npm worm"
    }
  ],
  "threat_matches": [
    {
      "ecosystem": "npm",
      "name": "@tanstack/query-core",
      "version": "5.62.9",
      "project": "internal-dashboard",
      "user": "dev-user",
      "threats": [
        {
          "attackType": "Mini Shai Hulud npm worm",
          "campaignName": "Mini Shai-Hulud npm worm wave",
          "catalog": "mini-shai-hulud.json"
        }
      ]
    }
  ]
}
```

**Interpretation:** **INCIDENT.** The compromised worm version of `@tanstack/query-core` is installed in the `internal-dashboard` project belonging to user `dev-user`. This package was part of the Mini Shai-Hulud supply chain attack. Immediate response:
1. Isolate the endpoint
2. Remove the compromised dependency (`npm install @tanstack/query-core@latest`)
3. Rotate all npm tokens, GitHub PATs, and credentials on this machine
4. Check npm publish history for the affected user's packages
5. Scan other machines where this user has access
