# 🐝 HiveGuard

**Cross-platform endpoint supply chain scanner with live threat intelligence.**

HiveGuard inventories every software component on a developer endpoint — npm, PyPI, Go, Composer, RubyGems, Cargo, IDE extensions, browser extensions, MCP server configs — and matches them against known supply chain compromise catalogs in real time.

## Features

- **Zero dependencies** — Pure Node.js 18+, no `npm install` required
- **Cross-platform** — Windows, macOS, Linux with OS-specific path detection
- **11 scanners** — npm, PyPI, Go, Composer, RubyGems, Cargo, editor extensions, browser extensions, MCP configs, npm globals, secrets hygiene
- **Live threat intel** — Fetches exposure catalogs from [Bumblebee](https://github.com/perplexityai/bumblebee) into memory at runtime, with bundled baseline fallback
- **Custom threat intel** — Add org-specific catalogs via `--custom-intel` or `~/.hiveguard/custom-catalogs/`
- **Known CVE checks** — Static rules for 20+ common vulnerabilities (express, lodash, axios, pip, setuptools, etc.)
- **Secrets hygiene** — Detects `.env` files with secrets, plaintext git credentials, SSH key audit
- **Interactive HTML report** — Searchable, filterable, with threat alert banners and package detail modals
- **Machine-readable output** — JSON for Tanium/Jamf/SIEM collection
- **Read-only** — Never executes package managers, never modifies files

## Installation

```bash
# Clone the repo (or copy the folder to the target machine)
git clone https://github.com/stephennotw/hiveguard.git
cd hiveguard

# No install step needed — zero dependencies
# Just requires Node.js 18+
node --version   # verify >=18
```

## How to Run

```bash
# Basic scan — results go to ./hiveguard-results/
node bin/hiveguard.js

# Custom output directory
node bin/hiveguard.js --output /path/to/results

# JSON to stdout (for automation / SIEM ingestion)
node bin/hiveguard.js --json > results.json

# Offline mode (uses bundled baseline catalogs, no network required)
node bin/hiveguard.js --offline

# Add custom threat intel from your security team
node bin/hiveguard.js --custom-intel /path/to/custom-catalogs

# Scan specific directories only
node bin/hiveguard.js --scan-dirs /home/user/projects,/opt/apps

# Verbose logging for debugging
node bin/hiveguard.js --verbose

# Combine flags
node bin/hiveguard.js --offline --custom-intel ./my-catalogs --output ./results --verbose
```

After a scan completes, open the generated HTML report in any browser to explore results interactively.

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `--output <dir>` | Output directory for results | `./hiveguard-results` |
| `--json` | JSON to stdout (quiet mode) | off |
| `--offline` | Use bundled baseline catalogs only | off |
| `--scan-dirs <dirs>` | Comma-separated scan roots | auto-detect |
| `--custom-intel <dir>` | Dir(s) with custom threat intel JSON | none |
| `--no-report` | Skip HTML report | off |
| `--no-secrets` | Skip secrets hygiene scan | off |
| `--max-depth <n>` | Max directory traversal depth | 6 |
| `--verbose` / `-v` | Debug logging | off |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no threats, no critical/high findings |
| `1` | Findings — medium/high CVEs or advisories present |
| `2` | Critical — supply chain compromise detected |
| `3` | Fatal error |

## Endpoint Deployment

HiveGuard is designed to be pushed to endpoints via any management tool (Jamf, Tanium, Intune, Ansible, etc.):

1. **Prerequisite** — Node.js 18+ must be available on the endpoint
2. **Deploy** — Copy the entire `hiveguard/` directory to the endpoint
3. **Run** — Execute: `node /path/to/hiveguard/bin/hiveguard.js --json --output /path/to/results > results.json`
4. **Collect** — Gather `results.json` from each endpoint
5. **Alert** — Use the exit code for automated alerting:
   - `0` = clean
   - `1` = findings present (review recommended)
   - `2` = **critical** — supply chain compromise detected (escalate immediately)

No admin/root privileges required — the scanner is fully read-only.

## Output Structure

```
hiveguard-results/
├── hiveguard-<hostname>-<timestamp>.json   # Full scan results
└── hiveguard-report-<hostname>.html        # Interactive HTML report
```

Note: Threat intel catalogs are loaded into memory at runtime — no disk cache required.

## Scanners

| Scanner | What it finds | Lockfile / Source |
|---|---|---|
| **npm** | Project + global dependencies | `package-lock.json` |
| **PyPI** | Venv packages, requirements.txt, global | `.dist-info/METADATA` |
| **Go** | Module dependencies | `go.sum` / `go.mod` |
| **Composer** | PHP dependencies | `composer.lock` |
| **RubyGems** | Ruby dependencies | `Gemfile.lock` |
| **Cargo** | Rust dependencies | `Cargo.lock` |
| **Editor Extensions** | VS Code, Windsurf, Cursor, VSCodium | Extension `package.json` |
| **Browser Extensions** | Chrome, Edge, Brave | Extension `manifest.json` |
| **MCP Configs** | Claude, Cursor, Windsurf MCP servers | Config JSON files |
| **Secrets Hygiene** | `.env` files, git creds, SSH keys | File detection + metadata |

## Threat Intelligence

HiveGuard uses a **tiered fallback chain** to ensure threat intel is always available:

| Priority | Source | Description |
|---|---|---|
| **1st** | Live fetch | Catalogs fetched from [Bumblebee](https://github.com/perplexityai/bumblebee) GitHub into memory at runtime |
| **2nd** | Bundled baseline | Snapshot of catalogs shipped inside HiveGuard (`data/baseline-catalogs/`) |
| **3rd** | Custom catalogs | User-provided JSON files via `--custom-intel` or `~/.hiveguard/custom-catalogs/` |

Custom catalogs are **always additive** — they merge on top of live/baseline and win on conflict.

The report and JSON output always indicate which source tier was used: `live`, `baseline`, `custom`, or `live+custom`.

### Custom Threat Intel Format

To add your own threat intel (e.g., internal SOC findings), create a JSON file:

```json
{
  "_comment": "Internal SOC findings — 2026-05-27",
  "_indicators": {
    "c2_domain": "bad.example.com",
    "reference": "SOC-2026-0042"
  },
  "entries": [
    {
      "name": "Backdoored internal-utils",
      "ecosystem": "npm",
      "package": "internal-utils",
      "source": "internal-soc",
      "versions": ["1.0.0", "1.0.1"]
    }
  ]
}
```

Place it in either:
- **`~/.hiveguard/custom-catalogs/`** — persistent per-machine
- **Any directory** passed via `--custom-intel <dir>` — for Jamf/Tanium push

Supported ecosystems: `npm`, `pypi`, `go`, `composer`, `rubygems`, `cargo`, `vscode-extension`, `chrome-extension`.

### Bundled Campaigns

Current baseline includes: mini-shai-hulud, antv-mini-shai-hulud, trapdoor-crypto-stealer, node-ipc-credential-stealer, nx-console-vscode, gemstuffer, laravel-lang, shopsprint-decimal-typosquat.

## Architecture

```
hiveguard/
├── bin/hiveguard.js          # CLI entry point + orchestrator
├── src/
│   ├── scanners/             # One module per ecosystem
│   ├── platform/             # OS-specific paths (win32, darwin, linux)
│   ├── threat-intel/         # Runtime fetch + matcher + baseline fallback
│   ├── cve/                  # Static known-vulnerability rules
│   ├── report/               # HTML report generator
│   └── utils/                # Logger, FS helpers, output writers
├── data/
│   └── baseline-catalogs/    # Frozen threat intel snapshot (offline fallback)
├── package.json
├── LICENSE
└── README.md
```

## Requirements

- **Node.js 18+** (uses built-in `fs`, `https`, `path`, `os` only)
- **No npm install needed** — zero external dependencies
- **Read-only filesystem access** — scans user home, project dirs, extension dirs without writing or executing anything

## Security

- **Read-only** — never writes outside the output directory, never executes package managers
- **No secret values read** — secrets hygiene scanner detects file presence and key names only, never reads values
- **No external calls** except optional GitHub API for live threat intel (skip with `--offline`)

## License

MIT
