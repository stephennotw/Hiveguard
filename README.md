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
git clone https://github.com/stephennotw/Hiveguard.git
cd hiveguard
```

That's it — no `npm install`, no dependencies. The bootstrap wrappers handle everything, including downloading Node.js if needed.

## How to Run

HiveGuard ships with bootstrap wrappers that **automatically download a portable Node.js** if one isn't already installed. No admin/root required.

### Windows — Command Prompt (CMD)

Open `cmd.exe` and run:

```cmd
run.bat
run.bat --offline --output C:\results --verbose
run.bat --json > results.json
```

### Windows — PowerShell

Open PowerShell and run:

```powershell
.\run.ps1
.\run.ps1 --offline --output C:\results --verbose
.\run.ps1 --json > results.json
```

> **Note**: If you see `execution of scripts is disabled`, either use `run.bat` instead or run:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass`

### macOS / Linux

```bash
chmod +x run.sh    # first time only
./run.sh
./run.sh --offline --output /tmp/results --verbose
./run.sh --json > results.json
```

### Direct (if Node.js 18+ is already installed)

If you already have Node.js 18+ on the system, you can skip the bootstrap wrappers entirely:

```bash
node bin/hiveguard.js
node bin/hiveguard.js --output /path/to/results --verbose
node bin/hiveguard.js --json --offline > results.json
node bin/hiveguard.js --custom-intel /path/to/custom-catalogs
node bin/hiveguard.js --scan-dirs /home/user/projects,/opt/apps
```

After a scan completes, open the generated HTML report in any browser to explore results interactively.

### How the Bootstrap Works

The `run.bat` / `run.ps1` (Windows) and `run.sh` (macOS/Linux) wrappers make HiveGuard truly zero-prerequisite:

1. **Check system** — looks for an existing `node` binary with version >=18
2. **Download if missing** — if Node.js isn't found (or is too old), downloads a portable Node.js binary from `nodejs.org` into a local `.node/` directory inside the repo. No system-level install, no admin/root, no PATH changes.
3. **Cache for reuse** — the downloaded binary (~30MB) is kept in `.node/` so subsequent runs start instantly
4. **Pass through** — all CLI flags are forwarded directly to `bin/hiveguard.js`

The `.node/` directory is gitignored and never committed to the repo.

| Wrapper | Shell | When to use |
|---|---|---|
| `run.bat` | CMD (Command Prompt) | Default for Windows — works everywhere, no execution policy issues |
| `run.ps1` | PowerShell | If you prefer PowerShell or are running from a PS terminal |
| `run.sh` | Bash / Zsh | macOS and Linux |

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `--output <dir>` | Output directory for results | `./hiveguard-results` |
| `--json` | JSON to stdout (quiet mode) | off |
| `--offline` | Use bundled baseline catalogs only | off |
| `--scan-dirs <dirs>` | Comma-separated scan roots | auto-detect |
| `--normal-priority` | Run at normal CPU priority instead of below normal | off |
| `--users-root <dir>` | Enumerate user profiles under `<dir>` instead of `/home`, `/Users` or `C:\Users`, and skip system-wide locations (e.g. scanning a mounted disk image) | off |
| `--custom-intel <dir>` | Dir(s) with custom threat intel JSON | none |
| `--no-report` | Skip HTML report | off |
| `--no-secrets` | Skip secrets hygiene scan | off |
| `--max-depth <n>` | Max directory traversal depth | 4 |
| `--verbose` / `-v` | Debug logging | off |

## Self-Check (try it on your own machine)

```bash
node tools/self-check.js            # offline scan, nothing leaves the machine
node tools/self-check.js --online   # also query OSV.dev / Bumblebee / GitHub
```

Runs a normal scan and prints a summary of timings, inventory counts and finding categories. The summary contains no file paths, usernames, hostnames or package names, so it is safe to share; it is also saved as `selfcheck-summary.txt`. The full JSON/HTML report (which does contain paths) stays in a temp folder for your own review.

## Testing

```bash
npm test                    # unit, end-to-end CLI and corpus tests
npm run test:corpus:update  # regenerate corpus expectations after an intended change (review the diff!)
```

The corpus (`test/corpus/`) builds synthetic endpoints — a typical developer laptop, a fake-interview repo, an npm worm, a power user's dotfiles — scans each in isolation with `--users-root`, and compares the results with `test/corpus/expected/*.json`, which also record known detection gaps.

CI (`.github/workflows/ci.yml`) runs the suite on Linux (Node 18 and 22), macOS and Windows, including the `run.bat` / `run.ps1` wrappers. It is opt-in to save Actions minutes: it runs only for pushed commits whose message contains `[ci]`, or when started manually from the Actions tab.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no threats, no critical/high findings |
| `1` | Findings — medium/high CVEs or advisories present |
| `2` | Critical — supply chain compromise detected |
| `3` | Fatal error |

## Endpoint Deployment

HiveGuard is designed to be pushed to endpoints via any management tool (Tanium, Jamf, Intune, Ansible, etc.).
No prerequisites required — the bootstrap wrappers download Node.js automatically if needed.

### Option A: ZIP Package (recommended for Tanium / remote deployment)

1. **Prepare** — Zip the folder containing HiveGuard (e.g. `Hiveguard/`) into `Hiveguard.zip`
2. **Upload** — Upload `Hiveguard.zip` as the package file
3. **Command** — The package command extracts the ZIP, then runs the bootstrap:
   - **Windows (CMD)**: `cmd /c powershell -NoProfile -NonInteractive -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive -Path 'Hiveguard.zip' -DestinationPath '.' -Force" && Hiveguard\run.bat --json`
   - **Windows (PowerShell)**: `cmd /c powershell -NoProfile -NonInteractive -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive -Path 'Hiveguard.zip' -DestinationPath '.' -Force" && powershell Hiveguard\run.ps1 --json`
   - **macOS/Linux (Tanium)**: `/bin/bash -c "unzip -qo Hiveguard.zip && cd Hiveguard && chmod +x run.sh && ./run.sh --json"`
   - **macOS/Linux (shell)**: `unzip -qo Hiveguard.zip && chmod +x Hiveguard/run.sh && Hiveguard/run.sh --json`

> **Important:**
> - The folder name inside the ZIP determines the path after `&&`. If your folder is named `Hiveguard`, the path is `Hiveguard\run.bat`.
> - Results are written to `./hiveguard-results/` in the current directory by default. Use `--output <dir>` to change.
> - **Do not** add `> results.json` to the command. The `--output` flag already writes all results (JSON + HTML) to the specified directory.
> - **macOS note:** ZIPs created on Windows lose the execute permission on `run.sh`. The `chmod +x` step fixes this. If `unzip` is unavailable, use: `python3 -c "import zipfile; zipfile.ZipFile('Hiveguard.zip').extractall('.')" && chmod +x Hiveguard/run.sh && Hiveguard/run.sh --json`
> - **Tanium macOS note:** Tanium passes the command to `/bin/bash` directly. You **must** use `/bin/bash -c "..."` to wrap the full command, otherwise `unzip` will fail with `cannot execute binary file` (exit code 126).

### Option B: Direct Copy

1. **Deploy** — Copy the entire `hiveguard/` directory to the endpoint
2. **Run** — Execute the bootstrap wrapper:
   - **Windows (CMD)**: `cmd /c C:\path\to\hiveguard\run.bat --json`
   - **Windows (PowerShell)**: `powershell -ExecutionPolicy Bypass -File C:\path\to\hiveguard\run.ps1 --json`
   - **macOS/Linux**: `/path/to/hiveguard/run.sh --json`

### Collecting Results

- **Collect** — Gather the JSON output from the `--output` directory on each endpoint
- **Alert** — Use the exit code for automated alerting:
  - `0` = clean
  - `1` = findings present (review recommended)
  - `2` = **critical** — supply chain compromise detected (escalate immediately)

### Tanium 7.8 On-Prem Quick Reference

| Step | Where | What |
|---|---|---|
| Create package (Win) | Administration → Content → Packages → New Package | Upload `Hiveguard.zip` |
| Set command (Win) | Package → Command field | `cmd /c powershell -NoProfile -NonInteractive -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive -Path 'Hiveguard.zip' -DestinationPath '.' -Force" && Hiveguard\run.bat --json` |
| Create package (Mac) | Administration → Content → Packages → New Package | Upload `Hiveguard.zip` |
| Set command (Mac) | Package → Command field | `/bin/bash -c "unzip -qo Hiveguard.zip && cd Hiveguard && chmod +x run.sh && ./run.sh --json"` |
| Set timeout | Package → Command Timeout | `600` seconds (extraction + possible Node.js download) |
| Target endpoints | Interact → Ask question | `Get Computer Name from all machines` |
| Deploy | Select endpoints → Deploy Action → choose package | Run once or schedule |
| Collect results | Create sensor to read `hiveguard-results/*.json` in the action directory | Pull back via Interact |

No admin/root privileges required. Results are written to `./hiveguard-results/` in the current directory by default. If the endpoint already has Node.js 18+, the wrapper uses it directly. Otherwise it downloads a portable binary on first run (~30MB, cached for subsequent scans).

## Output Structure

```
hiveguard-results/
├── hiveguard-<hostname>-<timestamp>.json   # Full scan results
└── hiveguard-report-<hostname>.html        # Interactive HTML report
```

Note: Threat intel catalogs are loaded into memory at runtime — no disk cache required.

> **📖 For a complete guide to understanding results — findings, severity scoring, dependencies, field reference, and examples — see [`docs/RESULTS-GUIDE.md`](docs/RESULTS-GUIDE.md).**

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
| **Install Scripts** | Suspicious `preinstall`/`install`/`postinstall` hooks, including the files they run (e.g. `node setup_bun.js`) | `node_modules/**/package.json` (project, nested, scoped, global) |
| **Git Hooks** | Custom and suspicious hooks, including `core.hooksPath` (repo and global) and symlinks leaving the repo | `.git/hooks`, `.git/config`, `~/.gitconfig` |
| **AI Assistant Files** | Instruction/config files read by AI coding tools: prompt injection, hidden Unicode, exfiltration instructions, auto-run VS Code tasks, Claude Code hook commands | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.claude/settings.json`, `.vscode/tasks.json`, … (project and user level) |

Install-script, git-hook and AI-file excerpts in the output are attacker-controlled text; invisible and control characters are stripped from them.

## AI on This Machine

HiveGuard inventories AI tooling by **structure, not product name**, so new tools show up (under their folder name) without anyone maintaining a product catalog:

| Signal | How it is found |
|---|---|
| MCP servers | Any config with `mcpServers` / `servers` / `context_servers` keys or TOML `[mcp_servers.*]`, in home dot-folders, `~/.claude.json` and app config roots (`%APPDATA%`, `%LOCALAPPDATA%`, `~/Library/Application Support`, `~/.config`). Servers launched through `npx`/`uvx`/`dlx` without a pinned version are flagged (medium); pinned ones are matched against threat intel like any package. |
| Editors | Any `~/.<name>/extensions/extensions.json` (VS Code and its forks); their extensions join the extension inventory. |
| Agent files | `skills/*/SKILL.md`, `rules/`, `commands/`, `agents/`, `prompts/`, `instructions/` in any dot-folder of a home or project, checked like other AI instruction files. |
| Local models | `.gguf`, `.safetensors`, `.onnx`, `.pt`, `.ckpt`, … ≥ 10 MB, format confirmed from the first bytes (model bodies are never read); Hugging Face, Ollama and LM Studio stores. Pickle-format models, which can run code when loaded, are marked. |
| Provider credentials | Well-known variable names or key formats in `.env` files, shell/PowerShell profiles and MCP configs. Only the provider, file and variable name are reported, never the value. |
| AI SDKs | ~80 SDK packages tagged in the existing dependency inventory. |

A short list of common AI apps that leave no structural footprint (for example the ChatGPT desktop app) is kept in `data/ai-apps.json` and used only to report "installed". Each entry lists per-OS locations; edit that file to add or correct an app (the `observed` flag marks entries confirmed on a real endpoint).

MCP servers started through a wrapper (security proxies, launchers: `<wrapper> … npx foo`) are unwrapped so the real package is checked; the wrapper name is recorded.

Files inside cloud-sync folders (OneDrive, Dropbox, Google Drive, iCloud) are listed by name only and never read, because reading an online-only file makes the OS download it. HiveGuard also runs at below-normal CPU priority by default (`--normal-priority` to opt out).

## Threat Intelligence

HiveGuard uses a **tiered fallback chain** to ensure threat intel is always available:

| Priority | Source | Description |
|---|---|---|
| **1st** | Live fetch | Catalogs fetched from [Bumblebee](https://github.com/perplexityai/bumblebee) GitHub into memory at runtime |
| **2nd** | Bundled baseline | Snapshot of catalogs shipped inside HiveGuard (`data/baseline-catalogs/`) |
| **3rd** | Custom catalogs | User-provided JSON files via `--custom-intel` or `~/.hiveguard/custom-catalogs/` |

Custom catalogs are **always additive** — they merge on top of live/baseline and win on conflict.

Two live sources are also queried for the exact installed `name@version` of every package (skipped with `--offline`):

| Source | What it adds | Requirements |
|---|---|---|
| [OSV.dev](https://osv.dev) | OpenSSF malicious-package advisories (`MAL-*`), with summary, hashes and origin | None |
| [GitHub Advisory Database](https://github.com/advisories?query=type%3Amalware) | GitHub malware advisories | `GITHUB_TOKEN` (or `GH_TOKEN`); skipped without it. OSV already includes most of this data. |

Every source reports its status in `threat_intel.sources` (`ok`, `partial`, `failed`, `skipped`) and failures are printed to stderr, so an unreachable source is never mistaken for a clean result.

Outbound requests honour `HTTPS_PROXY` / `https_proxy` and `NO_PROXY` / `no_proxy`.

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
├── run.bat                  # Bootstrap wrapper (Windows CMD)
├── run.ps1                  # Bootstrap wrapper (Windows PowerShell)
├── run.sh                   # Bootstrap wrapper (macOS/Linux)
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

- **None** — the bootstrap wrappers (`run.bat` / `run.ps1` / `run.sh`) download Node.js automatically if not present
- **No npm install needed** — zero external dependencies
- **Read-only filesystem access** — scans user home, project dirs, extension dirs without writing or executing anything
- If running directly via `node bin/hiveguard.js`, Node.js 18+ is required (uses built-in `fs`, `https`, `path`, `os` only)

## Security

- **Read-only** — never writes outside the output directory, never executes package managers
- **No secret values read** — secrets hygiene scanner detects file presence and key names only, never reads values
- **No external calls** except optional GitHub API for live threat intel (skip with `--offline`)

## License

MIT
