# 🐝 HiveGuard 2.0

**Find compromised packages, malicious install scripts, persistence and risky AI tooling on developer machines, without installing anything.**

HiveGuard is a read-only scanner for Windows, macOS and Linux endpoints. It builds an inventory of what is on a machine (packages, extensions, AI tools, programs that start on login), checks it against live threat intelligence, and writes a JSON result plus an HTML report you can open in any browser.

> **New in 2.0:** more lockfile formats, persistence and IOC detection, AI tooling found by structure, GlassWorm and Phantom Gyp detection, SARIF / CycloneDX / NDJSON output, and `--ioc` search for incident response. See **[What's new in 2.0](docs/WHATS-NEW-2.0.md)**.

---

## Contents

- [Quick start](#quick-start)
- [What HiveGuard checks](#what-hiveguard-checks)
- [Reading the result](#reading-the-result)
- [Common tasks](#common-tasks)
- [Options](#options)
- [Safety on corporate machines](#safety-on-corporate-machines)
- [Documentation](#documentation)

---

## Quick start

You do not need to install anything. If Node.js 18 or newer is missing, the launcher downloads a portable copy into the HiveGuard folder.

**1. Get HiveGuard**

```bash
git clone https://github.com/stephennotw/Hiveguard.git
cd Hiveguard
```

(Or copy/unzip the folder onto the machine.)

**2. Run it**

| Platform | Command |
|---|---|
| Windows (Command Prompt) | `run.bat` |
| Windows (PowerShell) | `.\run.ps1` |
| macOS / Linux | `./run.sh` (run `chmod +x run.sh` the first time) |
| Node.js 18+ already installed | `node bin/hiveguard.js` |

**3. Open the report**

When the scan finishes it prints where the results are (by default `./hiveguard-results/`). Open `hiveguard-report-<hostname>.html` in a browser.

A typical developer laptop takes from a few seconds up to a minute or two. HiveGuard runs at low CPU priority so it does not slow the machine down.

---

## What HiveGuard checks

### Inventory and threat intelligence

| Area | What is collected | From |
|---|---|---|
| **JavaScript** | Every dependency of every project | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `bun.lock`, global npm |
| **Python** | Installed and locked packages | virtual environments, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| **Go, PHP, Ruby, Rust** | Module, package, gem and crate versions | `go.sum`, `composer.lock`, `Gemfile.lock`, `Cargo.lock` |
| **Editor extensions** | VS Code, Cursor, Windsurf, VSCodium and any other VS Code fork | extension folders |
| **Browser extensions** | Chrome, Edge, Brave | browser profiles |
| **MCP servers** | Servers configured for any AI agent, and the package each one runs | agent config files |

Every component is checked against:

- **Threat-intel catalogs** of known-compromised package versions (live from [Bumblebee](https://github.com/perplexityai/bumblebee), with a bundled offline copy, plus your own catalogs).
- **OSV.dev** malicious-package advisories, including VS Code extensions.
- **GitHub Advisory Database** malware advisories (when `GITHUB_TOKEN` is set).
- **Known CVE rules** for about 20 widely used packages.

### Code that runs automatically

| Check | Catches |
|---|---|
| **Install scripts** | `preinstall` / `install` / `postinstall` hooks and the files they run (Shai-Hulud style worms), `binding.gyp` commands (Phantom Gyp), dependencies downloaded from a URL outside any registry (PhantomRaven) |
| **Git hooks** | Suspicious hooks in repositories and in a global `core.hooksPath` |
| **AI assistant files** | Prompt injection, hidden Unicode, exfiltration instructions and permission bypasses in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, rules/skills folders; agent hooks and VS Code tasks that run when a folder opens, and the scripts they run |
| **Autostart and persistence** | macOS LaunchAgents, Linux autostart and systemd user units, the Windows Startup folder; Windows scheduled tasks and cron tables when run elevated |
| **Extensions** | Code hidden as invisible Unicode in an extension (GlassWorm) |
| **Indicators of compromise** | Payload file names, file hashes, persistence files and exfiltration hosts published in threat-intel catalogs |

### AI on this machine

AI tools are found by **how they are laid out on disk**, not by a product list, so new tools show up without anyone updating HiveGuard:

- MCP servers (configured, available-but-unused, disabled), with unpinned packages flagged
- VS Code forks, agent skills and rules folders
- Local models (GGUF, safetensors, ONNX, PyTorch, …) and which ones use the unsafe pickle format
- AI provider API keys stored in plain text (only the provider and file are reported, never the key)
- AI SDKs used in projects
- Common AI desktop apps

### Secrets hygiene

`.env` files containing secrets, plain-text git credentials, weak or old SSH keys. Only file names and key names are reported, never values.

---

## Reading the result

The console summary and the exit code tell you how urgent the result is:

| Exit code | Meaning | What to do |
|---|---|---|
| `0` | Clean: no threat match, nothing critical or high | Nothing urgent |
| `1` | At least one critical or high finding (for example a malicious install script, a vulnerable package, plain-text credentials) | Review the findings |
| `2` | A known-compromised package is installed, or an indicator you searched for was found | Treat as an incident |
| `3` | HiveGuard could not run | Check the console output |

In the HTML report, start with **Overview**, then **Findings**. Every finding names the file or project it came from and the user it belongs to.

For what each finding means and what to do about it, see the **[Results guide](docs/RESULTS-GUIDE.md)**.

---

## Common tasks

| I want to… | Command | Guide |
|---|---|---|
| Scan without any network access | `run.bat --offline` | [How-to](docs/HOW-TO.md#scan-without-network-access) |
| Check whether an indicator is on this machine | `run.bat --ioc "@antv/a8@0.1.1,t.m-kosche.com"` | [How-to](docs/HOW-TO.md#hunt-for-indicators-of-compromise) |
| Send results to a SIEM | `run.bat --format ndjson` | [How-to](docs/HOW-TO.md#send-results-to-a-siem) |
| Produce an SBOM | `run.bat --format cyclonedx` | [How-to](docs/HOW-TO.md#produce-an-sbom) |
| Load findings into a code-scanning dashboard | `run.bat --format sarif` | [How-to](docs/HOW-TO.md#load-findings-into-a-security-dashboard) |
| Add our own list of bad packages | `run.bat --custom-intel C:\intel` | [Threat intel](docs/THREAT-INTEL.md#add-your-own-catalogs) |
| Deploy with Tanium, Jamf, Intune, … | see guide | [Deployment](docs/DEPLOYMENT.md) |
| Scan a mounted disk image | `./run.sh --users-root /mnt/image/Users` | [How-to](docs/HOW-TO.md#scan-a-mounted-disk-image) |
| Try it and share a summary safely | `node tools/self-check.js` | [How-to](docs/HOW-TO.md#run-the-self-check) |

(On macOS/Linux use `./run.sh` instead of `run.bat`.)

---

## Options

| Option | What it does | Default |
|---|---|---|
| `--output <dir>` | Where to write results | `./hiveguard-results` |
| `--offline` | Use only the bundled threat intel; make no network requests | off |
| `--json` | Also print the JSON result to standard output (quiet mode) | off |
| `--format <list>` | Also write `sarif`, `cyclonedx`, `ndjson`, or `all` | none |
| `--ioc <values>` | Look for indicators; comma-separated, can be repeated | none |
| `--ioc-file <file>` | Indicators from a file, one per line | none |
| `--custom-intel <dirs>` | Extra threat-intel catalog folders (comma-separated) | none |
| `--scan-dirs <dirs>` | Scan only these folders for projects (comma-separated) | user profiles |
| `--users-root <dir>` | Treat `<dir>` as the users folder and skip system locations | off |
| `--max-depth <n>` | How deep to look for projects | `4` |
| `--no-report` | Skip the HTML report | off |
| `--no-secrets` | Skip the secrets hygiene checks | off |
| `--normal-priority` | Run at normal instead of low CPU priority | off |
| `--verbose`, `-v` | Detailed logging | off |
| `--help`, `-h` | Show help | |

Network settings: `HTTPS_PROXY` / `NO_PROXY` are honoured. Set `GITHUB_TOKEN` to add the GitHub Advisory Database.

---

## Safety on corporate machines

- **Read-only.** HiveGuard never runs package managers, scripts or anything it finds. It writes only to its output folder (and, if Node.js is missing, downloads it into its own `.node` folder).
- **No registry reads.** Windows checks use files only.
- **Gentle.** Below-normal CPU priority by default; file reads are capped in size.
- **Cloud folders are not downloaded.** Files in OneDrive, Dropbox, Google Drive and iCloud folders are listed by name only, because opening an online-only file makes the OS download it.
- **No secret values.** Secrets checks report file and key names, never values.
- **Network use is limited to threat intel:** Bumblebee catalogs on GitHub, OSV.dev and (with a token) the GitHub Advisory Database. Only package names and versions are sent to OSV.dev and GitHub. `--offline` turns all of it off.
- **Zero dependencies.** Pure Node.js; nothing is installed from npm.

---

## Documentation

| Document | For |
|---|---|
| [What's new in 2.0](docs/WHATS-NEW-2.0.md) | Upgrading from 1.x: new features, changed behaviour, compatibility |
| [How-to guides](docs/HOW-TO.md) | Step-by-step tasks: scanning, IOC hunting, exports, self-check, troubleshooting |
| [Deployment](docs/DEPLOYMENT.md) | Running HiveGuard across a fleet (Tanium, Jamf, Intune, scripts) and collecting results |
| [Results guide](docs/RESULTS-GUIDE.md) | Every finding type, what it means and what to do; JSON fields |
| [Threat intelligence](docs/THREAT-INTEL.md) | Where intel comes from, custom catalogs, indicators |
| [Development](docs/DEVELOPMENT.md) | Code layout, tests, the synthetic-machine corpus, CI |
| [Changelog](CHANGELOG.md) | Version history |

## License

MIT
