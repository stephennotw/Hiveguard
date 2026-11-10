# What's new in HiveGuard 2.0

HiveGuard 1.x inventoried packages and matched them against a single source of threat intelligence. In 2.0 it also checks the code that runs on its own (install scripts, git hooks, AI agent hooks, programs that start on login), finds AI tooling, and plugs into enterprise tooling.

This page covers:

1. [Highlights](#highlights)
2. [New detections](#new-detections)
3. [Better coverage of what is installed](#better-coverage-of-what-is-installed)
4. [AI on this machine](#ai-on-this-machine)
5. [Output and integrations](#output-and-integrations)
6. [Accuracy and reliability fixes](#accuracy-and-reliability-fixes)
7. [Changed behaviour](#changed-behaviour)
8. [Upgrading from 1.x](#upgrading-from-1x)
9. [Known limitations](#known-limitations)

---

## Highlights

| | 1.x | 2.0 |
|---|---|---|
| Threat-intel sources | Bumblebee catalogs, your own catalogs | + OSV.dev, GitHub Advisory Database (with `GITHUB_TOKEN`), file-level indicators |
| JavaScript lockfiles | `package-lock.json` | + `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `bun.lock` |
| Python sources | venvs, `requirements.txt` | + `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| Code that runs automatically | not checked | install scripts, `binding.gyp`, git hooks, AI agent hooks, auto-run VS Code tasks, autostart entries |
| AI tooling | a few known MCP config files | found by structure: any agent's MCP servers, VS Code forks, skills, local models, API keys, SDKs, AI apps |
| Extensions | inventory only | + OSV.dev malicious-extension advisories, GlassWorm hidden-code detection, extension packs |
| Output | JSON + HTML | + SARIF, CycloneDX SBOM, NDJSON for SIEMs |
| Incident response | none | `--ioc` search: "is this package / file / domain on the machine?" |
| Testing | none | 200+ automated tests, five synthetic machines, CI on Windows, macOS and Linux |
| Speed on Windows | every file opened in turn | only packages with install scripts are read (npm, pnpm 10+); remaining reads run in parallel |

---

## New detections

### Install-time attacks (npm)

- **Malicious install scripts.** `preinstall`, `install` and `postinstall` hooks are checked for download-and-run, reverse shells, encoded payloads, credential theft and similar behaviour. The script files a hook runs (for example `node setup_bun.js`) are opened and checked too. This catches Shai-Hulud style worms.
- **Phantom Gyp.** `binding.gyp` files can run commands when a native module is built, with no install script at all. HiveGuard flags commands that download code or run a script file, and leaves the standard `node-addon-api` forms alone.
- **PhantomRaven.** Dependencies downloaded from an arbitrary URL instead of a package registry are flagged. Private registries such as Artifactory are not flagged.
- pnpm, Yarn and npm workspaces are covered, including the pnpm store.

### Persistence

New **autostart scanner** for programs that start on login:

| OS | Locations |
|---|---|
| macOS | `~/Library/LaunchAgents` |
| Linux | `~/.config/autostart`, `~/.config/systemd/user`, cron tables (elevated scans) |
| Windows | the Startup folder; scheduled tasks (elevated scans, for example via Tanium) |

Every entry is listed in the report. An entry is flagged when it runs a script from a temporary, hidden or `node_modules` folder, uses download-and-run or encoded PowerShell, or matches a threat-intel indicator.

### Indicators of compromise

Threat-intel catalogs often publish more than package versions: payload file names, file hashes, persistence files and exfiltration hosts. HiveGuard 2.0 uses them:

- persistence files (for example the Nx Console backdoor `~/.local/share/kitty/cat.py`) are checked per user profile;
- payload file names are matched in every folder the scan walks;
- hashes and hosts are matched in the script files HiveGuard inspects.

No extra configuration is needed. New catalog indicators are picked up automatically.

### Git hooks and AI agent files

- Git hooks in every repository and in a global `core.hooksPath`, including hooks symlinked from elsewhere.
- AI instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules`, Copilot instructions, skills, …) are checked for prompt injection, hidden Unicode, exfiltration instructions and permission bypasses.
- Agent hooks (for example Claude Code `SessionStart` hooks in a cloned repository) and VS Code tasks that run when a folder opens are flagged, and **the script files they run are inspected**, including their direct imports. This is the "fake job interview" attack pattern.

### Extensions

- **OSV.dev** now covers VS Code-family extensions, so compromised releases such as Nx Console 18.95.0 are reported.
- **GlassWorm:** extension code hidden as long runs of invisible Unicode characters is detected.
- Extension packs and dependencies are listed, so you can see which extensions pull in others.

---

## Better coverage of what is installed

- **Lockfiles:** pnpm (all lockfile versions in use), Yarn classic and Berry, Bun's text lockfile, Poetry, uv and Pipenv. The binary `bun.lockb` is listed so you know it was not read.
- **Repositories anywhere in a profile**, including Downloads, OneDrive, Dropbox and Library, are checked for git hooks and AI files.
- **Pinned MCP server packages** are matched against threat intel like any other dependency.

---

## AI on this machine

A new report panel shows the AI tooling on the machine. Tools are found by how they are laid out on disk, so tools released after this version still show up, under their folder name:

| Signal | Details |
|---|---|
| MCP servers | Any agent's configuration, configured vs. available-but-unused vs. disabled. Servers that run an unpinned package (`npx -y something`) are flagged. |
| Editors | Any VS Code fork (Cursor, Windsurf, Kiro, Antigravity, …) |
| Agent skills and rules | `skills/`, `rules/`, `commands/`, `agents/`, `prompts/` folders in any tool's dot-folder |
| Local models | GGUF, safetensors, ONNX, PyTorch, … including Hugging Face, Ollama and LM Studio stores. Pickle-format models, which can run code when loaded, are marked. |
| API keys | Provider keys stored in plain text in `.env` files, shell profiles and MCP configs. Only the provider, file and variable name are reported. |
| SDKs | About 80 AI SDKs tagged in the dependency inventory |
| Apps | Common AI desktop apps that leave no other trace (list in `data/ai-apps.json`) |

---

## Output and integrations

| Option | Produces |
|---|---|
| `--format sarif` | SARIF 2.1.0 findings for code-scanning / vulnerability dashboards, with stable IDs to track a finding across scans |
| `--format cyclonedx` | A CycloneDX 1.5 SBOM of the machine, with package URLs and threat matches as vulnerabilities |
| `--format ndjson` | One JSON event per line (a summary plus one per finding) for Splunk, Sentinel, Elastic, … |
| `--ioc` / `--ioc-file` | An answer to "is this indicator here?" for each package, path, file name, hash or domain you give it |

Also:

- `threat_intel.sources` reports the status of each intel source (`ok`, `partial`, `failed`, `skipped`), so an unreachable source is never mistaken for a clean result.
- `HTTPS_PROXY` / `NO_PROXY` are supported.
- `tools/self-check.js` runs a scan and prints a summary that is safe to share (no paths, usernames or package names).

---

## Accuracy and reliability fixes

- The bundled AntV / Mini Shai-Hulud catalog listed 287 packages as `@@antv/...`, so they could never match. Fixed in the data, and HiveGuard now normalises this mistake in any catalog.
- HTML report: closed a cross-site scripting hole via crafted package names; only `http(s)` links are clickable.
- `--json` output piped to a file is no longer cut off at 64 KB.
- A special file such as a FIFO can no longer hang the scan, and large files are read with size caps.
- Version handling: pre-release versions, `v`-prefixed Go versions and scoped global npm packages are handled correctly; several CVE rules had wrong version boundaries.
- The bootstrap scripts keep `--json` output on standard output clean and return exit code 3 on bootstrap failures.

---

## Changed behaviour

| Change | Why | If you need the old behaviour |
|---|---|---|
| Runs at **below-normal CPU priority** | Stays out of the user's way | `--normal-priority` |
| Files in **cloud-sync folders are listed, not read** | Reading an online-only file downloads it | none (by design) |
| **More findings** can raise the exit code to `1` (critical or high findings from the new checks) | New detections | Filter on `findings[].type` if you only want the old types |
| **Exit code `2`** also means an `--ioc` indicator was found | Incident response | Only applies when `--ioc` is used |
| OSV.dev is queried in online mode (package names and versions only) | Malicious-package advisories | `--offline` |

---

## Upgrading from 1.x

The upgrade is a drop-in replacement. There is no configuration to migrate.

1. **Replace the HiveGuard folder** (or ZIP package) with 2.0. Keep your deployment command as it is.
2. **Custom catalogs keep working** unchanged, from `--custom-intel` or `~/.hiveguard/custom-catalogs/`. For extensions use the ecosystem `editor-extension` (see [Threat intelligence](THREAT-INTEL.md#catalog-format)).
3. **Review alerting thresholds.** 2.0 finds more, so expect more exit-code-`1` results on developer machines at first. Read the [Results guide](RESULTS-GUIDE.md) for what each new finding means.
4. **Update parsers if you read the JSON.** All 1.x fields are still there with the same meaning. New data is additive:
   - new finding `type` values: `suspicious_lifecycle_script`, `remote_url_dependency`, `suspicious_git_hook`, `suspicious_ai_instruction`, `suspicious_autostart`, `suspicious_extension`, `known_ioc_file`, `mcp_server_risk`, `ioc_match`;
   - new `ecosystems` sections: `lifecycle_scripts`, `git_hooks`, `ai_instructions`, `ai_models`, `ai_usage`, `ai_apps`, `persistence`, `lockfiles`;
   - new `summary.ecosystems` counters, `threat_intel.sources`, `ioc_search` (with `--ioc`), and `location` on supply-chain findings.
5. **Optional:** add `--format ndjson` or `--format sarif` to feed your SIEM or dashboard directly.
6. **Optional:** set `GITHUB_TOKEN` on endpoints that should also query the GitHub Advisory Database.

---

## Known limitations

- Pickle-format AI models are marked but their contents are not inspected.
- Hashes and text indicators are compared against the script files HiveGuard inspects, not every file on disk.
- The binary `bun.lockb` (Bun before 1.2) is not parsed.
- Windows scheduled tasks and cron tables are only readable when HiveGuard runs elevated.
- Browser extensions are inventoried, but there is no public malicious-extension feed to match them against yet. You can list known-bad extensions (by name and version, ecosystem `browser-extension`) in a custom catalog.
