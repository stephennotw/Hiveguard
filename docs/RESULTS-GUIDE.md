# HiveGuard results guide

What a HiveGuard result tells you, what each finding means, and what to do about it.

1. [Triage in five minutes](#triage-in-five-minutes)
2. [Exit codes](#exit-codes)
3. [Severity](#severity)
4. [Finding types](#finding-types)
5. [Trigger glossary](#trigger-glossary)
6. [What the JSON contains](#what-the-json-contains)
7. [Examples](#examples)

---

## Triage in five minutes

Check these in order (HTML report: **Overview** and **Findings**; JSON: the fields named):

| # | Check | Where | If it is set |
|---|---|---|---|
| 1 | Known-compromised package? | `summary.threat_matches > 0` | **Incident.** See [`supply_chain_compromise`](#supply_chain_compromise) |
| 2 | Searched indicator found? | `ioc_search[].found` | **Incident.** See [`ioc_match`](#ioc_match) |
| 3 | Any critical finding? | `summary.findings_critical` | Investigate today: malware behaviour, persistence or a catalog indicator |
| 4 | Any high finding? | `summary.findings_high` | Review this week |
| 5 | Was threat intel current? | `threat_intel.source`, `threat_intel.sources` | `baseline` or a `failed` source means matches may be incomplete; rerun online |
| 6 | Were the right users scanned? | `meta.users_scanned` | Too few: rerun as Administrator / root |
| 7 | Is the inventory plausible? | `summary.total_components` | Near 0 on a developer machine: profiles were not readable |

Every finding names the **file or project** it came from (`path`, `location` or `project`) and the **user** (`user`) it belongs to.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No threat match and no critical or high finding |
| `1` | At least one critical or high finding, but no known-compromised package |
| `2` | A known-compromised package is installed, or an `--ioc` indicator was found |
| `3` | HiveGuard could not run |

---

## Severity

| Severity | Meaning | Typical response |
|---|---|---|
| **critical** | Confirmed or near-certain compromise: a known-bad package, a catalog indicator, malware behaviour (download-and-run, reverse shell, encoded PowerShell), hidden extension code | Isolate if needed, investigate today |
| **high** | Strongly suspicious or seriously exposed: obfuscated install script, script launched from a hidden folder at login, exploitable CVE, plain-text credentials | Review this week |
| **medium** | Worth checking: an agent hook that came with a cloned repo, an unpinned MCP server, a moderate CVE, a `.env` file with secrets | Plan a fix |
| **low** | Hygiene: old SSH keys, outdated CA bundle | When convenient |
| **info** | For awareness only | none |

Findings are sorted from critical to info.

---

## Finding types

Each finding has a `type`. All findings share these fields:

| Field | Meaning |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `type` | One of the types below |
| `text` | One-line explanation |
| `user` | The user profile it belongs to |
| `ecosystem` | `npm`, `pypi`, `go`, `editor-extension`, `git`, `ai-tools`, `persistence`, `secrets`, … |
| `package`, `version` | The package, hook, tool or file name concerned |
| `path` / `location` / `project` | Where it was found |
| `triggers` | The specific signals that fired (see the [glossary](#trigger-glossary)) |

### `supply_chain_compromise`

**Severity:** critical. **Exit code:** 2.

An installed package version is listed as compromised or malicious by a threat-intel source (a Bumblebee or custom catalog, OSV.dev or the GitHub Advisory Database). Matching is exact on ecosystem, name and version, never on similar names.

Extra fields: `catalog` (the catalog file, `osv.dev` or `github-advisory-db`), `attackType`, `campaignName`, `source` (the advisory), `indicators` (the campaign's published IOCs), `location` (the lockfile).

**What to do:**

1. Treat the machine as compromised. Isolate it if your process says so.
2. Remove the package and reinstall dependencies from a clean lockfile.
3. Rotate every credential the user had on the machine: npm, GitHub, cloud, SSH.
4. Check the campaign `indicators` (persistence files, hosts) on this and other machines with `--ioc`.

### `ioc_match`

**Severity:** critical. **Exit code:** 2.

A package you passed to `--ioc` is installed. `location` says where. (File, hash and text indicators appear as `known_ioc_file`, or as `known-…` triggers on other findings, and in `ioc_search`.)

**What to do:** follow your incident process for that indicator.

### `known_ioc_file`

**Severity:** critical.

A file named by a threat-intel catalog or by `--ioc` exists: a known persistence file (for example `~/.local/share/kitty/cat.py` from the Nx Console compromise) or a known payload file name (`setup_bun.js`, `trap-core.js`, …) seen while scanning. `ioc` says which indicator matched.

**What to do:** treat as a compromise. Preserve the file for analysis before removing it.

### `suspicious_lifecycle_script`

**Severity:** critical, high or medium, depending on the triggers.

Code that npm runs automatically when a package is installed looks malicious:

- a `preinstall`, `install`, `postinstall` (or similar) script (`hook` names which one; `script` shows it);
- a file that script runs (`script_files`), for example `node setup_bun.js`;
- a `binding.gyp` command (`hook` is `binding.gyp`) that downloads code or runs a script file when the native module is built (Phantom Gyp).

`path` is the package folder. `project` is the project it is installed in, or `(global)`.

**What to do:** look at the script. If it is not legitimate, remove the package, check whether it ran (it runs on every `npm install`), and rotate credentials. Legitimate packages rarely trigger critical; `medium` alone (for example a plain `spawn` call) is often benign.

### `remote_url_dependency`

**Severity:** high when the URL is plain `http://` or an IP address, otherwise medium.

A package depends on something downloaded straight from a web server instead of a package registry (`dependency` and `url`), or was installed from such a URL (`dependency` is `resolved`). Registries never see or scan that code. This is the PhantomRaven technique. Tarballs from private registries such as Artifactory, and GitHub/GitLab sources, are not flagged.

**What to do:** check whether the URL is one your organisation uses. If not, treat the package as malicious.

### `suspicious_git_hook`

**Severity:** critical, high or medium.

A git hook (a script git runs on commit, checkout, merge, push, …) looks malicious. `repo` is the repository or `(global …)` for a global `core.hooksPath`; `origin` says where the hook is configured. Hooks in cloned repositories are not run by git unless someone installs them, but a global hooks path runs in every repository.

Custom hooks that look harmless are listed in `ecosystems.git_hooks` with severity `info` (for example Git LFS `pre-push` hooks) and are not counted as findings.

**What to do:** read the hook. Remove it if unexpected, and check `git config --global core.hooksPath`.

### `suspicious_ai_instruction`

**Severity:** high or medium (critical for embedded reverse shells / encoded PowerShell).

An instruction or configuration file read by an AI coding assistant (`tool`: Claude Code, Cursor, Copilot, Codex, Gemini, …) contains something an attacker would put there:

- prompt injection or a jailbreak persona;
- instructions to send secrets somewhere, or to hide actions from the user;
- hidden Unicode (invisible text the AI reads but people do not see);
- agent hooks or VS Code tasks that run automatically when a project is opened, and the script files those run (`script_files`);
- settings that turn off the agent's permission prompts.

A permission-bypass flag such as `--dangerously-skip-permissions` mentioned in the user's **own** files (home folder: `~/.claude`, `~/.codex`, skills, …) is `medium`, because it is usually their notes on running an agent headless; in a repository's files it stays `high`.

**What to do:** open the file (`path`) and read it, including what the hook or task runs. Files that came with a cloned repository deserve the most suspicion. Do not open such a project in an AI agent until it is clean.

### `suspicious_autostart`

**Severity:** critical or high.

A program set to start automatically (`autostart_kind`: `launch-agent`, `xdg-autostart`, `systemd-user`, `startup-folder`, `scheduled-task`, `crontab`) looks malicious: it runs a script from a temporary, hidden or `node_modules` folder, downloads and runs code, uses encoded or hidden PowerShell, or matches an indicator. `command` shows what it runs; `script_files` lists the scripts it starts.

All autostart entries, flagged or not, are listed in `ecosystems.persistence.entries` and in the report.

**What to do:** identify the program. If unknown, disable the entry, preserve the script and investigate how it got there.

### `suspicious_extension`

**Severity:** critical (high for shorter runs).

An editor extension hides code as a long run of invisible Unicode characters in its main file. This is the GlassWorm technique; normal extensions never do this. `editor` names the editor (`vscode`, `cursor`, or the folder name of a fork).

**What to do:** uninstall the extension in every editor, then rotate the credentials the user had access to.

### `mcp_server_risk`

**Severity:** medium.

An MCP server configured for an AI agent (`server`, `app`) is started with `npx`, `uvx` or similar **without a pinned version**. Every start may download whatever was published last, so a compromised release would run immediately.

**What to do:** pin the version in the config, for example `npx -y some-server@1.4.2`.

### `known_cve`

**Severity:** high, medium or low.

A package version is affected by a well-known vulnerability (`cve`). HiveGuard has built-in rules for about 20 widely used packages; this is not a full vulnerability scanner.

**What to do:** upgrade to the version named in `text`.

### Secrets hygiene

**Severity:** high, medium, low or info. **ecosystem:** `secrets`; `type` is the specific check:

| `type` | Severity | Meaning |
|---|---|---|
| `git_plaintext_credentials` | high | Git stores passwords in plain text (`credential.helper = store`) |
| `git_hardcoded_token` | high | A git remote URL contains a token |
| `git_credentials_file` | medium | A `~/.git-credentials` file exists |
| `env_secrets_detected` | medium | A `.env` file contains secret-looking keys (only key names are reported) |
| `ssh_weak_key` | high | DSA SSH key |
| `ssh_rsa_key` | low | RSA key; Ed25519 is recommended |
| `ssh_old_key` | low | SSH key older than a year |
| `ssh_authorized_keys` | info | `authorized_keys` exists; review its entries |

Values are never read or reported.

---

## Trigger glossary

`triggers` explain *why* a finding fired. The same name means the same thing everywhere.

**Indicators**

| Trigger | Meaning |
|---|---|
| `known-worm-filename` | The file has the name of a known payload (catalog or `--ioc`) |
| `known-malicious-hash` | The file's SHA-256 is a known-bad hash |
| `known-ioc-string` | The file contains a catalog marker or exfiltration host |
| `known-persistence-file`, `known-payload-filename` | A file named by an indicator exists |
| `cli-ioc-package` | A package given with `--ioc` is installed |

**Running code**

| Trigger | Meaning |
|---|---|
| `pipe-to-shell` | Downloads something and pipes it into a shell (`curl … \| sh`) |
| `download-and-run` | PowerShell downloads and executes code (`iex (iwr …)`) |
| `powershell-encoded`, `hidden-powershell` | PowerShell with encoded commands, or hidden-window inline code |
| `reverse-shell`, `netcat-exec`, `bash-tcp` | Opens a shell to a remote machine |
| `mshta-remote` | `mshta` loading a remote page |
| `eval-call`, `eval`, `eval-decoded-payload`, `node-eval`, `python-inline` | Runs code built from a string |
| `exec-call`, `execSync-call`, `spawn-call`, `child_process-import` | Starts other programs |
| `script-in-hidden-or-temp-dir` | An autostart entry runs a script stored in a temp, hidden or `node_modules` folder |
| `gyp-runs-script`, `gyp-runs-package-entry` | `binding.gyp` runs a script file (the package's own entry file is the Phantom Gyp pattern) |
| `gyp-network-or-eval`, `gyp-url` | `binding.gyp` fetches from the network or evaluates code |
| `user-creation`, `permission-change` | Creates accounts or makes files executable |

**Hiding**

| Trigger | Meaning |
|---|---|
| `base64-decode`, `hex-encoded-strings` | Decodes encoded data |
| `hidden-unicode` | Invisible characters in an AI instruction file |
| `invisible-unicode-payload` | Long run of invisible characters in extension code (GlassWorm) |
| `oversized-install-script` | An install-time script over 1 MB, typical of bundled payloads |
| `concealment-from-user` | Tells the AI to hide something from the user |

**Data theft**

| Trigger | Meaning |
|---|---|
| `credential-file-access`, `credential-access`, `credential-file-ref` | Touches `.ssh`, `.aws`, `.npmrc`, `.netrc`, … |
| `token-env-harvest` | Reads `NPM_TOKEN`, `GITHUB_TOKEN`, AWS keys from the environment |
| `secret-scanner-download` | Downloads a secret-scanning tool such as TruffleHog (used by worms to find credentials) |
| `exfil-instruction`, `exfil-keyword` | Instructions or code to send data out |
| `home-dir-access` | Reads the home directory location |

**Network**

| Trigger | Meaning |
|---|---|
| `ip-address-url`, `public-ip-url` | Contacts a raw IP address |
| `url-dependency`, `plaintext-http` | Dependency downloaded from a web server, possibly unencrypted |

**AI agents**

| Trigger | Meaning |
|---|---|
| `prompt-injection`, `jailbreak-persona` | Tries to override the AI's instructions |
| `project-agent-hooks` | A repository's own settings define agent hooks (they run when the agent starts in that folder) |
| `autorun-on-folder-open` | A VS Code task runs as soon as the folder is opened |
| `permission-bypass-mode`, `ai-cli-permission-bypass` | Turns off the agent's permission prompts |
| `symlink-outside-project`, `symlink-outside-repo` | The file is a link to somewhere outside the project |
| `mcp-unpinned-package` | MCP server runs an unpinned package |

---

## What the JSON contains

```text
{
  "meta":           scan details: version, time, host, OS, users scanned
  "threat_intel":   intel sources used, their status, number of matches
  "summary":        counts for quick triage
  "findings":       every finding, most severe first
  "ecosystems":     full detail from each scanner
  "packages":       flat list of every inventoried component
  "threat_matches": packages matched by threat intel, with the matching threats
  "ioc_search":     (with --ioc) each indicator: found or not, and where
  "catalogs":       the threat-intel catalogs loaded
}
```

### `summary`

| Field | Meaning |
|---|---|
| `total_components` | Packages, extensions and MCP packages inventoried |
| `threat_matches` | Packages matched by threat intel. **Above 0 means incident.** |
| `findings_critical` … `findings_low`, `findings_total` | Finding counts by severity |
| `ecosystems` | Counters per area: `npm_projects`, `pypi_packages`, `extra_lockfiles`, `editor_extensions`, `mcp_servers`, `lifecycle_scripts_findings`, `git_hooks_suspicious`, `ai_instruction_suspicious`, `ai_models`, `ai_provider_credentials`, `autostart_entries`, `threat_intel_iocs`, … |

### `threat_intel`

| Field | Meaning |
|---|---|
| `source` | `live` (fetched from GitHub), `baseline` (bundled copy), `custom`, or `live+custom` |
| `sources` | Status per source: `bumblebee`, `osv`, `ghsa`, each `ok`, `partial`, `failed` or `skipped`, with the error if any |
| `catalogs_loaded`, `total_known_bad_versions` | Size of the loaded catalogs |
| `matches`, `osv_matches`, `ghsa_matches` | Matches overall and per online source |

A `failed` or `partial` source means matches from it may be missing; it does **not** mean the machine is clean.

### `ecosystems`

| Section | Contains |
|---|---|
| `npm`, `npm_global`, `pypi`, `go`, `composer`, `rubygems`, `cargo` | Projects and their dependencies. Projects read from pnpm, Yarn or Bun lockfiles have `lockfile_type` |
| `lockfiles` | Which extra lockfiles were parsed, and which were not (`unparsed`, e.g. binary `bun.lockb`) |
| `editor_extensions`, `browser_extensions` | Installed extensions per editor / browser |
| `mcp_configs` | MCP config files and servers; `state` is `configured` or `available` (a tool's catalog) |
| `lifecycle_scripts` | Install-script findings, packages checked and timing |
| `git_hooks` | Every custom hook, including harmless ones (`info`) |
| `ai_instructions` | Every AI instruction/config file found (`inventory`) and findings |
| `ai_models`, `ai_usage`, `ai_apps` | Local models, plain-text provider keys and AI SDKs, known AI apps |
| `persistence` | Every autostart entry (`entries`) and persistence findings |
| `secrets_hygiene` | `.env`, git credential and SSH findings |

### `packages`

One row per component **per location**, so the same `name@version` appears once for each project it is in. This is intentional: during an incident you need every location.

| Field | Meaning |
|---|---|
| `ecosystem` | `npm`, `pypi`, `go`, `composer`, `rubygems`, `cargo`, `editor-extension`, `browser-extension`, … |
| `name`, `version` | The component |
| `user`, `project`, `source` | Who and where |
| `confidence` | `high` from lockfiles and installed metadata, `medium` from manifests and requirement files |

---

## Examples

### Clean (exit code 0)

```json
{ "summary": { "total_components": 2437, "threat_matches": 0, "findings_critical": 0, "findings_high": 0, "findings_medium": 4, "findings_total": 6 } }
```

Nothing urgent. The medium findings (for example unpinned MCP servers, `.env` files with secrets) can be fixed when convenient.

### Malicious install script (exit code 1)

```json
{
  "severity": "critical",
  "type": "suspicious_lifecycle_script",
  "package": "@beproduct/nestjs-auth",
  "project": "api",
  "hook": "preinstall",
  "script": "node setup_bun.js",
  "script_files": ["setup_bun.js"],
  "triggers": ["known-worm-filename", "known-ioc-string"],
  "path": "/Users/lee/projects/api/node_modules/@beproduct/nestjs-auth"
}
```

The package runs a Shai-Hulud payload file on install, and the file contains a known exfiltration host. Remove the package, assume the worm ran on the last `npm install`, and rotate the user's npm and GitHub tokens.

### Persistence (exit code 1)

```json
{
  "severity": "high",
  "type": "suspicious_autostart",
  "autostart_kind": "launch-agent",
  "name": "com.user.kitty-monitor.plist",
  "command": "/usr/bin/python3 ~/.local/share/kitty/cat.py",
  "triggers": ["script-in-hidden-or-temp-dir"]
}
```

plus

```json
{ "severity": "critical", "type": "known_ioc_file", "path": "/Users/kim/.local/share/kitty/cat.py", "ioc": "nx-console-vscode-2026-05-18.json: persistence_files" }
```

A LaunchAgent starts a Python script from a hidden folder at every login, and that script is the published Nx Console backdoor. Unload and preserve both files, then handle as a compromise.

### Known-compromised package (exit code 2)

```json
{
  "severity": "critical",
  "type": "supply_chain_compromise",
  "ecosystem": "npm",
  "package": "@antv/a8",
  "version": "0.1.1",
  "catalog": "antv-mini-shai-hulud.json",
  "location": "/Users/lee/projects/charts/yarn.lock",
  "text": "@antv/a8@0.1.1 — SUPPLY CHAIN COMPROMISE: ..."
}
```

A version published by the Mini Shai-Hulud worm is in a Yarn project. Follow the [`supply_chain_compromise`](#supply_chain_compromise) steps, and search the fleet for the campaign's indicators with `--ioc`.
