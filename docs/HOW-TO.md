# HiveGuard how-to guides

Short, step-by-step instructions for common tasks. The examples use `run.bat` (Windows Command Prompt); use `.\run.ps1` in PowerShell, `./run.sh` on macOS/Linux, or `node bin/hiveguard.js` when Node.js 18+ is installed. The options are the same everywhere.

- [Run a scan](#run-a-scan)
- [Read the report](#read-the-report)
- [Scan without network access](#scan-without-network-access)
- [Use a proxy or a GitHub token](#use-a-proxy-or-a-github-token)
- [Hunt for indicators of compromise](#hunt-for-indicators-of-compromise)
- [Send results to a SIEM](#send-results-to-a-siem)
- [Produce an SBOM](#produce-an-sbom)
- [Load findings into a security dashboard](#load-findings-into-a-security-dashboard)
- [Add your own threat intelligence](#add-your-own-threat-intelligence)
- [Scan only some folders](#scan-only-some-folders)
- [Scan a mounted disk image](#scan-a-mounted-disk-image)
- [Run the self-check](#run-the-self-check)
- [Add or correct an AI app](#add-or-correct-an-ai-app)
- [Troubleshooting](#troubleshooting)

---

## Run a scan

1. Open a terminal in the HiveGuard folder.
2. Run:

   | Platform | Command |
   |---|---|
   | Windows, Command Prompt | `run.bat` |
   | Windows, PowerShell | `.\run.ps1` |
   | macOS / Linux | `./run.sh` |

3. Wait for the summary. It ends with something like:

   ```
   ✅ Scan complete in 24.3s
      📦 2437 components inventoried
      🛡️  8 threat catalogs (2291 known-bad versions)
      ✅ 0 threat matches
      ⚠️  12 findings (0 critical, 2 high)
      📁 Results: ./hiveguard-results
   ```

4. Open `hiveguard-results/hiveguard-report-<hostname>.html` in a browser.

**Which users are scanned?** Run normally, HiveGuard scans the profiles it can read. Run as Administrator / root (or from Tanium, Jamf, Intune as SYSTEM) to scan every user profile and to include Windows scheduled tasks and cron tables.

**Where do results go?** `./hiveguard-results/` by default. Change it with `--output <folder>`.

---

## Read the report

The HTML report is a single file. It works offline and needs no server.

| Panel | Use it to |
|---|---|
| **Overview** | See the verdict, threat-intel status and counts at a glance |
| **All Packages** | Search every component by name, version, user or project; export to CSV |
| **Threat Intel** | See which known-compromised packages were found and which campaign they belong to |
| **Findings** | Work through every finding, most severe first |
| **npm / Python / Go** | Browse dependencies per project |
| **Extensions** | Editor and browser extensions, with hidden-code warnings and extension packs |
| **MCP** | MCP servers per AI tool, configured vs. available |
| **AI on this machine** | AI tools, models, API keys in plain text, SDKs |
| **Scripts, Hooks, AI Files & Autostart** | Install scripts, `binding.gyp`, git hooks, AI agent files and programs that start on login |

Start with **Overview**, then **Findings**. The [Results guide](RESULTS-GUIDE.md) explains every finding and what to do.

---

## Scan without network access

```cmd
run.bat --offline
```

HiveGuard then uses only the threat intel bundled in `data/baseline-catalogs/` plus any custom catalogs, and makes no network requests. The report shows the threat-intel source as **baseline**.

If Node.js 18+ is not installed, the launcher still needs to download it once from `nodejs.org`. On machines without internet access, install Node.js 18+ first, or copy a HiveGuard folder that already contains the downloaded `.node` folder for the same OS.

---

## Use a proxy or a GitHub token

HiveGuard honours the standard proxy variables:

```cmd
set HTTPS_PROXY=http://proxy.example.com:8080
set NO_PROXY=localhost,.internal.example.com
run.bat
```

To also check the GitHub Advisory Database, set a token (no scopes are needed):

```cmd
set GITHUB_TOKEN=ghp_...
run.bat
```

Without a token that source is skipped; OSV.dev already covers most of the same advisories.

---

## Hunt for indicators of compromise

Use `--ioc` during an incident to answer "is this on the machine?".

**1. Give the indicators**

```cmd
run.bat --ioc "@antv/a8@0.1.1,t.m-kosche.com,~/.local/share/kitty/cat.py"
```

You can repeat `--ioc`, or put one indicator per line in a file:

```text
# incident 2026-0042
@antv/a8@0.1.1
pypi:requests@2.31.0
vscode:nrwl.angular-console@18.95.0
setup_bun.js
~/.local/share/kitty/cat.py
%APPDATA%\Evil\run.js
t.m-kosche.com
239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420
```

```cmd
run.bat --ioc-file incident-0042.txt
```

**2. Which forms are understood**

| Write it as | Treated as | Looked for in |
|---|---|---|
| `name@version`, `@scope/name@version`, `@scope/name` | npm package (any version if none given) | every inventoried component |
| `pypi:name@version`, `go:`, `cargo:`, `composer:`, `gem:`, `vscode:` | package in that ecosystem | every inventoried component |
| `~/path`, `/path`, `C:\path`, `%APPDATA%\path` (a `*` is allowed in the last part) | file path | on disk, for every user profile when it starts with `~/` or `%VAR%` |
| `name.ext` (no slashes) | file name | every folder the scan walks, script files, autostart entries |
| 64 hex characters | SHA-256 | script files HiveGuard inspects |
| anything else (domain, URL, text) | text | script files HiveGuard inspects |

A plain word such as `lodash` is treated as text. Write `npm:lodash` to mean the package.

**3. Read the answer**

The console lists each indicator:

```
🔎 Indicators: 2 of 3 found
   FOUND      @antv/a8@0.1.1 (package)
              @antv/a8@0.1.1 in /Users/lee/projects/charts/yarn.lock
   FOUND      ~/.local/share/kitty/cat.py (path)
              /Users/kim/.local/share/kitty/cat.py
   not found  t.m-kosche.com (string)
```

The same answer is in the JSON under `ioc_search`, and in the report at the top of **Findings**. Any hit makes the exit code `2`, so a fleet tool can alert on it directly.

> "Not found" for a hash or text indicator means it was not in the files HiveGuard inspects (install scripts, `binding.gyp` targets, AI hook scripts, autostart entries). It does not search every file on disk.

---

## Send results to a SIEM

```cmd
run.bat --format ndjson
```

This writes `hiveguard-<hostname>-<timestamp>.ndjson` next to the JSON. Each line is one event:

- one `hiveguard_scan_summary` event with all counters;
- one `hiveguard_finding` event per finding.

Every event carries `host`, `scan_time`, `hiveguard_version` and `platform`, and finding events add `severity`, `type`, `package`, `version`, `location`, `user`, `triggers` and `text`. Point your forwarder (Splunk Universal Forwarder, Azure Monitor Agent, Elastic Agent, …) at the output folder and parse the file as JSON lines.

Useful searches:

- `event=hiveguard_finding severity=critical` for incidents;
- `type=supply_chain_compromise OR type=ioc_match` for known-compromised packages;
- `type=suspicious_autostart` for persistence.

---

## Produce an SBOM

```cmd
run.bat --format cyclonedx
```

This writes `hiveguard-<hostname>-<timestamp>.cdx.json`, a CycloneDX 1.5 SBOM of the machine:

- one component per package and version, with a package URL (`pkg:npm/…`, `pkg:pypi/…`, …) where one exists;
- where each component was found, as `hiveguard:location` properties;
- threat-intel matches and CVEs as `vulnerabilities`, linked to the affected components.

Import it into Dependency-Track or any other CycloneDX tool.

---

## Load findings into a security dashboard

```cmd
run.bat --format sarif
```

This writes `hiveguard-<hostname>-<timestamp>.sarif` (SARIF 2.1.0). Each finding becomes a result with:

- a rule per finding type;
- `error` / `warning` / `note` levels and a numeric `security-severity`;
- the file it concerns;
- a stable fingerprint, so the same finding is recognised across scans.

DefectDojo, and other tools that accept SARIF, can import it.

You can combine formats: `--format sarif,ndjson`, or `--format all`.

---

## Add your own threat intelligence

1. Create a JSON file listing the bad packages:

   ```json
   {
     "_comment": "Internal SOC findings, 2026-11",
     "_indicators": {
       "payload_filename": "update-helper.js",
       "c2_host": "bad.example.com"
     },
     "entries": [
       { "name": "Backdoored internal-utils", "ecosystem": "npm", "package": "internal-utils", "versions": ["1.0.0", "1.0.1"] }
     ]
   }
   ```

2. Put it in a folder and pass the folder:

   ```cmd
   run.bat --custom-intel C:\hiveguard-intel
   ```

   Or place it in `~/.hiveguard/custom-catalogs/` on the machine to load it on every scan.

See [Threat intelligence](THREAT-INTEL.md) for the full format and how indicators are used.

---

## Scan only some folders

```cmd
run.bat --scan-dirs C:\src,D:\projects
```

Only these folders are searched for projects. User-level locations (extensions, AI tools, autostart) are still checked. Use `--max-depth <n>` to change how deep HiveGuard looks for projects (default 4).

---

## Scan a mounted disk image

To scan a copy of another machine's disk (for example a forensic image mounted read-only):

```bash
./run.sh --users-root /mnt/image/Users --offline --output ./image-results
```

HiveGuard treats every folder under `/mnt/image/Users` as a user profile and skips the system-wide locations of the machine it is running on (global npm, scheduled tasks, cron), so the result describes only the image.

---

## Run the self-check

The self-check runs a normal scan and prints a summary you can share: counts, timings and finding categories, but no file paths, usernames, hostnames or package names.

```bash
node tools/self-check.js            # offline, nothing leaves the machine
node tools/self-check.js --online   # also query the online threat-intel sources
```

The summary is printed and saved as `selfcheck-summary.txt`. The full report, which does contain paths, stays in a temporary folder whose location is printed at the end; it is for your eyes only.

It needs Node.js 18+ on the path (the self-check does not use the launcher).

---

## Add or correct an AI app

Most AI tools are found automatically by their folder structure. A few desktop apps leave no such trace, so they are listed in `data/ai-apps.json`:

```json
{
  "id": "chatgpt",
  "name": "ChatGPT (desktop)",
  "vendor": "OpenAI",
  "kind": "desktop-app",
  "windows": ["%LOCALAPPDATA%/Packages/OpenAI.ChatGPT-Desktop_*", "%LOCALAPPDATA%/Programs/ChatGPT"],
  "darwin": ["/Applications/ChatGPT.app", "~/Library/Application Support/com.openai.chat"]
}
```

Add an entry with the paths where the app installs on each OS (`windows`, `darwin`, `linux`). `~/`, `%APPDATA%/` and `%LOCALAPPDATA%/` are expanded for each user, and `*` matches any characters in the last part of a path. The list is only used to report that an app is installed.

---

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| PowerShell says *running scripts is disabled* | Use `run.bat`, or run `powershell -ExecutionPolicy Bypass -File run.ps1` |
| macOS / Linux: *permission denied* on `run.sh` | Run `chmod +x run.sh` (ZIPs made on Windows drop the execute bit) |
| *Could not download Node.js* | The machine cannot reach `nodejs.org`. Install Node.js 18+ yourself, or allow that site through the proxy |
| Report says threat intel **baseline** although you are online | GitHub could not be reached. Check proxy settings (`HTTPS_PROXY`); the console shows the error. The bundled catalogs were used instead |
| A threat-intel source shows **failed** or **partial** | That source could not be fully queried, so matches may be incomplete. The console and `threat_intel.sources` show why. Rerun when the network is available |
| Very few components on a developer machine | HiveGuard could not read the user profiles. Run as Administrator / root, or check `meta.users_scanned` |
| Scan is slow | Run with `--verbose` to see per-scanner timings. Large `node_modules` trees (especially pnpm stores) take the longest on Windows because of antivirus file scanning |
| `--json` output looks mixed with log lines | Logs go to standard error and the JSON to standard output. Redirect only standard output: `run.bat --json > result.json` |
| Exit code `3` | HiveGuard or the launcher could not run. The last console lines say why (for example the output folder could not be created) |
