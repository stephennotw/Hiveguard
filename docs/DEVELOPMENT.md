# Developing HiveGuard

How the code is organised, the rules it follows, and how to test and release changes.

- [Design rules](#design-rules)
- [How a scan runs](#how-a-scan-runs)
- [Code layout](#code-layout)
- [Testing](#testing)
- [CI](#ci)
- [Adding a check](#adding-a-check)
- [Releasing](#releasing)

---

## Design rules

These are requirements, not preferences. A change that breaks one needs a very good reason.

1. **Zero dependencies.** Only Node.js 18+ built-ins. No `npm install`, ever.
2. **Read-only.** Never run anything found on the machine (package managers, scripts, hooks). Write only to the output folder.
3. **Non-disruptive.** Below-normal CPU priority by default; cap the size of every read; prefer listing directories the walk has already listed over new file system calls. Windows endpoints run antivirus on every file open, so each read costs real time.
4. **Files only.** No Windows registry reads, no system APIs beyond the file system and the threat-intel HTTPS calls.
5. **Cloud-sync folders are names-only.** Never open a file under OneDrive, Dropbox, Google Drive or iCloud; it would download.
6. **Detect by structure, not by product name.** New AI tools, editors and agents must show up without a code change. Product lists (like `data/ai-apps.json`) are a last resort.
7. **Output is backward compatible.** Add fields and finding types; never rename or remove them.
8. **No false comfort.** If a source fails, say so (`threat_intel.sources`); never present an incomplete result as clean.
9. **Attacker-controlled text is data.** Excerpts in output are stripped of invisible/control characters; the HTML report escapes everything.

---

## How a scan runs

All in `bin/hiveguard.js`:

1. Parse options; lower CPU priority.
2. Detect the platform and user profiles (`src/platform/`).
3. Load threat intel: live Bumblebee catalogs or the bundled baseline, plus custom catalogs (`src/threat-intel/sync.js`). Build the match index (`matcher.js`) and extract file-level indicators (`iocs.js`, plus `--ioc` values from `cli-iocs.js`).
4. **One directory walk** over the project roots (`fs-safe.js` `findMultipleFiles`). It collects lockfiles and, through `onDir` callbacks, project folders, model files, `.env` files and indicator file names, so later scanners do not walk again.
5. Run the scanners (`src/scanners/`), each timed in the console with `--verbose`.
6. Attribute every result to a user profile.
7. Build the flat package list and match it: catalogs, then OSV.dev and the GitHub Advisory Database (`osv.js`, `ghsa.js`), then the CVE rules (`src/cve/`).
8. Collect findings from every scanner, answer `--ioc`, sort by severity.
9. Write the JSON, the HTML report (`src/report/html-report.js`) and any `--format` exports (`src/report/exports.js`).
10. Exit with 0, 1, 2 or 3.

---

## Code layout

```text
bin/hiveguard.js              CLI, orchestration, findings aggregation, exit code
src/
  platform/                   per-OS paths (windows.js, darwin.js, linux.js) and user enumeration
  scanners/
    npm.js pypi.js go.js composer.js rubygems.js cargo.js   ecosystem inventories
    lockfiles.js              pnpm, Yarn, Bun, Poetry, uv, Pipenv lockfile parsers
    editor-extensions.js      VS Code-family extensions, GlassWorm check
    browser-extensions.js     Chrome / Edge / Brave
    mcp-configs.js            MCP servers by structure, package-runner parsing
    lifecycle-scripts.js      npm install hooks, binding.gyp, URL dependencies
    git-hooks.js              repository and global hooks
    ai-instructions.js        AI instruction/config files, agent hooks, auto-run tasks
    ai-models.js ai-usage.js ai-apps.js   local models, API keys and SDKs, known AI apps
    persistence.js            autostart entries, catalog persistence files
    secrets-hygiene.js        .env, git credentials, SSH keys
  threat-intel/
    sync.js                   catalog loading (live, baseline, custom)
    matcher.js                exact ecosystem/name/version index
    osv.js ghsa.js http.js    online sources and the proxy-aware HTTPS client
    iocs.js cli-iocs.js       indicators from catalogs and from --ioc
  cve/known-vulns.js          static CVE rules
  report/                     HTML report and SARIF / CycloneDX / NDJSON exports
  utils/
    fs-safe.js                bounded reads, the shared walk, cloud-folder detection
    script-inspect.js         shared command / script-file inspection and IOC matching
    ai-roots.js               where AI tools keep state (dot-folders, app config roots)
    text.js jsonc.js logger.js output.js
data/
  baseline-catalogs/          bundled threat intel
  ai-apps.json                AI apps with no structural footprint
tools/self-check.js           shareable summary of a real scan
test/                         unit, end-to-end and corpus tests
run.bat run.ps1 run.sh        launchers that fetch a portable Node.js when needed
```

---

## Testing

```bash
npm test                     # everything: unit, CLI end-to-end, corpus
node --test test/lockfiles.test.js   # one file
```

The suite has no dependencies and makes no network calls (online sources are stubbed).

### The corpus: synthetic machines

`test/corpus/machines.js` builds five fake machines from code, each with real-world content:

| Machine | What it represents |
|---|---|
| `typical-dev` | An ordinary laptop. **Nothing should be flagged above medium**: the false-positive guard |
| `fake-interview` | A take-home assignment that runs code on `npm install`, on folder open and on agent start; a backdoored hook in OneDrive |
| `npm-worm` | Catalog matches across lockfile types, a worm payload, Phantom Gyp, PhantomRaven, a Startup-folder dropper |
| `power-user` | Global hooks, symlinked agent files, a jailbreak, Nx Console persistence next to a normal LaunchAgent |
| `ai-workstation` | AI tooling found by structure, local models, API keys, a GlassWorm extension |

`test/corpus.test.js` scans each one in isolation (`--users-root`, offline) and compares a summary with `test/corpus/expected/<machine>.json`. Those files also list `known_gaps`: things the machine contains that HiveGuard does not yet detect.

When a change is meant to alter results:

```bash
npm run test:corpus:update   # rewrite the expectations
git diff test/corpus/expected   # review every line before committing
```

A new detection should come with a corpus scenario, and a benign look-alike next to it where false positives are possible.

### Self-check on a real machine

`node tools/self-check.js` scans the machine it runs on and prints a summary safe to share (no paths, usernames, hostnames or package names). It is the best way to get feedback from real endpoints: ask the person to paste the summary. When you add a scanner, add its counts and timings to the self-check, never names.

---

## CI

`.github/workflows/ci.yml` runs the suite on Ubuntu (Node 18 and 22), macOS and Windows; on Windows it also runs the `run.bat` / `run.ps1` launchers.

To save Actions minutes it is **opt-in**: it runs only when a pushed commit message contains `[ci]`, or when started by hand from the Actions tab. Add `[ci]` to the last commit of a change that touches platform-specific code (paths, symlinks, launchers) or before a release.

---

## Adding a check

1. **Find the right place.** Code that runs a command or script belongs in `utils/script-inspect.js` patterns; a new location to inventory belongs in a scanner; a new file format belongs next to similar parsers.
2. **Reuse the walk.** If you need to see files across projects, add an `onDir` collector to the shared walk instead of walking again.
3. **Bound everything.** Cap file sizes, entries per folder and total work; bound every regex gap (`[^\n]{0,200}`) so hostile input cannot make it slow.
4. **Return findings in the common shape:** `severity`, `type`, `text`, `path`, `triggers`, plus whatever identifies the item. Use an existing `type` when the meaning is the same; add a new one otherwise and document it in [RESULTS-GUIDE.md](RESULTS-GUIDE.md).
5. **Wire it up** in `bin/hiveguard.js`: run it with `timedScan`, add its findings to the aggregation, and add a counter to `summary.ecosystems`.
6. **Show it:** a report panel or card, a self-check line (counts only).
7. **Test it:** unit tests with a benign and a malicious case, and a corpus scenario.

---

## Releasing

1. Update `version` in `package.json` (the only place it is set).
2. Add an entry to [CHANGELOG.md](../CHANGELOG.md).
3. Refresh `data/baseline-catalogs/` from Bumblebee if there are new campaigns.
4. Run `npm test`, then push a commit with `[ci]` and check that all four jobs pass.
5. Ask for a self-check from at least one real Windows and one macOS machine.
6. Tag the release (`git tag v2.0.0`) and publish the ZIP used for deployment.
