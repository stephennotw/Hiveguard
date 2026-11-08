# Threat intelligence in HiveGuard

Where HiveGuard's knowledge of "bad" comes from, how it is matched, and how to add your own.

- [Sources](#sources)
- [How matching works](#how-matching-works)
- [Indicators of compromise](#indicators-of-compromise)
- [Add your own catalogs](#add-your-own-catalogs)
- [Catalog format](#catalog-format)
- [Checking which intel was used](#checking-which-intel-was-used)

---

## Sources

| Source | What it provides | When it is used |
|---|---|---|
| **Bumblebee catalogs** ([perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)) | Package versions published by supply-chain campaigns, plus campaign indicators | Fetched from GitHub on every online scan, held in memory only |
| **Bundled baseline** (`data/baseline-catalogs/`) | A snapshot of those catalogs shipped with HiveGuard | When the live fetch fails, or with `--offline` |
| **Your catalogs** | Anything you add | Always, on top of the above |
| **OSV.dev** | OpenSSF malicious-package advisories (`MAL-…`) for npm, PyPI, Go, crates.io, RubyGems, Packagist and VS Code extensions | Online scans |
| **GitHub Advisory Database** | GitHub malware advisories | Online scans when `GITHUB_TOKEN` (or `GH_TOKEN`) is set |
| **Known CVE rules** (`src/cve/known-vulns.js`) | About 20 well-known vulnerabilities in common packages | Always (offline) |

The bundled baseline currently covers: Mini Shai-Hulud, AntV / Mini Shai-Hulud, node-ipc credential stealer, Nx Console VS Code extension, GemStuffer, Laravel Lang, ShopSprint decimal typosquat, Trapdoor crypto stealer.

**What is sent over the network:** for OSV.dev and GitHub, the ecosystem, name and version of inventoried packages. Nothing else about the machine. `--offline` disables all three online sources.

---

## How matching works

A package matches when **ecosystem, name and version are all equal** to a catalog entry. There is no fuzzy or "similar name" matching, so a match is a strong signal.

- Names are compared case-insensitively.
- A leading `v` in versions is ignored (`v1.2.3` equals `1.2.3`).
- A scoped name written with a doubled `@` in a catalog (`@@scope/name`, a mistake seen in published catalogs) is treated as `@scope/name`.
- Every location of a matching package is reported, so you can clean up all of them.

OSV.dev and the GitHub Advisory Database are asked about the exact installed versions. Their matches are merged with catalog matches, so a package flagged by several sources appears once with all its threats.

Each source reports its status in the result (`threat_intel.sources`). If a source failed, its matches may be missing: **a failed source does not mean the machine is clean.**

---

## Indicators of compromise

Catalogs can include an `_indicators` block with anything the researchers published. HiveGuard uses the parts it can check on an endpoint, recognised by key name and value shape, without code for each campaign:

| Indicator | Recognised from | Checked against |
|---|---|---|
| File hash | any 64-character hex value (SHA-256) | script files HiveGuard inspects |
| Payload file name | keys ending in `filename` | every folder the scan walks, script files, autostart entries |
| Persistence path | lists under keys like `persistence_files`, `*_paths`, `*_files` that start with `~/`, `/`, `C:\` or `%VAR%` | existence on disk; `~/` and `%APPDATA%`-style paths are checked for every user profile; `*` is allowed in the last part |
| Marker text | keys ending in `marker` | contents of script files HiveGuard inspects |
| Exfiltration host | keys ending in `endpoint`, `host` or `domain` (common hosts such as `github.com` are ignored) | contents of script files HiveGuard inspects |

"Script files HiveGuard inspects" means install-hook scripts and the files they run, `binding.gyp` targets, AI agent hook scripts, and autostart scripts. HiveGuard does not hash or read other files just to look for indicators.

Other indicator keys (descriptions, commit hashes, dates, …) are kept in the result for analysts and shown in the report.

You can also search for indicators ad hoc with `--ioc`; see [Hunt for indicators of compromise](HOW-TO.md#hunt-for-indicators-of-compromise).

---

## Add your own catalogs

1. Write a catalog file (format below). Give it a **unique file name**: a custom catalog with the same file name as a Bumblebee catalog replaces it.
2. Make it available in either place:

   | Place | Use when |
   |---|---|
   | `~/.hiveguard/custom-catalogs/` on the machine | It should load on every scan |
   | Any folder passed with `--custom-intel <folder>` (comma-separate several) | You push it with the scan, for example inside the deployment ZIP |

3. Run a scan. The console and `threat_intel.custom_catalogs` show how many custom catalogs were loaded, and the source reads `live+custom` or `baseline+custom`.

Custom catalogs are loaded in addition to the live or bundled ones, including with `--offline`.

---

## Catalog format

```json
{
  "_comment": "Internal SOC findings, incident 2026-0042",
  "_indicators": {
    "payload_filename": "update-helper.js",
    "payload_sha256": "239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420",
    "persistence_files": ["~/Library/LaunchAgents/com.example.updater.plist", "%APPDATA%\\Updater\\run.js"],
    "plaintext_marker": "a distinctive string from the payload",
    "c2_host": "bad.example.com",
    "reference": "SOC-2026-0042"
  },
  "entries": [
    {
      "id": "soc-2026-0042-internal-utils",
      "name": "Backdoored internal-utils",
      "ecosystem": "npm",
      "package": "internal-utils",
      "versions": ["1.0.0", "1.0.1"],
      "severity": "critical",
      "source": "https://wiki.example.com/soc/2026-0042"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `_comment` | no | Campaign description; shown as the campaign name |
| `_indicators` | no | Indicators of compromise (see above); also shown to analysts |
| `entries[].ecosystem` | yes | `npm`, `pypi`, `go`, `composer`, `rubygems`, `cargo`, `editor-extension` (VS Code family; name is `publisher.name`), `browser-extension` (name as shown in the browser) |
| `entries[].package` | yes | Package name exactly as published (scoped npm names include the scope) |
| `entries[].versions` | yes | Exact bad versions. List each one; ranges are not supported |
| `entries[].name` | no | What the entry is called in findings |
| `entries[].source` | no | Link or reference for analysts |
| `entries[].id`, `severity` | no | Kept for reference |

---

## Checking which intel was used

In the JSON (`threat_intel`) and on the report's Overview:

| Field | Meaning |
|---|---|
| `source` | `live`, `baseline`, `custom`, `live+custom` or `baseline+custom` |
| `last_sync` | When the live catalogs were fetched |
| `catalogs_loaded`, `total_known_bad_versions` | How much was loaded |
| `custom_catalogs`, `custom_dirs` | Your catalogs and where they came from |
| `sources.bumblebee`, `sources.osv`, `sources.ghsa` | `ok`, `partial`, `failed` or `skipped`, with the error if any |

`baseline` on a machine that should be online means GitHub could not be reached (check the proxy). The bundled catalogs are only as current as your HiveGuard version.
