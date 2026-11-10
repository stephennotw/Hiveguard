# Changelog

## 2.0.0 (2026-11-10)

A major release. Full description and upgrade notes: [docs/WHATS-NEW-2.0.md](docs/WHATS-NEW-2.0.md). Output is backward compatible: everything new is additive.

### Added

- **Threat intel:** OSV.dev malicious-package advisories (including VS Code extensions) and the GitHub Advisory Database (with `GITHUB_TOKEN`), with per-source status in `threat_intel.sources`.
- **Indicators of compromise:** payload file names, hashes, persistence paths and exfiltration hosts are taken from catalog `_indicators` and checked on the machine.
- **`--ioc` / `--ioc-file`:** search a machine for packages, paths, file names, hashes or text; hits exit with code 2.
- **Exports:** `--format sarif|cyclonedx|ndjson|all`.
- **Lockfiles:** `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `bun.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- **Install-time attacks:** suspicious npm install scripts and the files they run, `binding.gyp` commands (Phantom Gyp), dependencies fetched from URLs (PhantomRaven).
- **Git hooks:** repository and global `core.hooksPath` hooks.
- **AI assistant files:** prompt injection, hidden Unicode, exfiltration and permission-bypass instructions; agent hooks and auto-run VS Code tasks, and the scripts they run.
- **Autostart and persistence:** LaunchAgents, XDG autostart, systemd user units, Startup folder, scheduled tasks and cron (elevated).
- **Extensions:** GlassWorm hidden-code detection, extension packs and dependencies, any VS Code fork.
- **AI on this machine:** MCP servers by structure (configured / available / disabled, unpinned flagged), local models, plain-text provider keys, AI SDKs, AI apps.
- `--users-root` for scanning mounted images, `--normal-priority`, `HTTPS_PROXY` / `NO_PROXY` support.
- `tools/self-check.js`: a shareable summary of a real scan.
- 200+ tests, five synthetic machines, opt-in CI on Windows, macOS and Linux.

### Performance

- Install-script scan reads only the packages the package manager recorded as having install scripts: npm's `node_modules/.package-lock.json` and pnpm 10+'s `node_modules/.modules.yaml` (with a full walk as fallback; the reason is reported in `pnpm_record_fallbacks`).
- Files that must be read are read in parallel (8 `package.json` files, 4 extension entry files at a time), which hides most of Windows Defender's per-file scan time. On a real Windows developer profile a scan went from 64 s to 14–23 s.

### Changed

- Runs at below-normal CPU priority by default.
- Files in cloud-sync folders (OneDrive, Dropbox, Google Drive, iCloud) are listed but never read.
- Critical or high findings from the new checks can set exit code 1.
- Supply-chain findings include `location` (the lockfile).
- A permission-bypass flag (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) mentioned in the user's own AI files is medium; in repository files it is high.

### Fixed

- 287 AntV / Mini Shai-Hulud catalog entries written as `@@antv/...` never matched.
- HTML report: script injection through crafted package names; only `http(s)` links are clickable.
- `--json` output piped to a file was cut off at 64 KB.
- Scans could hang on a FIFO or other special file.
- Version handling for pre-releases, `v`-prefixed versions and scoped global npm packages; several CVE rule boundaries.

## 1.0.0

First release: npm, PyPI, Go, Composer, RubyGems, Cargo, editor and browser extensions, MCP configs and secrets hygiene; Bumblebee catalogs with bundled fallback and custom catalogs; JSON and HTML output; launchers that fetch Node.js; Tanium deployment.
