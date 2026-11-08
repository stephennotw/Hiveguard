# Deploying HiveGuard across a fleet

HiveGuard is a folder of scripts with no installer and no dependencies. Push it with any endpoint management tool (Tanium, Jamf, Intune, SCCM, Ansible, …), run one command, and collect one file.

- [Before you start](#before-you-start)
- [Step 1: Package HiveGuard](#step-1-package-hiveguard)
- [Step 2: Choose the command](#step-2-choose-the-command)
- [Step 3: Collect results](#step-3-collect-results)
- [Tanium](#tanium)
- [Jamf Pro (macOS)](#jamf-pro-macos)
- [Microsoft Intune (Windows)](#microsoft-intune-windows)
- [Scheduling and alerting](#scheduling-and-alerting)

---

## Before you start

| Question | Answer |
|---|---|
| Does it need admin / root? | No. Running as SYSTEM / root is recommended so every user profile, scheduled task and cron table is covered. |
| Does it need Node.js? | No. If Node.js 18+ is missing, the launcher downloads a portable copy (about 30 MB, once) into the HiveGuard folder. Endpoints then need to reach `nodejs.org`, or have Node.js installed. |
| What does it change on the machine? | Nothing outside its own folder and the output folder. It never runs package managers or anything it finds, and never reads the Windows registry. |
| How long does it take? | Seconds to about two minutes on a developer laptop. Allow 10 minutes for the first run (Node.js download, antivirus). |
| Will users notice? | It runs at below-normal CPU priority and does not download files from OneDrive/Dropbox/iCloud folders. |
| What leaves the machine? | Only threat-intel lookups (package names and versions to OSV.dev, catalog downloads from GitHub). Use `--offline` to disable them. Results stay on the machine until your tool collects them. |

---

## Step 1: Package HiveGuard

1. Download or clone HiveGuard.
2. Zip the folder so that the ZIP contains a single top-level folder named `Hiveguard`:

   ```
   Hiveguard.zip
   └── Hiveguard/
       ├── run.bat, run.ps1, run.sh
       ├── bin/, src/, data/
       └── ...
   ```

3. Optional: add your own catalogs in `Hiveguard/intel/` and pass `--custom-intel intel` in the command.

---

## Step 2: Choose the command

The recommended options for fleet use:

| Option | Why |
|---|---|
| `--output <fixed path>` | So your tool knows where to collect results |
| `--format ndjson` | One event per line for your SIEM (optional; add `sarif` or `cyclonedx` if you use them) |
| `--no-report` | Skip the HTML report if nobody will open it on the endpoint (optional) |

Do **not** add `> results.json`: the JSON is always written to the output folder.

**Windows (Command Prompt), from the ZIP**

```cmd
cmd /c powershell -NoProfile -NonInteractive -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive -Path 'Hiveguard.zip' -DestinationPath '.' -Force" && Hiveguard\run.bat --output C:\ProgramData\HiveGuard\results --format ndjson
```

**macOS / Linux, from the ZIP**

```bash
/bin/bash -c "unzip -qo Hiveguard.zip && cd Hiveguard && chmod +x run.sh && ./run.sh --output /var/tmp/hiveguard-results --format ndjson"
```

If `unzip` is missing on macOS:

```bash
/bin/bash -c "python3 -c \"import zipfile; zipfile.ZipFile('Hiveguard.zip').extractall('.')\" && cd Hiveguard && chmod +x run.sh && ./run.sh --output /var/tmp/hiveguard-results"
```

**Already copied to the machine**

| Platform | Command |
|---|---|
| Windows (CMD) | `cmd /c C:\path\to\Hiveguard\run.bat --output C:\ProgramData\HiveGuard\results` |
| Windows (PowerShell) | `powershell -NoProfile -ExecutionPolicy Bypass -File C:\path\to\Hiveguard\run.ps1 --output C:\ProgramData\HiveGuard\results` |
| macOS / Linux | `/path/to/Hiveguard/run.sh --output /var/tmp/hiveguard-results` |

---

## Step 3: Collect results

Each scan writes to the output folder:

| File | Collect it if you want |
|---|---|
| `hiveguard-<hostname>-<timestamp>.json` | Everything (always written) |
| `hiveguard-<hostname>-<timestamp>.ndjson` | SIEM ingestion (with `--format ndjson`) |
| `hiveguard-<hostname>-<timestamp>.sarif` | Dashboard import (with `--format sarif`) |
| `hiveguard-<hostname>-<timestamp>.cdx.json` | SBOM (with `--format cyclonedx`) |
| `hiveguard-report-<hostname>.html` | A human-readable report for that machine |

The **exit code** is the quickest signal:

| Code | Meaning | Suggested action |
|---|---|---|
| `0` | Clean | none |
| `1` | Critical or high findings (malicious script, vulnerable package, exposed credentials, …) | Review |
| `2` | Known-compromised package installed, or an `--ioc` indicator found | Open an incident |
| `3` | HiveGuard could not run | Check the console output captured by your tool |

For triage of individual findings, see the [Results guide](RESULTS-GUIDE.md).

---

## Tanium

| Step | Where | What |
|---|---|---|
| Create the package | Administration → Content → Packages → New Package | Upload `Hiveguard.zip` (one package per OS) |
| Command (Windows) | Package → Command | The Windows ZIP command from [Step 2](#step-2-choose-the-command) |
| Command (macOS / Linux) | Package → Command | The macOS / Linux ZIP command from Step 2. **It must be wrapped in `/bin/bash -c "…"`**; Tanium otherwise fails with exit code 126 |
| Timeout | Package → Command Timeout | `600` seconds |
| Target | Interact → ask a question | e.g. `Get Computer Name from all machines` |
| Deploy | Select endpoints → Deploy Action | Run once or on a schedule |
| Collect | A sensor that reads the newest `*.json` (or `*.ndjson`) in the output folder | Pull back via Interact |

Tanium runs as SYSTEM / root, so all user profiles, Windows scheduled tasks and cron tables are covered.

---

## Jamf Pro (macOS)

1. Upload `Hiveguard.zip` as a package that installs to `/Library/Application Support/HiveGuard/`.
2. Create a policy with a **Files and Processes → Execute Command**:

   ```bash
   cd "/Library/Application Support/HiveGuard" && unzip -qo Hiveguard.zip && cd Hiveguard && chmod +x run.sh && ./run.sh --output /var/tmp/hiveguard-results --format ndjson
   ```

3. Scope it, and set the frequency (for example once a week).
4. Collect `/var/tmp/hiveguard-results/*.ndjson` with your log forwarder, or read the exit code from the policy log.

---

## Microsoft Intune (Windows)

Use a **Platform script** (Devices → Scripts and remediations → Platform scripts), run in the system context, 64-bit:

```powershell
$dir = 'C:\ProgramData\HiveGuard'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# Copy or download Hiveguard.zip to $dir first (e.g. from an internal file share)
Expand-Archive -Path "$dir\Hiveguard.zip" -DestinationPath $dir -Force
& "$dir\Hiveguard\run.bat" --output "$dir\results" --format ndjson
exit $LASTEXITCODE
```

Collect `C:\ProgramData\HiveGuard\results\*.ndjson` with your log forwarder. For recurring scans, use a **Remediation** with this as the detection script.

---

## Scheduling and alerting

- **How often:** weekly is a good default; daily during an active supply-chain campaign.
- **During an incident:** push a one-off run with `--ioc` or `--ioc-file` and alert on exit code `2`. See [Hunt for indicators of compromise](HOW-TO.md#hunt-for-indicators-of-compromise).
- **Alert rules for a SIEM** (NDJSON events):
  - `type` is `supply_chain_compromise`, `ioc_match` or `known_ioc_file`: incident;
  - `severity` is `critical`: investigate the same day;
  - `severity` is `high`: review within the week.
- **Stale threat intel:** alert when `threat_intel_source` in the summary event is `baseline` on machines that should be online. It means GitHub could not be reached and the bundled catalogs were used.
