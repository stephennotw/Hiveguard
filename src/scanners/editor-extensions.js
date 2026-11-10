'use strict';

const fs = require('fs');
const path = require('path');
const { readJsonSafe, existsSafe, readdirSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'editor-extensions';

// GlassWorm-style payloads: code hidden as long runs of invisible Unicode variation
// selectors or tag characters in an extension's entry file. Emoji use one selector at a
// time; dozens in a row only make sense as encoded data.
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const RUN_HIGH = 32;
const RUN_CRITICAL = 200;
// Entry files are large bundles; on Windows most of a read is the antivirus scan, and
// overlapping a few of them hides most of that wait.
const READ_CONCURRENCY = 4;

/**
 * Scan editor extensions for VS Code, Windsurf, Cursor, VSCodium and other forks.
 * Reads package.json from each extension directory, then checks the entry files
 * (main / browser) in parallel for GlassWorm-style hidden code.
 */
async function scan(platform) {
  const results = {};
  const findings = [];
  const budget = { bytes: MAX_TOTAL_BYTES, files: 0, skipped: 0, ms: 0 };
  const entryQueue = [];

  for (const [editor, extDirOrDirs] of Object.entries(platform.editorExtensionDirs || {})) {
    const dirs = Array.isArray(extDirOrDirs) ? extDirOrDirs : [extDirOrDirs];

    const extensions = [];
    for (const extDir of dirs) {
      if (!existsSafe(extDir)) {
        logger.debug(SCANNER_ID, `${editor} extensions dir not found: ${extDir}`);
        continue;
      }

      for (const entry of readdirSafe(extDir)) {
        if (entry.startsWith('.')) continue;
        const extPath = path.join(extDir, entry);

        // Extension package.json
        const pkgJson = readJsonSafe(path.join(extPath, 'package.json'));
        if (!pkgJson) continue;

        extensions.push({
          id: entry,
          name: pkgJson.name || entry,
          displayName: pkgJson.displayName || pkgJson.name || entry,
          publisher: pkgJson.publisher || 'unknown',
          version: pkgJson.version || 'unknown',
          description: pkgJson.description || '',
          path: extDir,
          engines: pkgJson.engines?.vscode || null,
          categories: pkgJson.categories || [],
          extensionKind: pkgJson.extensionKind || null,
          activationEvents: (pkgJson.activationEvents || []).length,
          hasExtensionDeps: (pkgJson.extensionDependencies || []).length > 0,
          ...(listOf(pkgJson.extensionPack).length ? { extension_pack: listOf(pkgJson.extensionPack) } : {}),
          ...(listOf(pkgJson.extensionDependencies).length ? { extension_dependencies: listOf(pkgJson.extensionDependencies) } : {}),
        });
        for (const file of entryFiles(extPath, pkgJson, budget)) {
          entryQueue.push({ ext: extensions[extensions.length - 1], editor, extPath, file });
        }
      }
    }

    if (extensions.length > 0) {
      results[editor] = extensions;
      logger.info(SCANNER_ID, `${editor}: ${extensions.length} extensions`);
    }
  }

  const t0 = process.hrtime.bigint();
  const hits = await checkEntryFiles(entryQueue);
  budget.ms += Number(process.hrtime.bigint() - t0) / 1e6;
  budget.files = entryQueue.length;
  for (let i = 0; i < entryQueue.length; i++) {
    const r = hits[i];
    const { ext, editor, extPath, file } = entryQueue[i];
    if (!r || r.longest < RUN_HIGH || ext.hidden_unicode_run) continue;
    const rel = path.relative(extPath, file).split(path.sep).join('/');
    ext.hidden_unicode_run = r.longest;
    const id = `${ext.publisher}.${ext.name}`;
    findings.push({
      severity: r.longest >= RUN_CRITICAL ? 'critical' : 'high',
      type: 'suspicious_extension',
      ecosystem: 'editor-extension',
      package: id,
      version: ext.version,
      editor,
      path: file,
      triggers: ['invisible-unicode-payload'],
      text: `${editor} extension ${id}@${ext.version} hides ${r.total} invisible Unicode characters in ${rel} (longest run ${r.longest}), the GlassWorm technique`,
    });
  }

  return {
    ecosystem: SCANNER_ID,
    editors: results,
    total: Object.values(results).reduce((s, e) => s + e.length, 0),
    entry_files_checked: budget.files,
    entry_files_skipped: budget.skipped,
    entry_check_ms: Math.round(budget.ms),
    findings,
  };
}

const listOf = (v) => (Array.isArray(v) ? v.filter(x => typeof x === 'string').slice(0, 100) : []);

/** Entry files (main / browser) inside the extension, within the size budget. */
function entryFiles(extPath, pkgJson, budget) {
  const out = [];
  const root = path.resolve(extPath);
  for (const entry of [pkgJson.main, pkgJson.browser].filter(e => typeof e === 'string')) {
    let file = path.resolve(root, entry);
    if (!file.startsWith(root + path.sep)) continue;
    let st = statSafe(file);
    if (!st || !st.isFile()) { file += '.js'; st = statSafe(file); }
    if (!st || !st.isFile() || out.includes(file)) continue;
    if (st.size > MAX_ENTRY_BYTES || st.size > budget.bytes) { budget.skipped++; continue; }
    budget.bytes -= st.size;
    out.push(file);
  }
  return out;
}

/** invisibleRuns() of each file, READ_CONCURRENCY at a time; null for unreadable files. */
async function checkEntryFiles(queue) {
  const results = new Array(queue.length).fill(null);
  let next = 0;
  const worker = async () => {
    while (next < queue.length) {
      const i = next++;
      try {
        const buf = await fs.promises.readFile(queue[i].file);
        if (buf.length <= MAX_ENTRY_BYTES) results[i] = invisibleRuns(buf);
      } catch { /* unreadable: skipped */ }
    }
  };
  await Promise.all(Array.from({ length: Math.min(READ_CONCURRENCY, queue.length) }, worker));
  return results;
}

/**
 * Byte-level scan of UTF-8 for variation selectors (U+FE00-FE0F: EF B8 80-8F;
 * U+E0100-E01EF: F3 A0 84-87 xx) and tag characters (U+E0000-E007F: F3 A0 80-81 xx).
 * Returns { longest, total } over consecutive runs.
 */
function invisibleRuns(buf) {
  let longest = 0;
  let total = 0;
  let run = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0xEF && buf[i + 1] === 0xB8 && buf[i + 2] >= 0x80 && buf[i + 2] <= 0x8F) {
      run++; total++; i += 2;
    } else if (b === 0xF3 && buf[i + 1] === 0xA0 && buf[i + 2] >= 0x80 && buf[i + 2] <= 0x87 && buf[i + 2] !== 0x82 && buf[i + 2] !== 0x83) {
      run++; total++; i += 3;
    } else {
      if (run > longest) longest = run;
      run = 0;
    }
  }
  return { longest: Math.max(longest, run), total };
}

module.exports = { scan, SCANNER_ID, invisibleRuns };
