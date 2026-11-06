'use strict';

const fs = require('fs');
const path = require('path');
const { statSafe, readFileSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'ai-models';

const MODEL_EXTS = new Set(['.gguf', '.safetensors', '.onnx', '.ckpt', '.pt', '.pth', '.tflite', '.mlmodel', '.llamafile']);
const MIN_MODEL_BYTES = 10 * 1024 * 1024;
const ZIP_TAIL_BYTES = 64 * 1024;
const MAX_ITEMS = 2000;
// Formats that deserialize Python pickle, which can execute code when the model is loaded.
const PICKLE_FORMATS = new Set(['pickle', 'pytorch-zip']);

/** onDir callback for walkSync collecting model-file candidates by extension. */
function modelCandidateCollector(out) {
  return (dir, entries, info = {}) => {
    for (const e of entries) {
      if (e.isFile() && MODEL_EXTS.has(path.extname(e.name).toLowerCase())) out.push({ path: path.join(dir, e.name), cloud: !!info.cloud });
    }
  };
}

/**
 * Format from the first bytes only; never reads a model body. Zip files (PyTorch's
 * format) also get their last 64 KB read to look for the pickled data.pkl entry.
 */
function sniffFormat(filePath, size) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(16);
    const n = fs.readSync(fd, head, 0, 16, 0);
    if (n < 8) return 'unknown';
    if (head.toString('latin1', 0, 4) === 'GGUF') return 'gguf';
    if (head.toString('latin1', 4, 8) === 'TFL3') return 'tflite';
    const headerLen = Number(head.readBigUInt64LE(0));
    if (head[8] === 0x7B && headerLen > 1 && headerLen < 100 * 1024 * 1024 && headerLen < size) return 'safetensors';
    if (head[0] === 0x50 && head[1] === 0x4B && head[2] === 0x03 && head[3] === 0x04) {
      const len = Math.min(ZIP_TAIL_BYTES, size);
      const tail = Buffer.alloc(len);
      fs.readSync(fd, tail, 0, len, size - len);
      return tail.includes('data.pkl') ? 'pytorch-zip' : 'zip';
    }
    if (head[0] === 0x80 && head[1] >= 2 && head[1] <= 5) return 'pickle';
    if (head[0] === 0x08 && path.extname(filePath).toLowerCase() === '.onnx') return 'onnx';
    if (head.toString('latin1', 0, 2) === 'MZ' || head.toString('latin1', 0, 4) === '\x7fELF') return 'executable';
    return 'unknown';
  } catch {
    return 'unknown';
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ }
  }
}

function fileItem(filePath, cloud, extra = {}) {
  const st = statSafe(filePath);
  if (!st || !st.isFile() || st.size < MIN_MODEL_BYTES) return null;
  const format = cloud ? `${path.extname(filePath).slice(1).toLowerCase() || 'unknown'} (by extension)` : sniffFormat(filePath, st.size);
  const item = { path: filePath, format, size: st.size, pickle: PICKLE_FORMATS.has(format), ...extra };
  if (cloud) item.content_not_read = 'cloud-synced';
  return item;
}

function listEntries(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
}

const isInside = (p, roots) => roots.some(r => { const a = path.resolve(p); const b = path.resolve(r); return a === b || a.startsWith(b + path.sep); });

/** Hugging Face hub cache: one item per downloaded repo (models--org--name). */
function scanHuggingFace(hubDir, items) {
  for (const repo of listEntries(hubDir)) {
    if (!repo.isDirectory() || !repo.name.startsWith('models--')) continue;
    const repoDir = path.join(hubDir, repo.name);
    const formats = new Set();
    let size = 0;
    let files = 0;
    for (const snap of listEntries(path.join(repoDir, 'snapshots'))) {
      const snapDir = path.join(repoDir, 'snapshots', snap.name);
      for (const f of listEntries(snapDir)) {
        // Snapshot entries are symlinks into blobs/ on Linux/macOS and copies on Windows.
        const it = fileItem(path.join(snapDir, f.name), false);
        if (!it) continue;
        files++;
        size += it.size;
        formats.add(it.format);
      }
    }
    if (files === 0) continue;
    items.push({
      path: repoDir, store: 'huggingface', name: repo.name.slice('models--'.length).replace(/--/g, '/'),
      format: [...formats].sort().join(', '), files, size, pickle: [...formats].some(f => PICKLE_FORMATS.has(f)),
    });
  }
}

/** Ollama: model names from manifests, sizes from their layer lists. */
function scanOllama(modelsDir, items) {
  const manifests = path.join(modelsDir, 'manifests');
  for (const registry of listEntries(manifests)) {
    for (const ns of listEntries(path.join(manifests, registry.name))) {
      for (const model of listEntries(path.join(manifests, registry.name, ns.name))) {
        for (const tag of listEntries(path.join(manifests, registry.name, ns.name, model.name))) {
          if (!tag.isFile()) continue;
          const p = path.join(manifests, registry.name, ns.name, model.name, tag.name);
          let size = 0;
          try {
            const m = JSON.parse(readFileSafe(p, { maxBytes: 256 * 1024 }) || '{}');
            for (const layer of (m.layers || [])) if (/model/.test(layer.mediaType || '')) size += Number(layer.size) || 0;
          } catch { /* unreadable manifest: name only */ }
          const name = `${ns.name === 'library' ? '' : `${ns.name}/`}${model.name}:${tag.name}`;
          items.push({ path: p, store: 'ollama', name, format: 'gguf', size, pickle: false });
        }
      }
    }
  }
}

/** LM Studio and similar per-file stores: model files up to four levels deep. */
function scanFileStore(dir, store, items, depth = 0) {
  if (depth > 4) return;
  for (const e of listEntries(dir)) {
    const p = path.join(dir, e.name);
    if (e.isDirectory() && !e.isSymbolicLink()) scanFileStore(p, store, items, depth + 1);
    else if (e.isFile() && MODEL_EXTS.has(path.extname(e.name).toLowerCase())) {
      const it = fileItem(p, false, { store, name: path.relative(dir, p).split(path.sep).slice(0, -1).join('/') || e.name });
      if (it) items.push(it);
    }
  }
}

/**
 * Local AI models. candidates: [{ path, cloud }] from the shared walk. Known stores
 * are read per user home, plus HF_HOME / HF_HUB_CACHE / OLLAMA_MODELS when those
 * point inside a scanned home (so --users-root scans stay isolated).
 */
function scan(platform, opts = {}, candidates = []) {
  const items = [];
  const homes = platform.userHomes || [];
  const seenStores = new Set();
  const once = (dir) => { const k = path.resolve(dir); if (seenStores.has(k)) return false; seenStores.add(k); return true; };
  const env = opts.env || process.env;
  const envDir = (v) => (v && isInside(v, homes) ? v : null);

  const hfHubs = homes.map(h => path.join(h, '.cache', 'huggingface', 'hub'));
  if (envDir(env.HF_HUB_CACHE)) hfHubs.push(env.HF_HUB_CACHE);
  if (envDir(env.HF_HOME)) hfHubs.push(path.join(env.HF_HOME, 'hub'));
  for (const hub of hfHubs) if (once(hub)) scanHuggingFace(hub, items);

  const ollamaDirs = homes.map(h => path.join(h, '.ollama', 'models'));
  if (envDir(env.OLLAMA_MODELS)) ollamaDirs.push(env.OLLAMA_MODELS);
  for (const d of ollamaDirs) if (once(d)) scanOllama(d, items);

  for (const h of homes) {
    for (const d of [path.join(h, '.lmstudio', 'models'), path.join(h, '.cache', 'lm-studio', 'models')]) {
      if (once(d)) scanFileStore(d, 'lmstudio', items);
    }
  }

  const storeRoots = [...seenStores];
  for (const c of candidates) {
    if (items.length >= MAX_ITEMS) break;
    if (isInside(c.path, storeRoots)) continue;
    const it = fileItem(c.path, c.cloud);
    if (it) items.push(it);
  }

  const byFormat = {};
  for (const it of items) byFormat[it.format] = (byFormat[it.format] || 0) + 1;
  const totalSize = items.reduce((s, it) => s + (it.size || 0), 0);
  logger.info(SCANNER_ID, `Found ${items.length} local model(s), ${(totalSize / 1073741824).toFixed(1)} GB`);

  return {
    ecosystem: SCANNER_ID,
    total: items.length,
    total_size: totalSize,
    pickle_count: items.filter(i => i.pickle).length,
    by_format: byFormat,
    models: items.slice(0, MAX_ITEMS),
  };
}

module.exports = { scan, SCANNER_ID, sniffFormat, modelCandidateCollector, MODEL_EXTS };
