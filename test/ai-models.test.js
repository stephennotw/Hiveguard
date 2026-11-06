'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, sniffFormat, modelCandidateCollector } = require('../src/scanners/ai-models');

const MB = 1024 * 1024;

// Sparse file: only the head (and optional tail) bytes are written.
function sparse(p, size, head, tail) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const fd = fs.openSync(p, 'w');
  fs.writeSync(fd, head, 0, head.length, 0);
  fs.ftruncateSync(fd, size);
  if (tail) fs.writeSync(fd, tail, 0, tail.length, size - tail.length);
  fs.closeSync(fd);
}

const GGUF = Buffer.from('GGUF\x03\x00\x00\x00\x00\x00\x00\x00', 'latin1');
const SAFETENSORS = (() => { const json = Buffer.from('{"w":{"dtype":"F16"}}'); const len = Buffer.alloc(8); len.writeBigUInt64LE(BigInt(json.length)); return Buffer.concat([len, json]); })();
const ZIP_HEAD = Buffer.from('PK\x03\x04\x14\x00\x00\x00', 'latin1');
const TORCH_TAIL = Buffer.from('archive/data.pklarchive/version', 'latin1');
const PICKLE = Buffer.from([0x80, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00]);

describe('model format sniffing', () => {
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-models-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('recognises formats from magic bytes regardless of extension', () => {
    const cases = [
      ['a.gguf', GGUF, null, 'gguf'],
      ['b.safetensors', SAFETENSORS, null, 'safetensors'],
      ['c.pt', ZIP_HEAD, TORCH_TAIL, 'pytorch-zip'],
      ['d.ckpt', PICKLE, null, 'pickle'],
      ['e.bin', GGUF, null, 'gguf'],
      ['f.pt', ZIP_HEAD, Buffer.from('nothing here'), 'zip'],
    ];
    for (const [name, head, tail, expected] of cases) {
      const p = path.join(tmp, name);
      sparse(p, 12 * MB, head, tail);
      assert.equal(sniffFormat(p, 12 * MB), expected, name);
    }
  });
});

describe('local model inventory', () => {
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-models2-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('reports walk candidates, stores and pickle risk; skips small files; names-only in cloud folders', () => {
    const home = path.join(tmp, 'home');
    sparse(path.join(home, 'Downloads', 'llama-3-8b.Q4_K_M.gguf'), 20 * MB, GGUF);
    sparse(path.join(home, 'projects', 'ml', 'models', 'classifier.pt'), 15 * MB, ZIP_HEAD, TORCH_TAIL);
    fs.mkdirSync(path.join(home, 'projects', 'ml'), { recursive: true });
    fs.writeFileSync(path.join(home, 'projects', 'ml', 'distutils-precedence.pth'), 'import os');
    sparse(path.join(home, 'OneDrive', 'models', 'shared.safetensors'), 30 * MB, Buffer.from('not read'));
    sparse(path.join(home, '.cache', 'huggingface', 'hub', 'models--acme--tiny-llm', 'snapshots', 'abc123', 'model.safetensors'), 40 * MB, SAFETENSORS);
    sparse(path.join(home, '.cache', 'huggingface', 'hub', 'models--acme--tiny-llm', 'snapshots', 'abc123', 'pytorch_model.bin'), 40 * MB, ZIP_HEAD, TORCH_TAIL);
    fs.mkdirSync(path.join(home, '.ollama', 'models', 'manifests', 'registry.ollama.ai', 'library', 'llama3'), { recursive: true });
    fs.writeFileSync(path.join(home, '.ollama', 'models', 'manifests', 'registry.ollama.ai', 'library', 'llama3', '8b'),
      JSON.stringify({ layers: [{ mediaType: 'application/vnd.ollama.image.model', size: 4661211808 }, { mediaType: 'application/vnd.ollama.image.license', size: 12403 }] }));

    const candidates = [];
    const collector = modelCandidateCollector(candidates);
    const { walkSync } = require('../src/utils/fs-safe');
    walkSync(home, { maxDepth: 4, filter: () => false, onDir: collector });

    const r = scan({ userHomes: [home] }, { env: { HF_HOME: path.join(tmp, 'elsewhere') } }, candidates);
    const lines = r.models.map(m => [m.store || '-', m.name || path.relative(home, m.path).split(path.sep).join('/'), m.format, m.pickle ? 'pickle' : '', m.content_not_read || ''].join(' | ')).sort();
    assert.deepEqual(lines, [
      '- | Downloads/llama-3-8b.Q4_K_M.gguf | gguf |  | ',
      '- | OneDrive/models/shared.safetensors | safetensors (by extension) |  | cloud-synced',
      '- | projects/ml/models/classifier.pt | pytorch-zip | pickle | ',
      'huggingface | acme/tiny-llm | pytorch-zip, safetensors | pickle | ',
      'ollama | llama3:8b | gguf |  | ',
    ]);
    assert.equal(r.pickle_count, 2);
    assert.equal(r.models.find(m => m.store === 'ollama').size, 4661211808);
  });
});
