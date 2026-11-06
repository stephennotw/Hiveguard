'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

describe('output.writeStdout', () => {
  it('delivers large JSON through a pipe before exit', () => {
    const outputPath = path.resolve(__dirname, '../src/utils/output');
    const script = `require(${JSON.stringify(outputPath)}).writeStdout({ items: Array.from({ length: 50000 }, (_, i) => 'item-' + i) }).then(() => process.exit(0));`;
    const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    assert.equal(r.status, 0);
    assert.ok(r.stdout.length > 65536);
    assert.equal(JSON.parse(r.stdout).items.length, 50000);
  });
});
