'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/scanners/ai-apps');

describe('known AI apps catalog', () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'ai-apps.json'), 'utf8'));

  it('is well-formed', () => {
    assert.match(catalog.last_reviewed, /^\d{4}-\d{2}-\d{2}$/);
    const ids = new Set();
    for (const app of catalog.apps) {
      assert.ok(app.id && app.name && app.kind, JSON.stringify(app));
      assert.ok(!ids.has(app.id), `duplicate id ${app.id}`);
      ids.add(app.id);
      const patterns = [...(app.all || []), ...(app.windows || []), ...(app.darwin || []), ...(app.linux || [])];
      assert.ok(patterns.length > 0, app.id);
      for (const p of patterns) assert.match(p, /^(~\/|%APPDATA%\/|%LOCALAPPDATA%\/|\/)/, `${app.id}: ${p}`);
    }
  });
});

describe('known AI apps scan', () => {
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-apps-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const mk = (...parts) => fs.mkdirSync(path.join(tmp, ...parts), { recursive: true });

  it('finds Store-app folders by wildcard, per-user installs, and ignores system paths under --users-root', () => {
    mk('u', 'AppData', 'Local', 'Packages', 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0');
    mk('u', 'AppData', 'Roaming', 'devin');
    mk('u', '.antigravity-ide');
    mk('u', 'AppData', 'Local', 'Packages', 'Microsoft.WindowsCalculator_8wekyb3d8bbwe');
    const r = scan({ id: 'windows', userHomes: [path.join(tmp, 'u')], usersRoot: tmp });
    assert.deepEqual(r.apps.map(a => a.id).sort(), ['antigravity', 'chatgpt', 'devin']);
    assert.equal(r.apps.find(a => a.id === 'chatgpt').user, 'u');
  });

  it('uses the macOS entries on darwin', () => {
    mk('m', 'Library', 'Application Support', 'com.openai.chat');
    mk('m', 'AppData', 'Local', 'Packages', 'OpenAI.ChatGPT-Desktop_x');
    const r = scan({ id: 'darwin', userHomes: [path.join(tmp, 'm')], usersRoot: tmp });
    assert.deepEqual(r.apps.map(a => `${a.id}:${path.relative(tmp, a.evidence[0]).split(path.sep).join('/')}`), ['chatgpt:m/Library/Application Support/com.openai.chat']);
  });
});
