'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const mcp = require('../src/scanners/mcp-configs');
const { agentRoots, mcpCandidates, editorForks } = require('../src/utils/ai-roots');

describe('MCP package runners', () => {
  const spec = (cmd, args) => mcp.packageSpec(cmd, args);

  it('finds the npm package behind npx/bunx/pnpm dlx/yarn dlx and Windows cmd /c', () => {
    assert.deepEqual(spec('npx', ['-y', 'postmark-mcp']), { ecosystem: 'npm', name: 'postmark-mcp', version: null });
    assert.deepEqual(spec('npx', ['-y', '@acme/mcp-server@1.4.2', '--port', '3']), { ecosystem: 'npm', name: '@acme/mcp-server', version: '1.4.2' });
    assert.deepEqual(spec('npx', ['@acme/mcp-server@latest']), { ecosystem: 'npm', name: '@acme/mcp-server', version: null });
    assert.deepEqual(spec('C:\\Program Files\\nodejs\\npx.cmd', ['-y', 'x-mcp@2.0.0']), { ecosystem: 'npm', name: 'x-mcp', version: '2.0.0' });
    assert.deepEqual(spec('cmd', ['/c', 'npx', '-y', 'x-mcp']), { ecosystem: 'npm', name: 'x-mcp', version: null });
    assert.deepEqual(spec('pnpm', ['dlx', 'x-mcp@1.0.0']), { ecosystem: 'npm', name: 'x-mcp', version: '1.0.0' });
    assert.deepEqual(spec('npx', ['--package=y-mcp@3.1.0', 'y']), { ecosystem: 'npm', name: 'y-mcp', version: '3.1.0' });
  });

  it('finds the PyPI package behind uvx and pipx run', () => {
    assert.deepEqual(spec('uvx', ['mcp-server-fetch']), { ecosystem: 'pypi', name: 'mcp-server-fetch', version: null });
    assert.deepEqual(spec('uvx', ['--from', 'mcp-server-git==0.6.2', 'mcp-server-git']), { ecosystem: 'pypi', name: 'mcp-server-git', version: '0.6.2' });
    assert.deepEqual(spec('pipx', ['run', 'tool==1.0']), { ecosystem: 'pypi', name: 'tool', version: '1.0' });
  });

  it('ignores local scripts, binaries and containers', () => {
    assert.equal(spec('node', ['server.js']), null);
    assert.equal(spec('npx', ['./local-server']), null);
    assert.equal(spec('docker', ['run', '-i', 'mcp/fetch']), null);
    assert.equal(spec('/usr/local/bin/my-mcp', []), null);
  });
});

describe('MCP config formats', () => {
  it('reads Claude Code per-project servers and VS Code "servers" files', () => {
    const claude = JSON.stringify({ mcpServers: { a: { command: 'npx', args: ['a-mcp'] } }, projects: { '/p': { mcpServers: { b: { url: 'https://x.example/mcp' } } } } });
    assert.deepEqual(mcp.parseJsonServers(claude, false).map(s => [s.name, s.scope]), [['a', null], ['b', '/p']]);
    const vscode = JSON.stringify({ servers: { gh: { type: 'http', url: 'https://api.example/mcp' } }, inputs: [] });
    assert.deepEqual(mcp.parseJsonServers(vscode, true).map(s => s.name), ['gh']);
    assert.deepEqual(mcp.parseJsonServers(vscode, false), [], 'a bare "servers" key outside an mcp file is not trusted');
    assert.deepEqual(mcp.parseJsonServers(JSON.stringify({ mcp: { servers: { s: { command: 'x' } } } }), false).map(s => s.name), ['s']);
  });

  it('reads Codex-style TOML tables', () => {
    const toml = '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\n\n[mcp_servers.docs.env]\nAPI_TOKEN = "x"\n\n[other]\nkey = 1\n';
    const [s] = mcp.parseTomlServers(toml);
    assert.equal(s.name, 'docs');
    assert.deepEqual(s.cfg.args, ['-y', 'docs-mcp']);
    assert.deepEqual(Object.keys(s.cfg.env), ['API_TOKEN']);
  });
});

describe('AI tool discovery by structure', () => {
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-aidisc-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const write = (rel, content) => {
    const p = path.join(tmp, ...rel.split('/'));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content));
  };

  it('finds MCP configs of unknown agents and editor forks on a Windows-style profile', () => {
    const home = path.join(tmp, 'u');
    write('u/.brandnew-agent/mcp.json', { mcpServers: { files: { command: 'npx', args: ['-y', 'files-mcp'] } } });
    write('u/.codex/config.toml', '[mcp_servers.x]\ncommand = "uvx"\nargs = ["x-mcp==1.0"]\n');
    write('u/AppData/Roaming/SomeDesktopApp/claude_desktop_config.json', { mcpServers: {} });
    write('u/AppData/Roaming/NewIDE/User/settings.json', { 'editor.fontSize': 12, mcp: { servers: { db: { command: 'db-mcp' } } } });
    write('u/AppData/Roaming/NewIDE/User/globalStorage/some.ext/settings/ext_mcp_settings.json', { mcpServers: { deep: { command: 'npx', args: ['deep-mcp@1.0.0'] } } });
    write('u/AppData/Local/BigApp/Cache/huge/mcp.json', { mcpServers: { never: { command: 'x' } } });
    write('u/.newfork/extensions/extensions.json', '[]');
    write('u/.notaneditor/extensions/readme.txt', 'x');

    const platform = { id: 'windows', userHomes: [home], mcpConfigPaths: [] };
    const roots = agentRoots(platform);
    const r = mcp.scan(platform, {}, mcpCandidates(platform, roots));
    const servers = r.configs.flatMap(c => c.servers.map(s => `${c.app}:${s.name}`)).sort();
    assert.deepEqual(servers, ['NewIDE:db', 'NewIDE:deep', 'brandnew-agent:files', 'codex:x']);
    assert.deepEqual(r.findings.map(f => `${f.app}:${f.server}:${f.triggers}`), ['brandnew-agent:files:mcp-unpinned-package']);
    assert.deepEqual(editorForks(platform, roots), { newfork: [path.join(home, '.newfork', 'extensions')] });
  });

  it('uses ~/.config as the app root on Linux and keeps empty fixed configs listed', () => {
    const home = path.join(tmp, 'v');
    write('v/.config/someagent/mcp_servers.json', { mcpServers: { s: { url: 'https://x.example' } } });
    write('v/fixed.json', { other: true });
    const platform = { id: 'linux', userHomes: [home], mcpConfigPaths: [path.join(home, 'fixed.json')] };
    const r = mcp.scan(platform, {}, mcpCandidates(platform));
    assert.deepEqual(r.configs.map(c => [c.app, c.server_count]), [['v', 0], ['someagent', 1]]);
  });
});
