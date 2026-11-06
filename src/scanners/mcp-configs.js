'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'mcp-configs';
const MAX_CONFIG_BYTES = 20 * 1024 * 1024; // ~/.claude.json grows with history
const CRED_KEY = /api.?key|token|secret|password|auth|credential/i;

/**
 * MCP (Model Context Protocol) server configurations, recognised by structure rather
 * than by product: any JSON with mcpServers / servers (under "mcp" or in an mcp-named
 * file) / context_servers / mcp-servers, and TOML [mcp_servers.<name>] tables.
 *
 * Sources: platform.mcpConfigPaths (always listed, even if empty, as before) plus
 * discovered candidates [{ path, label }] (listed only when they define servers).
 */
function scan(platform, opts = {}, candidates = []) {
  const configs = [];
  const findings = [];
  const seen = new Set();
  const io = { files_read: 0, bytes_read: 0, read_parse_ms: 0, largest_file_bytes: 0 };

  const sources = [
    ...(platform.mcpConfigPaths || []).filter(p => typeof p === 'string').map(p => ({ path: p, label: path.basename(path.dirname(p)), fixed: true })),
    ...candidates.map(c => ({ ...c, fixed: false })),
  ];

  for (const src of sources) {
    const st = statSafe(src.path);
    if (!st || !st.isFile() || st.size > MAX_CONFIG_BYTES) continue;
    let real;
    try { real = fs.realpathSync.native(src.path); } catch { continue; }
    if (seen.has(real)) continue;
    seen.add(real);

    const t0 = process.hrtime.bigint();
    const raw = readFileSafe(src.path);
    if (raw == null) continue;
    const entries = src.path.toLowerCase().endsWith('.toml')
      ? parseTomlServers(raw)
      : parseJsonServers(raw, /mcp/i.test(path.basename(src.path)));
    io.files_read++;
    io.bytes_read += st.size;
    io.largest_file_bytes = Math.max(io.largest_file_bytes, st.size);
    io.read_parse_ms += Number(process.hrtime.bigint() - t0) / 1e6;
    if (entries == null) continue;
    if (entries.length === 0 && !src.fixed) continue;

    const servers = entries.map(({ name, cfg, scope }) => describeServer(name, cfg, scope));
    configs.push({
      config_path: src.path,
      config_name: path.basename(path.dirname(src.path)),
      app: src.label,
      server_count: servers.length,
      servers,
    });

    for (const s of servers) {
      if (s.unpinned) {
        findings.push({
          severity: 'medium',
          type: 'mcp_server_risk',
          ecosystem: s.package_ecosystem,
          package: s.package,
          server: s.name,
          app: src.label,
          path: src.path,
          triggers: ['mcp-unpinned-package'],
          text: `MCP server "${s.name}" (${src.label}) runs ${s.package} without a pinned version; each start may fetch whatever was published last`,
        });
      }
    }
    logger.info(SCANNER_ID, `${src.label}/${path.basename(src.path)}: ${servers.length} servers`);
  }

  return {
    ecosystem: SCANNER_ID,
    configs,
    total_configs: configs.length,
    total_servers: configs.reduce((s, c) => s + c.server_count, 0),
    findings,
    io: { ...io, read_parse_ms: Math.round(io.read_parse_ms) },
  };
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const looksLikeServer = (v) => isObj(v) && (typeof v.command === 'string' || typeof v.url === 'string'
  || typeof v.serverUrl === 'string' || typeof v.httpUrl === 'string');

// Returns [{ name, cfg, scope }] or null when the file is not valid JSON.
function parseJsonServers(raw, mcpNamedFile) {
  let data;
  try { data = JSON.parse(raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw); } catch { return null; }
  const found = [];
  const visit = (node, depth, parentKey, scope) => {
    if (!isObj(node) || depth > 4) return;
    for (const [key, value] of Object.entries(node)) {
      if (!isObj(value)) continue;
      const serverMap = key === 'mcpServers' || key === 'context_servers' || key === 'mcp-servers'
        || (key === 'servers' && (parentKey === 'mcp' || (depth === 0 && mcpNamedFile)));
      if (serverMap) {
        for (const [name, cfg] of Object.entries(value)) if (looksLikeServer(cfg)) found.push({ name, cfg, scope });
      } else {
        // Claude Code keeps per-project servers under projects[<path>].mcpServers.
        visit(value, depth + 1, key, parentKey === 'projects' ? key : scope);
      }
    }
  };
  visit(data, 0, null, null);
  return found;
}

// Minimal reader for TOML [mcp_servers.<name>] tables (Codex and similar CLIs).
function parseTomlServers(raw) {
  const servers = new Map();
  let current = null;
  let inEnv = false;
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const header = t.match(/^\[\s*mcp_servers\.(?:"([^"]+)"|([^\]".]+))(\.env)?\s*\]$/);
    if (header) {
      current = header[1] || header[2];
      inEnv = !!header[3];
      if (!servers.has(current)) servers.set(current, {});
      continue;
    }
    if (t.startsWith('[')) { current = null; continue; }
    if (!current) continue;
    const kv = t.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const cfg = servers.get(current);
    if (inEnv) {
      let envValue = kv[2].replace(/\s+#.*$/, '').trim();
      try { envValue = JSON.parse(envValue); } catch { envValue = envValue.replace(/^'(.*)'$/, '$1'); }
      (cfg.env = cfg.env || {})[kv[1]] = envValue;
      continue;
    }
    let value = kv[2].replace(/\s+#.*$/, '');
    try { value = JSON.parse(value); } catch { value = value.replace(/^'(.*)'$/, '$1'); }
    cfg[kv[1]] = value;
  }
  return [...servers.entries()].filter(([, cfg]) => looksLikeServer(cfg)).map(([name, cfg]) => ({ name, cfg, scope: null }));
}

function describeServer(name, cfg, scope) {
  const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
  const url = cfg.url || cfg.serverUrl || cfg.httpUrl || null;
  const envKeys = isObj(cfg.env) ? Object.keys(cfg.env) : [];
  // Keys whose value is written literally in the file (not ${env:X}, $X, %X% or empty).
  const literalKeys = envKeys.filter(k => {
    const v = cfg.env[k];
    return typeof v === 'string' && v.trim().length >= 8 && !/^\s*(\$|%)/.test(v);
  });
  const server = {
    name,
    transport: cfg.transport || cfg.type || (cfg.command ? 'stdio' : url ? 'http' : 'unknown'),
    command: typeof cfg.command === 'string' ? cfg.command : null,
    args,
    url,
    env_keys: envKeys,
    env_literal_keys: literalKeys,
    has_credentials: envKeys.some(k => CRED_KEY.test(k)),
  };
  if (scope) server.project = scope;
  const pkg = packageSpec(server.command, args);
  if (pkg) {
    server.package = pkg.name;
    server.package_version = pkg.version;
    server.package_ecosystem = pkg.ecosystem;
    server.unpinned = !pkg.version;
  }
  return server;
}

/**
 * The package a runner command fetches and starts: npx/bunx, pnpm/yarn dlx, uvx,
 * pipx run (also behind Windows "cmd /c"). Returns { ecosystem, name, version|null }
 * or null for anything else (local binaries, scripts, docker, ...).
 */
function packageSpec(command, args) {
  if (!command) return null;
  const base = (p) => String(p).split(/[\\/]/).pop().toLowerCase().replace(/\.(cmd|exe|bat)$/, '');
  let cmd = base(command);
  let rest = [...args];
  if (cmd === 'cmd' && /^\/c$/i.test(rest[0] || '')) {
    cmd = base(rest[1] || '');
    rest = rest.slice(2);
  }
  if ((cmd === 'pnpm' || cmd === 'yarn') && rest[0] === 'dlx') { cmd = 'npx'; rest = rest.slice(1); }
  if (cmd === 'pipx' && rest[0] === 'run') { cmd = 'uvx'; rest = rest.slice(1); }

  if (cmd === 'npx' || cmd === 'bunx') {
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '-p' || a === '--package') return npmSpec(rest[i + 1]);
      if (a.startsWith('--package=')) return npmSpec(a.slice(10));
      if (a.startsWith('-')) continue;
      return npmSpec(a);
    }
  }
  if (cmd === 'uvx') {
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '--from') return pySpec(rest[i + 1]);
      if (a.startsWith('--from=')) return pySpec(a.slice(7));
      if (a.startsWith('-')) continue;
      return pySpec(a);
    }
  }
  return null;
}

function npmSpec(spec) {
  if (!spec || /^[./\\]|^[a-z]+:/i.test(spec)) return null;
  const at = spec.lastIndexOf('@');
  if (at > 0) {
    const version = spec.slice(at + 1);
    return { ecosystem: 'npm', name: spec.slice(0, at), version: /^v?\d/.test(version) ? version : null };
  }
  return { ecosystem: 'npm', name: spec, version: null };
}

function pySpec(spec) {
  if (!spec || /^[./\\]|^[a-z]+:/i.test(spec)) return null;
  const m = spec.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:==\s*([\w.!+-]+))?/);
  if (!m) return null;
  return { ecosystem: 'pypi', name: m[1], version: m[2] || null };
}

module.exports = { scan, SCANNER_ID, packageSpec, parseJsonServers, parseTomlServers };
