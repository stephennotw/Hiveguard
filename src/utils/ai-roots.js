'use strict';

const fs = require('fs');
const path = require('path');
const { statSafe } = require('./fs-safe');

/**
 * Where AI tools keep per-user state, found by location rather than product name:
 *  - home dot-folders (~/.claude, ~/.codex, ~/.gemini, ~/.antigravity, ...)
 *  - per-OS application config roots (%APPDATA%, %LOCALAPPDATA%,
 *    ~/Library/Application Support, ~/.config)
 * Each root is labelled with its folder name, which is all the report needs.
 */

// Folders inside app roots that hold caches, logs or bulk data, never configuration.
const NOISE_DIR = /(cache|^logs?$|crash|gpu|indexeddb|local storage|session storage|service worker|blob_storage|webstorage|shadercache|^node_modules$|^extensions$|^resources$|^locales$|^workspacestorage$|^history$|^backups$|^temp$|^tmp$|^packages$|^dist$|^user data$)/i;

// Configs sit near the top of an app folder (deepest known: User/globalStorage/<ext>/settings/),
// so a shallow breadth-first walk with small budgets finds them without crawling big app trees.
const MAX_DEPTH = 4;
const MAX_DIRS_PER_ROOT = 60;
const MAX_DIRS_TOTAL = 4000;

function listDirs(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory() && !e.isSymbolicLink());
  } catch {
    return [];
  }
}

function appConfigRoots(home, platformId) {
  if (platformId === 'windows') return [path.join(home, 'AppData', 'Roaming'), path.join(home, 'AppData', 'Local')];
  if (platformId === 'darwin') return [path.join(home, 'Library', 'Application Support')];
  return [path.join(home, '.config')];
}

/** [{ dir, label, home, kind: 'dot' | 'app' }] for every user home. */
function agentRoots(platform) {
  const roots = [];
  const platformId = platform.id === 'windows' ? 'windows' : platform.id === 'darwin' ? 'darwin' : 'linux';
  for (const home of (platform.userHomes || [])) {
    for (const e of listDirs(home)) {
      if (e.name.startsWith('.') && e.name !== '.config' && e.name !== '.cache' && e.name !== '.local') {
        roots.push({ dir: path.join(home, e.name), label: e.name.slice(1), home, kind: 'dot' });
      }
    }
    for (const base of appConfigRoots(home, platformId)) {
      for (const e of listDirs(base)) {
        if (!NOISE_DIR.test(e.name)) roots.push({ dir: path.join(base, e.name), label: e.name, home, kind: 'app' });
      }
    }
  }
  return roots;
}

/**
 * Candidate MCP/agent config files under the roots, chosen by file name and position,
 * never by product: *mcp*.json/.toml anywhere (bounded), editor User/settings.json,
 * a dot-folder's top-level settings.json / config.toml / config.json, Claude Desktop's
 * config, and ~/.claude.json. Returns [{ path, label, home }]; stats (optional) receives
 * { roots, dirs_visited, roots_over_budget }.
 */
function mcpCandidates(platform, roots = agentRoots(platform), stats = {}) {
  const out = [];
  const add = (p, label, home) => out.push({ path: p, label, home });

  for (const home of (platform.userHomes || [])) {
    const claudeJson = path.join(home, '.claude.json');
    const st = statSafe(claudeJson);
    if (st && st.isFile()) add(claudeJson, 'claude', home);
  }

  stats.roots = roots.length;
  stats.dirs_visited = 0;
  stats.roots_over_budget = [];
  for (const root of roots) {
    let budget = MAX_DIRS_PER_ROOT;
    const queue = [[root.dir, 0]];
    while (queue.length > 0) {
      if (budget <= 0 || stats.dirs_visited >= MAX_DIRS_TOTAL) {
        stats.roots_over_budget.push(root.label);
        break;
      }
      const [dir, depth] = queue.shift();
      budget--;
      stats.dirs_visited++;
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        if (e.isSymbolicLink()) continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth < MAX_DEPTH && !NOISE_DIR.test(e.name)) queue.push([full, depth + 1]);
          continue;
        }
        if (!e.isFile()) continue;
        const name = e.name.toLowerCase();
        const isMcpNamed = /mcp/.test(name) && /\.(json|toml)$/.test(name);
        const isEditorSettings = name === 'settings.json' && path.basename(dir).toLowerCase() === 'user';
        const isDotTopConfig = depth === 0 && root.kind === 'dot' && /^(settings\.json|config\.toml|config\.json)$/.test(name);
        const isDesktopConfig = name === 'claude_desktop_config.json';
        if (isMcpNamed || isEditorSettings || isDotTopConfig || isDesktopConfig) add(full, root.label, root.home);
      }
    }
  }
  return out;
}

/**
 * VS Code-family editors by structure: any home dot-folder with extensions/extensions.json
 * (VS Code, Cursor, Windsurf, Antigravity, Kiro, ... and future forks).
 * Returns { label: [extensionsDir] }.
 */
function editorForks(platform, roots = agentRoots(platform)) {
  const forks = {};
  for (const root of roots) {
    if (root.kind !== 'dot') continue;
    const extDir = path.join(root.dir, 'extensions');
    const st = statSafe(path.join(extDir, 'extensions.json'));
    if (st && st.isFile()) (forks[root.label] = forks[root.label] || []).push(extDir);
  }
  return forks;
}

module.exports = { agentRoots, mcpCandidates, editorForks };
