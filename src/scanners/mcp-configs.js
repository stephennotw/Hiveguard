'use strict';

const path = require('path');
const { readJsonSafe, existsSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'mcp-configs';

/**
 * Scan MCP (Model Context Protocol) server configurations.
 * Checks Claude Desktop, Cursor, Windsurf, VS Code config files.
 */
function scan(platform) {
  const configs = [];

  for (const configPath of (platform.mcpConfigPaths || [])) {
    if (typeof configPath !== 'string') continue;
    if (!existsSafe(configPath)) continue;

    const data = readJsonSafe(configPath);
    if (!data) continue;

    // Different config formats
    let mcpServers = {};

    if (data.mcpServers) {
      // Claude Desktop / Cursor format
      mcpServers = data.mcpServers;
    } else if (data.mcp?.servers) {
      // Alternative format
      mcpServers = data.mcp.servers;
    } else if (data['mcp-servers']) {
      mcpServers = data['mcp-servers'];
    }

    const servers = [];
    for (const [name, cfg] of Object.entries(mcpServers)) {
      const server = {
        name,
        transport: cfg.transport || (cfg.command ? 'stdio' : cfg.url ? 'sse' : 'unknown'),
        command: cfg.command || null,
        args: cfg.args || [],
        url: cfg.url || null,
        env_keys: cfg.env ? Object.keys(cfg.env) : [],
        has_credentials: false,
      };

      // Flag if env contains obvious credential patterns
      if (cfg.env) {
        const credPatterns = /api.?key|token|secret|password|auth|credential/i;
        server.has_credentials = Object.keys(cfg.env).some(k => credPatterns.test(k));
      }

      servers.push(server);
    }

    configs.push({
      config_path: configPath,
      config_name: path.basename(path.dirname(configPath)),
      server_count: servers.length,
      servers,
    });

    logger.info(SCANNER_ID, `${path.basename(configPath)}: ${servers.length} servers`);
  }

  return {
    ecosystem: SCANNER_ID,
    configs,
    total_configs: configs.length,
    total_servers: configs.reduce((s, c) => s + c.server_count, 0),
  };
}

module.exports = { scan, SCANNER_ID };
