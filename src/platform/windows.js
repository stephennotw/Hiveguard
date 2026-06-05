'use strict';

const path = require('path');

/**
 * Generate Windows platform config for a given user home directory.
 * Called once per discovered user profile to enable multi-user scanning.
 */
module.exports = function getConfig(home) {
  const appData = path.join(home, 'AppData', 'Roaming');
  const localAppData = path.join(home, 'AppData', 'Local');

  return {
    id: 'windows',

    /** Directories to scan for project lockfiles */
    projectRoots: [
      home,
      path.join(home, 'Documents'),
      path.join(home, 'source'),
      path.join(home, 'repos'),
      path.join(home, 'projects'),
      path.join(home, 'Desktop'),
      'C:\\Projects',
      'C:\\dev',
      // OneDrive paths
      path.join(home, 'OneDrive'),
      path.join(home, 'OneDrive - *'),
    ],

    /** Python dist-info search roots */
    pythonRoots: [
      home,
      'C:\\Python*',
      path.join(localAppData, 'Programs', 'Python'),
      path.join(appData, 'Python'),
    ],

    /** Python global site-packages paths */
    pythonSitePackages: [
      path.join(localAppData, 'Programs', 'Python', '**', 'Lib', 'site-packages'),
    ],

    /** Global npm prefix */
    npmGlobalDirs: [
      path.join(appData, 'npm'),
      path.join(localAppData, 'npm'),
    ],

    /** Editor extension directories */
    editorExtensionDirs: {
      vscode: [path.join(home, '.vscode', 'extensions')],
      windsurf: [path.join(home, '.windsurf', 'extensions')],
      cursor: [path.join(home, '.cursor', 'extensions')],
      vscodium: [path.join(home, '.vscode-oss', 'extensions')],
    },

    /** Browser extension directories */
    browserExtensionDirs: {
      chrome: [path.join(localAppData, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions')],
      edge: [path.join(localAppData, 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions')],
      brave: [path.join(localAppData, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Extensions')],
      firefox_profiles: [path.join(appData, 'Mozilla', 'Firefox', 'Profiles')],
    },

    /** MCP config file locations */
    mcpConfigPaths: [
      path.join(appData, 'Claude', 'claude_desktop_config.json'),
      path.join(home, '.cursor', 'mcp.json'),
      path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
      path.join(appData, 'Code', 'User', 'settings.json'),
    ],

    /** SSH directories */
    sshDirs: [path.join(home, '.ssh')],

    /** Git config paths */
    gitConfigPaths: [path.join(home, '.gitconfig')],

    /** Common .env search roots */
    envSearchRoots: [
      home,
      path.join(home, 'Documents'),
      path.join(home, 'source'),
      path.join(home, 'repos'),
      path.join(home, 'projects'),
    ],

    /** Go module cache */
    goModCache: path.join(home, 'go', 'pkg', 'mod', 'cache'),

    /** Cargo registry */
    cargoRegistry: path.join(home, '.cargo', 'registry'),

    /** Composer global dir */
    composerGlobalDir: path.join(appData, 'Composer'),
  };
};
