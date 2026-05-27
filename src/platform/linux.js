'use strict';

const os = require('os');
const path = require('path');

const home = os.homedir();

module.exports = {
  id: 'linux',

  projectRoots: [
    home,
    path.join(home, 'Documents'),
    path.join(home, 'projects'),
    path.join(home, 'repos'),
    path.join(home, 'dev'),
    path.join(home, 'workspace'),
    '/opt',
    '/srv',
    '/var/www',
  ],

  pythonRoots: [
    home,
    '/usr/lib/python*',
    '/usr/local/lib/python*',
  ],

  pythonSitePackages: [
    '/usr/lib/python*/dist-packages',
    '/usr/local/lib/python*/dist-packages',
    '/usr/lib/python*/site-packages',
    '/usr/local/lib/python*/site-packages',
    path.join(home, '.local', 'lib', 'python*', 'site-packages'),
  ],

  npmGlobalDirs: [
    '/usr/lib/node_modules',
    '/usr/local/lib/node_modules',
    path.join(home, '.npm-global'),
  ],

  editorExtensionDirs: {
    vscode: path.join(home, '.vscode', 'extensions'),
    windsurf: path.join(home, '.windsurf', 'extensions'),
    cursor: path.join(home, '.cursor', 'extensions'),
    vscodium: path.join(home, '.vscode-oss', 'extensions'),
  },

  browserExtensionDirs: {
    chrome: path.join(home, '.config', 'google-chrome', 'Default', 'Extensions'),
    chromium: path.join(home, '.config', 'chromium', 'Default', 'Extensions'),
    edge: path.join(home, '.config', 'microsoft-edge', 'Default', 'Extensions'),
    brave: path.join(home, '.config', 'BraveSoftware', 'Brave-Browser', 'Default', 'Extensions'),
    firefox_profiles: path.join(home, '.mozilla', 'firefox'),
  },

  mcpConfigPaths: [
    path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    path.join(home, '.config', 'Code', 'User', 'settings.json'),
  ],

  sshDir: path.join(home, '.ssh'),
  gitConfigPath: path.join(home, '.gitconfig'),

  envSearchRoots: [
    home,
    path.join(home, 'projects'),
    path.join(home, 'repos'),
    path.join(home, 'dev'),
    '/opt',
    '/srv',
    '/var/www',
  ],

  goModCache: path.join(home, 'go', 'pkg', 'mod', 'cache'),
  cargoRegistry: path.join(home, '.cargo', 'registry'),
  composerGlobalDir: path.join(home, '.composer'),
};
