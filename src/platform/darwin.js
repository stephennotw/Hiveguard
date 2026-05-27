'use strict';

const os = require('os');
const path = require('path');

const home = os.homedir();
const library = path.join(home, 'Library');

module.exports = {
  id: 'darwin',

  projectRoots: [
    home,
    path.join(home, 'Documents'),
    path.join(home, 'Developer'),
    path.join(home, 'Projects'),
    path.join(home, 'repos'),
    path.join(home, 'Desktop'),
    '/opt/homebrew',
    '/usr/local',
  ],

  pythonRoots: [
    home,
    '/usr/local/lib/python*',
    '/opt/homebrew/lib/python*',
    path.join(library, 'Python'),
  ],

  pythonSitePackages: [
    '/usr/local/lib/python*/site-packages',
    '/opt/homebrew/lib/python*/site-packages',
    path.join(home, '.local', 'lib', 'python*', 'site-packages'),
  ],

  npmGlobalDirs: [
    '/usr/local/lib/node_modules',
    '/opt/homebrew/lib/node_modules',
    path.join(home, '.npm-global'),
  ],

  editorExtensionDirs: {
    vscode: path.join(home, '.vscode', 'extensions'),
    windsurf: path.join(home, '.windsurf', 'extensions'),
    cursor: path.join(home, '.cursor', 'extensions'),
    vscodium: path.join(home, '.vscode-oss', 'extensions'),
  },

  browserExtensionDirs: {
    chrome: path.join(library, 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions'),
    edge: path.join(library, 'Application Support', 'Microsoft Edge', 'Default', 'Extensions'),
    brave: path.join(library, 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default', 'Extensions'),
    firefox_profiles: path.join(library, 'Application Support', 'Firefox', 'Profiles'),
    safari_extensions: path.join(library, 'Safari', 'Extensions'),
  },

  mcpConfigPaths: [
    path.join(library, 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    path.join(library, 'Application Support', 'Code', 'User', 'settings.json'),
  ],

  sshDir: path.join(home, '.ssh'),
  gitConfigPath: path.join(home, '.gitconfig'),

  envSearchRoots: [
    home,
    path.join(home, 'Documents'),
    path.join(home, 'Developer'),
    path.join(home, 'Projects'),
    path.join(home, 'repos'),
  ],

  goModCache: path.join(home, 'go', 'pkg', 'mod', 'cache'),
  cargoRegistry: path.join(home, '.cargo', 'registry'),
  composerGlobalDir: path.join(home, '.composer'),
};
