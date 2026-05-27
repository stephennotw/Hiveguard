'use strict';

const LEVELS = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };
let currentLevel = LEVELS.info;

function setLevel(level) {
  if (typeof level === 'string') level = LEVELS[level] ?? LEVELS.info;
  currentLevel = level;
}

function log(level, tag, msg, data) {
  if (LEVELS[level] > currentLevel) return;
  const prefix = {
    error: '\x1b[31m✗\x1b[0m',
    warn: '\x1b[33m⚠\x1b[0m',
    info: '\x1b[36mℹ\x1b[0m',
    debug: '\x1b[90m·\x1b[0m'
  }[level] || ' ';

  const line = `${prefix} [${tag}] ${msg}`;
  if (level === 'error') {
    process.stderr.write(line + '\n');
  } else {
    process.stderr.write(line + '\n');
  }
  if (data && currentLevel >= LEVELS.debug) {
    process.stderr.write(`  ${JSON.stringify(data)}\n`);
  }
}

module.exports = {
  setLevel,
  error: (tag, msg, data) => log('error', tag, msg, data),
  warn: (tag, msg, data) => log('warn', tag, msg, data),
  info: (tag, msg, data) => log('info', tag, msg, data),
  debug: (tag, msg, data) => log('debug', tag, msg, data),
};
