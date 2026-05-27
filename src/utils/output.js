'use strict';

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Output module — writes scan results to JSON, CSV, stdout, or future webhook.
 */

function writeJson(filePath, data) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    logger.info('output', `JSON written: ${filePath}`);
    return true;
  } catch (e) {
    logger.error('output', `Failed to write JSON: ${e.message}`);
    return false;
  }
}

function writeStdout(data) {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
}

function writeHtml(filePath, htmlContent) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, htmlContent);
    logger.info('output', `HTML report written: ${filePath}`);
    return true;
  } catch (e) {
    logger.error('output', `Failed to write HTML: ${e.message}`);
    return false;
  }
}

module.exports = { writeJson, writeStdout, writeHtml };
