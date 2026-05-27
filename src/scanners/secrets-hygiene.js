'use strict';

const fs = require('fs');
const path = require('path');
const { readFileSafe, existsSafe, readdirSafe, statSafe, walkSync } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'secrets-hygiene';

/**
 * Lightweight secrets hygiene audit:
 * 1. Detect .env files with potential secrets
 * 2. Check git credential helpers for plaintext tokens
 * 3. Audit SSH keys (type, age, permissions)
 * 
 * NOTE: This scanner NEVER reads secret values — only detects presence and metadata.
 */
function scan(platform) {
  const results = {
    envFiles: scanEnvFiles(platform),
    gitCredentials: scanGitCredentials(platform),
    sshKeys: scanSshKeys(platform),
  };

  const totalFindings = results.envFiles.findings.length
    + results.gitCredentials.findings.length
    + results.sshKeys.findings.length;

  logger.info(SCANNER_ID, `Secrets hygiene: ${totalFindings} findings`);
  return { ecosystem: SCANNER_ID, ...results, totalFindings };
}

/**
 * Find .env files and flag ones likely containing secrets.
 * NEVER reads or logs actual secret values.
 */
function scanEnvFiles(platform) {
  const roots = platform.envSearchRoots || [];
  const foundPaths = [];
  const parsedFiles = [];
  const findings = [];

  for (const root of roots) {
    if (!existsSafe(root)) continue;
    const found = walkSync(root, {
      maxDepth: 4,
      filter: (name) => name === '.env' || name === '.env.local' || name === '.env.production'
        || name === '.env.development' || name.match(/^\.env\.\w+$/),
      skipDirs: ['node_modules', '.git', 'vendor', '__pycache__', '.venv', 'venv'],
    });
    foundPaths.push(...found);
  }

  for (const envFile of foundPaths) {
    const raw = readFileSafe(envFile);
    if (!raw) continue;

    const stat = statSafe(envFile);
    const secretPatterns = /^(.*(?:API_KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE_KEY|DATABASE_URL|MONGO_URI|REDIS_URL|AWS_ACCESS|STRIPE_|SENDGRID_|TWILIO_).*?)=/im;
    const lines = raw.split('\n');
    const secretKeys = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const match = trimmed.match(secretPatterns);
      if (match) {
        const keyName = trimmed.split('=')[0].trim();
        secretKeys.push(keyName);
      }
    }

    parsedFiles.push({
      path: envFile,
      size: stat?.size || 0,
      lineCount: lines.length,
      suspectedSecretKeys: secretKeys.length,
      keyNames: secretKeys.slice(0, 10),
    });

    if (secretKeys.length > 0) {
      findings.push({
        severity: 'medium',
        type: 'env_secrets_detected',
        path: envFile,
        message: `${secretKeys.length} potential secret key(s) found: ${secretKeys.slice(0, 5).join(', ')}${secretKeys.length > 5 ? '...' : ''}`,
      });
    }
  }

  logger.info(SCANNER_ID, `Found ${foundPaths.length} .env files`);
  return { files: foundPaths.length, findings };
}

/**
 * Check git config for credential helpers and plaintext tokens.
 * NEVER reads actual token values.
 */
function scanGitCredentials(platform) {
  const findings = [];
  const gitConfig = readFileSafe(platform.gitConfigPath);

  if (gitConfig) {
    // Check for plaintext credential storage
    if (gitConfig.includes('credential.helper=store') || gitConfig.includes('helper = store')) {
      findings.push({
        severity: 'high',
        type: 'git_plaintext_credentials',
        path: platform.gitConfigPath,
        message: 'Git credential helper is set to "store" — credentials saved in plaintext at ~/.git-credentials',
      });
    }

    // Check for hardcoded tokens in URLs
    const urlTokenPattern = /url\s*=\s*https?:\/\/[^@\s]*:[^@\s]*@/i;
    if (urlTokenPattern.test(gitConfig)) {
      findings.push({
        severity: 'high',
        type: 'git_hardcoded_token',
        path: platform.gitConfigPath,
        message: 'Git config contains URL(s) with embedded credentials',
      });
    }

    // Check for .git-credentials file
    const gitCredsFile = path.join(path.dirname(platform.gitConfigPath), '.git-credentials');
    if (existsSafe(gitCredsFile)) {
      const stat = statSafe(gitCredsFile);
      findings.push({
        severity: 'medium',
        type: 'git_credentials_file',
        path: gitCredsFile,
        message: `Plaintext git credentials file exists (${stat?.size || 0} bytes)`,
      });
    }
  }

  return { findings };
}

/**
 * Audit SSH keys — type, age, permissions.
 * NEVER reads private key content beyond header detection.
 */
function scanSshKeys(platform) {
  const sshDir = platform.sshDir;
  const findings = [];
  const keys = [];

  if (!existsSafe(sshDir)) {
    logger.debug(SCANNER_ID, 'No .ssh directory found');
    return { keys, findings };
  }

  for (const entry of readdirSafe(sshDir)) {
    const filePath = path.join(sshDir, entry);
    const stat = statSafe(filePath);
    if (!stat || !stat.isFile()) continue;

    // Read only first line to detect key type
    const raw = readFileSafe(filePath);
    if (!raw) continue;

    const firstLine = raw.split('\n')[0].trim();
    let keyType = null;
    let isPrivate = false;

    if (firstLine.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
      keyType = 'openssh'; isPrivate = true;
    } else if (firstLine.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
      keyType = 'rsa'; isPrivate = true;
    } else if (firstLine.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
      keyType = 'ec'; isPrivate = true;
    } else if (firstLine.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
      keyType = 'dsa'; isPrivate = true;
    } else if (firstLine.startsWith('ssh-rsa ') || firstLine.startsWith('ssh-ed25519 ')
      || firstLine.startsWith('ecdsa-sha2-')) {
      keyType = firstLine.split(' ')[0];
      isPrivate = false;
    } else {
      continue; // Not a key file
    }

    const ageDays = stat.mtime ? Math.round((Date.now() - stat.mtime.getTime()) / 86400000) : null;

    keys.push({
      filename: entry,
      keyType: keyType,
      isPrivate,
      size: stat.size,
      modified: stat.mtime?.toISOString() || null,
      ageDays,
    });

    // Findings
    if (isPrivate && keyType === 'dsa') {
      findings.push({
        severity: 'high',
        type: 'ssh_weak_key',
        path: filePath,
        message: `DSA key "${entry}" — DSA is deprecated and considered weak. Migrate to Ed25519.`,
      });
    }

    if (isPrivate && keyType === 'rsa') {
      findings.push({
        severity: 'low',
        type: 'ssh_rsa_key',
        path: filePath,
        message: `RSA key "${entry}" — consider migrating to Ed25519 for better security.`,
      });
    }

    if (isPrivate && ageDays && ageDays > 365) {
      findings.push({
        severity: 'low',
        type: 'ssh_old_key',
        path: filePath,
        message: `SSH key "${entry}" is ${ageDays} days old. Consider rotating keys annually.`,
      });
    }
  }

  // Check for authorized_keys (unexpected authorized keys could be persistence)
  const authKeys = path.join(sshDir, 'authorized_keys');
  if (existsSafe(authKeys)) {
    const raw = readFileSafe(authKeys);
    const keyCount = raw ? raw.split('\n').filter(l => l.trim() && !l.startsWith('#')).length : 0;
    if (keyCount > 0) {
      findings.push({
        severity: 'info',
        type: 'ssh_authorized_keys',
        path: authKeys,
        message: `${keyCount} authorized SSH key(s) — review for unexpected entries.`,
      });
    }
  }

  logger.info(SCANNER_ID, `Found ${keys.length} SSH keys, ${findings.length} findings`);
  return { keys, findings };
}

module.exports = { scan, SCANNER_ID };
