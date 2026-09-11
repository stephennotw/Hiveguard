'use strict';

const path = require('path');
const { readFileSafe, existsSafe, readdirSafe, statSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'ai-instructions';

const AI_INSTRUCTION_FILES = [
  { file: '.cursorrules', tool: 'Cursor' },
  { file: '.cursorignore', tool: 'Cursor' },
  { file: '.windsurfrules', tool: 'Windsurf' },
  { file: '.github/copilot-instructions.md', tool: 'GitHub Copilot' },
  { file: '.github/copilot-setup-steps.yml', tool: 'GitHub Copilot' },
  { file: '.claude/settings.json', tool: 'Claude Code' },
  { file: '.claude/settings.local.json', tool: 'Claude Code' },
  { file: '.claude/commands', tool: 'Claude Code', isDir: true },
  { file: 'CLAUDE.md', tool: 'Claude Code' },
  { file: 'claude.md', tool: 'Claude Code' },
  { file: '.aider.conf.yml', tool: 'Aider' },
  { file: '.aider.model.settings.yml', tool: 'Aider' },
  { file: '.continue/config.json', tool: 'Continue' },
  { file: '.codeiumrc', tool: 'Codeium' },
  { file: '.sourcegraph/cody.json', tool: 'Cody' },
  { file: '.clinerules', tool: 'Cline' },
  { file: '.roomodes', tool: 'Roo Code' },
  { file: '.roorules', tool: 'Roo Code' },
  { file: 'codex.md', tool: 'Codex' },
  { file: 'AGENTS.md', tool: 'Codex' },
  { file: '.copilot-codegeneration-instructions.md', tool: 'GitHub Copilot' },
];

const SUSPICIOUS_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, label: 'prompt-injection', severity: 'critical' },
  { pattern: /disregard\s+(all\s+)?prior/i, label: 'prompt-injection', severity: 'critical' },
  { pattern: /you\s+are\s+now\s+/i, label: 'role-hijack', severity: 'critical' },
  { pattern: /system\s*:\s*you\s+are/i, label: 'role-hijack', severity: 'critical' },
  { pattern: /\bcurl\b.*\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\bwget\b.*\|\s*(bash|sh|node)\b/, label: 'pipe-to-shell', severity: 'critical' },
  { pattern: /\beval\s*\(/, label: 'eval-call', severity: 'high' },
  { pattern: /\bexec\s*\(/, label: 'exec-call', severity: 'high' },
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/, label: 'ip-address-url', severity: 'high' },
  { pattern: /base64[_\s-]*(decode|encode|atob|btoa)/i, label: 'base64-operation', severity: 'high' },
  { pattern: /\bexfiltrate\b|\bsteal\b|\bextract\s+credentials/i, label: 'exfil-keyword', severity: 'critical' },
  { pattern: /\bsend\b.{0,30}\b(contents?|data|secrets?|tokens?|keys?|credentials?)\b.{0,30}https?:\/\//i, label: 'data-exfil-url', severity: 'critical' },
  { pattern: /\breverse\s+shell\b/i, label: 'reverse-shell', severity: 'critical' },
  { pattern: /never\s+(mention|reveal|tell|disclose|show)/i, label: 'concealment', severity: 'high' },
  { pattern: /do\s+not\s+(mention|reveal|tell|disclose|show)/i, label: 'concealment', severity: 'high' },
  { pattern: /hide\s+(this|these|the)\s+(instruction|rule|file)/i, label: 'concealment', severity: 'high' },
  { pattern: /process\.env\b/, label: 'env-access', severity: 'medium' },
  { pattern: /\.(ssh|gnupg|aws|npmrc|netrc|env)\b/, label: 'credential-file-ref', severity: 'medium' },
  { pattern: /\bchmod\b.*\+[xs]/, label: 'permission-change', severity: 'medium' },
  { pattern: /\bpowershell\b.*-enc/i, label: 'powershell-encoded', severity: 'critical' },
];

function scan(platform, opts = {}) {
  const projectRoots = platform.projectRoots || [];
  const maxDepth = opts.maxDepth || 4;
  const findings = [];
  const inventory = [];

  const projectDirs = findProjectDirs(projectRoots, maxDepth);

  for (const projectDir of projectDirs) {
    for (const entry of AI_INSTRUCTION_FILES) {
      const fullPath = path.join(projectDir, entry.file);

      if (entry.isDir) {
        if (!existsSafe(fullPath)) continue;
        const st = statSafe(fullPath);
        if (!st || !st.isDirectory()) continue;

        const files = readdirSafe(fullPath);
        const mdFiles = files.filter(f => f.endsWith('.md'));
        if (mdFiles.length > 0) {
          inventory.push({
            path: fullPath,
            tool: entry.tool,
            type: 'directory',
            files: mdFiles.length,
            project: projectDir,
          });

          for (const mdFile of mdFiles) {
            const content = readFileSafe(path.join(fullPath, mdFile), { maxBytes: 16384 });
            if (content) {
              const hits = checkContent(content, path.join(fullPath, mdFile), entry.tool, projectDir);
              findings.push(...hits);
            }
          }
        }
        continue;
      }

      if (!existsSafe(fullPath)) continue;
      const st = statSafe(fullPath);
      if (!st || !st.isFile()) continue;

      const content = readFileSafe(fullPath, { maxBytes: 16384 });

      inventory.push({
        path: fullPath,
        tool: entry.tool,
        type: path.extname(entry.file) || 'text',
        size: st.size,
        project: projectDir,
      });

      if (content) {
        const hits = checkContent(content, fullPath, entry.tool, projectDir);
        findings.push(...hits);
      }
    }
  }

  const suspiciousCount = findings.filter(f => f.severity !== 'info').length;
  if (suspiciousCount > 0) {
    logger.warn(SCANNER_ID, `Found ${suspiciousCount} suspicious AI instruction files`);
  } else {
    logger.info(SCANNER_ID, `Inventoried ${inventory.length} AI instruction files across ${projectDirs.length} projects (none suspicious)`);
  }

  return {
    ecosystem: SCANNER_ID,
    projects_scanned: projectDirs.length,
    files_found: inventory.length,
    total_findings: findings.length,
    suspicious: suspiciousCount,
    inventory,
    findings,
  };
}

function checkContent(content, filePath, tool, projectDir) {
  const hits = [];
  const matched = [];

  for (const { pattern, label, severity } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      matched.push({ label, severity });
    }
  }

  if (matched.length > 0) {
    const worstSeverity = matched.reduce((worst, m) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[m.severity] ?? 3) < (order[worst] ?? 3) ? m.severity : worst;
    }, 'low');

    hits.push({
      severity: worstSeverity,
      type: 'suspicious_ai_instruction',
      tool,
      path: filePath,
      project: projectDir,
      triggers: matched.map(m => m.label),
      text: `Suspicious AI instruction file for ${tool} at ${filePath}: ${matched.map(m => m.label).join(', ')}`,
    });
  }

  return hits;
}

function findProjectDirs(roots, maxDepth) {
  const results = new Set();
  const fs = require('fs');

  const PROJECT_MARKERS = new Set([
    'package.json', 'go.mod', 'Cargo.toml', 'composer.json',
    'Gemfile', 'pyproject.toml', 'setup.py', 'pom.xml',
    'build.gradle', '.git',
  ]);

  function walk(dir, depth) {
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }

    let isProject = false;
    for (const entry of entries) {
      if (entry.isFile() && PROJECT_MARKERS.has(entry.name)) {
        isProject = true;
        break;
      }
      if (entry.isDirectory() && entry.name === '.git') {
        isProject = true;
        break;
      }
    }

    if (isProject) {
      results.add(dir);
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.isSymbolicLink()) continue;
      const name = entry.name.toLowerCase();
      if (name === 'node_modules' || name === '.git' || name === '__pycache__'
          || name === 'dist' || name === 'build' || name === 'target'
          || name === '.cache' || name === '.local' || name === 'vendor') continue;
      walk(path.join(dir, entry.name), depth + 1);
    }
  }

  for (const root of roots) {
    if (existsSafe(root)) walk(root, 0);
  }

  return Array.from(results);
}

module.exports = { scan, checkContent, SCANNER_ID };
