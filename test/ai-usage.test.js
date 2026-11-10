'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, providersInText, sdkName } = require('../src/scanners/ai-usage');

// Fake keys assembled at runtime so no key-shaped literal sits in the source.
const fake = (prefix, n) => prefix + 'A1b2C3d4'.repeat(Math.ceil(n / 8)).slice(0, n);

describe('AI provider credentials', () => {
  const found = (text) => Object.fromEntries([...providersInText(text)].map(([p, h]) => [p, h.how]));

  it('detects well-known variables with real-looking values in env, shell and PowerShell syntax', () => {
    assert.deepEqual(found([
      `ANTHROPIC_API_KEY=${fake('x', 40)}`,
      `export OPENAI_API_KEY="${fake('y', 40)}"`,
      `$env:GEMINI_API_KEY = '${fake('z', 39)}'`,
      `setx GROQ_API_KEY ${fake('g', 40)}`,
      `set -gx MISTRAL_API_KEY ${fake('m', 32)}`,
    ].join('\n')), { anthropic: 'variable', openai: 'variable', google: 'variable', groq: 'variable', mistral: 'variable' });
  });

  it('detects provider key formats wherever they appear', () => {
    assert.deepEqual(found(`const client = new Client("${fake('sk-ant-api03-', 40)}")\nhf = "${fake('hf_', 34)}"`), { anthropic: 'key-pattern', huggingface: 'key-pattern' });
  });

  it('ignores placeholders, references, comments and prose', () => {
    assert.deepEqual(found([
      'OPENAI_API_KEY=your-openai-key-here',
      'ANTHROPIC_API_KEY=<paste key>',
      'GEMINI_API_KEY=',
      'export OPENAI_API_KEY="$(pass show openai)"',
      'GROQ_API_KEY=${{ secrets.GROQ_API_KEY }}',
      `# ANTHROPIC_API_KEY=${fake('x', 40)}`,
      'OPENAI_API_KEY is required to run the examples',
    ].join('\n')), {});
  });
});

describe('AI SDK tagging', () => {
  it('matches SDKs per ecosystem, prefixes and PyPI name normalisation', () => {
    assert.equal(sdkName({ ecosystem: 'npm', name: '@anthropic-ai/sdk' }), '@anthropic-ai/sdk');
    assert.equal(sdkName({ ecosystem: 'npm', name: '@ai-sdk/openai' }), '@ai-sdk/openai');
    assert.equal(sdkName({ ecosystem: 'npm', name: 'express' }), null);
    assert.equal(sdkName({ ecosystem: 'pypi', name: 'Llama_Index' }), 'Llama_Index');
    assert.equal(sdkName({ ecosystem: 'pypi', name: 'langchain-openai' }), 'langchain-openai');
    assert.equal(sdkName({ ecosystem: 'go', name: 'github.com/ollama/ollama/api' }), 'github.com/ollama/ollama/api');
  });
});

describe('ai-usage scan', () => {
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-aiuse-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('combines env files, shell profiles and MCP env keys, skipping cloud files; aggregates SDKs', () => {
    const home = path.join(tmp, 'home');
    const write = (rel, c) => { const p = path.join(home, ...rel.split('/')); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); return p; };
    const env = write('app/.env', `OPENAI_API_KEY=${fake('k', 40)}\nDB=x\n`);
    const cloudEnv = write('OneDrive/app/.env', `ANTHROPIC_API_KEY=${fake('k', 40)}\n`);
    write('.zshrc', `export ANTHROPIC_API_KEY=${fake('k', 40)}\n`);
    const r = scan({ userHomes: [home] }, {}, {
      envFiles: [{ path: env, cloud: false }, { path: cloudEnv, cloud: true }],
      mcpConfigs: [{ config_path: '/cfg/mcp.json', servers: [{ env_keys: ['GITHUB_TOKEN', 'HF_TOKEN', 'OPENAI_API_KEY'], env_literal_keys: ['GITHUB_TOKEN', 'HF_TOKEN'] }] }],
      packages: [
        { ecosystem: 'npm', name: 'openai', version: '4.0.0', source: 'a/package-lock.json' },
        { ecosystem: 'npm', name: 'openai', version: '4.1.0', source: 'b/package-lock.json' },
        { ecosystem: 'npm', name: 'left-pad', version: '1.3.0', source: 'a/package-lock.json' },
      ],
    });
    assert.deepEqual(r.providers.map(p => `${p.provider}:${p.source}:${p.variable}`).sort(),
      ['anthropic:shell-profile:ANTHROPIC_API_KEY', 'huggingface:mcp-config:HF_TOKEN', 'openai:env-file:OPENAI_API_KEY']);
    assert.ok(!JSON.stringify(r).includes(fake('k', 40)), 'key values never appear in output');
    assert.deepEqual(r.sdks, [{ ecosystem: 'npm', name: 'openai', versions: ['4.0.0', '4.1.0'], projects: 2 }]);
  });
});
