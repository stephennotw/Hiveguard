'use strict';

const path = require('path');
const { readFileSafe } = require('../utils/fs-safe');
const logger = require('../utils/logger');

const SCANNER_ID = 'ai-usage';
const MAX_FILE_BYTES = 256 * 1024;

// Well-known environment variable names per provider (stable, a handful of vendors).
const PROVIDER_VARS = {
  ANTHROPIC_API_KEY: 'anthropic', CLAUDE_API_KEY: 'anthropic', ANTHROPIC_AUTH_TOKEN: 'anthropic',
  OPENAI_API_KEY: 'openai', AZURE_OPENAI_API_KEY: 'azure-openai',
  GEMINI_API_KEY: 'google', GOOGLE_API_KEY: 'google', GOOGLE_GENERATIVE_AI_API_KEY: 'google',
  HF_TOKEN: 'huggingface', HUGGINGFACE_API_KEY: 'huggingface', HUGGING_FACE_HUB_TOKEN: 'huggingface',
  GROQ_API_KEY: 'groq', MISTRAL_API_KEY: 'mistral', XAI_API_KEY: 'xai', DEEPSEEK_API_KEY: 'deepseek',
  OPENROUTER_API_KEY: 'openrouter', COHERE_API_KEY: 'cohere', CO_API_KEY: 'cohere',
  PERPLEXITY_API_KEY: 'perplexity', PPLX_API_KEY: 'perplexity', TOGETHER_API_KEY: 'together',
  FIREWORKS_API_KEY: 'fireworks', REPLICATE_API_TOKEN: 'replicate', VOYAGE_API_KEY: 'voyage',
  AWS_BEARER_TOKEN_BEDROCK: 'aws-bedrock',
};

// Key formats with a provider-specific prefix. Values are never stored or reported.
const KEY_PATTERNS = [
  [/\bsk-ant-[a-z]+\d*-[A-Za-z0-9_-]{20,}/, 'anthropic'],
  [/\bsk-or-v1-[a-f0-9]{20,}/, 'openrouter'],
  [/\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/, 'openai'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, 'google'],
  [/\bhf_[A-Za-z0-9]{30,}\b/, 'huggingface'],
  [/\bgsk_[A-Za-z0-9]{40,}\b/, 'groq'],
  [/\bxai-[A-Za-z0-9]{40,}\b/, 'xai'],
  [/\bpplx-[A-Za-z0-9]{30,}\b/, 'perplexity'],
  [/\br8_[A-Za-z0-9]{30,}\b/, 'replicate'],
];

// NAME=value, export NAME=value, NAME: value, $env:NAME = value; setx NAME value; fish: set -gx NAME value
const ASSIGNMENTS = [
  /^\s*(?:export\s+|\$env:)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*)$/i,
  /^\s*setx\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$/i,
  /^\s*set\s+(?:-[a-zA-Z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$/,
];
const PLACEHOLDER = /^(|your[-_ ]?.*|<.*>|x{3,}.*|changeme|replace[-_ ]?me.*|todo|none|null|undefined|\.\.\.|sk-\.\.\..*)$/i;
const REFERENCE = /^(\$|%|`)/;
const ENV_FILE = /^\.env(\.[\w.-]+)?$/;
const EXAMPLE_ENV = /\.(example|sample|template|dist|defaults?)$/i;

/** onDir callback for walkSync collecting .env files (not examples). */
function envFileCollector(out) {
  return (dir, entries, info = {}) => {
    for (const e of entries) {
      if (e.isFile() && ENV_FILE.test(e.name) && !EXAMPLE_ENV.test(e.name)) out.push({ path: path.join(dir, e.name), cloud: !!info.cloud });
    }
  };
}

function shellProfiles(home) {
  return [
    '.bashrc', '.bash_profile', '.profile', '.zshrc', '.zprofile', '.zshenv', '.config/fish/config.fish',
    'Documents/PowerShell/Microsoft.PowerShell_profile.ps1',
    'Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1',
  ].map(rel => path.join(home, ...rel.split('/')));
}

/** Providers whose credentials appear in plain text in this file content. */
function providersInText(text) {
  const hits = new Map(); // provider -> { how, variable }
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('//')) continue;
    const m = ASSIGNMENTS.map(re => t.match(re)).find(Boolean);
    if (m && PROVIDER_VARS[m[1].toUpperCase()]) {
      const value = m[2].replace(/\s+#.*$/, '').trim().replace(/^["']|["';]+$/g, '');
      if (value.length >= 8 && !PLACEHOLDER.test(value) && !REFERENCE.test(value)) {
        const provider = PROVIDER_VARS[m[1].toUpperCase()];
        if (!hits.has(provider)) hits.set(provider, { how: 'variable', variable: m[1].toUpperCase() });
      }
    }
    for (const [re, provider] of KEY_PATTERNS) {
      if (re.test(t) && !hits.has(provider)) hits.set(provider, { how: 'key-pattern', variable: null });
    }
  }
  return hits;
}

// Popular AI SDKs per ecosystem: a short list that changes slowly.
const SDKS = {
  npm: ['openai', '@anthropic-ai/sdk', '@anthropic-ai/claude-agent-sdk', '@google/generative-ai', '@google/genai',
    '@mistralai/mistralai', 'groq-sdk', 'cohere-ai', 'ai', 'langchain', 'llamaindex', 'ollama', '@huggingface/inference',
    '@huggingface/transformers', '@xenova/transformers', '@modelcontextprotocol/sdk', 'replicate',
    '@aws-sdk/client-bedrock-runtime', '@azure/openai', 'onnxruntime-node', 'node-llama-cpp', '@openai/agents'],
  npmPrefixes: ['@ai-sdk/', '@langchain/', '@tensorflow/tfjs'],
  pypi: ['openai', 'anthropic', 'google-generativeai', 'google-genai', 'mistralai', 'groq', 'cohere', 'langchain',
    'llama-index', 'transformers', 'torch', 'tensorflow', 'keras', 'onnxruntime', 'sentence-transformers',
    'huggingface-hub', 'ollama', 'llama-cpp-python', 'vllm', 'litellm', 'crewai', 'pyautogen', 'mcp', 'fastmcp',
    'openai-agents', 'dspy', 'semantic-kernel', 'diffusers', 'peft', 'tiktoken', 'chromadb'],
  pypiPrefixes: ['langchain-', 'llama-index-', 'autogen'],
  go: ['github.com/sashabaranov/go-openai', 'github.com/openai/openai-go', 'github.com/anthropics/anthropic-sdk-go',
    'github.com/google/generative-ai-go', 'google.golang.org/genai', 'github.com/tmc/langchaingo', 'github.com/ollama/ollama',
    'github.com/mark3labs/mcp-go', 'github.com/modelcontextprotocol/go-sdk'],
  cargo: ['async-openai', 'ollama-rs', 'candle-core', 'rig-core', 'tch', 'ort', 'llama-cpp-2', 'rmcp'],
  rubygems: ['ruby-openai', 'anthropic', 'langchainrb', 'ruby_llm'],
  composer: ['openai-php/client', 'llphant/llphant'],
};

function sdkName(pkg) {
  const eco = (pkg.ecosystem || '').toLowerCase();
  const name = String(pkg.name || '');
  // PyPI names compare case-insensitively with -, _ and . equivalent (PEP 503).
  const key = eco === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
  const list = SDKS[eco] || [];
  if (list.includes(key)) return name;
  const prefixes = SDKS[`${eco}Prefixes`] || [];
  if (prefixes.some(p => key.startsWith(p))) return name;
  if (eco === 'go' && list.some(m => name === m || name.startsWith(m + '/'))) return name;
  return null;
}

/**
 * AI usage signals: provider credentials (by variable name or key format, never the
 * value) in .env files, shell profiles and MCP configs; AI SDKs in the dependency
 * inventory. envFiles: [{ path, cloud }] from the shared walk.
 */
function scan(platform, opts = {}, inputs = {}) {
  const { envFiles = [], mcpConfigs = [], packages = [] } = inputs;
  const providers = [];
  const add = (provider, source, p, hit) => {
    if (providers.some(x => x.provider === provider && x.path === p)) return;
    providers.push({ provider, source, path: p, how: hit.how, variable: hit.variable });
  };

  for (const f of envFiles) {
    if (f.cloud) continue;
    const text = readFileSafe(f.path, { maxBytes: MAX_FILE_BYTES });
    if (text) for (const [provider, hit] of providersInText(text)) add(provider, 'env-file', f.path, hit);
  }
  for (const home of (platform.userHomes || [])) {
    for (const p of shellProfiles(home)) {
      const text = readFileSafe(p, { maxBytes: MAX_FILE_BYTES });
      if (text) for (const [provider, hit] of providersInText(text)) add(provider, 'shell-profile', p, hit);
    }
  }
  for (const cfg of mcpConfigs) {
    for (const srv of (cfg.servers || [])) {
      // Only literal values count as plain-text credentials; references (${env:X}) do not.
      for (const key of (srv.env_literal_keys || [])) {
        const provider = PROVIDER_VARS[String(key).toUpperCase()];
        if (provider) add(provider, 'mcp-config', cfg.config_path, { how: 'variable', variable: String(key).toUpperCase() });
      }
    }
  }

  const sdkMap = new Map();
  for (const pkg of packages) {
    if (String(pkg.project || '').startsWith('MCP: ')) continue;
    const name = sdkName(pkg);
    if (!name) continue;
    const key = `${pkg.ecosystem}:${name}`;
    if (!sdkMap.has(key)) sdkMap.set(key, { ecosystem: pkg.ecosystem, name, versions: new Set(), projects: new Set() });
    const e = sdkMap.get(key);
    if (pkg.version) e.versions.add(pkg.version);
    e.projects.add(pkg.source || pkg.project || '');
  }
  const sdks = [...sdkMap.values()]
    .map(e => ({ ecosystem: e.ecosystem, name: e.name, versions: [...e.versions].sort(), projects: e.projects.size }))
    .sort((a, b) => b.projects - a.projects || a.name.localeCompare(b.name));

  logger.info(SCANNER_ID, `AI provider credentials in ${providers.length} place(s); ${sdks.length} AI SDK(s) in dependencies`);
  return { ecosystem: SCANNER_ID, providers, sdks };
}

module.exports = { scan, SCANNER_ID, envFileCollector, providersInText, sdkName };
