'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const VERSION = require('../version');
const logger = require('../utils/logger');

const MAX_BODY_BYTES = 50 * 1024 * 1024;
const USER_AGENT = `hiveguard/${VERSION}`;

const warnedProxies = new Set();
function warnProxyOnce(value, reason) {
  if (warnedProxies.has(value)) return;
  warnedProxies.add(value);
  logger.warn('http', `Ignoring HTTPS_PROXY (${reason}); connecting directly`);
}

/**
 * Normalised proxy URL, or null when unusable. "host:port" gets an http:// scheme;
 * only http:// and https:// proxies (HTTP CONNECT) are supported.
 */
function normalizeProxy(value) {
  const raw = String(value).trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let parsed;
  try { parsed = new URL(withScheme); } catch {
    warnProxyOnce(raw, 'not a valid URL');
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    warnProxyOnce(raw, `unsupported scheme ${parsed.protocol}`);
    return null;
  }
  if (!parsed.hostname) {
    warnProxyOnce(raw, 'no host');
    return null;
  }
  return parsed.href;
}

/**
 * Proxy URL for a target, from HTTPS_PROXY/https_proxy, honouring NO_PROXY/no_proxy
 * (comma-separated hosts or .suffixes; "*" disables). Returns null for direct access.
 */
function proxyFor(targetUrl, env = process.env) {
  const configured = env.HTTPS_PROXY || env.https_proxy;
  if (!configured) return null;
  const proxy = normalizeProxy(configured);
  if (!proxy) return null;
  const host = new URL(targetUrl).hostname.toLowerCase();
  const noProxy = (env.NO_PROXY || env.no_proxy || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  for (const entry of noProxy) {
    if (entry === '*') return null;
    const bare = entry.replace(/^\*?\./, '').replace(/:\d+$/, '');
    if (host === bare || host.endsWith('.' + bare)) return null;
  }
  return proxy;
}

// https.Agent that reaches the target through an HTTP CONNECT tunnel.
class TunnelAgent extends https.Agent {
  constructor(proxyUrl) {
    super({ keepAlive: false });
    this.proxy = new URL(proxyUrl);
  }

  createConnection(options, callback) {
    const target = `${options.host}:${options.port || 443}`;
    let done = false;
    const finish = (err, socket) => {
      if (done) return;
      done = true;
      callback(err, socket);
    };
    const headers = { Host: target };
    if (this.proxy.username) {
      const creds = `${decodeURIComponent(this.proxy.username)}:${decodeURIComponent(this.proxy.password)}`;
      headers['Proxy-Authorization'] = `Basic ${Buffer.from(creds).toString('base64')}`;
    }
    const transport = this.proxy.protocol === 'https:' ? https : http;
    const req = transport.request({
      host: this.proxy.hostname,
      port: this.proxy.port || (this.proxy.protocol === 'https:' ? 443 : 80),
      method: 'CONNECT',
      path: target,
      headers,
      agent: false,
    });
    // The request's own timeout only starts once a socket exists, so the CONNECT
    // handshake needs its own; a silent proxy would otherwise hang the scan.
    req.setTimeout(options.timeout || 20000, () => {
      req.destroy(new Error(`proxy CONNECT ${target} timed out`));
    });
    req.once('connect', (res, socket) => {
      req.setTimeout(0);
      if (res.statusCode !== 200) {
        socket.destroy();
        finish(new Error(`proxy CONNECT ${target} failed: ${res.statusCode}`));
        return;
      }
      finish(null, tls.connect({ ...options, socket, servername: options.servername || options.host }));
    });
    req.once('error', (err) => finish(err));
    req.end();
  }
}

const agents = new Map();
function agentFor(url) {
  const proxy = proxyFor(url);
  if (!proxy) return undefined;
  if (!agents.has(proxy)) agents.set(proxy, new TunnelAgent(proxy));
  return agents.get(proxy);
}

/**
 * Minimal HTTPS request helper. Resolves { status, headers, body } for any status;
 * rejects only on network errors, timeouts, or oversized bodies.
 */
function request(url, { method = 'GET', body = null, headers = {}, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = body == null ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const reqHeaders = { 'User-Agent': USER_AGENT, ...headers };
    if (payload != null) {
      reqHeaders['Content-Type'] = reqHeaders['Content-Type'] || 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = https.request({
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: parsed.pathname + parsed.search,
      method,
      headers: reqHeaders,
      timeout,
      agent: agentFor(url),
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (d) => {
        size += d.length;
        if (size > MAX_BODY_BYTES) {
          req.destroy(new Error(`response from ${parsed.hostname} exceeded ${MAX_BODY_BYTES} bytes`));
          return;
        }
        chunks.push(d);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`request to ${parsed.hostname} timed out`)));
    if (payload != null) req.write(payload);
    req.end();
  });
}

module.exports = { request, proxyFor, agentFor, USER_AGENT };
