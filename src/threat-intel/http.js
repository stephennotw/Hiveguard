'use strict';

const https = require('https');

const MAX_BODY_BYTES = 50 * 1024 * 1024;

/**
 * Minimal HTTPS request helper. Resolves { status, headers, body } for any status;
 * rejects only on network errors, timeouts, or oversized bodies.
 */
function request(url, { method = 'GET', body = null, headers = {}, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = body == null ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const reqHeaders = { 'User-Agent': 'hiveguard', ...headers };
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

module.exports = { request };
