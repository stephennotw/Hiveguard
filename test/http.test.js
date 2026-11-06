'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const httpMod = require('node:http');
const { proxyFor, request } = require('../src/threat-intel/http');

describe('proxy support', () => {
  it('uses HTTPS_PROXY unless the host is excluded by NO_PROXY', () => {
    const env = { HTTPS_PROXY: 'http://proxy.corp:8080', NO_PROXY: 'localhost,.internal.corp, example.org' };
    assert.equal(proxyFor('https://api.osv.dev/v1/querybatch', env), 'http://proxy.corp:8080');
    assert.equal(proxyFor('https://svc.internal.corp/x', env), null);
    assert.equal(proxyFor('https://example.org/x', env), null);
    assert.equal(proxyFor('https://api.example.org/x', env), null);
    assert.equal(proxyFor('https://notexample.org/x', env), 'http://proxy.corp:8080');
    assert.equal(proxyFor('https://api.osv.dev/', { https_proxy: 'http://p:1', no_proxy: '*' }), null);
    assert.equal(proxyFor('https://api.osv.dev/', {}), null);
  });

  it('tunnels requests through the proxy with CONNECT and proxy auth', async () => {
    const seen = [];
    const proxy = httpMod.createServer();
    proxy.on('connect', (req, socket) => {
      seen.push({ url: req.url, auth: req.headers['proxy-authorization'] });
      socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    });
    await new Promise(r => proxy.listen(0, '127.0.0.1', r));
    const saved = { HTTPS_PROXY: process.env.HTTPS_PROXY, NO_PROXY: process.env.NO_PROXY, https_proxy: process.env.https_proxy, no_proxy: process.env.no_proxy };
    try {
      delete process.env.https_proxy; delete process.env.no_proxy; delete process.env.NO_PROXY;
      process.env.HTTPS_PROXY = `http://user:p%40ss@127.0.0.1:${proxy.address().port}`;
      await assert.rejects(request('https://api.osv.dev/v1/querybatch', { method: 'POST', body: {}, timeout: 5000 }), /proxy CONNECT api.osv.dev:443 failed: 403/);
      assert.deepEqual(seen, [{ url: 'api.osv.dev:443', auth: `Basic ${Buffer.from('user:p@ss').toString('base64')}` }]);
    } finally {
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      proxy.close();
    }
  });
});
