// Tiny zero-dependency HTTP helpers + router for the control plane.
import http from 'node:http';

export function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > limit) reject(new Error('body too large'));
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

export function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

// Minimal router with :param support. Handlers: async (req, res, ctx) => any|void
export class Router {
  constructor() {
    this.routes = [];
  }
  add(method, pattern, handler, opts = {}) {
    const parts = pattern.split('/').filter(Boolean);
    this.routes.push({ method, parts, handler, raw: !!opts.raw });
    return this;
  }
  get(p, h) { return this.add('GET', p, h); }
  post(p, h) { return this.add('POST', p, h); }
  put(p, h) { return this.add('PUT', p, h); }
  delete(p, h) { return this.add('DELETE', p, h); }
  // raw routes get the unread req stream (no JSON pre-parse / 1MB cap) — for binary bodies like bundles.
  putRaw(p, h) { return this.add('PUT', p, h, { raw: true }); }

  _match(method, pathname) {
    const segs = pathname.split('/').filter(Boolean);
    for (const r of this.routes) {
      if (r.method !== method || r.parts.length !== segs.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < r.parts.length; i++) {
        const p = r.parts[i];
        if (p.startsWith(':')) params[p.slice(1)] = decodeURIComponent(segs[i]);
        else if (p !== segs[i]) { ok = false; break; }
      }
      if (ok) return { handler: r.handler, params, raw: r.raw };
    }
    return null;
  }

  listen(port, host, onReady) {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://x');
      const m = this._match(req.method, url.pathname);
      if (!m) return sendJson(res, 404, { error: 'not found' });
      try {
        const body = (!m.raw && ['POST', 'PUT', 'PATCH'].includes(req.method)) ? await readBody(req) : {};
        const query = Object.fromEntries(url.searchParams);
        const result = await m.handler({ req, res, params: m.params, body, query });
        if (result !== undefined && !res.writableEnded) sendJson(res, 200, result);
      } catch (e) {
        if (!res.writableEnded) sendJson(res, e.status || 400, { error: e.message, code: e.code });
      }
    });
    server.listen(port, host, () => onReady?.(server));
    return server;
  }
}
