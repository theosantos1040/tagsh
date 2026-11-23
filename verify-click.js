'use strict';
/**
 * Vercel Serverless Function — POST /api/verify-click
 * Wrapper (req,res) -> event -> handlers/verify-click -> res.
 * O handler emite o header Set-Cookie sc_pass (HttpOnly) ao aprovar o clique.
 * IP real via x-forwarded-for / x-real-ip / socket (Vercel manda x-forwarded-for).
 */
const h = require('../handlers/verify-click');

module.exports = async (req, res) => {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = String(v);
  // IP real: Vercel manda x-forwarded-for / x-real-ip
  headers['x-nf-client-connection-ip'] =
    String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || String(req.headers['x-real-ip'] || '')
    || (req.socket && req.socket.remoteAddress) || '';
  const event = {
    httpMethod: req.method,
    headers,
    body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {})
  };
  const out = await h.handler(event);
  res.status(out.statusCode || 200);
  for (const [k, v] of Object.entries(out.headers || {})) res.setHeader(k, v);
  res.send(out.body || '');
};
