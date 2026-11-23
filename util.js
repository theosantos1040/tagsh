'use strict';
/**
 * ShieldCheck v2 — util.js
 * Utilitários compartilhados das Netlify Functions (Node 18, CommonJS, zero deps).
 * - HMAC-SHA256 sign/verify (SHIELD_SECRET, fallback dev)
 * - getIP (x-nf-client-connection-ip > client-ip > x-forwarded-for[0])
 * - fetchIPIntel (ipapi.co timeout 3s, fallback ip-api.com)
 * - helpers JSON (CORS same-origin, só POST)
 * - gerador de captcha SVG de 5 letras com distorção e ruído
 */
const crypto = require('crypto');

/* ------------------------------------------------------------------ */
/* HMAC sign/verify                                                    */
/* ------------------------------------------------------------------ */

function getSecret() {
  return process.env.SHIELD_SECRET || 'dev-secret-trocar-em-producao';
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

function hmac(data) {
  return crypto.createHmac('sha256', getSecret()).update(data).digest();
}

/**
 * Assina um payload (objeto JSON). Formato: base64url(payload).base64url(hmac)
 */
function sign(payload) {
  const body = b64urlJson(payload);
  const mac = b64url(hmac(body));
  return body + '.' + mac;
}

/**
 * Verifica token assinado. Retorna o payload ou null (assinatura/exp inválidos).
 */
function verify(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const body = parts[0];
    const mac = parts[1];
    const expected = b64url(hmac(body));
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));
    if (payload && payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function randomToken(bytes) {
  return b64url(crypto.randomBytes(bytes || 16));
}

/* ------------------------------------------------------------------ */
/* IP do cliente                                                       */
/* ------------------------------------------------------------------ */

function getIP(event) {
  const h = (event && event.headers) || {};
  const pick = (k) => h[k] || h[k.toLowerCase()] || h[k.toUpperCase()] || '';
  let ip = pick('x-nf-client-connection-ip');
  if (!ip) ip = pick('client-ip');
  if (!ip) {
    const xff = pick('x-forwarded-for');
    if (xff) ip = String(xff).split(',')[0].trim();
  }
  return String(ip || '').trim();
}

/* ------------------------------------------------------------------ */
/* Reputação de IP (server-side)                                       */
/* ------------------------------------------------------------------ */

const BAD_ORG_RE = /vpn|proxy|hosting|datacenter|data center|nord|mullvad|proton|digitalocean|ovh|hetzner|contabo|vultr|linode|amazon|aws|google llc|microsoft|oracle|alibaba|tunnel/i;

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then((v) => { clearTimeout(t); resolve(v); },
                 (e) => { clearTimeout(t); reject(e); });
  });
}

async function fetchJson(url, timeoutMs) {
  const res = await withTimeout(fetch(url, {
    headers: { 'User-Agent': 'ShieldCheck/2.0', 'Accept': 'application/json' }
  }), timeoutMs);
  if (!res.ok) throw new Error('http ' + res.status);
  return res.json();
}

/**
 * Consulta reputação do IP. Nunca lança: falha de rede => neutro.
 * Retorna { ip, org, timezone, vpn, proxy, hosting, flagged, source }
 */
async function fetchIPIntel(ip) {
  const out = {
    ip: ip || '', org: '', timezone: '', asn: '',
    vpn: false, proxy: false, hosting: false, flagged: false, source: 'none'
  };
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') ||
      ip.startsWith('192.168.') || ip.startsWith('169.254.')) {
    return out; // IPs privados/loopback: neutro
  }
  // 1) ipapi.co (timeout 3s)
  try {
    const d = await fetchJson('https://ipapi.co/' + encodeURIComponent(ip) + '/json/', 3000);
    if (d && !d.error) {
      out.source = 'ipapi.co';
      out.org = String(d.org || d.asn || '');
      out.timezone = String(d.timezone || '');
      out.asn = String(d.asn || '');
      // ipapi não expõe flags de proxy no plano livre; heurística por org
      const orgHit = BAD_ORG_RE.test(out.org) || BAD_ORG_RE.test(out.asn);
      out.vpn = orgHit;
      out.hosting = orgHit;
      out.proxy = orgHit && /proxy/i.test(out.org);
      out.flagged = orgHit;
      return out;
    }
    throw new Error('ipapi error payload');
  } catch (e) {
    // 2) fallback ip-api.com
    try {
      const d = await fetchJson(
        'http://ip-api.com/json/' + encodeURIComponent(ip) +
        '?fields=status,proxy,hosting,query,org,as,timezone', 3000);
      if (d && d.status === 'success') {
        out.source = 'ip-api.com';
        out.org = String(d.org || '');
        out.asn = String(d.as || '');
        out.timezone = String(d.timezone || '');
        out.proxy = !!d.proxy;
        out.hosting = !!d.hosting;
        const orgHit = BAD_ORG_RE.test(out.org) || BAD_ORG_RE.test(out.asn);
        out.vpn = out.proxy || out.hosting || orgHit;
        out.flagged = out.vpn;
        return out;
      }
    } catch (e2) {
      /* neutro */
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Helpers HTTP (CORS same-origin, só POST)                            */
/* ------------------------------------------------------------------ */

function json(statusCode, obj, extraHeaders) {
  return {
    statusCode,
    headers: Object.assign({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    }, extraHeaders || {}),
    body: JSON.stringify(obj)
  };
}

/** Retorna resposta de erro se o método não for POST; senão null. */
function rejectNonPost(event) {
  if (!event || event.httpMethod !== 'POST') {
    return json(405, { ok: false, error: 'method_not_allowed' }, { 'Allow': 'POST' });
  }
  return null;
}

function parseBody(event) {
  try {
    if (!event || !event.body) return {};
    return JSON.parse(event.body);
  } catch (e) {
    return {};
  }
}

/* ------------------------------------------------------------------ */
/* Captcha SVG — 5 letras, sem I/O/1/0                                 */
/* ------------------------------------------------------------------ */

const CAPTCHA_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // sem I, O (e sem dígitos 1/0)

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

const CAPTCHA_COLORS = ['#38bdf8', '#7dd3fc', '#0ea5e9', '#818cf8', '#a5b4fc', '#67e8f9', '#e2e8f0'];

/**
 * Gera captcha de 5 letras. Retorna { code, svg }.
 * Cada letra: rotação/translação/cor aleatória + 3-4 linhas de ruído.
 */
function generateCaptcha() {
  let code = '';
  for (let i = 0; i < 5; i++) code += CAPTCHA_ALPHABET[randInt(0, CAPTCHA_ALPHABET.length - 1)];

  const W = 240, H = 80;
  let parts = [];
  parts.push('<rect width="' + W + '" height="' + H + '" fill="#0f172a" rx="10"/>');

  // linhas de ruído (3-4), atrás das letras
  const noiseCount = randInt(3, 4);
  for (let i = 0; i < noiseCount; i++) {
    const x1 = randInt(0, 40), y1 = randInt(5, H - 5);
    const x2 = randInt(W - 40, W), y2 = randInt(5, H - 5);
    const cx = randInt(40, W - 40), cy = randInt(0, H);
    const color = pick(CAPTCHA_COLORS);
    parts.push('<path d="M' + x1 + ' ' + y1 + ' Q' + cx + ' ' + cy + ' ' + x2 + ' ' + y2 +
      '" stroke="' + color + '" stroke-width="' + randInt(1, 2) +
      '" fill="none" opacity="0.45"/>');
  }
  // alguns pontos de ruído
  for (let i = 0; i < 18; i++) {
    parts.push('<circle cx="' + randInt(4, W - 4) + '" cy="' + randInt(4, H - 4) +
      '" r="' + (Math.random() * 1.4 + 0.4).toFixed(1) + '" fill="#334155" opacity="0.7"/>');
  }

  // letras
  const step = (W - 40) / 5;
  for (let i = 0; i < 5; i++) {
    const ch = code[i];
    const x = 24 + step * i + randInt(-4, 4);
    const y = randInt(48, 58);
    const rot = randInt(-28, 28);
    const size = randInt(30, 38);
    const color = pick(CAPTCHA_COLORS);
    const skew = randInt(-12, 12);
    parts.push('<text x="' + x + '" y="' + y + '" ' +
      'transform="rotate(' + rot + ' ' + x + ' ' + y + ') skewX(' + skew + ')" ' +
      'font-family="Georgia, \'Times New Roman\', serif" font-weight="700" ' +
      'font-size="' + size + '" fill="' + color + '" ' +
      'style="letter-spacing:2px">' + ch + '</text>');
  }

  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + W + '" height="' + H +
    '" viewBox="0 0 ' + W + ' ' + H + '">' + parts.join('') + '</svg>';
  return { code, svg };
}

module.exports = {
  getSecret, sign, verify, randomToken,
  getIP, fetchIPIntel, BAD_ORG_RE,
  json, rejectNonPost, parseBody,
  generateCaptcha, CAPTCHA_ALPHABET
};
