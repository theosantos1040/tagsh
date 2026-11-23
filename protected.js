'use strict';
/**
 * Vercel Serverless Function — GATE de conteúdo protegido.
 * O vercel.json reescreve para cá tudo que não é /api/*, index.html ou assets.
 *
 *  - Cookie sc_pass válido (HMAC + exp, typ 'pass') => serve protected.html (200),
 *    com o score do token injetado no HTML.
 *  - Alternativa "sem cookie": ?t=<passToken> válido => valida, seta o cookie
 *    sc_pass e serve a página (200).
 *  - Inválido/ausente/expirado => 403 com página de bloqueio (dark premium) e
 *    botão "Verificar agora" apontando para /?next=<caminho original>.
 */
const { verify } = require('../lib/util');
// Página protegida embutida como string (não existe como arquivo estático,
// então nenhum acesso direto a /protected.html a expõe fora do gate).
const PROTECTED_HTML = require('../lib/protected-page');

const COOKIE_NAME = 'sc_pass';
const COOKIE_MAX_AGE = 600; // 10 min, igual à validade do passToken

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) {
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim();
      if (k) out[k] = v;
    }
  });
  return out;
}

function passCookie(token, secure) {
  return COOKIE_NAME + '=' + token +
    '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + COOKIE_MAX_AGE +
    (secure ? '; Secure' : '');
}

/** Página de bloqueio 403 (dark premium, zero emojis). */
function blockPage(expired) {
  const title = expired ? 'Sessão expirada' : 'Conteúdo protegido';
  const msg = expired
    ? 'Sua sessão de verificação expirou ou é inválida. Faça uma nova verificação rápida para continuar de onde parou.'
    : 'Esta página é protegida contra bots e acessos automatizados. Conclua a verificação rápida para continuar — leva só alguns segundos.';
  return '<!DOCTYPE html>\n' +
'<html lang="pt-BR">\n' +
'<head>\n' +
'<meta charset="UTF-8">\n' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
'<meta name="robots" content="noindex, nofollow">\n' +
'<title>' + title + ' — ShieldCheck</title>\n' +
'<style>\n' +
'    :root {\n' +
'        --bg: #0a0e1a; --panel: #111827; --panel-2: #0d1424;\n' +
'        --accent: #38bdf8; --accent-soft: rgba(56,189,248,0.14);\n' +
'        --text: #e5e7eb; --muted: #94a3b8; --warn: #fbbf24;\n' +
'        --border: rgba(148,163,184,0.14);\n' +
'    }\n' +
'    * { box-sizing: border-box; }\n' +
'    html, body { height: 100%; }\n' +
'    body {\n' +
'        margin: 0;\n' +
'        background:\n' +
'            radial-gradient(1000px 500px at 80% -10%, rgba(56,189,248,0.08), transparent 60%),\n' +
'            radial-gradient(800px 400px at 10% 110%, rgba(56,189,248,0.06), transparent 60%),\n' +
'            var(--bg);\n' +
'        color: var(--text);\n' +
'        font-family: "Inter", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;\n' +
'        display: flex; flex-direction: column; align-items: center; justify-content: center;\n' +
'        min-height: 100vh; padding: 24px; -webkit-font-smoothing: antialiased;\n' +
'    }\n' +
'    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 22px; color: var(--text); letter-spacing: 0.2px; font-weight: 600; font-size: 15px; }\n' +
'    .brand svg { color: var(--accent); }\n' +
'    .brand small { color: var(--muted); font-weight: 400; }\n' +
'    .card {\n' +
'        width: 100%; max-width: 460px; text-align: center;\n' +
'        background: linear-gradient(180deg, var(--panel), var(--panel-2));\n' +
'        border: 1px solid var(--border); border-radius: 16px; padding: 36px 28px;\n' +
'        box-shadow: 0 24px 60px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.03);\n' +
'    }\n' +
'    .icon {\n' +
'        width: 54px; height: 54px; border-radius: 50%; margin: 2px auto 16px;\n' +
'        background: rgba(251,191,36,0.12); color: var(--warn);\n' +
'        display: flex; align-items: center; justify-content: center;\n' +
'    }\n' +
'    .icon svg { width: 26px; height: 26px; }\n' +
'    h1 { font-size: 19px; font-weight: 650; margin: 0 0 8px; }\n' +
'    .sub { color: var(--muted); font-size: 13.5px; margin: 0 0 22px; line-height: 1.6; }\n' +
'    .btn {\n' +
'        appearance: none; border: 0; cursor: pointer; text-decoration: none;\n' +
'        display: inline-flex; align-items: center; justify-content: center; gap: 9px;\n' +
'        background: linear-gradient(180deg, #4cc7fb, #1ea5e8);\n' +
'        color: #04121f; font-weight: 700; font-size: 14.5px;\n' +
'        padding: 13px 26px; border-radius: 11px; min-width: 220px;\n' +
'        box-shadow: 0 10px 26px rgba(56,189,248,0.28), inset 0 1px 0 rgba(255,255,255,0.35);\n' +
'        transition: transform 0.12s ease, box-shadow 0.2s ease, filter 0.2s ease;\n' +
'        user-select: none;\n' +
'    }\n' +
'    .btn:hover { filter: brightness(1.06); box-shadow: 0 14px 32px rgba(56,189,248,0.34); }\n' +
'    .btn:active { transform: translateY(1px) scale(0.99); }\n' +
'    .btn svg { width: 16px; height: 16px; }\n' +
'    .foot { margin-top: 18px; font-size: 11.5px; color: #64748b; display: flex; align-items: center; justify-content: center; gap: 6px; }\n' +
'    .foot svg { width: 12px; height: 12px; }\n' +
'</style>\n' +
'</head>\n' +
'<body>\n' +
'<div class="brand">\n' +
'    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>\n' +
'    ShieldCheck <small>verificação anti-bot</small>\n' +
'</div>\n' +
'<main class="card">\n' +
'    <div class="icon">\n' +
'        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>\n' +
'    </div>\n' +
'    <h1>' + title + '</h1>\n' +
'    <p class="sub">' + msg + '</p>\n' +
'    <a class="btn" id="btn-verify" href="/?next=/">\n' +
'        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>\n' +
'        Verificar agora\n' +
'    </a>\n' +
'    <div class="foot">\n' +
'        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>\n' +
'        Protegido por ShieldCheck — acesso liberado somente após verificação\n' +
'    </div>\n' +
'</main>\n' +
'<script>\n' +
'(function () {\n' +
'    // O rewrite da Vercel preserva a URL original no navegador: monta o\n' +
'    // "next" com o caminho (e query) que o usuário tentou acessar.\n' +
'    try {\n' +
'        var p = window.location.pathname || "/";\n' +
'        if (p.charAt(0) !== "/" || p.charAt(1) === "/") p = "/";\n' +
'        var alvo = p + (window.location.search || "");\n' +
'        document.getElementById("btn-verify").setAttribute("href", "/?next=" + encodeURIComponent(alvo));\n' +
'    } catch (e) { /* mantém href padrão */ }\n' +
'})();\n' +
'</script>\n' +
'</body>\n' +
'</html>\n';
}

module.exports = async (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.status(405);
    res.setHeader('Allow', 'GET, HEAD');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send('Method Not Allowed');
    return;
  }

  const secure = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  const cookies = parseCookies(req.headers.cookie);
  let token = cookies[COOKIE_NAME] || '';
  let viaQuery = false;

  // modo "sem cookie": aceita ?t=<passToken> como alternativa ao cookie
  if (!token) {
    try {
      const u = new URL(req.url || '/', 'http://localhost');
      const t = u.searchParams.get('t');
      if (t) { token = t; viaQuery = true; }
    } catch (e) { /* sem query utilizável */ }
  }

  const hadCredential = !!token;
  const tok = token ? verify(token) : null;
  const valid = !!(tok && tok.typ === 'pass');

  if (!valid) {
    res.status(403);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(blockPage(hadCredential));
    return;
  }

  let html = PROTECTED_HTML;

  // score vem do token assinado (cookie HttpOnly não é legível no cliente)
  html = html.replace(/__SCORE__/g, String(tok.score || 0));

  res.status(200);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (viaQuery) {
    // ?t= válido => já seta o cookie para as próximas navegações
    res.setHeader('Set-Cookie', passCookie(token, secure));
  }
  res.send(html);
};
