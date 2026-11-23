'use strict';
/**
 * ShieldCheck v2 — ratelimit.js
 * Modo "Under Attack" + rate limiting por IP.
 *
 * IMPORTANTE (limitação serverless): os contadores vivem em memória de módulo.
 * Em ambiente serverless (Netlify Functions / AWS Lambda) cada instância quente
 * tem a sua própria memória, e instâncias podem ser recicladas a qualquer
 * momento. Portanto este mecanismo é BEST-EFFORT: funciona bem enquanto a mesma
 * instância atende o tráfego, mas não é um registro global garantido. Para
 * precisão total seria necessário um store externo (ex.: Netlify Blobs, Redis).
 */

const WINDOW_MS = 60 * 1000;        // janela deslizante de 60s
const GLOBAL_START_LIMIT = 80;      // >80 starts globais/60s => underAttack
const IP_START_LIMIT = 12;          // >12 starts/60s por IP => IP forçado a challenge
const INVALID_TOKEN_LIMIT = 5;      // >5 submits c/ token inválido/60s por IP => challenge forçado
const UNDER_ATTACK_TTL = 5 * 60 * 1000; // underAttack dura 5min
const KNOWN_GOOD_SCORE = 90;        // score mínimo para entrar no cache de IP bom
const KNOWN_GOOD_TTL = 30 * 60 * 1000;  // cache de IP bom dura 30min
const CLEANUP_INTERVAL = 60 * 1000;

// ---- estado em memória de módulo (best-effort, ver nota acima) ----
const globalStarts = [];            // timestamps dos starts (global)
const ipStarts = new Map();         // ip -> [timestamps]
const ipInvalidTokens = new Map();  // ip -> [timestamps]
const flaggedIps = new Map();       // ip -> timestamp até quando está marcado (0 = indefinido na sessão)
let underAttackUntil = 0;           // timestamp até quando o modo under attack está ON
const knownGoodIps = new Map();     // hash(ip) -> timestamp de expiração
let lastCleanup = 0;

function pruneOld(arr, now) {
  const cutoff = now - WINDOW_MS;
  let i = 0;
  while (i < arr.length && arr[i] <= cutoff) i++;
  if (i > 0) arr.splice(0, i);
  return arr;
}

function pushTs(map, key, now) {
  let arr = map.get(key);
  if (!arr) { arr = []; map.set(key, arr); }
  pruneOld(arr, now);
  arr.push(now);
  return arr.length;
}

function cleanup(now) {
  if (now - lastCleanup < CLEANUP_INTERVAL) return;
  lastCleanup = now;
  pruneOld(globalStarts, now);
  for (const [k, arr] of ipStarts) { pruneOld(arr, now); if (!arr.length) ipStarts.delete(k); }
  for (const [k, arr] of ipInvalidTokens) { pruneOld(arr, now); if (!arr.length) ipInvalidTokens.delete(k); }
  for (const [k, until] of flaggedIps) { if (until && now > until) flaggedIps.delete(k); }
  for (const [k, exp] of knownGoodIps) { if (now > exp) knownGoodIps.delete(k); }
}

/**
 * Registra um verify-start. Retorna { underAttack, ipFlagged }.
 * >80 starts globais/60s => underAttack ON por 5min (expira automaticamente).
 * >12 starts/60s por IP => IP marcado (sempre cai em challenge).
 */
function recordStart(ip) {
  const now = Date.now();
  cleanup(now);

  pruneOld(globalStarts, now);
  globalStarts.push(now);
  if (globalStarts.length > GLOBAL_START_LIMIT) {
    underAttackUntil = now + UNDER_ATTACK_TTL;
  }

  const ipCount = pushTs(ipStarts, ip || 'unknown', now);
  if (ipCount > IP_START_LIMIT) {
    flaggedIps.set(ip || 'unknown', now + UNDER_ATTACK_TTL);
  }

  return { underAttack: isUnderAttack(), ipFlagged: isIpFlagged(ip) };
}

/** Registra submit com token inválido. >5/60s por IP => challenge forçado. */
function recordInvalidToken(ip) {
  const now = Date.now();
  cleanup(now);
  const count = pushTs(ipInvalidTokens, ip || 'unknown', now);
  if (count > INVALID_TOKEN_LIMIT) {
    flaggedIps.set(ip || 'unknown', now + UNDER_ATTACK_TTL);
  }
  return count;
}

function isUnderAttack() {
  return Date.now() < underAttackUntil;
}

function isIpFlagged(ip) {
  const until = flaggedIps.get(ip || 'unknown');
  if (until === undefined) return false;
  if (until && Date.now() > until) { flaggedIps.delete(ip || 'unknown'); return false; }
  return true;
}

/** Cache de hash de IP legítimo (passou antes com score alto). */
function markKnownGood(ipHash) {
  if (!ipHash) return;
  knownGoodIps.set(ipHash, Date.now() + KNOWN_GOOD_TTL);
}

function isKnownGood(ipHash) {
  const exp = knownGoodIps.get(ipHash);
  if (exp === undefined) return false;
  if (Date.now() > exp) { knownGoodIps.delete(ipHash); return false; }
  return true;
}

/** Apenas para testes. */
function _reset() {
  globalStarts.length = 0;
  ipStarts.clear();
  ipInvalidTokens.clear();
  flaggedIps.clear();
  knownGoodIps.clear();
  underAttackUntil = 0;
  lastCleanup = 0;
}

module.exports = {
  recordStart,
  recordInvalidToken,
  isUnderAttack,
  isIpFlagged,
  markKnownGood,
  isKnownGood,
  KNOWN_GOOD_SCORE,
  _reset,
  // exportados p/ testes/documentação
  WINDOW_MS, GLOBAL_START_LIMIT, IP_START_LIMIT, INVALID_TOKEN_LIMIT, UNDER_ATTACK_TTL
};
