'use strict';
/**
 * Tower Defense 3D – server s účty a cloudovým ukládáním.
 *  - servíruje hru (public/index.html) i API na jednom místě (žádné CORS)
 *  - hesla: scrypt (vestavěný crypto), přihlášení: podepsaný token (HMAC-SHA256, platnost 30 dní)
 *  - úložiště: PostgreSQL (DATABASE_URL), jinak lokální soubor data/db.json (jen pro vývoj)
 *  - jediná závislost: pg
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (PROD ? null : 'dev-only-secret-change-me');
if (!SECRET) { console.error('Chybí proměnná prostředí JWT_SECRET.'); process.exit(1); }
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const INDEX = path.join(__dirname, 'public', 'index.html');

/* ------------------------------------------------------------------ úložiště */
async function pgStore(url) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, max: 5, ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false } });
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    username_lc TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    save JSONB,
    save_ts BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  const row = r => r && { id: r.id, username: r.username, passHash: r.pass_hash, save: r.save, ts: Number(r.save_ts) };
  return {
    kind: 'PostgreSQL',
    async findByName(lc) { return row((await pool.query('SELECT * FROM users WHERE username_lc=$1', [lc])).rows[0]); },
    async findById(id) { return row((await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0]); },
    async create(username, passHash, save, ts) {
      try {
        const r = await pool.query('INSERT INTO users (username, username_lc, pass_hash, save, save_ts) VALUES ($1,$2,$3,$4,$5) RETURNING id',
          [username, username.toLowerCase(), passHash, save ? JSON.stringify(save) : null, ts]);
        return r.rows[0].id;
      } catch (e) { if (e.code === '23505') return null; throw e; }       // jméno už existuje
    },
    // zapíše jen když není uložen novější postup (ochrana proti starému zařízení)
    async setSave(id, save, ts) {
      const r = await pool.query('UPDATE users SET save=$2, save_ts=$3 WHERE id=$1 AND save_ts <= $3', [id, JSON.stringify(save), ts]);
      return r.rowCount > 0;
    }
  };
}

function fileStore(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let db = { next: 1, users: [] };
  try { db = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { /* nový soubor */ }
  const flush = () => { const tmp = file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, file); };
  return {
    kind: 'soubor ' + file + ' (jen pro vývoj!)',
    async findByName(lc) { return db.users.find(u => u.lc === lc) || null; },
    async findById(id) { return db.users.find(u => u.id === id) || null; },
    async create(username, passHash, save, ts) {
      if (db.users.some(u => u.lc === username.toLowerCase())) return null;
      const u = { id: db.next++, username, lc: username.toLowerCase(), passHash, save, ts };
      db.users.push(u); flush(); return u.id;
    },
    async setSave(id, save, ts) {
      const u = db.users.find(x => x.id === id);
      if (!u || u.ts > ts) return false;
      u.save = save; u.ts = ts; flush(); return true;
    }
  };
}

/* ------------------------------------------------------------------ hesla a tokeny */
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, k) => (e ? rej(e) : res(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return 's1$' + salt.toString('base64') + '$' + (await scrypt(pw, salt)).toString('base64');
}
async function checkPw(pw, stored) {
  const [v, s, h] = String(stored).split('$');
  if (v !== 's1' || !s || !h) return false;
  const k = await scrypt(pw, Buffer.from(s, 'base64')), hb = Buffer.from(h, 'base64');
  return hb.length === k.length && crypto.timingSafeEqual(hb, k);
}
const DUMMY_HASH = 's1$' + Buffer.alloc(16).toString('base64') + '$' + Buffer.alloc(64).toString('base64');   // vyrovná čas u neexistujícího účtu

const hmac = body => crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
function signToken(uid, username) {
  const body = Buffer.from(JSON.stringify({ uid, u: username, exp: Date.now() + TOKEN_TTL })).toString('base64url');
  return body + '.' + hmac(body);
}
function verifyToken(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(hmac(body));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}

/* ------------------------------------------------------------------ omezení počtu pokusů */
const rl = {
  m: new Map(),
  hit(key, win) { const now = Date.now(); let h = this.m.get(key); if (!h || h.reset < now) { h = { n: 0, reset: now + win }; this.m.set(key, h); } return ++h.n; },
  get(key) { const h = this.m.get(key); return h && h.reset > Date.now() ? h.n : 0; }
};
setInterval(() => { const now = Date.now(); for (const [k, h] of rl.m) if (h.reset < now) rl.m.delete(k); }, 60000).unref();
const clientIp = req => (process.env.RENDER ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '') || req.socket.remoteAddress || '?';

/* ------------------------------------------------------------------ validace */
const NAME_RE = /^[A-Za-z0-9_-]{3,20}$/;
const ID_RE = /^[a-z0-9_]{1,24}$/;
/** Ověří a očistí uložený postup (server nezná herní logiku, hlídá jen tvar a rozumné meze). */
function cleanSave(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return null;
  const ids = (a, max) => (Array.isArray(a) ? [...new Set(a.filter(x => typeof x === 'string' && ID_RE.test(x)))].slice(0, max) : []);
  const best = {};
  if (s.best && typeof s.best === 'object' && !Array.isArray(s.best)) {
    for (const [k, v] of Object.entries(s.best).slice(0, 30)) if (ID_RE.test(k) && Number.isFinite(v)) best[k] = Math.max(0, Math.min(1e6, Math.floor(v)));
  }
  return {
    coins: Number.isFinite(s.coins) ? Math.max(0, Math.min(1e9, Math.floor(s.coins))) : 0,
    unlocked: ids(s.unlocked, 40), equipped: ids(s.equipped, 12), best,
    ts: Number.isFinite(s.ts) ? Math.max(0, Math.min(Date.now() + 86400000, Math.floor(s.ts))) : 0
  };
}

/* ------------------------------------------------------------------ HTTP */
const SEC = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'SAMEORIGIN' };
// CORS: hru lze otevřít i odjinud (např. ze souboru) a přesto se přihlásit; přihlášení je v hlavičce Authorization, ne v cookies
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Max-Age': '86400' };
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { ...SEC, ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
const fail = (status, msg) => Object.assign(new Error(msg), { status });
function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false; const chunks = [];
    req.on('data', c => {                                   // zbytek přeposílaných dat jen zahodíme a odpovíme 413
      size += c.length;
      if (size > limit) { if (!tooBig) { tooBig = true; reject(fail(413, 'Příliš velký požadavek.')); } } else chunks.push(c);
    });
    req.on('end', () => { if (tooBig) return; try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(fail(400, 'Neplatný JSON.')); } });
    req.on('error', reject);
  });
}
function authUser(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const p = m && verifyToken(m[1]);
  if (!p) throw fail(401, 'Nepřihlášen nebo vypršela platnost přihlášení.');
  return p;
}

let indexCache = null;
function serveIndex(req, res) {
  if (!indexCache || !PROD) {
    const raw = fs.readFileSync(INDEX);
    indexCache = { raw, gz: zlib.gzipSync(raw) };
  }
  const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  const body = gz ? indexCache.gz : indexCache.raw;
  res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Length': body.length, ...(gz ? { 'Content-Encoding': 'gzip', Vary: 'Accept-Encoding' } : {}) });
  res.end(req.method === 'HEAD' ? undefined : body);
}

function makeHandler(store) {
  return async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x'), p = url.pathname;
      if (req.method === 'OPTIONS') { res.writeHead(204, { ...SEC, ...CORS }); return res.end(); }
      if ((req.method === 'GET' || req.method === 'HEAD') && (p === '/' || p === '/index.html')) return serveIndex(req, res);
      if (p === '/favicon.ico') { res.writeHead(204); return res.end(); }
      if (p === '/api/health') return send(res, 200, { ok: true });

      if (p === '/api/register' && req.method === 'POST') {
        const ip = clientIp(req);
        if (rl.hit('reg:' + ip, 3600e3) > 10 || rl.hit('ip:' + ip, 900e3) > 60) throw fail(429, 'Příliš mnoho pokusů, zkus to později.');
        const b = await readBody(req);
        const username = String(b.username || '').trim(), password = String(b.password || '');
        if (!NAME_RE.test(username)) throw fail(400, 'Jméno: 3–20 znaků (písmena, číslice, _ nebo -).');
        if (password.length < 6 || Buffer.byteLength(password) > 72) throw fail(400, 'Heslo musí mít 6–72 znaků.');
        const save = cleanSave(b.save);
        const id = await store.create(username, await hashPw(password), save, save ? save.ts : 0);
        if (id === null) throw fail(409, 'Toto jméno už je obsazené.');
        return send(res, 201, { token: signToken(id, username), username, save, ts: save ? save.ts : 0 });
      }

      if (p === '/api/login' && req.method === 'POST') {
        const ip = clientIp(req);
        if (rl.hit('ip:' + ip, 900e3) > 60) throw fail(429, 'Příliš mnoho pokusů, zkus to později.');
        const b = await readBody(req);
        const username = String(b.username || '').trim(), password = String(b.password || ''), lc = username.toLowerCase();
        if (rl.get('f:' + lc) >= 10) throw fail(429, 'Příliš mnoho nesprávných pokusů, zkus to za chvíli.');
        const u = NAME_RE.test(username) ? await store.findByName(lc) : null;
        const ok = await checkPw(password, u ? u.passHash : DUMMY_HASH);
        if (!u || !ok) { rl.hit('f:' + lc, 900e3); throw fail(401, 'Nesprávné jméno nebo heslo.'); }
        return send(res, 200, { token: signToken(u.id, u.username), username: u.username, save: u.save || null, ts: u.ts || 0 });
      }

      if (p === '/api/me' && req.method === 'GET') {
        const t = authUser(req), u = await store.findById(t.uid);
        if (!u) throw fail(401, 'Účet neexistuje.');
        return send(res, 200, { username: u.username, save: u.save || null, ts: u.ts || 0 });
      }

      if (p === '/api/save' && req.method === 'PUT') {
        const t = authUser(req);
        if (rl.hit('sv:' + t.uid, 60e3) > 60) throw fail(429, 'Příliš časté ukládání.');
        const save = cleanSave((await readBody(req)).save);
        if (!save) throw fail(400, 'Neplatný postup.');
        if (await store.setSave(t.uid, save, save.ts)) return send(res, 200, { ok: true, ts: save.ts });
        const u = await store.findById(t.uid);             // v cloudu je novější postup → klient ho převezme
        return send(res, 409, { error: 'V cloudu je novější postup.', save: u && u.save, ts: u ? u.ts : 0 });
      }

      if (p.startsWith('/api/')) throw fail(404, 'Neexistující endpoint.');
      res.writeHead(404, SEC); res.end('Not found');
    } catch (e) {
      if (!e.status) console.error(e);
      if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'Chyba serveru.' });
    }
  };
}

async function main() {
  const store = process.env.DATABASE_URL ? await pgStore(process.env.DATABASE_URL) : fileStore(process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json'));
  const server = http.createServer(makeHandler(store));
  server.listen(PORT, () => console.log(`Tower Defense 3D běží na portu ${PORT} · úložiště: ${store.kind}`));
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
}
if (require.main === module) main().catch(e => { console.error(e); process.exit(1); });
module.exports = { makeHandler, fileStore, cleanSave, hashPw, checkPw, signToken, verifyToken };
