/**
 * devstack-stub.cjs — R3b e2e 的 hermetic /sreq 站 stub（零外網；仿 tacet devstack＋probe 母型）。
 *
 * 實作 request-secret 的 API 面（R1 問 5/8/9/10 契約）：
 *   GET  /sreq、/secret      → 頁 fixture（e2e 可換頁做 N3 毒化）
 *   POST /api/sreq           → 開 slot（a_pub_jwk 形檢＋ttl 白名單＋annual 層）
 *   POST /api/sreq/fill?s=   → write-once 填內容（ciphertext 形檢；404 三因不可區分）
 *   GET  /api/sreq/<id>?t=   → burn 取件（token 單用；過期 410；已燒 404）
 *   GET  /api/sreq/status?s= → 狀態（filled/pending；404/410）
 *
 * 請求日誌（method＋path）公開給 probe 做斷言（N3 先於 API、fill 零重試、token 單用等）。
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const JR5E_PREFIX = 'jr5e.';
// blob = jr5e. + b64url( eph_pub[65] ‖ iv[12] ‖ ct ‖ tag[16] )；raw 最小＝65+12+1+16＝94B
// （JR5E_BLOB_MIN_BYTES；最小形字元＝5 + b64url(94B)＝133）
const RAW_MIN = 94;
const BLOB_MAX = 96093;

function hex(n) {
  return crypto.randomBytes(n).toString('hex');
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function confCodeOf(ephPubBytes, nonceHex) {
  return crypto.createHash('sha256').update(Buffer.concat([ephPubBytes, Buffer.from(nonceHex, 'hex')])).digest('hex').slice(0, 4);
}

class SreqStub {
  constructor(pagesDir, { freeTtls = [600000, 3600000, 259200000, 604800000], annualTtls = [600000, 3600000, 259200000, 604800000, 1209600000] } = {}) {
    this.pagesDir = pagesDir;
    this.freeTtls = freeTtls;
    this.annualTtls = annualTtls;
    this.slots = new Map(); // slotId -> slot
    this.reqLog = []; // {method, path}
    this.server = http.createServer((req, res) => {
      this.reqLog.push({ method: req.method, path: req.url.split('?')[0] });
      this.handle(req, res).catch((e) => {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'stub-internal: ' + String(e) }));
      });
    });
  }

  listen() {
    return new Promise((resolve) => {
      this.server.listen(0, '127.0.0.1', () => {
        this.port = this.server.address().port;
        this.base = `http://127.0.0.1:${this.port}`;
        resolve(this);
      });
    });
  }

  close() {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  countPaths(pred) {
    return this.reqLog.filter((r) => pred(r.path)).length;
  }

  slotIds() {
    return [...this.slots.keys()];
  }

  async handle(req, res) {
    const u = new URL(req.url, this.base);
    const m = req.method;
    const readBody = () =>
      new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
      });
    const json = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    if (m === 'GET' && (u.pathname === '/sreq' || u.pathname === '/secret')) {
      const fs = require('node:fs');
      const name = u.pathname === '/sreq' ? 'sreq.html' : 'secret.html';
      try {
        const b = fs.readFileSync(`${this.pagesDir}/${name}`);
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(b);
      } catch {
        res.writeHead(404);
        res.end('stub: page fixture missing');
      }
      return;
    }

    if (m === 'POST' && u.pathname === '/api/sreq') {
      const body = JSON.parse((await readBody()) || '{}');
      const jwk = body.a_pub_jwk;
      if (
        !jwk ||
        jwk.kty !== 'EC' ||
        jwk.crv !== 'P-256' ||
        typeof jwk.x !== 'string' ||
        jwk.x.length !== 43 ||
        typeof jwk.y !== 'string' ||
        jwk.y.length !== 43
      ) {
        return json(400, { error: 'a_pub_jwk 形不符（P-256 JWK：kty/crv/x/y）' });
      }
      if (jwk.d !== undefined) return json(400, { error: 'a_pub_jwk 不得含私鑰欄 d' });
      const ttl = body.ttl_ms;
      const isAnnual = body.annual_token !== undefined;
      if (isAnnual && (typeof body.annual_token !== 'string' || body.annual_token.length === 0)) {
        return json(400, { error: 'annual_token 需非空字串' });
      }
      const allowed = isAnnual ? this.annualTtls : this.freeTtls;
      if (typeof ttl === 'number' && !allowed.includes(ttl)) {
        return json(400, { error: `ttl_ms 不在白名單（tier=${isAnnual ? 'annual' : 'free'}）` });
      }
      const ttlMs = typeof ttl === 'number' ? ttl : 604800000; // 缺席＝預設 7d
      const id = hex(16);
      const token = hex(32);
      const nonce = hex(16);
      this.slots.set(id, {
        id,
        token,
        tokenHash: sha256Hex(token),
        nonce,
        pubJwk: jwk,
        tier: isAnnual ? 'annual' : 'free',
        openedAt: Date.now(),
        exp: Date.now() + ttlMs,
        ciphertext: null,
        ephPub: null,
        writtenAt: 0,
        taken: false,
      });
      return json(200, {
        ok: true,
        slot_id: id,
        token,
        slot_nonce: nonce,
        exp: Date.now() + ttlMs,
        fill_url: `${this.base}/sreq/?s=${id}`,
        retrieve_url: `${this.base}/sreq/?s=${id}`,
      });
    }

    if (m === 'POST' && u.pathname === '/api/sreq/fill') {
      const s = u.searchParams.get('s');
      const slot = s ? this.slots.get(s) : null;
      if (!slot || slot.taken || slot.ciphertext !== null || slot.exp <= Date.now()) {
        return json(404, { error: '此請求已無法填寫' }); // 三因不可區分（R1 問 9）
      }
      const body = JSON.parse((await readBody()) || '{}');
      const ct = body.ciphertext;
      if (typeof ct !== 'string' || !ct.startsWith(JR5E_PREFIX) || ct.length > BLOB_MAX) {
        return json(400, { error: 'ciphertext 形不符（jr5e. 前綴＋長帽）' });
      }
      const raw = Buffer.from(ct.slice(JR5E_PREFIX.length), 'base64url');
      if (raw.length < RAW_MIN) return json(400, { error: 'ciphertext 解碼後過短（<94B 最小形）' });
      slot.ciphertext = ct;
      slot.ephPub = raw.subarray(0, 65); // eph_pub 在 blob 頭（65B 0x04 點）
      slot.writtenAt = Date.now();
      return json(200, { ok: true, conf_code: confCodeOf(slot.ephPub, slot.nonce) });
    }

    if (m === 'GET' && u.pathname === '/api/sreq/status') {
      const s = u.searchParams.get('s');
      const slot = s ? this.slots.get(s) : null;
      if (!slot || slot.taken) return json(404, { error: '不存在' });
      if (slot.exp <= Date.now()) return json(410, { error: '已過期' });
      return json(200, { state: slot.ciphertext !== null ? 'filled' : 'pending' });
    }

    const burn = /^\/api\/sreq\/([0-9a-f]{32})$/.exec(u.pathname);
    if (m === 'GET' && burn) {
      const slot = this.slots.get(burn[1]);
      const t = u.searchParams.get('t');
      if (!slot || slot.taken || (t && sha256Hex(t) !== slot.tokenHash)) return json(404, { error: '不存在' });
      if (slot.exp <= Date.now()) return json(410, { error: '已過期' });
      if (slot.ciphertext === null) {
        return json(200, { ciphertext: null, written_at: 0, conf_code: null });
      }
      slot.taken = true;
      return json(200, { ciphertext: slot.ciphertext, written_at: slot.writtenAt, conf_code: confCodeOf(slot.ephPub, slot.nonce) });
    }

    json(404, { error: 'not found' });
  }
}

module.exports = { SreqStub };
