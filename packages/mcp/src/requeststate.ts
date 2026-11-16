/**
 * requeststate.ts — MRTR requestState 完整性（spec 2026-07-28 basic/patterns/mrtr 安全段）。
 *
 * requestState＝opaque blob：client 重試時原樣回帶，server 自行判讀。本實現：
 *   HMAC-SHA256（MUST：integrity 面）——在 core sha256Hex 上手寫 HMAC（零自帶加密、
 *   零 Node 內建 crypto 模組；core 已是本 repo 的加密原語層）＋32B 隨機金鑰
 *   （stateDir/mcp-state.key，0600）＋TTL 10 分鐘＋principal（本地使用者——stdio
 *   本機形下身分綁定＝本機使用者，非遠端授權推導，R3c §2 裁定）＋原請求
 *   {name,arguments} 規範摘要（跨請求重用即 digest mismatch）。
 *
 * 編碼：b64url(payloadJSON) + '.' + b64url(hmacHexBytes)
 * 判定序：format → mac（完整性門在前；未認證的 payload 不比對其餘欄）→ digest
 *   → principal → expired。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256Hex } from '@tacet-ink/journal-core/server/hash';
import { stateDir } from '@tacet-ink/journal-cli/dist/refs.js';
import { ensureStateDir } from '@tacet-ink/journal-cli/dist/state.js';

export const STATE_TTL_MS = 10 * 60_000;
const KEY_FILE_NAME = 'mcp-state.key';
const BLOCK = 64; // SHA-256 block size

export interface StatePayload {
  v: 1;
  tool: 'request';
  slot_id: string;
  tier: 'free' | 'annual';
  exp: number;
  origin: string;
  out_path: string;
  fill_link: string;
  req_digest: string;
  principal: string;
  iat: number;
}

/** 規範 JSON（鍵排序、遞迴）——摘要穩定，不依賴序列化順序 */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return '[' + v.map((x) => canonicalJson(x)).join(',') + ']';
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

export async function canonicalDigest(v: unknown): Promise<string> {
  return sha256Hex(canonicalJson(v));
}

/** HMAC-SHA256(key≤64B, msg)：H(K'⊕opad ‖ H(K'⊕ipad ‖ m))；H＝core sha256Hex */
async function hmacSha256Hex(key: Uint8Array, msg: string): Promise<string> {
  if (key.length > BLOCK) throw new Error('hmac key > block（不應發生：本鍵恆 32B）');
  const ipad = Buffer.alloc(BLOCK, 0x36);
  const opad = Buffer.alloc(BLOCK, 0x5c);
  for (let i = 0; i < key.length; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }
  const inner = await sha256Hex(Buffer.concat([ipad, Buffer.from(msg, 'utf8')]).toString('latin1'));
  return sha256Hex(Buffer.concat([opad, Buffer.from(inner, 'hex')]).toString('latin1'));
}

function keyPath(): string {
  return path.join(stateDir(), KEY_FILE_NAME);
}

function loadOrCreateKey(): Uint8Array {
  ensureStateDir();
  const p = keyPath();
  if (fs.existsSync(p)) {
    const b = fs.readFileSync(p);
    if (b.length !== 32) {
      throw new Error(`mcp-state.key 形態錯（${b.length}B，預期 32B）——刪除 ${p} 重試`);
    }
    return new Uint8Array(b);
  }
  const key = new Uint8Array(32);
  crypto.getRandomValues(key); // WebCrypto 全域（零內建 crypto）
  fs.writeFileSync(p, key, { mode: 0o600 });
  fs.chmodSync(p, 0o600); // 不依賴 umask
  return key;
}

const b64url = (input: string | Buffer): string =>
  (typeof input === 'string' ? Buffer.from(input, 'utf8') : input).toString('base64url');

const isB64Url = (s: string): boolean => s.length > 0 && /^[A-Za-z0-9_-]+$/.test(s);

export async function signState(payload: StatePayload): Promise<string> {
  const body = b64url(JSON.stringify(payload));
  const mac = await hmacSha256Hex(loadOrCreateKey(), body);
  return body + '.' + b64url(Buffer.from(mac, 'hex'));
}

export type VerifyVerdict =
  | { ok: true; payload: StatePayload }
  | { ok: false; reason: 'format' | 'mac' | 'expired' | 'principal' | 'digest' };

export async function verifyState(token: string, expectedDigest: string): Promise<VerifyVerdict> {
  const dot = token.indexOf('.');
  if (dot <= 0 || !isB64Url(token.slice(0, dot)) || !isB64Url(token.slice(dot + 1))) {
    return { ok: false, reason: 'format' };
  }
  const body = token.slice(0, dot);
  let payload: StatePayload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'format' };
  }
  if (
    !payload ||
    payload.v !== 1 ||
    payload.tool !== 'request' ||
    typeof payload.req_digest !== 'string'
  ) {
    return { ok: false, reason: 'format' };
  }
  const mac = await hmacSha256Hex(loadOrCreateKey(), body);
  const expectedMac = b64url(Buffer.from(mac, 'hex'));
  if (!ctEqual(expectedMac, token.slice(dot + 1))) return { ok: false, reason: 'mac' };
  if (payload.req_digest !== expectedDigest) return { ok: false, reason: 'digest' };
  if (payload.principal !== os.userInfo().username) return { ok: false, reason: 'principal' };
  if (typeof payload.iat !== 'number' || payload.iat + STATE_TTL_MS < Date.now()) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, payload };
}

/** 恆定時間比較（MAC 面；長度不同直接 false——MAC 長度恆定） */
function ctEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
