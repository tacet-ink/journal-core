/**
 * auth.ts — 零知識伺服器端 auth 核心邏輯（品牌／schema 參數化）。
 * 抽取自 sennight backend/src/routes/auth.ts（e2e 時代，prod 已驗證）。
 *
 * 不變量（勿破壞）：
 * - pass 明文永不過線：線上憑證送 PH1 = SHA-256(pass)，伺服器存 PH2 = SHA-256(PH1)
 * - hash-ladder 雙軌：舊式存 PH1 直比 → 命中即「順手升級」寫回 PH2
 * - 常數時間比較（timingSafeEq）防時序側信道
 * - 密語重設 = 舊憑證可能已洩漏 → 撤銷該身份全部 session
 * - 金鑰包裹欄組（wrapped+salt）缺一整組放棄；rec 包裹與種子 hash 必須成對出現
 *
 * 與 sennight 的結構差異（tacet 設計 §1/§13 已入型別）：
 * - identity 由伺服器端生成（隨機 account_id），不由客戶端帶入 soulKey——
 *   本核心以 identityCallback 抽象兩種模型，schema 欄位名由各 fork 自訂。
 */

import { corsResponse } from './cors';
import { sha256Hex, generateSessionToken, timingSafeEq } from './hash';
import { checkRate, type RateWindow } from './ratelimit';
import type { Env } from './env';

// ── 格式驗證（自 noteCrypt.ts 抽出；前綴由 config 注入） ─────────────────────

export interface CipherFormats {
  /** 密文前綴家族 regex 來源字串，如 '^sn1[ub]\\.' → '^jr1[gb]\\.'。 */
  cipherPrefixes: [string, string];
  /** 金鑰包裹前綴，如 'snw1.'。 */
  wrapPrefix: string;
  /** 密文位元組上限（入庫原樣、禁截斷密文）。 */
  cipherMax: number;
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BINARY_RE = /[\x00-\x08\x0e-\x1f]/;
const HASH64_RE = /^[0-9a-f]{64}$/;
const SALT32_RE = /^[0-9a-f]{32}$/;

function cipherRe(c: CipherFormats): RegExp {
  const escaped = c.cipherPrefixes.map(p => p.replace('.', '\\.'));
  return new RegExp(`^(${escaped.join('|')})[A-Za-z0-9+/]+={0,2}$`);
}

/**
 * 入庫前校正：前綴密文原樣入庫；超限密文／編碼丟棄（截斷必壞）、明文截到上限照收。
 * plainMax：明文相容層上限（sennight = 700 同密文；vestige = 120；tacet 無明文相容層可設 0）。
 */
export function makeInboundCipher(c: CipherFormats) {
  const RE = new RegExp(`^(${c.cipherPrefixes.map(p => p.replace('.', '\\.')).join('|')})[A-Za-z0-9+/]+={0,2}$`);
  return function inboundCipher(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const text = raw.trim();
    if (!text) return null;
    if (text.length > c.cipherMax) {
      return RE.test(text) || BASE64_RE.test(text)
        ? null // 密文/編碼超限：截斷必壞，直接丟棄
        : text.slice(0, c.cipherMax); // 純明文（舊版客戶端）：截到上限照收
    }
    if (RE.test(text)) return text; // 前綴密文：原樣入庫
    if (BASE64_RE.test(text) && text.length > 40) return text; // 舊客戶端 b64 慣例：照收
    if (BINARY_RE.test(text)) return null; // 控制字元垃圾：丟棄
    return text; // 真明文：照收（舊版相容）
  };
}

export function isCipherFor(text: string | null | undefined, c: CipherFormats): boolean {
  if (typeof text !== 'string') return false;
  return text.startsWith(c.cipherPrefixes[0]) || text.startsWith(c.cipherPrefixes[1]);
}

export function validWrappedKey(v: unknown, wrapPrefix: string): string | null {
  const re = new RegExp(`^${wrapPrefix.replace('.', '\\.')}[A-Za-z0-9+/]+={0,2}$`);
  return typeof v === 'string' && v.length <= 200 && re.test(v) ? v : null;
}

export function validHash64(v: unknown): string | null {
  return typeof v === 'string' && HASH64_RE.test(v) ? v : null;
}

export function validSalt(v: unknown): string | null {
  return typeof v === 'string' && SALT32_RE.test(v) ? v : null;
}

/** 綁定/復原共用的金鑰包裹欄組：wrapped 與 salt 必須成對，缺一整組放棄。 */
export function pickKeyPackage(body: any, wrapPrefix: string): { wrapped: string | null; salt: string | null } {
  const wrapped = validWrappedKey(body?.note_wrapped ?? body?.wrapped, wrapPrefix);
  const salt = validSalt(body?.note_salt ?? body?.salt);
  return { wrapped: wrapped && salt ? wrapped : null, salt: wrapped && salt ? salt : null };
}

// ── 介面：各 fork 接線自己的 schema 欄位 ─────────────────────────────────────

export interface KeyPackage {
  wrapped: string;
  salt: string;
}

export interface AuthStore {
  /** 以 PH2 查身份（PH2 UNIQUE；tacet：隨機 account_id 在此建立）。 */
  findByIdentityQuery(ph2: string): Promise<AuthRow | null>;
  /** 建立（tacet：生成隨機 account_id；sennight/vestige：guest 自動註冊語意）。 */
  createUser(ph2: string): Promise<string>;
  getByUserKey(key: string): Promise<AuthRow | null>;
  getByRecHash(recHash: string): Promise<AuthRow | null>;
  setWrapped(userKey: string, ph2: string, pkg: KeyPackage, recPkg: string | null, recHash: string | null): Promise<void>;
  revokeAllSessions(userKey: string): Promise<void>;
  insertSession(tokenHash: string, userKey: string, expiresAt: number): Promise<void>;
}

export interface AuthRow {
  userKey: string; // identity（account_id / user id）
  ph2: string | null; // SHA-256(PH1)；null = 未綁定 guest
  salt: string | null;
  wrapped: string | null;
  wrappedRec: string | null;
  recHash: string | null;
}

export const AUTH_RATE: RateWindow = { table: 'login_rate', windowMs: 60_000, max: 10 };

export function errResponse(code: string, status: number): Response {
  return corsResponse(new Response(code, { status }));
}

// ── /auth/login：PH1 進站 → PH2 查詢（UNIQUE）→ session ─────────────────────

export async function loginRouteCore(env: Env & Record<string, unknown>, store: AuthStore, ip: string, ph1In: unknown): Promise<Response> {
  if (!(await checkRate(env, AUTH_RATE, ip))) return errResponse('ERR_RATE_LIMITED', 429);
  const ph1 = validHash64(ph1In);
  if (!ph1) return errResponse('ERR_BAD_REQUEST', 400);
  const ph2 = await sha256Hex(ph1);
  const user = await store.findByIdentityQuery(ph2);
  const userKey: string = user ? user.userKey : await store.createUser(ph2);
  const token = generateSessionToken();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // PWA：30 天
  await store.insertSession(await sha256Hex(token), userKey, expiresAt);
  return corsResponse(new Response(JSON.stringify({
    sessionToken: token,
    userKey,
    status: user?.ph2 ? 'ready' : 'require_binding',
  }), { headers: { 'Content-Type': 'application/json' } }));
}