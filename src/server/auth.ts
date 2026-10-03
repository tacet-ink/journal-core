/**
 * auth.ts — 零知識伺服器端 auth 核心邏輯（品牌／schema 參數化）。
 *
 * 本檔實作的契約：
 * - pass 明文永不過線：線上憑證送 PH1（雜湊形），伺服器存 PH2 = SHA-256(PH1)。
 *   PH1 派生方式由各產品自定義（快雜湊或 Argon2id 派生皆可）——本層只驗
 *   hex64 形，不驗 PH1 派生方式（伺服器零知識，無從也無需區分形別）。
 * - 入庫前密文／包裹格式驗證（inboundCipher／isCipherFor／validWrappedKey／
 *   pickKeyPackage 等，前綴由 config 注入）。
 * - /auth/login 核心動線（loginRouteCore）：rate-limit 閘 → PH1 驗形 →
 *   PH2 → store 查詢／建號 → session token 簽發（30 天）。
 *
 * 呼叫端（fork）職責——本檔只定義介面，機制在呼叫端實作：
 * - identity 生成：AuthStore.createUser 由各 fork 自決（隨機 account_id 或
 *   客戶端帶入語意皆可）；PH2 UNIQUE 衝突（兩個同時首登同密語）是 store
 *   責任——tacet 參考實作：UNIQUE 失敗重查既有列回 userKey（非 5xx）。
 * - hash-ladder 雙軌（舊式 PH1 直比 → 升級寫回 PH2）與密語重設後的 session
 *   撤銷時機：fork 呼叫端接線（revokeAllSessions 介面已備）。
 * - 常數時間比較 timingSafeEq：./hash.ts 匯出（login 動線經 PH2 查詢不直比）。
 *
 * 不變量（勿破壞）：
 * - 金鑰包裹欄組（wrapped+salt）缺一整組放棄——pair 檢查本體在 pickKeyPackage。
 * - recPkg 與 recHash 成對出現＝呼叫端（fork store）職責：本層介面兩參各自可空、
 *   不做 pair 檢查（r2 MINOR-4 照此收口；pickKeyPackage 是同職責的成對檢查先例）。
 */

import { corsResponse } from './cors.ts';
import { sha256Hex, generateSessionToken } from './hash.ts';
import { checkRate, type RateWindow } from './ratelimit.ts';
import type { Env } from './env.ts';

// ── 格式驗證（自 noteCrypt.ts 抽出；前綴由 config 注入） ─────────────────────

export interface CipherFormats {
  /** 密文前綴家族字面（startsWith 語意，非 regex 來源），如 'jr1b.'。 */
  cipherPrefixes: [string, string];
  /** 金鑰包裹前綴，如 'jr1w.'。 */
  wrapPrefix: string;
  /** 密文上限：UTF-16 code unit 計數（.length 語意；非 UTF-8 bytes）。 */
  cipherMax: number;
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BINARY_RE = /[\x00-\x08\x0e-\x1f]/;
const HASH64_RE = /^[0-9a-f]{64}$/;
const SALT32_RE = /^[0-9a-f]{32}$/;

/** regex 用字面跳脫：全字元掃描（.replace('.',) 只跳第一個點——前綴含第二個 . 即壞）。 */
function escapeReLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** 前綴家族 → 密文形 regex（單一組裝點；cipherRe 死碼退場）。 */
function cipherPrefixRe(cipherPrefixes: readonly string[]): RegExp {
  const escaped = cipherPrefixes.map(p => escapeReLiteral(p));
  return new RegExp(`^(${escaped.join('|')})[A-Za-z0-9+/]+={0,2}$`);
}

/**
 * 入庫前校正：前綴密文原樣入庫；超限密文／編碼丟棄（截斷必壞）、明文截到上限照收。
 * cipherMax（UTF-16 單位）同為明文截斷帽：明文相容層無 opt-out——明文一律照收、
 * 截到 cipherMax 入庫（r2 MINOR-5：JSDoc 幽靈參數 plainMax 摘除）。
 */
export function makeInboundCipher(c: CipherFormats) {
  const RE = cipherPrefixRe(c.cipherPrefixes);
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

export function validWrappedKey(v: unknown, wrapPrefix: string | string[]): string | null {
  const prefixes = Array.isArray(wrapPrefix) ? wrapPrefix : [wrapPrefix];
  const re = cipherPrefixRe(prefixes);
  return typeof v === 'string' && v.length <= 200 && re.test(v) ? v : null;
}

export function validHash64(v: unknown): string | null {
  return typeof v === 'string' && HASH64_RE.test(v) ? v : null;
}

export function validSalt(v: unknown): string | null {
  return typeof v === 'string' && SALT32_RE.test(v) ? v : null;
}

/** 綁定/復原共用的金鑰包裹欄組：wrapped 與 salt 必須成對，缺一整組放棄。 */
export function pickKeyPackage(body: any, wrapPrefix: string | string[]): { wrapped: string | null; salt: string | null } {
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
  /** 建立（identity 生成由各 fork 自決——見檔頭「呼叫端職責」；PH2 UNIQUE 衝突亦是 store 責任）。 */
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
  /** 訂閱方案（tacet：users.plan，'free'/'paid'）；兄弟 fork 無訂閱面時預設 'free'。 */
  plan?: string;
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