/**
 * jr5s.ts — 一次性密語密文原語（jr5s.，/secret 方案 B 契約 core 收編；R3a t_c4ecb987，core 0.11.0）。
 *
 * 契約真源（逐位元組）：tacet repo public/secret.html（inline 正形——單檔可逐位元組驗證）
 * ＋backend/src/lib/secrets.ts（伺服器端形檢面 validSecretCipher／SECRET_MAX_* 常數族）。
 * 本模組＝同契約第二實作（R3 CLI/MCP 只 import core，brief L132 禁自帶加密）；兩端一致性
 * 靠向量對拍維持（docs/vectors/kat.json jr5s_kat＋閘 [33] 行為面＋[26] 同源對帳），
 * 非靠共用代碼（L133：/secret 頁零改動）。
 *
 * wire 形（正形＝b64url 無 padding，'-'/'_' 字母表）：
 *   jr5s. + b64url( iv[12] ‖ GCM_out )
 *   GCM_out = AES-256-GCM(key=S raw 32B, iv, plain=0x73 ‖ UTF8(明文), aad=UTF8('jr5s:'+id)) → ct‖tag[16]
 * - S（密鑰）＝32 隨機 byte；b64url(S)＝43 字元；S 只進連結 fragment（#k=），不上線。
 * - id＝locator key＝sha256Hex(UTF8(b64url(S))) 前 32 hex（小寫）——伺服器只收 id＋密文。
 * - AAD 綁自家 locator key（'jr5s:'+id）：密文搬行／locator 錯位／欄位竄改恆拒（GCM auth 域）。
 * - 0x73＝字串標記 's' byte 形（三態字串標記），置 GCM 明文首；讀端先驗首字元再剝除。
 * - 上限導出鏈（常數為導出值，非魔數）：明文 ≤ 512 UTF-16 code units（String.length）
 *   → UTF-8 最差 3B/unit（3 byte BMP 字元恰為緊界）＝1536B → blob ∈ [30, 1565]B
 *   → wire ∈ [前綴+30B 碼, 2092] 字元。29B（空明文 tag-only）＝拒。
 *
 * 失敗契約（unwrap 跨前綴恆 null 母型）：jr5sDecrypt 對 prefix/形/長度/AAD 錯位/GCM 認證/
 * 標記錯 任何一環回 null、不拋；jr5sEncrypt 壞輸入 fail-loud（空明文／key≠32B／
 * id 非 32hex 小寫／iv≠12B → TypeError）。
 * 值不回呼叫端明文以外任何面（R3 §2-2：輸入 env:/file: 參照、輸出「已寫入」、恆不回傳明文）。
 *
 * 編碼例外面：本家族 b64url 無 padding（沿用 /secret 線上正形），與舊家族 b64 帶 padding
 * 不同——前綴已負版本空間，編碼屬前綴契約的一部分（format-spec §4.15）。
 */

import { b64urlDecode, b64urlEncode, bytesToHex, concatBytes3 } from './util.ts';

/** wire 前綴（ASCII 契約字面，參數化面） */
export const JR5S_PREFIX = 'jr5s.';
/** AAD 域前綴（部署＝/secret locator 綁結；函式面以 aad 參數化，域常量僅部署形） */
export const JR5S_AAD_DOMAIN = 'jr5s:';
/** 字串標記 's' 的 byte 形（0x73），置 GCM 明文首 */
export const JR5S_TAG_BYTE = 0x73;
export const JR5S_IV_BYTES = 12;
export const JR5S_GCM_TAG_BYTES = 16;
/** 明文上限：UTF-16 code units（String.length 計法，與 /secret 頁輸入帽同值） */
export const JR5S_PLAIN_MAX_UNITS = 512;
/** UTF-8 最差 3B/unit（3 byte BMP 字元緊界） */
export const JR5S_PLAIN_MAX_UTF8_BYTES = JR5S_PLAIN_MAX_UNITS * 3;
/** blob = iv ‖ (0x73 ‖ ct) ‖ tag 上限 */
export const JR5S_BLOB_MAX_BYTES = JR5S_IV_BYTES + 1 + JR5S_PLAIN_MAX_UTF8_BYTES + JR5S_GCM_TAG_BYTES;
/** blob 下限＝至少 1 byte 真明文（29B tag-only＝空明文＝拒） */
export const JR5S_BLOB_MIN_BYTES = JR5S_IV_BYTES + 1 + 1 + JR5S_GCM_TAG_BYTES;
/** wire = 前綴 + b64url(blob)（無 padding）上限（無呼叫導出：b64url 無 padding 字元數
 * = floor((4n+2)/3) ≡ ceil(4n/3)；整數算術避頂層裸呼叫——閘 [14]） */
export const JR5S_WIRE_MAX_CHARS = (JR5S_PREFIX.length + ((JR5S_BLOB_MAX_BYTES * 4 + 2) / 3)) | 0;
/** locator key 形：sha256Hex 前 32 hex 小寫 */
const JR5S_ID_RE = /^[0-9a-f]{32}$/;

// encoder／decoder 逐呼叫建置（閘 [14] sideEffects 前提：模組頂層零執行點——宣告行
// 初始化式 new 即模組載入執行點；TextEncoder／TextDecoder 無狀態且輕量，逐呼叫成本可忽略）。
function enc(): TextEncoder { return new TextEncoder(); }
function dec(): TextDecoder { return new TextDecoder('utf-8', { fatal: true }); }

/**
 * 形檢（同步、純；validSecretCipher 同源鏡像——R3b CLI POST 前本地驗形用）。
 * 正形：前綴＋無 padding b64url（'=' 任意位置拒；'+'/'/' 字母表相容）＋解碼長 ∈ [30,1565]。
 */
export function jr5sWireShapeOk(wire: unknown): boolean {
  if (typeof wire !== 'string' || !wire.startsWith(JR5S_PREFIX)) return false;
  const body = wire.slice(JR5S_PREFIX.length);
  if (body.length === 0 || body.length % 4 === 1) return false;
  if (!/^[A-Za-z0-9+/_-]+$/.test(body)) return false;
  const n = Math.floor((body.length * 3) / 4);
  return n >= JR5S_BLOB_MIN_BYTES && n <= JR5S_BLOB_MAX_BYTES;
}

/**
 * 建 S：32 隨機 byte → { key, keyB64url(43 字元), id(locator key) }。
 * 連結形＝<url>#k=<keyB64url>；id＝locator（伺服器端唯一金鑰面）。
 */
export async function generateSecretKey(): Promise<{ key: Uint8Array; keyB64url: string; id: string }> {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  const keyB64url = b64urlEncode(key);
  return { key, keyB64url, id: await secretIdOfKey(keyB64url) };
}

/** locator key 推導：sha256Hex(UTF8(keyB64url)) 前 32 hex（小寫）。 */
export async function secretIdOfKey(keyB64url: string): Promise<string> {
  if (typeof keyB64url !== 'string') throw new TypeError('jr5s: keyB64url must be a string');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc().encode(keyB64url)));
  return bytesToHex(h).slice(0, 32);
}

/**
 * 封裝（寫面）：明文＋S＋locator → wire。iv 缺省＝隨機 12B（同明文兩封恆異）。
 * 壞輸入 throw TypeError（fail-loud；open 面才是 null 母型）。
 */
export async function jr5sEncrypt(plaintext: string, key: Uint8Array, id: string, iv?: Uint8Array): Promise<string> {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new TypeError('jr5s: plaintext must be a non-empty string');
  }
  if (plaintext.length > JR5S_PLAIN_MAX_UNITS) {
    throw new TypeError('jr5s: plaintext over cap (' + JR5S_PLAIN_MAX_UNITS + ' UTF-16 units)');
  }
  if (key == null || key.length !== 32) throw new TypeError('jr5s: key must be exactly 32 bytes');
  if (typeof id !== 'string' || !JR5S_ID_RE.test(id)) throw new TypeError('jr5s: id must be 32 lowercase hex');
  let ivB: Uint8Array<ArrayBuffer>;
  if (iv === undefined) {
    ivB = new Uint8Array(JR5S_IV_BYTES);
    crypto.getRandomValues(ivB);
  } else {
    ivB = iv.slice(); // 新 ArrayBuffer 承載（TS7 typed-array 泛型面＋呼叫端 buffer 零別名）
  }
  if (ivB.length !== JR5S_IV_BYTES) throw new TypeError('jr5s: iv must be 12 bytes');
  const utf8 = enc().encode(plaintext);
  if (utf8.length > JR5S_PLAIN_MAX_UTF8_BYTES) {
    throw new TypeError('jr5s: plaintext UTF-8 over cap (' + JR5S_PLAIN_MAX_UTF8_BYTES + ' bytes)');
  }
  const plain = new Uint8Array(1 + utf8.length);
  plain[0] = JR5S_TAG_BYTE;
  plain.set(utf8, 1);
  const aesKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const ctTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivB as BufferSource, additionalData: enc().encode(JR5S_AAD_DOMAIN + id) as BufferSource },
    aesKey, plain as BufferSource));
  const blob = new Uint8Array(JR5S_IV_BYTES + ctTag.length);
  blob.set(ivB, 0);
  blob.set(ctTag, JR5S_IV_BYTES);
  return JR5S_PREFIX + b64urlEncode(blob);
}

/**
 * 解封（讀面，null 母型）：wire＋S＋locator → 明文；任何一環不符回 null 不拋。
 * 驗序：前綴 → b64url 正形（無 padding）→ blob 長界 → GCM 認證（AAD='jr5s:'+id）
 * → 0x73 標記 → UTF-8（fatal 解碼，非合法 UTF-8＝null）。
 */
export async function jr5sDecrypt(wire: unknown, key: Uint8Array, id: unknown): Promise<string | null> {
  if (typeof wire !== 'string' || !wire.startsWith(JR5S_PREFIX)) return null;
  if (typeof id !== 'string' || !JR5S_ID_RE.test(id)) return null;
  if (key == null || key.length !== 32) return null;
  let raw: Uint8Array;
  try { raw = b64urlDecode(wire.slice(JR5S_PREFIX.length)); } catch { return null; }
  if (raw.length < JR5S_BLOB_MIN_BYTES || raw.length > JR5S_BLOB_MAX_BYTES) return null;
  const iv = raw.subarray(0, JR5S_IV_BYTES);
  const ctTag = raw.subarray(JR5S_IV_BYTES);
  try {
    const aesKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: enc().encode(JR5S_AAD_DOMAIN + id) as BufferSource },
      aesKey, ctTag as BufferSource));
    if (plain.length < 1 || plain[0] !== JR5S_TAG_BYTE) return null;
    return dec().decode(plain.subarray(1));
  } catch { return null; }
}
