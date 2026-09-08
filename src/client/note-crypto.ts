/**
 * note-crypto.ts — 自由書寫 e2e 加密，品牌參數化核心（2026-09-07 抽取）。
 *
 * 抽取自 sennight src/domain/noteCrypto.ts（37 斷言 verify-note-crypto.ts 母型）。
 * 兩 fork diff 已證實：除品牌前綴（sennight-/vestige-、sn1↔同一家族、KDF salt 前綴）
 * 與產品附加機制（vestige testaments）外，密碼學本體完全一致——本檔收編該本體。
 *
 * 兩時代金鑰模型（不變量，勿破壞）：
 *   時代 1（未綁定 guest）：K_u = SHA-256(guestKdfPrefix ‖ identity) — 純客戶端派生，混淆級
 *   時代 2（綁定後）：隨機 256-bit noteKey；日常加解密只用 noteKey，passphrase 以
 *     KEK = PBKDF2(pass, salt, 600000, SHA-256) 包裹成 wrapped 上傳；復原套件 wrappedRec
 *     = 同款包裹在 KEK_rec = PBKDF2(recToken, salt = recSaltPrefix ‖ identity) 下。
 *     passphrase 從此不過線：線上憑證送 PH1 = SHA-256(pass)，伺服器存 PH2。
 *
 * 前綴全部可配置（帶內版本化：升級 KDF 參數 = 換新前綴）。AAD 由呼叫端傳入——
 * sennight 綁 `lifeId:day`、vestige 留言綁 `tst:<lifeId>`、tacet 綁 `noteId`。
 *
 * ⚠️ extractable 鐵律（2026-09-06 iOS 實機炸證）：所有要被 exportKey/wrap 的 key，
 * import 當下就必須 extractable=true。noteKey 全部產生路徑（generate/unwrap×3）
 * 一律顯式 true；KEK/guest key 保持 nonextractable（只加解密、永不 export）。
 */

// ── 配置 ────────────────────────────────────────────────────────────────────

export interface NoteCryptoConfig {
  /** guest 時代 KDF 前綴，如 'sennight-note-u1'。 */
  guestKdfPrefix: string;
  /** 復原包裹 KDF salt 前綴，如 'sennight-note-rec1:'。 */
  recSaltPrefix: string;
  /** 密文前綴：guest 時代，如 'sn1u.'。 */
  cipherGuest: string;
  /** 密文前綴：綁定時代，如 'sn1b.'。 */
  cipherBound: string;
  /** 金鑰包裹前綴，如 'snw1.'。 */
  wrap: string;
  /** 雙因子合鑰包裹前綴（jr2w.，PIN 第二因子）。未配置 = dual API 拒絕（兄弟 fork 行為不變）。 */
  wrapDual?: string;
  /** 雙因子 pin 段 PBKDF2 salt 前綴，如 'tacet-note-pin1:'（pinSalt 內嵌 payload 後拼接）。 */
  pinSaltPrefix?: string;
  /** 分享包裹前綴（jrsw.，單篇分享連結 V1）。未配置 = share API 拒絕（兄弟 fork 行為不變）。 */
  wrapShare?: string;
  /** localStorage key store（品牌前綴由 keys.ts 管理）。 */
  store: import('./keys').KeyStore;
}

export const PBKDF2_ITERATIONS = 600_000; // OWASP 2023 建議值
export const PIN_PBKDF2_ITERATIONS = 2_000_000; // 雙因子 pin 段（設計 v2：6 位數字也要扛離線爆破）
export const IV_LEN = 12;

const HEX32_RE = /^[0-9a-f]{32}$/; // 16-byte salt hex

// ── 基礎工具 ────────────────────────────────────────────────────────────────

function b64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function unb64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array((hex.match(/.{2}/g) ?? []).map(h => parseInt(h, 16)));
}

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(new Uint8Array(d));
}

/** SHA-256 hex（分享定位鍵雜湊等呼叫端雜湊用；與伺服器端 sha256Hex 同構）。 */
export function sha256HexExport(text: string): Promise<string> {
  return sha256Hex(text);
}

async function importAesGcm(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  // extractable 預設 false（最小權限）；唯一需要 true 的是 noteKey。
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

async function deriveGuestKey(cfg: NoteCryptoConfig, identity: string): Promise<CryptoKey> {
  const material = new TextEncoder().encode(cfg.guestKdfPrefix + identity);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  return importAesGcm(digest);
}

async function deriveKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password) as BufferSource, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ── 雙因子合鑰（jr2w.，PIN 第二因子；2026-09-09 定案 v2） ────────────────────
//
// KEK2 = HKDF-SHA256( ikm = PBKDF2(pass, salt1, 600k)[32B] ‖ PBKDF2(pin, pinSaltPrefix‖pinSalt, 2M)[32B],
//                     salt = pinSalt（同 16B，公開非秘密）, info = 'journal-kek2-v1:' + wrapDual, L=32 )
// payload = pinSalt[16B] ‖ iv[12B] ‖ AES-GCM(KEK2, hex(noteKey), aad='notekey2')
// wrapped2 = 'jr2w.' + b64(payload) —— pinSalt 內嵌自描述：unwrap 不需 identity/salt 參數。
// 兩段 PBKDF2 bits 不落地（用完即棄）；KEK2 import 當下 nonextractable；
// 輸出 noteKey 一律 extractable=true（鐵律 4）。

/** PIN 正規化契約：NFKC → trim → lowercase（不分大小寫；正規化後內含空白由強度檢拒絕）。 */
export function normalizePin(pin: string): string {
  return pin.normalize('NFKC').trim().toLowerCase();
}

async function derivePbkdf2Bits(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password) as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, keyMat, 256);
  return new Uint8Array(bits);
}

async function deriveKek2(cfg: NoteCryptoConfig, passphrase: string, pin: string, salt1: Uint8Array, pinSalt: Uint8Array): Promise<CryptoKey> {
  const passBits = await derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS);
  const pinBits = await derivePbkdf2Bits(pin, new TextEncoder().encode(cfg.pinSaltPrefix + toHex(pinSalt)), PIN_PBKDF2_ITERATIONS);
  const ikm = new Uint8Array(passBits.byteLength + pinBits.byteLength);
  ikm.set(passBits, 0);
  ikm.set(pinBits, passBits.byteLength);
  const hkdfBase = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: pinSalt as BufferSource, info: new TextEncoder().encode('journal-kek2-v1:' + cfg.wrapDual) as BufferSource },
    hkdfBase,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

const DUAL_SALT_LEN = 16;
const DUAL_IV_LEN = 12;

/** 雙因子包裹：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, hex(noteKey))；salt1 隨機由呼叫端存 users.salt。 */
export async function wrapNoteKeyDual(cfg: NoteCryptoConfig, noteKey: CryptoKey, passphrase: string, pin: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapDual || !cfg.pinSaltPrefix) throw new Error('ERR_DUAL_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_DUAL_NOT_CONFIGURED');
  const salt1 = crypto.getRandomValues(new Uint8Array(16));
  const pinSalt = crypto.getRandomValues(new Uint8Array(DUAL_SALT_LEN));
  const kek2 = await deriveKek2(cfg, passphrase, pinNorm, salt1, pinSalt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('notekey2') as BufferSource },
    kek2,
    new TextEncoder().encode(rawHex) as BufferSource,
  ));
  const payload = new Uint8Array(DUAL_SALT_LEN + iv.byteLength + ct.byteLength);
  payload.set(pinSalt, 0);
  payload.set(iv, DUAL_SALT_LEN);
  payload.set(ct, DUAL_SALT_LEN + iv.byteLength);
  return { wrapped: cfg.wrapDual + b64(payload), salt: toHex(salt1) };
}

/** 雙因子解包：pinSalt 內嵌自描述，salt1 取自 login 回應（與 jr1w 同形）；任何不符回 null，不拋。 */
export async function unwrapNoteKeyDual(cfg: NoteCryptoConfig, wrapped: string, passphrase: string, pin: string, salt1Hex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapDual || !cfg.pinSaltPrefix) return null;
    if (!wrapped.startsWith(cfg.wrapDual)) return null;
    const salt1 = hexToBytes(salt1Hex);
    if (salt1.length !== 16) return null;
    const payload = unb64(wrapped.slice(cfg.wrapDual.length));
    // 嚴格長度：pinSalt(16) + iv(12) + ct(hex(noteKey) 64B + GCM tag 16B) = 108B 固定
    if (payload.length !== DUAL_SALT_LEN + DUAL_IV_LEN + 80) return null;
    const pinSalt = payload.slice(0, DUAL_SALT_LEN);
    const ivPrefixedCt = payload.slice(DUAL_SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek2 = await deriveKek2(cfg, passphrase, pinNorm, salt1, pinSalt);
    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹（鐵律）
  } catch {
    return null;
  }
}

// ── 對稱核心：encrypt / decrypt（AAD 由呼叫端指定） ──────────────────────────

async function encryptWithKey(key: CryptoKey, plaintext: string, aad: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad) as BufferSource },
    key,
    new TextEncoder().encode(plaintext) as BufferSource,
  ));
  const out = new Uint8Array(IV_LEN + ct.byteLength);
  out.set(iv, 0);
  out.set(ct, IV_LEN);
  return b64(out);
}

async function decryptWithKey(key: CryptoKey, payload: Uint8Array, aad: string): Promise<string | null> {
  try {
    const iv = payload.slice(0, IV_LEN);
    const ct = payload.slice(IV_LEN);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: new TextEncoder().encode(aad) as BufferSource },
      key,
      ct as BufferSource,
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null; // 錯誤金鑰 / AAD 不符 / 密文損壞 → 呼叫端回落降級句
  }
}

// ── noteKey（時代 2）─────────────────────────────────────────────────────────

/** 綁定當下生成：random 256-bit AES-GCM key。必須 extractable（包裹靠 exportKey）。 */
export async function generateNoteKey(): Promise<CryptoKey> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return importAesGcm(raw, true);
}

/** 登入憑證：PH1 = SHA-256(pass)——pass 明文從此不過線（伺服器存 PH2）。 */
export function ph1Of(passphrase: string): Promise<string> {
  return sha256Hex(passphrase);
}

/** 復原種子：32 bytes hex，只顯示一次；伺服器只收 SHA-256。 */
export function generateRecToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function recTokenHash(recToken: string): Promise<string> {
  return sha256Hex(recToken);
}

// ── 金鑰包裹 ────────────────────────────────────────────────────────────────

/** passphrase 包裹：salt 隨機 16 bytes（hex 存於 users.salt）。 */
export async function wrapNoteKey(cfg: NoteCryptoConfig, noteKey: CryptoKey, passphrase: string): Promise<{ wrapped: string; salt: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKek(passphrase, salt);
  const payload = new Uint8Array(await crypto.subtle.exportKey('raw', noteKey));
  const wrapped = cfg.wrap + await encryptWithKey(kek, toHex(payload), 'notekey');
  return { wrapped, salt: toHex(salt) };
}

export async function unwrapNoteKey(cfg: NoteCryptoConfig, wrapped: string, passphrase: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!wrapped.startsWith(cfg.wrap)) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== 16 || !HEX32_RE.test(saltHex)) return null;
    const kek = await deriveKek(passphrase, salt);
    const rawHex = await decryptWithKey(kek, unb64(wrapped.slice(cfg.wrap.length)), 'notekey');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹
  } catch {
    return null;
  }
}

// ── 分享包裹（jrsw.，單篇分享連結 V1）────────────────────────────────────────
//
// KEK_share = PBKDF2(sharePass, salt 16B 隨機, 600k, SHA-256)（與 jr1w 同構），
// payload = iv[12] ‖ AES-GCM(KEK_share, hex(noteKey), aad='notekey-share')，
// wrapped = 'jrsw.' + b64(payload)。salt 由呼叫端存 D1（shares.salt）；
// 分享密語永不過線（與 passphrase 同律）。AAD 用獨立字串，兩種包裹結構不可互換。

/** 分享包裹：salt 隨機 16 bytes（hex 由呼叫端存 shares.salt）。 */
export async function wrapNoteKeyShare(cfg: NoteCryptoConfig, noteKey: CryptoKey, sharePass: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapShare) throw new Error('ERR_SHARE_NOT_CONFIGURED');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKek(sharePass, salt);
  const payload = new Uint8Array(await crypto.subtle.exportKey('raw', noteKey));
  const wrapped = cfg.wrapShare + await encryptWithKey(kek, toHex(payload), 'notekey-share');
  return { wrapped, salt: toHex(salt) };
}

/** 分享解包：salt 取自 GET /shares/:hash 回應（與 jr1w 同形）；任何不符回 null，不拋。 */
export async function unwrapNoteKeyShare(cfg: NoteCryptoConfig, wrapped: string, sharePass: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapShare) return null;
    if (!wrapped.startsWith(cfg.wrapShare)) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== 16 || !HEX32_RE.test(saltHex)) return null;
    const kek = await deriveKek(sharePass, salt);
    const rawHex = await decryptWithKey(kek, unb64(wrapped.slice(cfg.wrapShare.length)), 'notekey-share');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：解出後要能解日記密文（鐵律）
  } catch {
    return null;
  }
}

/** 復原套件包裹：KEK_rec = PBKDF2(recToken, salt = recSaltPrefix ‖ identity)。 */
async function deriveRecKek(cfg: NoteCryptoConfig, recToken: string, identity: string): Promise<CryptoKey> {
  return deriveKek(recToken, new TextEncoder().encode(cfg.recSaltPrefix + identity));
}

export async function wrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, noteKey: CryptoKey, recToken: string, identity: string): Promise<string> {
  const kek = await deriveRecKek(cfg, recToken, identity);
  const payload = new Uint8Array(await crypto.subtle.exportKey('raw', noteKey));
  return cfg.wrap + await encryptWithKey(kek, toHex(payload), 'notekey');
}

export async function unwrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, wrapped: string, recToken: string, identity: string): Promise<CryptoKey | null> {
  try {
    if (!wrapped.startsWith(cfg.wrap)) return null;
    const kek = await deriveRecKek(cfg, recToken, identity);
    const rawHex = await decryptWithKey(kek, unb64(wrapped.slice(cfg.wrap.length)), 'notekey');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // 復原後要能重新包裹
  } catch {
    return null;
  }
}

/** 綁定請求的金鑰包裹三件套（bind 用）+ recovery_token_hash。 */
export async function buildBindPayload(
  cfg: NoteCryptoConfig,
  noteKey: CryptoKey,
  passphrase: string,
  recToken: string,
  identity: string,
): Promise<{ wrapped: string; salt: string; wrappedRec: string; recTokenHash: string }> {
  const { wrapped, salt } = await wrapNoteKey(cfg, noteKey, passphrase);
  const wrappedRec = await wrapNoteKeyWithRecToken(cfg, noteKey, recToken, identity);
  return {
    wrapped,
    salt,
    wrappedRec,
    recTokenHash: await recTokenHash(recToken),
  };
}

// ── 本機包裹（PWA session 期免重打密語） ─────────────────────────────────────

export async function storeLocalWrap(cfg: NoteCryptoConfig, identity: string, noteKey: CryptoKey): Promise<void> {
  try {
    const guest = await deriveGuestKey(cfg, identity);
    const raw = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
    cfg.store.set(cfg.store.noteKeyWrap(identity), cfg.wrap + await encryptWithKey(guest, raw, 'notekey-local'));
  } catch { /* private mode：不阻擋主流程 */ }
}

async function loadLocalWrap(cfg: NoteCryptoConfig, identity: string): Promise<CryptoKey | null> {
  try {
    const stored = cfg.store.get(cfg.store.noteKeyWrap(identity));
    if (!stored || !stored.startsWith(cfg.wrap)) return null;
    const guest = await deriveGuestKey(cfg, identity);
    const rawHex = await decryptWithKey(guest, unb64(stored.slice(cfg.wrap.length)), 'notekey-local');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true);
  } catch {
    return null;
  }
}

export function clearLocalWrap(cfg: NoteCryptoConfig, identity: string): void {
  cfg.store.remove(cfg.store.noteKeyWrap(identity));
}

// ── 日記密文入口（held key 狀態機） ─────────────────────────────────────────

export interface HeldKey {
  get(): CryptoKey | null;
  set(key: CryptoKey | null): void;
}

export function makeHeldKey(): HeldKey {
  let held: CryptoKey | null = null;
  return { get: () => held, set: (k) => { held = k; } };
}

export interface IdentityProvider {
  /** 當前身份字串（sennight/vestige = soulKey；tacet = account_id 或空）。 */
  current(): string;
}

/** 加密一則：綁定時代持有 noteKey → cipherBound；否則 guest key → cipherGuest。
 *  held 為空時先試本機包裹（reload / PWA 續存期免重打密語）。 */
export async function encryptNote(
  cfg: NoteCryptoConfig,
  held: HeldKey,
  plaintext: string,
  aad: string,
  idp: IdentityProvider,
): Promise<string> {
  if (!held.get()) {
    const identity = idp.current();
    if (identity) held.set(await loadLocalWrap(cfg, identity));
  }
  if (held.get()) {
    return cfg.cipherBound + await encryptWithKey(held.get()!, plaintext, aad);
  }
  const guest = await deriveGuestKey(cfg, idp.current());
  return cfg.cipherGuest + await encryptWithKey(guest, plaintext, aad);
}

/** 解密一則：按前綴選鑰匙；無前綴 = 舊版明文（相容層）原樣返回；失敗回 null。 */
export async function decryptNote(
  cfg: NoteCryptoConfig,
  held: HeldKey,
  cipher: string,
  aad: string,
  idp: IdentityProvider,
): Promise<string | null> {
  try {
    const isGuest = cipher.startsWith(cfg.cipherGuest);
    const isBound = cipher.startsWith(cfg.cipherBound);
    if (!isGuest && !isBound) return cipher; // 舊版明文（相容層）：原樣顯示
    if (isGuest) {
      const guest = await deriveGuestKey(cfg, idp.current());
      return await decryptWithKey(guest, unb64(cipher.slice(cfg.cipherGuest.length)), aad);
    }
    if (!held.get()) {
      const identity = idp.current();
      held.set(identity ? await loadLocalWrap(cfg, identity) : null);
    }
    if (!held.get()) return null;
    return await decryptWithKey(held.get()!, unb64(cipher.slice(cfg.cipherBound.length)), aad);
  } catch {
    return null;
  }
}