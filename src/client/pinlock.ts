/**
 * pinlock.ts — 本機 PIN 鎖定包裹原語（jr1p.，「開啟時鎖定」，2026-09-24 動工）。
 *
 * 威脅模型：裝置被順手翻看／拔走。raw noteKey 摘除、以 PIN 派生 KEK 包裹，
 * 鎖定期間 localStorage 無 raw key（鐵律 8 誠實姿態的實質升級）。
 * jr1p. 刻意用 PBKDF2-SHA256 600k，不用 Argon2id：解鎖每次啟動都要經歷，
 * 鎖定閘要即時性＋省電；鎖定閘非登入 oracle 戰場（離線爆破 6 位純數字以 RTX 4090 公開基準
 * PBKDF2-SHA256 ≈ 8.8e9 iter/s ≈ 68 秒、8 位數字 ≈ 1.9 小時、6 碼小寫英數 ≈ 41 小時
 *（PoC C 實證底：4 位 16 核 CPU 28.7s 命中）＝門檻不是牆——即時性 vs 強度的取捨不變）。
 * KDF 升級走帶內版本化（新前綴），禁原地改語意。
 *
 * payload（pinSalt 內嵌自描述，與 jr2w./jr3d. 同構）：
 *   jr1p. + b64( pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad='notekey-pinlock') )，嚴格 108B
 *   KEK = PBKDF2-SHA256(pinNorm, 'tacet-pinlock-v1:' + hex(pinSalt), 600k) → AES-GCM key（nonextractable）
 * ⚠️ unwrap 輸出 noteKey 一律 extractable=true（鐵律 1：要能再包裹/匯出）；KEK nonextractable。
 * ⚠️ cfg 未配置 = 全拒（wrapDual/wrapShare3 同款 opt-in 律，兄弟 fork 零影響）。
 * ⚠️ 語意分離：jr1p. 是本機裝置閘，與登入第二因子（jr2w./jr3d.）契約、payload、威脅模型全分離。
 *
 * jr2p.（Argon2id pinlock，rotation-design §7.1；J3 併案）：
 *   jr2p. + b64( pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad=<cfg.pinLockAad>) )，嚴格 108B
 *   KEK = Argon2id(pinNorm, pinLockSaltPrefix + hex(pinSalt), 256MiB, t=1, p=1) → AES-256
 * AAD 零動（沿用 cfg.pinLockAad——新前綴新 KDF 同 AAD；前綴已負版本空間）。
 * 帶內版本化（讀舊寫新）：unwrap 路由「先試 jr2p.、回落 jr1p.」＝依前綴分派（非 KDF 失敗重試）；
 * rewrap 觸發＝解鎖命中 jr1p.→同 PIN 重包 jr2p. 回寫一次（重包成功即止；接線點 tacet lock-store）。
 */

import {
  b64, unb64, toHex, hexToBytes, decryptWithKey, importAesGcm, normalizePin,
} from './note-crypto.ts';
import { deriveArgon2id } from './argon2.ts';

/** 雙因子 pin 段等級（2M）過重：鎖定閘要即時性，600k 與 jr1w. 同級。 */
export const PINLOCK_ITERATIONS = 600_000;

/** jr2p.（Argon2id pinlock）fast 檔參數（rotation-design §7.1；預設，行動裝置優先）：
 *  m=256MiB（262144 KiB）、t=1、p=1。強度帳（§7.1）：256MiB（t=1）≈200-1000 猜/s（外推非實測，
 *  階段 2 前實測校準）；參數凍結進 KAT 向量（改參數＝換新前綴 jr3p.，帶內版本化）。
 *  heavy 檔（m=1GiB）＝可選升級面，本模組先落 fast 檔＝單一真相。 */
export const PINLOCK2_MEMORY_KIB = 262144; // 256 MiB
export const PINLOCK2_ITERATIONS = 1; // t
export const PINLOCK2_PARALLELISM = 1; // p

/** jr2p. 參數凍結 KAT（J14 母型：ARGON_PROD_PARAMS＋argon_prod 向量先例）——fast 檔參數
 *  定案後凍結進向量（§7.1 參數凍結律；改參數＝換新前綴 jr3p.）。pwd/salt＝確定性測試
 *  輸入（pin＝閘字面 '2580ab' 過 normalizePin；salt＝pinLockSaltPrefix ＋ 16B 0x00 hex——
 *  與 ARGON_PROD 同慣例），凍結值由 scripts/generate-vectors.ts 呼叫真原語產生
 *（kat.json `pinlock2_kat`）；verifyPinLock2KatProd 同源。KEK 輸出 32B（AES-256 直接作
 *  AES-GCM key，無 tagLen 參數——deriveArgon2id 定長輸出）。 */
export const PINLOCK2_KAT = Object.freeze({
  password: '2580ab',
  salt: 'tacet-pinlock-v1:' + '00'.repeat(16),
  memoryKib: PINLOCK2_MEMORY_KIB,
  iterations: PINLOCK2_ITERATIONS,
  parallelism: PINLOCK2_PARALLELISM,
} as const);

/** 凍結值（kat.json pinlock2_kat.expected_kek_hex 同源；node 真原語產生）。 */
export const PINLOCK2_KAT_EXPECTED =
  'aa6eacc6e786b3e7464afd7db13d17a5a1f9a20d9ba19cdf6d763c37ffe77137';

/** jr2p. fast 檔 KAT（J14a 母型）：驗證當前 Argon2id 載體對**凍結 fast 檔參數**（256MiB
 *  t=1 p=1）的推導＝凍結值——RFC 小參數 KAT 只覆蓋 m=32，argon_prod 覆蓋 64MiB t=3；
 *  本面覆蓋 pinlock fast 檔路（載體缺席回 false 不拋，與 verifyArgonKatProd 同形）。 */
export async function verifyPinLock2KatProd(): Promise<boolean> {
  const k = PINLOCK2_KAT;
  try {
    const raw = await deriveArgon2id(k.password, new TextEncoder().encode(k.salt), k.memoryKib, k.iterations, k.parallelism);
    return toHex(raw) === PINLOCK2_KAT_EXPECTED;
  } catch {
    return false;
  }
}

const SALT_LEN = 16;
const IV_LEN = 12;
/** pinSalt(16) + iv(12) + ct(hex 字串 64B + GCM tag 16B) = 108B 固定（jr1p./jr2p. 同構）。 */
const PAYLOAD_LEN = SALT_LEN + IV_LEN + 80;

/** 本機鎖定 cfg（各 fork config 注入；未配置 = API 拒絕，兄弟 fork 行為不變）。
 *  noteKeyExtractable 必填死欄移除——解包輸出恆 extractable（鐵律 1，
 *  要能再包裹／匯出）不是可調選項；tacet 消費端 TACET_PINLOCK 同步摘欄。
 *  pinLock2（jr2p.）選配欄：未配置 = jr2p. API 拒絕、jr1p. 面零變（cfg 選配律）。 */
export interface PinLockConfig {
  /** 本機鎖定包裹前綴，如 'jr1p.'. 未配置 = 拒絕。 */
  pinLock?: string;
  /** KDF salt 前綴，如 'tacet-pinlock-v1:'（拼接 hex(pinSalt) 後整串當 salt）。 */
  pinLockSaltPrefix?: string;
  /** AAD（鎖定包裹專用，與登入第二因子/分享包裹互斥）。未配置 = 拒絕。 */
  pinLockAad?: string;
  /** jr2p.（Argon2id pinlock）前綴，如 'jr2p.'. 未配置 = jr2p. API 拒絕，jr1p. 面零變。 */
  pinLock2?: string;
}

/** KEK = PBKDF2-SHA256(pinNorm, pinLockSaltPrefix + hex(pinSalt), 600k) → AES-GCM key（nonextractable）。 */
async function deriveLockKek(pinNorm: string, pinSalt: Uint8Array, cfg: PinLockConfig): Promise<CryptoKey> {
  if (!cfg.pinLock || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) throw new Error('ERR_PINLOCK_NOT_CONFIGURED');
  const keyMat = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pinNorm) as BufferSource,
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(cfg.pinLockSaltPrefix + toHex(pinSalt)) as BufferSource,
      iterations: PINLOCK_ITERATIONS,
    },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false, // KEK nonextractable
    ['encrypt', 'decrypt'],
  );
}

/** jr1p. 包裹：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad)；全自描述（salt 內嵌）。
 *  鹽內嵌家族（jr2w./jr3d./jr1p.）自帶三段組裝——sealNoteKey 是鹽外置家族形（iv‖ct），
 *  內嵌鹽的 pinSalt 前綴不在其契約內（毒化輪回歸實證：亂收口＝unwrap 恆 null）。 */
export async function wrapNoteKeyPinLock(cfg: PinLockConfig, noteKey: CryptoKey, pin: string): Promise<string> {
  if (!cfg.pinLock || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) throw new Error('ERR_PINLOCK_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_PINLOCK_EMPTY');
  const pinSalt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const kek = await deriveLockKek(pinNorm, pinSalt, cfg);
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(cfg.pinLockAad) as BufferSource },
    kek,
    new TextEncoder().encode(rawHex) as BufferSource,
  ));
  const payload = new Uint8Array(PAYLOAD_LEN);
  payload.set(pinSalt, 0);
  payload.set(iv, SALT_LEN);
  payload.set(ct, SALT_LEN + IV_LEN);
  return cfg.pinLock + b64(payload);
}

/** jr1p. 解包：全自描述；任何不符（前綴/長度/PIN 空/AAD）回 null 不拋；成功 → noteKey extractable=true（鐵律 1）。
 *  嚴格檢查為鹽內嵌族自有（payload 嚴格 108B＋rawHex hex 形檢查；
 *  hexToBytes fail-closed 由 try/catch 承接＝行為不變）——不經 openNoteKey 本體
 *  （openNoteKey 是鹽外置家族 92B 形，pinSalt 前綴不在其契約內）。 */
export async function unwrapNoteKeyPinLock(cfg: PinLockConfig, wrapped: string, pin: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.pinLock || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) return null;
    if (!wrapped.startsWith(cfg.pinLock)) return null;
    const payload = unb64(wrapped.slice(cfg.pinLock.length));
    if (payload.length !== PAYLOAD_LEN) return null;
    const pinSalt = payload.slice(0, SALT_LEN);
    const ivPrefixedCt = payload.slice(SALT_LEN); // 鹽內嵌家族：payload = pinSalt[16] ‖ iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek = await deriveLockKek(pinNorm, pinSalt, cfg);
    const rawHex = await decryptWithKey(kek, ivPrefixedCt, cfg.pinLockAad);
    if (!rawHex || rawHex.length !== 64 || !/^[0-9a-f]+$/.test(rawHex)) return null;
    return importAesGcm(hexToBytes(rawHex), true);
  } catch {
    return null;
  }
}

// ── jr2p.（Argon2id pinlock，rotation-design §7.1；J3 併案） ──────────────────

async function deriveLockKekArgon(pinNorm: string, pinSalt: Uint8Array, cfg: PinLockConfig): Promise<CryptoKey> {
  if (!cfg.pinLockSaltPrefix || !cfg.pinLockAad) throw new Error('ERR_PINLOCK2_NOT_CONFIGURED');
  // 無載體（無注入 loader＋非 node）即 throw＝禁 fallback 鐵律（與 argon2.ts 同律）。
  const raw = await deriveArgon2id(
    pinNorm,
    new TextEncoder().encode(cfg.pinLockSaltPrefix + toHex(pinSalt)),
    PINLOCK2_MEMORY_KIB,
    PINLOCK2_ITERATIONS,
    PINLOCK2_PARALLELISM,
  );
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** jr2p. 包裹：payload 同 jr1p.（pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad)），KEK 升 Argon2id。
 *  鹽內嵌家族自帶三段組裝（與 wrapNoteKeyPinLock 同形）；KEK nonextractable（鐵律 1 對偶面）。 */
export async function wrapNoteKeyPinLock2(cfg: PinLockConfig, noteKey: CryptoKey, pin: string): Promise<string> {
  if (!cfg.pinLock2 || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) throw new Error('ERR_PINLOCK2_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_PINLOCK_EMPTY');
  const pinSalt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const kek = await deriveLockKekArgon(pinNorm, pinSalt, cfg);
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(cfg.pinLockAad) as BufferSource },
    kek,
    new TextEncoder().encode(rawHex) as BufferSource,
  ));
  const payload = new Uint8Array(PAYLOAD_LEN);
  payload.set(pinSalt, 0);
  payload.set(iv, SALT_LEN);
  payload.set(ct, SALT_LEN + IV_LEN);
  return cfg.pinLock2 + b64(payload);
}

/** jr2p. 解包（blob 直解）：嚴格 108B＋rawHex hex 形（與 unwrapNoteKeyPinLock 同嚴格度）；
 *  任何不符（前綴/長度/PIN 空/GCM/AAD）回 null 不拋。成功 → noteKey extractable=true（鐵律 1）。 */
async function unwrapPinLock2Blob(cfg: PinLockConfig, wrapped: string, pin: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.pinLock2 || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) return null;
    if (!wrapped.startsWith(cfg.pinLock2)) return null;
    const payload = unb64(wrapped.slice(cfg.pinLock2.length));
    if (payload.length !== PAYLOAD_LEN) return null;
    const pinSalt = payload.slice(0, SALT_LEN);
    const ivPrefixedCt = payload.slice(SALT_LEN); // 鹽內嵌家族：payload = pinSalt[16] ‖ iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek = await deriveLockKekArgon(pinNorm, pinSalt, cfg);
    const rawHex = await decryptWithKey(kek, ivPrefixedCt, cfg.pinLockAad);
    if (!rawHex || rawHex.length !== 64 || !/^[0-9a-f]+$/.test(rawHex)) return null;
    return importAesGcm(hexToBytes(rawHex), true);
  } catch {
    return null;
  }
}

/**
 * jr2p./jr1p. 解鎖路由（讀舊寫新，§7.1）：**依前綴分派，非 KDF 失敗重試**——
 * - blob 前綴 `jr2p.` → 走 jr2p. 路徑；GCM 失敗回 null（**不再試 jr1p.**）；
 * - blob 前綴 `jr1p.` → 走 jr1p. 回落路徑（舊 blob 恆可解、jr1p. 讀契約保留——
 *   存量 PIN 用戶的解鎖不能斷；帶內版本化解舊寫新）。
 * 回傳 { key, upgraded }：upgraded=true＝命中 jr1p. 舊形**且 pinLock2 已配置**＝呼叫端
 * rewrap 觸發面（§7.1 r4 修案：同 PIN 重包 jr2p. 回寫一次、重包成功即止；接線點＝tacet
 * lock-store enableLock 解鎖成功路徑——core 只提供命中回傳面）。pinLock2 未配置（兄弟
 * fork 選配律）＝upgraded 恆 false（無升級路徑可觸發——不給呼叫端一個會 throw 的觸發面）。
 * 兩前綴皆非（junk/他家族）＝ { key: null, upgraded: false }（fail-closed 不拋）。
 * 實作者不可漏 jr1p. 回落（漏＝存量 PIN 用戶鎖死，違反卡體否決案）。
 */
export async function unwrapNoteKeyPinLock2(
  cfg: PinLockConfig,
  wrapped: string,
  pin: string,
): Promise<{ key: CryptoKey | null; upgraded: boolean }> {
  if (cfg.pinLock2 && wrapped.startsWith(cfg.pinLock2)) {
    return { key: await unwrapPinLock2Blob(cfg, wrapped, pin), upgraded: false };
  }
  if (cfg.pinLock && wrapped.startsWith(cfg.pinLock)) {
    const key = await unwrapNoteKeyPinLock(cfg, wrapped, pin);
    return { key, upgraded: key !== null && cfg.pinLock2 !== undefined };
  }
  return { key: null, upgraded: false };
}

/** jr2p. 前綴判定（lock-store 分流/形狀面用；cfg 未配置恆 false）。 */
export function isPinLockWrap2(wrapped: string, cfg: PinLockConfig): boolean {
  return !!cfg.pinLock2 && wrapped.startsWith(cfg.pinLock2);
}
