/**
 * pinlock.ts — 本機 PIN 鎖定包裹原語（jr1p.，「開啟時鎖定」，2026-09-24 動工）。
 *
 * 威脅模型：裝置被順手翻看／拔走。raw noteKey 摘除、以 PIN 派生 KEK 包裹，
 * 鎖定期間 localStorage 無 raw key（鐵律 8 誠實姿態的實質升級）。
 * jr1p. 刻意用 PBKDF2-SHA256 600k，不用 Argon2id：解鎖每次啟動都要經歷，
 * 鎖定閘要即時性＋省電；鎖定閘非登入 oracle 戰場（離線爆破 6 位數字 ≈ 單 GPU 數天＝門檻不是牆）。
 * KDF 升級走帶內版本化（新前綴），禁原地改語意。
 *
 * payload（pinSalt 內嵌自描述，與 jr2w./jr3d. 同構）：
 *   jr1p. + b64( pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad='notekey-pinlock') )，嚴格 108B
 *   KEK = PBKDF2-SHA256(pinNorm, 'tacet-pinlock-v1:' + hex(pinSalt), 600k) → AES-GCM key（nonextractable）
 * ⚠️ unwrap 輸出 noteKey 一律 extractable=true（鐵律 1：要能再包裹/匯出）；KEK nonextractable。
 * ⚠️ cfg 未配置 = 全拒（wrapDual/wrapShare3 同款 opt-in 律，兄弟 fork 零影響）。
 * ⚠️ 語意分離：jr1p. 是本機裝置閘，與登入第二因子（jr2w./jr3d.）契約、payload、威脅模型全分離。
 */

import {
  b64, unb64, toHex, hexToBytes, decryptWithKey, importAesGcm, normalizePin,
} from './note-crypto.ts';

/** 雙因子 pin 段等級（2M）過重：鎖定閘要即時性，600k 與 jr1w. 同級。 */
export const PINLOCK_ITERATIONS = 600_000;

const SALT_LEN = 16;
const IV_LEN = 12;
/** pinSalt(16) + iv(12) + ct(hex(noteKey) 64B + GCM tag 16B) = 108B 固定。 */
const PAYLOAD_LEN = SALT_LEN + IV_LEN + 80;

/** 本機鎖定 cfg（各 fork config 注入；未配置 = API 拒絕，兄弟 fork 行為不變）。 */
export interface PinLockConfig {
  /** 本機鎖定包裹前綴，如 'jr1p.'. 未配置 = 拒絕。 */
  pinLock?: string;
  /** KDF salt 前綴，如 'tacet-pinlock-v1:'（拼接 hex(pinSalt) 後整串當 salt）。 */
  pinLockSaltPrefix?: string;
  /** AAD（鎖定包裹專用，與登入第二因子/分享包裹互斥）。未配置 = 拒絕。 */
  pinLockAad?: string;
  /** 解包輸出的 noteKey（要能再包裹/匯出，鐵律 1）。 */
  noteKeyExtractable: boolean;
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

/** jr1p. 包裹：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad)；全自描述（salt 內嵌）。 */
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

/** jr1p. 解包：全自描述；任何不符（前綴/長度/PIN 空/AAD）回 null 不拋；成功 → noteKey extractable=true（鐵律 1）。 */
export async function unwrapNoteKeyPinLock(cfg: PinLockConfig, wrapped: string, pin: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.pinLock || !cfg.pinLockSaltPrefix || !cfg.pinLockAad) return null;
    if (!wrapped.startsWith(cfg.pinLock)) return null;
    const payload = unb64(wrapped.slice(cfg.pinLock.length));
    if (payload.length !== PAYLOAD_LEN) return null;
    const pinSalt = payload.slice(0, SALT_LEN);
    const ivPrefixedCt = payload.slice(SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek = await deriveLockKek(pinNorm, pinSalt, cfg);
    const rawHex = await decryptWithKey(kek, ivPrefixedCt, cfg.pinLockAad);
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true);
  } catch {
    return null;
  }
}