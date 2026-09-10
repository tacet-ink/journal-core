/**
 * argon2.ts — Argon2id 包裹原語（jr3w./jr3d.，安全路線第 2 步，2026-09-14）。
 *
 * 動機（安全路線定案）：離線 oracle 的戰利品是 wrapped（/auth/login 回應帶 wrapped+salt，
 * 拿到一次回應即可永久離線猜）。PBKDF2-SHA256 600k 對 GPU 友善；Argon2id 的記憶體困難
 * 讓每猜成本上升一至兩個數量級，oracle 實際價值大幅中和。OPAQUE 降級為後續精益求精。
 *
 * 帶內版本化契約（不變量 5）：升級 KDF = 換新前綴，禁原地改語意。
 *   jr3w. 單因子：結構與 jr1w. 同構（salt 獨立存 users.salt；wrapped = prefix + b64(iv[12] ‖ ct)，
 *         ct = AES-GCM(KEK, hex(noteKey), aad='notekey')），只換 KEK 派生：
 *         KEK = Argon2id(pass, salt, m=64MiB, t=3, p=1, tag=32B) → AES-GCM key。
 *   jr3d. 雙因子（jr2w. 後繼）：payload 同 jr2w.（pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, hex(noteKey), aad='notekey2')），
 *         KEK2 = HKDF-SHA256( ikm = Argon2id(pass, salt1)[32] ‖ Argon2id(pinNorm, pinSalt3Prefix‖hex(pinSalt))[32],
 *                             salt = pinSalt, info = 'journal-kek2-v1:' + wrapDual3, L = 32 )。
 * 兩 payload 長度相同（皆 108B）：客戶端按前綴分流（jr3w.→單因子、jr3d.→雙因子），形狀互斥由
 * AAD 與長度把關，跨前綴呼叫一律回 null（unwrap 有前綴守衛，驗證閘有跨協議斷言）。
 *
 * 雙載體（同一 spec 兩端一致，交叉驗證逐位元一致）：
 * - node（驗證閘/prod smoke）：node:crypto.argon2（Node 26 原生，26.8.1 實測）
 * - 瀏覽器：hash-wasm argon2id（純 wasm 內嵌 base64，零網路請求，4.12.0 實測 64MiB t=3 ≈ 180ms）
 * 標準向量：RFC 9106 無 secret/associated-data Argon2id（t=3, m=32, p=4, pwd=32B 0x01, salt=16B 0x00）
 *   = 72d2a36fd5c266bcc96121b24937bc253338cdfcbd273713655748c54b4dd503（兩載體實測 MATCH）。
 *
 * 遷移契約（禁強制重置）：既有 jr1w./jr2w. 帳戶在下次成功 unwrap 後由客戶端靜默
 * re-wrap 推 jr3w./jr3d.（手上有 noteKey、同一 noteKey 重包，資料零換鑰）；舊前綴照解。
 *
 * ⚠️ 鐵律：unwrap 輸出 noteKey 一律 extractable=true（要能再包裹）；KEK/KEK2 nonextractable。
 * ⚠️ deriveArgon2id 禁 fallback（零知識）：無載體即 throw，禁降級 PBKDF2 或 zeros 兜底。
 * ⚠️ wrappedRec（復原套件）維持 jr1w.：recToken 是 256-bit 實體因子，KDF 強度無意義，不動。
 */

import { IV_LEN, normalizePin } from './note-crypto.ts';
import {
  b64, unb64, toHex, hexToBytes, encryptWithKey, decryptWithKey, importAesGcm,
} from './note-crypto.ts';

/** RFC 9106 無 secret/ad 標準向量（Argon2id v=0x13, t=3, m=32, p=4, T=32, pwd=32B 0x01, salt=16B 0x00）。 */
export const ARGON_RFC9106_EXPECTED =
  '72d2a36fd5c266bcc96121b24937bc253338cdfcbd273713655748c54b4dd503';

/**
 * PH1 v2 固定域鹽（登入憑證 Argon2id 派生，2026-09-10 安全路線第 4 步）。
 *
 * 固定鹽是被迫設計：per-user 鹽會摧毀 PH2 UNIQUE（同一密語必須恒生同一 ph2，
 * 幽靈帳號機制與「同密語不可開第二帳戶」都靠它）。帶內版本化：改參數 = 換鹽尾碼
 * （v2/v3…）重遷移，禁原地改語意。實長 12B（RFC 9106 鹽最小 8B；Task 0 探針實證）。
 */
export const PH1_V2_SALT = 'tacet-ph1-v1';

/**
 * PH1 v2：登入憑證 = Argon2id(pass, 固定域鹽, m=64MiB, t=3, p=1) → hex64。
 *
 * 動機：DB 全洩後 ph2 = sha256(ph1) 是離線爆破讀日記的最後一個快雜湊面（候選密語
 * 重算 sha256(sha256(g)) 對 ph2 命中即 g 是密語）。ph1 改 Argon2id 派生後每猜成本
 * ×10⁴-10⁶。參數沿 jr3w. 同一組常數（單一碼路）；無載體即 throw（禁 fallback 鐵律）。
 */
export async function derivePh1Argon(passphrase: string): Promise<string> {
  return toHex(await deriveArgon2id(
    passphrase,
    new TextEncoder().encode(PH1_V2_SALT),
    ARGON_MEMORY_KIB,
    ARGON_ITERATIONS,
    ARGON_PARALLELISM,
  ));
}

/** Argon2id 參數（jr3w./jr3d. pass 段；前綴即版本，參數寫死本模組）。 */
export const ARGON_MEMORY_KIB = 65536; // 64 MiB（手機實測基準；瀏覽器 wasm ~180ms）
export const ARGON_ITERATIONS = 3; // t
export const ARGON_PARALLELISM = 1; // p（瀏覽器 wasm 無平行收益，定 1 兩端一致）
export const ARGON_TAG_LEN = 32; // 256-bit AES key

/** 雙因子 pin 段 Argon2id 參數（PIN 弱 → 記憶體補償；與 pass 段同級）。 */
export const ARGON_PIN_MEMORY_KIB = 65536;
export const ARGON_PIN_ITERATIONS = 3;
export const ARGON_PIN_PARALLELISM = 1;

const SALT_LEN = 16;
const DUAL_SALT_LEN = 16;
const DUAL_IV_LEN = 12;

/** jr3w 家族前綴（各 fork config 注入；未配置 = jr3w API 拒絕，兄弟 fork 行為不變）。 */
export interface Argon3Config {
  /** 單因子包裹前綴，如 'jr3w.'。未配置 = 拒絕。 */
  wrap3?: string;
  /** 雙因子包裹前綴，如 'jr3d.'。未配置 = 拒絕。 */
  wrapDual3?: string;
  /** 雙因子 pin 段 Argon2id salt 前綴，如 'tacet-note-pin3:'（拼接 hex(pinSalt) 後整串當 salt）。 */
  pinSalt3Prefix?: string;
  /** 分享包裹前綴（jr3s.，單篇分享連結 Argon2id 版）。未配置 = 分享 API 拒絕（兄弟 fork 行為不變）。 */
  wrapShare3?: string;
}

interface HashWasmArgon2id {
  (params: {
    password: string | Uint8Array;
    salt: Uint8Array;
    iterations: number;
    parallelism: number;
    memorySize: number;
    hashLength: number;
    outputType: 'binary' | 'hex' | 'encoded';
  }): Promise<Uint8Array | string>;
}

type ArgonLoader = () => Promise<{ argon2id: HashWasmArgon2id }>;

let injectedLoader: ArgonLoader | null = null;

/** 載體注入（瀏覽器端由接線層指定 hash-wasm；node 端不注入走 node:crypto 原生）。 */
export function setArgonLoader(loader: ArgonLoader | null): void {
  injectedLoader = loader;
}

/**
 * Argon2id 派生 32B。雙載體：injectedLoader（瀏覽器 hash-wasm）優先；
 * 無注入時走 node:crypto 原生（僅 node 執行環境可達）。皆不可得即 throw（禁 fallback）。
 */
async function deriveArgon2id(
  password: string | Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  passes: number,
  parallelism: number,
): Promise<Uint8Array> {
  if (injectedLoader) {
    const mod = await injectedLoader();
    const out = await mod.argon2id({
      password,
      salt,
      iterations: passes,
      parallelism,
      memorySize: memoryKib,
      hashLength: ARGON_TAG_LEN,
      outputType: 'binary',
    });
    const bytes = typeof out === 'string' ? hexToBytes(out) : new Uint8Array(out);
    if (bytes.length !== ARGON_TAG_LEN) throw new Error('ERR_ARGON2_TAGLEN');
    return bytes;
  }
  const nodeCrypto = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { argon2?: NodeArgonFn } | undefined };
  }).process?.getBuiltinModule?.('node:crypto');
  if (!nodeCrypto?.argon2) throw new Error('ERR_ARGON2_UNAVAILABLE');
  return new Promise<Uint8Array>((resolve, reject) => {
    nodeCrypto.argon2!(
      'argon2id',
      {
        message: password,
        nonce: salt,
        memory: memoryKib,
        passes,
        parallelism,
        tagLength: ARGON_TAG_LEN,
        maxmem: 2 * 1024 * 1024 * 1024, // 2GiB：node 原生預設 1GiB 上限對 m+128*p*8 記帳過緊
      },
      (err: Error | null, key: Uint8Array) => (err ? reject(err) : resolve(new Uint8Array(key))),
    );
  });
}

type NodeArgonFn = (
  algorithm: 'argon2d' | 'argon2i' | 'argon2id',
  parameters: {
    message: string | Uint8Array;
    nonce: Uint8Array;
    memory: number;
    passes: number;
    parallelism: number;
    tagLength: number;
    maxmem?: number;
  },
  callback: (err: Error | null, key: Uint8Array) => void,
) => void;

/** 標準向量 KAT：驗證當前載體的 Argon2id 實作正確性（驗證閘起手式）。 */
export async function verifyArgonKat(): Promise<boolean> {
  const raw = await deriveArgon2id(new Uint8Array(32).fill(1), new Uint8Array(16), 32, 3, 4);
  return toHex(raw) === ARGON_RFC9106_EXPECTED;
}

// ── jr3w. 單因子包裹 ──────────────────────────────────────────────────────────

async function argonKekFromRaw(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** KEK = Argon2id(pass, salt, m=64MiB, t=3, p=1) → AES-GCM key（nonextractable）。 */
export async function deriveKekArgon(password: string, salt: Uint8Array): Promise<CryptoKey> {
  return argonKekFromRaw(await deriveArgon2id(password, salt, ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM));
}

/** jr3w. 包裹：payload = salt[16] ‖ iv[12] ‖ AES-GCM(KEK, hex(noteKey), aad='notekey')；salt 由呼叫端存 users.salt。 */
export async function wrapNoteKey3(cfg: Argon3Config, noteKey: CryptoKey, passphrase: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrap3) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const kek = await deriveKekArgon(passphrase, salt);
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const wrapped = cfg.wrap3 + await encryptWithKey(kek, rawHex, 'notekey');
  return { wrapped, salt: toHex(salt) };
}

/** jr3w. 解包：任何不符（前綴/salt 形/長度/AAD）回 null 不拋；成功 → noteKey extractable=true（鐵律 4）。 */
export async function unwrapNoteKey3(cfg: Argon3Config, wrapped: string, passphrase: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrap3 || !wrapped.startsWith(cfg.wrap3)) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(saltHex)) return null;
    const payload = unb64(wrapped.slice(cfg.wrap3.length));
    // 嚴格長度：iv(12) + ct(hex(noteKey) 64B + GCM tag 16B) = 92B 固定（salt 在 users.salt 不內嵌）
    if (payload.length !== IV_LEN + 80) return null;
    const kek = await deriveKekArgon(passphrase, salt);
    const rawHex = await decryptWithKey(kek, payload, 'notekey');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true);
  } catch {
    return null;
  }
}

// ── jr3d. 雙因子合鑰（PIN 第二因子，jr2w. 的 Argon2id 版） ─────────────────────
//
// KEK2 = HKDF-SHA256( ikm = Argon2id(pass, salt1)[32] ‖ Argon2id(pinNorm, prefix‖hex(pinSalt))[32],
//                     salt = pinSalt, info = 'journal-kek2-v1:' + wrapDual3, L = 32 )
// info 字串與 jr2w. 家族同名（journal-kek2-v1）：HKDF 合成步驟同構，兩家族 KEK2 值
// 因 KDF bits 不同而天然互斥（驗證閘有跨家族隔離斷言）。
// 兩段 Argon2 bits 用完即棄；KEK2 import 當下 nonextractable；輸出 noteKey extractable=true。

async function deriveKek2Argon(
  cfg: Argon3Config,
  passphrase: string,
  pinNorm: string,
  salt1: Uint8Array,
  pinSalt: Uint8Array,
): Promise<CryptoKey> {
  if (!cfg.pinSalt3Prefix) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  const passBits = await deriveArgon2id(passphrase, salt1, ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM);
  const pinBits = await deriveArgon2id(
    pinNorm,
    new TextEncoder().encode(cfg.pinSalt3Prefix + toHex(pinSalt)),
    ARGON_PIN_MEMORY_KIB,
    ARGON_PIN_ITERATIONS,
    ARGON_PIN_PARALLELISM,
  );
  const ikm = new Uint8Array(passBits.byteLength + pinBits.byteLength);
  ikm.set(passBits, 0);
  ikm.set(pinBits, passBits.byteLength);
  const hkdfBase = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: pinSalt as BufferSource, info: new TextEncoder().encode('journal-kek2-v1:' + cfg.wrapDual3) as BufferSource },
    hkdfBase,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** jr3d. 包裹：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, hex(noteKey), aad='notekey2')；salt1 由呼叫端存 users.salt。 */
export async function wrapNoteKeyDual3(
  cfg: Argon3Config,
  noteKey: CryptoKey,
  passphrase: string,
  pin: string,
): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapDual3 || !cfg.pinSalt3Prefix) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  const salt1 = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const pinSalt = crypto.getRandomValues(new Uint8Array(DUAL_SALT_LEN));
  const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt);
  const iv = crypto.getRandomValues(new Uint8Array(DUAL_IV_LEN));
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('notekey2') as BufferSource },
    kek2,
    new TextEncoder().encode(rawHex) as BufferSource,
  ));
  const payload = new Uint8Array(DUAL_SALT_LEN + DUAL_IV_LEN + ct.byteLength);
  payload.set(pinSalt, 0);
  payload.set(iv, DUAL_SALT_LEN);
  payload.set(ct, DUAL_SALT_LEN + DUAL_IV_LEN);
  return { wrapped: cfg.wrapDual3 + b64(payload), salt: toHex(salt1) };
}

/** jr3d. 解包：pinSalt 內嵌自描述，salt1 取自 login 回應；任何不符回 null，不拋。 */
export async function unwrapNoteKeyDual3(
  cfg: Argon3Config,
  wrapped: string,
  passphrase: string,
  pin: string,
  salt1Hex: string,
): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapDual3 || !cfg.pinSalt3Prefix) return null;
    if (!wrapped.startsWith(cfg.wrapDual3)) return null;
    const salt1 = hexToBytes(salt1Hex);
    if (salt1.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(salt1Hex)) return null;
    const payload = unb64(wrapped.slice(cfg.wrapDual3.length));
    // 嚴格長度：pinSalt(16) + iv(12) + ct(hex(noteKey) 64B + GCM tag 16B) = 108B 固定
    if (payload.length !== DUAL_SALT_LEN + DUAL_IV_LEN + 80) return null;
    const pinSalt = payload.slice(0, DUAL_SALT_LEN);
    const ivPrefixedCt = payload.slice(DUAL_SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt);
    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹（鐵律）
  } catch {
    return null;
  }
}

// ── jr3s. 分享包裹（分享連結 V2，安全路線商用前清單；jrsw. 的 Argon2id 版） ───
//
// KEK_share = Argon2id(sharePass, salt, m=64MiB, t=3, p=1, tag=32B)（與 jr3w. 同級參數），
// payload = iv[12] ‖ GCM(KEK_share, hex(noteKey), aad='notekey-share')（與 jrsw. 同構只換 KDF），
// wrapped = 'jr3s.' + b64(payload)，嚴格 92B；salt 由呼叫端存 shares.salt（與 jr1w./jr3w. 同形）。
// AAD 沿用 'notekey-share'：兩代分享包裹結構同構，跨代誤用由 KDF 差異與前綴守衛雙層把關。
// 帶內版本化：share KDF 升級 = 換新前綴（jrsw. → jr3s.），舊前綴語意不動；讀取端兩代並行，
// 建立端只收 jr3s.（關閉弱 KDF 建立面）。
// ⚠️ unwrap 輸出 noteKey 一律 extractable=true（要能解日記密文；鐵律 4）。

/** jr3s. 包裹：salt 隨機 16 bytes（hex 由呼叫端存 shares.salt）。 */
export async function wrapNoteKeyShare3(cfg: Argon3Config, noteKey: CryptoKey, sharePass: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapShare3) throw new Error('ERR_JR3S_NOT_CONFIGURED');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const kek = await deriveKekArgon(sharePass, salt);
  const rawHex = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const wrapped = cfg.wrapShare3 + await encryptWithKey(kek, rawHex, 'notekey-share');
  return { wrapped, salt: toHex(salt) };
}

/** jr3s. 解包：salt 取自 GET /shares/:hash 回應（與 jr1w 同形）；任何不符回 null，不拋。 */
export async function unwrapNoteKeyShare3(cfg: Argon3Config, wrapped: string, sharePass: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapShare3 || !wrapped.startsWith(cfg.wrapShare3)) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(saltHex)) return null;
    const payload = unb64(wrapped.slice(cfg.wrapShare3.length));
    // 嚴格長度：iv(12) + ct(hex(noteKey) 64B + GCM tag 16B) = 92B 固定（salt 在 shares.salt 不內嵌）
    if (payload.length !== IV_LEN + 80) return null;
    const kek = await deriveKekArgon(sharePass, salt);
    const rawHex = await decryptWithKey(kek, payload, 'notekey-share');
    if (!rawHex) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：解出後要能解日記密文（鐵律）
  } catch {
    return null;
  }
}