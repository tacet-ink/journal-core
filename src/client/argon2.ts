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
 * - node（驗證閘/prod smoke）：node:crypto.argon2（24.7.0 落地版，26.8.1 實測）
 * - 瀏覽器：hash-wasm argon2id（純 wasm 內嵌 base64，零網路請求，4.12.0 實測 64MiB t=3 ≈ 180ms）
 * 標準向量：RFC 9106 無 secret/associated-data Argon2id（t=3, m=32, p=4, pwd=32B 0x01, salt=16B 0x00）
 *   = 72d2a36fd5c266bcc96121b24937bc253338cdfcbd273713655748c54b4dd503（兩載體實測 MATCH）。
 *
 * 遷移契約（禁強制重置）：既有 jr1w./jr2w. 帳戶在下次成功 unwrap 後由客戶端靜默
 * re-wrap 推 jr3w./jr3d.（手上有 noteKey、同一 noteKey 重包，資料零換鑰）；舊前綴照解。
 *
 * ⚠️ 鐵律：unwrap 輸出 noteKey 一律 extractable=true（要能再包裹）；KEK/KEK2 nonextractable。
 * ⚠️ deriveArgon2id 禁 fallback（零知識）：無載體即 throw，禁降級 PBKDF2 或 zeros 兜底。
 * ⚠️ wrappedRec（復原套件）世代化：KEK_rec 派生世代（HKDF，recKekHkdf 配置面）
 * ＋專用前綴 jr1r.（wrapRec）落地在 note-crypto.ts；本檔 recToken 256-bit 實體因子、
 * KEK 強度無意義的原判不變（世代收的是派生域＋契約面分離）。檢查對齊收口：wrapRec＋
 * recKekHkdf 兩欄一體（部分配置＝ERR_REC_CFG_PARTIAL 拒寫）；HKDF 世代前綴面專屬 jr1r.
 * ＋AAD 'notekey-rec'，jr1w. 前綴回歸僅 carrying passphrase-PBKDF2 派生（未配置世代
 * wrappedRec 續走 jr1w.＋PBKDF2＋'notekey'）。
 */

import { normalizePin, normalizePassphrase } from './note-crypto.ts';
import {
  b64, unb64, toHex, hexToBytes, decryptWithKey, importAesGcm, openNoteKey, sealNoteKey,
} from './note-crypto.ts';

/** KDF 派生輸入正規化收口（mirror normalizePin 先例）：v3 入口 = normalizePassphrase(pass)；raw 世代入口 = 原密語。
 *  正規化永不進共用派生本體：deriveKekArgon/deriveKek2Argon 吃的是「派生輸入」——
 *  raw 契約（jr3d./jr2w.…）不經此面（帶內版本化「契約面永不變」的結構保證）。
 *  三面單一真相：本體**委派** normalizePassphrase（語意唯一真相在
 *  note-crypto.ts 本體，本函式只是入口收口位命名）——禁自帶 .normalize 實作（閘形錨咬住）； */
function deriveInput(passphrase: string): string {
  return normalizePassphrase(passphrase);
}

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
export async function derivePh1Argon(passphrase: string, saltArg?: Uint8Array): Promise<string> {
  // PH1 鹽可注入：預設 PH1_V2_SALT 舊值＝tacet 零行為變更；
  // 其他產品可自選鹽但 per-product 恆固定（PH2 UNIQUE 約束——per-user 鹽會摧毀它）。
  return toHex(await deriveArgon2id(
    passphrase,
    saltArg ?? new TextEncoder().encode(PH1_V2_SALT),
    ARGON_MEMORY_KIB,
    ARGON_ITERATIONS,
    ARGON_PARALLELISM,
  ));
}

/**
 * PH1 v3 鹽（密語正規化 v3 世代）：'tacet-ph1-v2'——鹽域版本代沿
 * PH1_V2_SALT（常數名='tacet-ph1-v1'）既有先例模式：常數名＝PH1 規格代、鹽域值＝鹽域代。
 * 鹽域世代分離：若續用 v2 鹽域，v3 世代（normalizePassphrase 後 'ＰＡＳＳ'→'PASS'）與
 * v2 世代 raw 'PASS' 會派生出同一 ph2＝跨世代帳戶空間混合；新鹽域把跨世代 identity
 * 問題留在遷移層查表（v2-first 三腿查表職責），核心層零承擔。
 * ⚠️ 鹽撞位警告（NFKC-effective 帳）：`PH1_V3_SALT` 禁當 `derivePh1Argon` 的
 * `saltArg` 餵入——v3 派生輸入吃 normalizePassphrase，同鹽域值錯面餵入＝NFKC-effective
 * 密語與 v2 raw 密語同值撞 ph2。fork 對兩面自選鹽時兩值必須互異（README PH1 節同款警告）。
 */
export const PH1_V3_SALT = 'tacet-ph1-v2';

/**
 * PH1 v3：登入憑證 = Argon2id(normalizePassphrase(pass), 固定域鹽, m=64MiB, t=3, p=1) → hex64。
 * 正規化收口在入口（密語 v3 契約 NFKC-only——normalizePassphrase 檔頭三面單一真相）；
 * 鹽可注入（saltArg 慣例：預設 PH1_V3_SALT；per-product 恆固定＝PH2 UNIQUE 約束同 v2 母型）。
 * 參數沿 jr3w./PH1 v2 同一組常數（單一碼路）；無載體即 throw（禁 fallback 鐵律）。
 * v2/legacy 契約面零動：derivePh1Argon 不吃正規化（舊世代 raw 派生，帶內版本化）。
 */
export async function derivePh1ArgonV3(passphrase: string, saltArg?: Uint8Array): Promise<string> {
  return toHex(await deriveArgon2id(
    deriveInput(passphrase),
    saltArg ?? new TextEncoder().encode(PH1_V3_SALT),
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
  /** 密語正規化 v3 世代單因子包裹前綴（jr4w.，KEK=Argon2id(normalizePassphrase(pass))）。未配置 = 拒絕。 */
  wrap4?: string;
  /** 密語正規化 v3 世代雙因子包裹前綴（jr4d.，pass 段正規化＋PIN 段照舊）。未配置 = 拒絕。 */
  wrapDual4?: string;
}

export interface HashWasmArgon2id {
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

export type ArgonLoader = () => Promise<{ argon2id: HashWasmArgon2id }>;

let injectedLoader: ArgonLoader | null = null;

/** 載體注入（瀏覽器端由接線層指定 hash-wasm；node 端不注入走 node:crypto 原生）。 */
export function setArgonLoader(loader: ArgonLoader | null): void {
  injectedLoader = loader;
}

/** 現行注入載體（唯讀查詢；未注入＝null）。argon-auto.ts 據此判「呼叫端覆寫優先」——0.3.1 新增 export。 */
export function getArgonLoader(): ArgonLoader | null {
  return injectedLoader;
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
  const wrapped = await sealNoteKey(cfg.wrap3, noteKey, kek, 'notekey');
  return { wrapped, salt: toHex(salt) };
}

/** jr3w. 解包：任何不符（前綴/salt 形/長度/AAD）回 null 不拋；成功 → noteKey extractable=true（鐵律 4）。
 *  快速前綴快檢在場（deriveKekArgon 前——t_87ef62dd；unwrapNoteKey4 母型）：錯前綴 junk 免付 Argon。
 *  收口 openNoteKey：嚴格 92B＋rawHex 形＋hex fail-closed 全在共用核心；本函式只做
 *  家族守衛（wrap3 未配置回 null）、salt1 hex-形檢查與 KEK 派生——payload 形是鹽外置家族（iv‖ct），
 *  own 92B 檢已隨收口摘除（jr3s 同；鹽內嵌族 own 108B 保留）。 */
export async function unwrapNoteKey3(cfg: Argon3Config, wrapped: string, passphrase: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrap3) return null;
    if (!wrapped.startsWith(cfg.wrap3)) return null; // 快速前綴快檢（t_87ef62dd）：錯前綴 junk 免付 64 MiB Argon 成本
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(saltHex)) return null;
    const kek = await deriveKekArgon(passphrase, salt);
    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap3);
  } catch {
    return null;
  }
}

// ── jr4w. 單因子包裹（密語正規化 v3 世代） ────────────────────
//
// 帶內版本化：密語 KEK 輸入契約改變（raw → normalizePassphrase NFKC-only）＝新前綴，
// 舊前綴契約面永不變——jr4w. 的函式體與 jr3w. 同構（openNoteKey 共用核心、payload 嚴格
// 92B、AAD 'notekey'、嚴格長度全在 openNoteKey 本體），唯一差異＝入口吃 normalizePassphrase(pass)
// 與 cfg.wrap4 前綴。舊 payload（jr1w./jr3w.）永遠可解＝raw 派生；新 payload 只由 jr4w. 產生。
// pinSaltPrefix 沿用 cfg 既有欄（Argon3 家族 PIN 鹽域，非 jr3d. 專屬）。

/** jr4w. 包裹（v3 密語）：payload = salt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad='notekey')；salt 呼叫端存 users.salt。 */
export async function wrapNoteKey4(cfg: Argon3Config, noteKey: CryptoKey, passphrase: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrap4) throw new Error('ERR_JR4W_NOT_CONFIGURED');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const kek = await deriveKekArgon(deriveInput(passphrase), salt);
  const wrapped = await sealNoteKey(cfg.wrap4, noteKey, kek, 'notekey');
  return { wrapped, salt: toHex(salt) };
}

/** jr4w. 解包（v3 密語）：任何不符（前綴/salt 形/長度/AAD）回 null 不拋；成功 → noteKey extractable=true（鐵律 4）。
 *  家族守衛（wrap4 未配置回 null）＋快速前綴快檢（錯前綴 junk 免付 64 MiB Argon）＋salt hex-形檢＋
 *  KEK 派生（normalizePassphrase 收口在入口）——payload 形檢在 openNoteKey 本體（鹽外置家族：嚴格 92B＋
 *  rawHex 形＋hex fail-closed）。 */
export async function unwrapNoteKey4(cfg: Argon3Config, wrapped: string, passphrase: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrap4) return null;
    if (!wrapped.startsWith(cfg.wrap4)) return null; // 快速前綴快檢：錯前綴 junk 免付 64 MiB Argon 成本
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(saltHex)) return null;
    const kek = await deriveKekArgon(deriveInput(passphrase), salt);
    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap4);
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
// HKDF info 由呼叫端帶入（hkdfInfo 參數）：jr3d. 預設域 = 'journal-kek2-v1:' + cfg.wrapDual3——
// jr4d. 必帶自有域 'journal-kek2-v1:' + cfg.wrapDual4，KEK2 域分離由 info 承載（兩入參數同輸入
// 而派生域不同——同鹽同段 bits 在 NFKC-effective 密語下會同 KEK2；域即世代空間）。

async function deriveKek2Argon(
  cfg: Argon3Config,
  passphrase: string,
  pinNorm: string,
  salt1: Uint8Array,
  pinSalt: Uint8Array,
  hkdfInfo: string,
): Promise<CryptoKey> {
  if (!cfg.pinSalt3Prefix) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  // ⚠️ 瀏覽器 hash-wasm Argon2 禁並行：純 wasm Argon2id 共享記憶體池，
  // 兩實例並行在部分引擎靜態直 throw——這裡故意保持串行（與 jr2w. PBKDF2 版
  // deriveKek2 的 Promise.all 並行不同：那裡並行的前提是 crypto.subtle 原生派生）。
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
    { name: 'HKDF', hash: 'SHA-256', salt: pinSalt as BufferSource, info: new TextEncoder().encode(hkdfInfo) as BufferSource },
    hkdfBase,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** jr3d. 包裹：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, hex(noteKey), aad='notekey2')；salt1 由呼叫端存 users.salt。 */
export async function wrapNoteKeyDual3(cfg: Argon3Config, noteKey: CryptoKey, passphrase: string, pin: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapDual3 || !cfg.pinSalt3Prefix) throw new Error('ERR_JR3W_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_PIN_EMPTY');
  const salt1 = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const pinSalt = crypto.getRandomValues(new Uint8Array(DUAL_SALT_LEN));
  const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual3);
  const iv = crypto.getRandomValues(new Uint8Array(DUAL_IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('notekey2') as BufferSource },
    kek2,
    new TextEncoder().encode(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)))) as BufferSource,
  ));
  const payload = new Uint8Array(DUAL_SALT_LEN + DUAL_IV_LEN + ct.byteLength);
  payload.set(pinSalt, 0);
  payload.set(iv, DUAL_SALT_LEN);
  payload.set(ct, DUAL_SALT_LEN + DUAL_IV_LEN);
  return { wrapped: cfg.wrapDual3 + b64(payload), salt: toHex(salt1) };
}

/** jr3d. 解包：pinSalt 內嵌自描述，salt1 取自 login 回應；任何不符回 null，不拋。
 *  嚴格檢查為鹽內嵌族自有——payload 嚴格 108B（pinSalt 16
 *  ＋ iv 12＋ct 80）＋ decryptWithKey 後 rawHex hex 形檢查（hexToBytes fail-closed），
 *  不經 openNoteKey 本體（鹽外置 92B 形）；與 openNoteKey 同嚴格度。 */
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
    // 嚴格長度：pinSalt(16) + iv(12) + ct(hex 字串 64B + GCM tag 16B) = 108B 固定
    if (payload.length !== DUAL_SALT_LEN + DUAL_IV_LEN + 80) return null;
    const pinSalt = payload.slice(0, DUAL_SALT_LEN);
    const ivPrefixedCt = payload.slice(DUAL_SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual3);
    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');
    if (!rawHex || rawHex.length !== 64 || !/^[0-9a-f]+$/.test(rawHex)) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹（鐵律）
  } catch {
    return null;
  }
}

// ── jr4d. 雙因子合鑰（密語正規化 v3 世代＝jr3d. 的 v3 後繼） ────
//
// 帶內版本化：pass 段 KEK 輸入契約改變（raw → normalizePassphrase NFKC-only）＝新前綴；
// PIN 段契約照舊（normalizePin：NFKC→trim→lowercase，pinlock/dual 面不動）。
// KEK2 合成步驟與 jr3d. 同構：deriveKek2Argon 共用本體（pass 段正規化收口在 wrap/unwrap
// 入口層——deriveInput 收口、正規化永不進共用派生函式，jr3d. raw 契約面零動如實不經測不變）；
// payload 嚴格 108B＋rawHex 形檢在 own 本體（鹽內嵌族 openNoteKey 不覆蓋）；
// HKDF info 沿 'journal-kek2-v1:' 合成名＋hkdfInfo 呼叫端帶入（域=jr4d.：KDF 互斥由 bits＋info 域承載）。

/** jr4d. 包裹（v3 密語）：payload = pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, hex(noteKey), aad='notekey2')；salt1 呼叫端存 users.salt。 */
export async function wrapNoteKeyDual4(cfg: Argon3Config, noteKey: CryptoKey, passphrase: string, pin: string): Promise<{ wrapped: string; salt: string }> {
  if (!cfg.wrapDual4 || !cfg.pinSalt3Prefix) throw new Error('ERR_JR4D_NOT_CONFIGURED');
  const pinNorm = normalizePin(pin);
  if (!pinNorm) throw new Error('ERR_PIN_EMPTY'); // 空 PIN ≠ 未配置（語意分離）
  const salt1 = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const pinSalt = crypto.getRandomValues(new Uint8Array(DUAL_SALT_LEN));
  const kek2 = await deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);
  const iv = crypto.getRandomValues(new Uint8Array(DUAL_IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('notekey2') as BufferSource },
    kek2,
    new TextEncoder().encode(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)))) as BufferSource,
  ));
  const payload = new Uint8Array(DUAL_SALT_LEN + DUAL_IV_LEN + ct.byteLength);
  payload.set(pinSalt, 0);
  payload.set(iv, DUAL_SALT_LEN);
  payload.set(ct, DUAL_SALT_LEN + DUAL_IV_LEN);
  return { wrapped: cfg.wrapDual4 + b64(payload), salt: toHex(salt1) };
}

// jr4d. 解包（v3 密語）：pinSalt 內嵌自描述，salt1 取自 login 回應；任何不符回 null，不拋。
//  嚴格檢查為鹽內嵌族自有（payload 嚴格 108B＋rawHex 形檢，不經 openNoteKey 92B 鹽外置本體）；
//  pass 段正規化收口在入口（deriveInput＝normalizePassphrase 同語意本體收口），pinNorm 與 jr3d. 同契約。
//  KEK2 HKDF info＝'journal-kek2-v1:' + cfg.wrapDual4（自有域——jr3d/jr4d 兩入參數同輸入而域分離；
//  NFKC-effective 密語下 bits 段同值，域由 info 承載——凍結 KAT 兩 blob 互解 null 承載）。
export async function unwrapNoteKeyDual4(
  cfg: Argon3Config,
  wrapped: string,
  passphrase: string,
  pin: string,
  salt1Hex: string,
): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapDual4 || !cfg.pinSalt3Prefix) return null;
    if (!wrapped.startsWith(cfg.wrapDual4)) return null;
    const salt1 = hexToBytes(salt1Hex);
    if (salt1.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(salt1Hex)) return null;
    const payload = unb64(wrapped.slice(cfg.wrapDual4.length));
    // 嚴格長度：pinSalt(16) + iv(12) + ct(hex 字串 64B + GCM tag 16B) = 108B 固定
    if (payload.length !== DUAL_SALT_LEN + DUAL_IV_LEN + 80) return null;
    const pinSalt = payload.slice(0, DUAL_SALT_LEN);
    const ivPrefixedCt = payload.slice(DUAL_SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek2 = await deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);
    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');
    if (!rawHex || rawHex.length !== 64 || !/^[0-9a-f]+$/.test(rawHex)) return null;
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
  const wrapped = await sealNoteKey(cfg.wrapShare3, noteKey, kek, 'notekey-share');
  return { wrapped, salt: toHex(salt) };
}

/** jr3s. 解包：salt 取自 GET /shares/:hash 回應（與 jr1w 同形）；任何不符回 null，不拋。
 *  快速前綴快檢在場（deriveKekArgon 前——t_87ef62dd；unwrapNoteKey4 母型）：錯前綴 junk 免付 Argon。
 *  收口 openNoteKey：鹽外置家族（payload 嚴格 92B＋rawHex 形＋hex fail-closed
 *  全在共用核心）；本函式只做家族守衛、salt hex-形檢查與 KEK 派生——own 92B 檢已隨收口摘除。 */
export async function unwrapNoteKeyShare3(cfg: Argon3Config, wrapped: string, sharePass: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapShare3) return null;
    if (!wrapped.startsWith(cfg.wrapShare3)) return null; // 快速前綴快檢（t_87ef62dd）：錯前綴 junk 免付 64 MiB Argon 成本
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN || !/^[0-9a-f]{32}$/.test(saltHex)) return null;
    const kek = await deriveKekArgon(sharePass, salt);
    return await openNoteKey(wrapped, kek, 'notekey-share', cfg.wrapShare3);
  } catch {
    return null;
  }
}

// ── ladder 重試鹽面：unwrapNoteKeyDual4WithSalt ────
//
// 為何同構再開一支：v3 遷移（登入即重遷）會旋轉 salt1（wrapNoteKeyDual4 落新值）；
// login 舊形面帶回的 salt（v2 世代的 salt1）在遷移後已解不開 v3 新包裹──呼叫端
// （tacet loginAndUnwrap 的 jr4d. 腿）以「login 回應當下帶回的新 salt」重取入參
// 重試 unwrap 就是本變體唯一承載面。本體與 unwrapNoteKeyDual4 完全同構（同嚴格
// 檢查、同 HKDF info 域、同輸出契約）──開支出零差異；命名開新支是「重取鹽」的
// 語意承載位（呼叫端 grep 可審計），零新增實作面。
//
// 補記（家族嚴格度）：salt1 形檢／payload 108B／rawHex 形檢全在
// unwrapNoteKeyDual4 本體（共用）；本變體純語意薄身。

/** jr4d. 解包（重取 salt1 面）：pinSalt 內嵌自描述，salt1 由呼叫端重取後帶入（ladder 遷移後的新値）；任何不符回 null，不拋。 */
export async function unwrapNoteKeyDual4WithSalt(
  cfg: Argon3Config,
  wrapped: string,
  passphrase: string,
  pin: string,
  salt1Hex: string,
): Promise<CryptoKey | null> {
  return unwrapNoteKeyDual4(cfg, wrapped, passphrase, pin, salt1Hex);
}