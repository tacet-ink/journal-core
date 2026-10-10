/**
 * vault.ts — 高階 Vault API（0.3.1 批 A3）：createVault／unlockVault／recoverVault → VaultHandle。
 *
 * 定位：低階原語（note-crypto.ts／argon2.ts）的**呼叫端**——additive-only，零改動原語語意。
 * 一個 vault＝一把隨機 256-bit noteKey（generateNoteKey）＋伺服器存的包裹欄（wrapped＋salt）
 * ＋選配復原套件（jr1r. 家族 wrappedRec）。本模組無儲存面（pure object）：storage 域
 *（keys.ts 品牌命名空間）是上層責任，serverRecord 由呼叫端上傳／覆存。
 *
 * 鐵律承襲（逐條落點）：
 * - extractable：noteKey 恆來自 generateNoteKey／unwrap 家族（皆 extractable=true）——本檔不自 import 金鑰。
 * - AAD 由呼叫端指定：本檔就是呼叫端——記錄密文 AAD＝`<app>:<recordId>`（app 由配置定、
 *   recordId 由 API 參數帶入；低階原語簽名不動）。
 * - 帶內版本化：寫面恆最新家族（jr4w.／PIN 時 jr4d.）；upgrade＝新前綴包同一 noteKey，舊前綴語意不動。
 * - zero-fallback：Argon2id 載體缺席＝ERR_VAULT_KDF_UNSUPPORTED，禁 PBKDF2／zeros 兜底
 *  （jr1w./jr2w. 舊世代讀面本就是 PBKDF2 契約——那是家族語意，不是兜底）。
 * - opt-in 未配置即拒：配置缺欄／serverRecord 缺欄＝ERR_VAULT_*，不猜。
 *
 * 記錄密文形（本 API 自有契約，前綴由配置 `cipher` 定——一個前綴一份契約，禁借 cipherBound）：
 *   blob = cipher + b64( iv[12] ‖ AES-GCM-256(noteKey, tag[1] ‖ body, aad = UTF8(app + ':' + recordId)) )
 *   tag：0x73 's'＝字串（body＝UTF-8）／0x6a 'j'＝JSON（body＝UTF-8(JSON.stringify)）／0x62 'b'＝位元組（body＝原樣）。
 */

import {
  generateNoteKey,
  generateRecToken,
  recTokenHash,
  wrapNoteKeyWithRecToken,
  unwrapNoteKeyWithRecToken,
  unwrapNoteKey,
  unwrapNoteKeyDual,
  normalizePin,
  b64,
  unb64,
  IV_LEN,
  type NoteCryptoConfig,
} from './note-crypto.ts';
import {
  wrapNoteKey4,
  unwrapNoteKey4,
  wrapNoteKeyDual4,
  unwrapNoteKeyDual4,
  unwrapNoteKey3,
  unwrapNoteKeyDual3,
  type Argon3Config,
} from './argon2.ts';
import type { KeyStore } from './keys.ts';
import { VaultError, isVaultError, type VaultErrorCode } from './vault-error.ts';
import { ensureArgonCarrier, argonCarrierFailures, type ArgonCarrierKind, type ArgonCarrierOptions } from './argon-auto.ts';

export { VaultError, isVaultError, type VaultErrorCode };
export {
  ensureArgonCarrier,
  currentArgonCarrier,
  resetArgonCarrier,
  DEFAULT_ARGON_CHAIN,
  type ArgonCarrierKind,
  type ArgonCarrierChoice,
  type ArgonCarrierOptions,
  type ArgonFallbackEvent,
} from './argon-auto.ts';
export { argonWorkerSource, createBlobArgonWorker, type ArgonWorkerLike } from './argon-worker.ts';

// ── 型別 ────────────────────────────────────────────────────────────────────

export interface VaultConfig {
  /** 應用域（AAD 前段）：記錄密文 AAD＝`<app>:<recordId>`。必填非空。 */
  app: string;
  /** 記錄密文前綴（如 'jr1v.'）。必填非空，且與所有包裹前綴互不為前綴。 */
  cipher: string;
  /** Argon2id 家族前綴：`wrap4` 必填（寫面）；`wrapDual4`＋`pinSalt3Prefix`＝PIN 寫面；
   *  `wrap3`／`wrapDual3`＝舊世代讀面（unlock＋upgrade 來源）。`wrapShare3` 本 API 不用。 */
  argon: Argon3Config;
  /** PBKDF2 舊世代讀面（jr1w.＝`wrap`；jr2w.＝`wrapDual`＋`pinSaltPrefix`）。只讀不寫。 */
  legacy?: { wrap?: string; wrapDual?: string; pinSaltPrefix?: string };
  /** 復原套件（jr1r. HKDF 世代；兩欄一體）。未配置＝createVault 不產復原套件、recoverVault 拒。 */
  recovery?: { wrapRec: string; recKekHkdf: string; recKekSalt?: string };
}

export interface VaultOptions extends VaultConfig {
  /** PIN 第二因子：create＝寫 jr4d.；unlock＝雙因子家族必帶。 */
  pin?: string;
  /** Argon2id 載體選項（回退鏈／Worker 工廠／回退通知）。setArgonLoader 注入恆優先。 */
  carrier?: ArgonCarrierOptions;
}

/** 伺服器存的包裹欄（login 回應帶回；兩欄成對）。 */
export interface VaultServerRecord {
  wrapped: string;
  salt: string;
}

/** 復原套件：recToken 只顯示一次（可經 bip39.ts 轉 24 詞）；伺服器存 wrappedRec＋recTokenHash。 */
export interface VaultRecoveryKit {
  recToken: string;
  wrappedRec: string;
  recTokenHash: string;
}

/** 包裹家族（以配置欄名識別——前綴值由各產品配置）。 */
export type VaultWrapFamily = 'wrap4' | 'wrapDual4' | 'wrap3' | 'wrapDual3' | 'wrap' | 'wrapDual';

export type VaultJson = string | number | boolean | null | VaultJson[] | { [k: string]: VaultJson };
/** encrypt 資料形：字串／JSON 值（物件、陣列、數、布林、null）／Uint8Array。decrypt 還原同形。 */
export type VaultData = string | Uint8Array | VaultJson;

export interface VaultHandle {
  /** 現行包裹家族（recoverVault 後未 changePassphrase＝null）。 */
  readonly family: VaultWrapFamily | null;
  /** 現行伺服器包裹欄副本（recoverVault 後未 changePassphrase＝null）。 */
  readonly serverRecord: VaultServerRecord | null;
  /** 最近一次 Argon2id 派生所用載體（未用過 Argon＝null，例：jr1w. 解鎖、復原）。 */
  readonly carrier: ArgonCarrierKind | null;
  /** 加密一則：AAD＝`<app>:<recordId>`。 */
  encrypt(recordId: string, data: VaultData): Promise<string>;
  /** 解密一則：recordId 不符（搬列）／竄改＝ERR_VAULT_DECRYPT。 */
  decrypt<T extends VaultData = VaultData>(recordId: string, blob: string): Promise<T>;
  /** 換密語：同一 noteKey 以最新家族重包（資料零換鑰）。pin：字串＝jr4d.；null＝改單因子；
   *  省略＝沿現行（雙因子 vault 省略＝ERR_VAULT_PIN_REQUIRED——本 API 不保留 PIN）。回新包裹欄供覆存。 */
  changePassphrase(newPassphrase: string, opts?: { pin?: string | null }): Promise<VaultServerRecord>;
  /** 包裹家族非最新世代（jr1w./jr2w./jr3w./jr3d. → jr4 家族）。 */
  needsUpgrade(): boolean;
  /** 同一 noteKey 重包最新家族（同因子形）。先以 passphrase（＋pin）解現行包裹驗證同鑰，
   *  不符＝ERR_VAULT_WRAP_MISMATCH（防錯密語重包鎖死帳戶）。已最新＝原包裹欄原樣回（無寫入）。 */
  upgrade(passphrase: string, opts?: { pin?: string }): Promise<VaultServerRecord>;
}

// ── 配置驗證 ────────────────────────────────────────────────────────────────

const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

interface FamilySpec {
  family: VaultWrapFamily;
  dual: boolean;
  current: boolean;
  argon: boolean;
  prefix: (c: VaultConfig) => string | undefined;
}

/** 讀面次序（新→舊）：jr4 家族優先，舊世代依序。 */
const FAMILIES: readonly FamilySpec[] = [
  { family: 'wrap4', dual: false, current: true, argon: true, prefix: (c) => c.argon.wrap4 },
  { family: 'wrapDual4', dual: true, current: true, argon: true, prefix: (c) => (c.argon.pinSalt3Prefix ? c.argon.wrapDual4 : undefined) },
  { family: 'wrap3', dual: false, current: false, argon: true, prefix: (c) => c.argon.wrap3 },
  { family: 'wrapDual3', dual: true, current: false, argon: true, prefix: (c) => (c.argon.pinSalt3Prefix ? c.argon.wrapDual3 : undefined) },
  { family: 'wrap', dual: false, current: false, argon: false, prefix: (c) => c.legacy?.wrap },
  { family: 'wrapDual', dual: true, current: false, argon: false, prefix: (c) => (c.legacy?.pinSaltPrefix ? c.legacy?.wrapDual : undefined) },
];

function specOf(family: VaultWrapFamily): FamilySpec {
  return FAMILIES.find((f) => f.family === family)!;
}

function validateConfig(c: VaultConfig): void {
  if (!c || typeof c !== 'object') throw new VaultError('ERR_VAULT_CONFIG', 'config missing');
  if (!nonEmpty(c.app)) throw new VaultError('ERR_VAULT_CONFIG', 'app');
  if (!nonEmpty(c.cipher)) throw new VaultError('ERR_VAULT_CONFIG', 'cipher');
  if (!c.argon || !nonEmpty(c.argon.wrap4)) throw new VaultError('ERR_VAULT_CONFIG', 'argon.wrap4');
  const prefixes: string[] = [c.cipher];
  for (const f of FAMILIES) {
    const p = f.prefix(c);
    if (p !== undefined && p !== '') prefixes.push(p);
  }
  if (c.recovery !== undefined) {
    const r = c.recovery;
    // 兩欄一體（ERR_REC_CFG_PARTIAL 母型）：部分配置拒——禁寫出跨契約 blob。
    if (!r || !nonEmpty(r.wrapRec) || !nonEmpty(r.recKekHkdf)) throw new VaultError('ERR_VAULT_CONFIG', 'recovery.wrapRec+recKekHkdf');
    if (r.recKekSalt !== undefined && !HEX32_RE.test(r.recKekSalt)) throw new VaultError('ERR_VAULT_CONFIG', 'recovery.recKekSalt');
    prefixes.push(r.wrapRec);
  }
  // 前綴互斥：任兩前綴互不為前綴（startsWith 家族辨識的唯一性前提——歧義配置不猜）。
  for (let i = 0; i < prefixes.length; i++) {
    for (let j = 0; j < prefixes.length; j++) {
      if (i !== j && prefixes[i].startsWith(prefixes[j])) throw new VaultError('ERR_VAULT_CONFIG', 'prefix overlap: ' + prefixes[i] + ' / ' + prefixes[j]);
    }
  }
}

function checkPassphrase(p: unknown): asserts p is string {
  if (!nonEmpty(p)) throw new VaultError('ERR_VAULT_BAD_PASSPHRASE');
}

function checkPin(pin: string): void {
  if (typeof pin !== 'string' || !normalizePin(pin)) throw new VaultError('ERR_VAULT_BAD_PIN');
}

function checkDualWritable(c: VaultConfig): void {
  if (!nonEmpty(c.argon.wrapDual4) || !nonEmpty(c.argon.pinSalt3Prefix)) {
    throw new VaultError('ERR_VAULT_CONFIG', 'argon.wrapDual4+pinSalt3Prefix (PIN write)');
  }
}

/** 低階原語只吃完整 NoteCryptoConfig；本 API 用到的欄位只有 wrap/wrapDual/pinSaltPrefix/復原面——
 *  store 面不被觸及（vault 無儲存），以惰性空殼滿足型別。 */
const NO_STORE: KeyStore = { get: () => null, set: () => {}, remove: () => {}, noteKeyWrap: (k: string) => k };

function legacyCfg(c: VaultConfig): NoteCryptoConfig {
  return {
    guestKdfPrefix: '',
    recSaltPrefix: '',
    cipherBound: c.cipher,
    wrap: c.legacy?.wrap ?? '',
    wrapDual: c.legacy?.wrapDual,
    pinSaltPrefix: c.legacy?.pinSaltPrefix,
    store: NO_STORE,
  };
}

/** 復原面專用 cfg：wrap='' ＝舊契約回落腿關閉（identity 綁域的 jr1w. 復原套件不屬本 API）。 */
function recoveryCfg(c: VaultConfig): NoteCryptoConfig {
  const r = c.recovery!;
  return {
    guestKdfPrefix: '',
    recSaltPrefix: '',
    cipherBound: c.cipher,
    wrap: '',
    wrapRec: r.wrapRec,
    recKekHkdf: r.recKekHkdf,
    recKekSalt: r.recKekSalt,
    store: NO_STORE,
  };
}

// ── 邊界轉譯 ────────────────────────────────────────────────────────────────

/** 低階 throw（字串錯誤碼）→ VaultError；VaultError 原樣上拋。 */
async function translate<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (isVaultError(e)) throw e;
    const msg = e instanceof Error ? e.message : String(e);
    if (/ARGON2/.test(msg)) throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', msg, { cause: e });
    if (/NOT_CONFIGURED/.test(msg)) throw new VaultError('ERR_VAULT_CONFIG', msg, { cause: e });
    if (msg === 'ERR_PIN_EMPTY') throw new VaultError('ERR_VAULT_BAD_PIN', msg, { cause: e });
    throw new VaultError('ERR_VAULT_INTERNAL', msg, { cause: e });
  }
}

// ── 包裹分派 ────────────────────────────────────────────────────────────────

function detectFamily(c: VaultConfig, wrapped: string): FamilySpec | null {
  for (const f of FAMILIES) {
    const p = f.prefix(c);
    if (p && wrapped.startsWith(p)) return f;
  }
  return null;
}

async function unwrapBy(f: FamilySpec, c: VaultConfig, rec: VaultServerRecord, pass: string, pin: string): Promise<CryptoKey | null> {
  switch (f.family) {
    case 'wrap4': return unwrapNoteKey4(c.argon, rec.wrapped, pass, rec.salt);
    case 'wrapDual4': return unwrapNoteKeyDual4(c.argon, rec.wrapped, pass, pin, rec.salt);
    case 'wrap3': return unwrapNoteKey3(c.argon, rec.wrapped, pass, rec.salt);
    case 'wrapDual3': return unwrapNoteKeyDual3(c.argon, rec.wrapped, pass, pin, rec.salt);
    case 'wrap': return unwrapNoteKey(legacyCfg(c), rec.wrapped, pass, rec.salt);
    case 'wrapDual': return unwrapNoteKeyDual(legacyCfg(c), rec.wrapped, pass, pin, rec.salt);
  }
}

async function wrapCurrent(c: VaultConfig, noteKey: CryptoKey, pass: string, pin: string | null): Promise<{ rec: VaultServerRecord; family: VaultWrapFamily }> {
  if (pin === null) return { rec: await wrapNoteKey4(c.argon, noteKey, pass), family: 'wrap4' };
  return { rec: await wrapNoteKeyDual4(c.argon, noteKey, pass, pin), family: 'wrapDual4' };
}

/** 解包 null 的歸因：期間載體失效計數有增＝KDF_UNSUPPORTED（低階 unwrap 吞錯回 null，邊界還原真因）。 */
async function unwrapOrThrow(f: FamilySpec, c: VaultConfig, rec: VaultServerRecord, pass: string, pin: string): Promise<CryptoKey> {
  const before = argonCarrierFailures();
  const key = await unwrapBy(f, c, rec, pass, pin);
  if (key) return key;
  if (argonCarrierFailures() !== before) throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', 'carrier failed during unwrap');
  throw new VaultError('ERR_VAULT_WRAP_MISMATCH');
}

async function sameKey(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const [ra, rb] = await Promise.all([crypto.subtle.exportKey('raw', a), crypto.subtle.exportKey('raw', b)]);
  const x = new Uint8Array(ra);
  const y = new Uint8Array(rb);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// ── 記錄密文 ────────────────────────────────────────────────────────────────

const TAG_STRING = 0x73; // 's'
const TAG_JSON = 0x6a; // 'j'
const TAG_BYTES = 0x62; // 'b'
const GCM_TAG_LEN = 16;

function aadOf(app: string, recordId: unknown): Uint8Array {
  if (!nonEmpty(recordId)) throw new VaultError('ERR_VAULT_BAD_RECORD_ID');
  return new TextEncoder().encode(app + ':' + recordId);
}

function encodeData(data: VaultData): Uint8Array {
  let tag: number;
  let body: Uint8Array;
  if (typeof data === 'string') {
    tag = TAG_STRING;
    body = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    tag = TAG_BYTES;
    body = data;
  } else {
    // ArrayBuffer／其他 view：JSON.stringify 會靜默變 {}（資料滅失）——明拒，不猜。
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) throw new VaultError('ERR_VAULT_BAD_DATA', 'binary must be Uint8Array');
    let json: string | undefined;
    try { json = JSON.stringify(data); } catch (e) { throw new VaultError('ERR_VAULT_BAD_DATA', 'JSON', { cause: e }); }
    if (json === undefined) throw new VaultError('ERR_VAULT_BAD_DATA', 'not JSON-serializable');
    tag = TAG_JSON;
    body = new TextEncoder().encode(json);
  }
  const out = new Uint8Array(1 + body.byteLength);
  out[0] = tag;
  out.set(body, 1);
  return out;
}

function decodeData(plain: Uint8Array): VaultData {
  if (plain.length < 1) throw new VaultError('ERR_VAULT_BAD_BLOB', 'empty plaintext');
  const body = plain.subarray(1);
  try {
    switch (plain[0]) {
      case TAG_STRING: return new TextDecoder('utf-8', { fatal: true }).decode(body);
      case TAG_JSON: return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) as VaultJson;
      case TAG_BYTES: return body.slice();
    }
  } catch (e) {
    throw new VaultError('ERR_VAULT_BAD_BLOB', 'body decode', { cause: e });
  }
  throw new VaultError('ERR_VAULT_BAD_BLOB', 'type tag');
}

async function sealRecord(c: VaultConfig, noteKey: CryptoKey, recordId: string, data: VaultData): Promise<string> {
  const aad = aadOf(c.app, recordId);
  const plain = encodeData(data);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad as BufferSource }, noteKey, plain as BufferSource));
  const out = new Uint8Array(IV_LEN + ct.byteLength);
  out.set(iv, 0);
  out.set(ct, IV_LEN);
  return c.cipher + b64(out);
}

async function openRecord(c: VaultConfig, noteKey: CryptoKey, recordId: string, blob: string): Promise<VaultData> {
  const aad = aadOf(c.app, recordId);
  if (typeof blob !== 'string' || !blob.startsWith(c.cipher)) throw new VaultError('ERR_VAULT_BAD_BLOB', 'prefix');
  let payload: Uint8Array;
  try { payload = unb64(blob.slice(c.cipher.length)); } catch (e) { throw new VaultError('ERR_VAULT_BAD_BLOB', 'base64', { cause: e }); }
  if (payload.length < IV_LEN + GCM_TAG_LEN + 1) throw new VaultError('ERR_VAULT_BAD_BLOB', 'length');
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: payload.subarray(0, IV_LEN) as BufferSource, additionalData: aad as BufferSource },
      noteKey,
      payload.subarray(IV_LEN) as BufferSource,
    ));
  } catch (e) {
    throw new VaultError('ERR_VAULT_DECRYPT', undefined, { cause: e });
  }
  return decodeData(plain);
}

// ── handle ──────────────────────────────────────────────────────────────────

interface HandleState {
  rec: VaultServerRecord | null;
  family: VaultWrapFamily | null;
  carrier: ArgonCarrierKind | null;
}

function makeHandle(c: VaultConfig, noteKey: CryptoKey, st: HandleState, carrierOpts: ArgonCarrierOptions | undefined): VaultHandle {
  const ensure = async (): Promise<void> => { st.carrier = await ensureArgonCarrier(carrierOpts); };
  return {
    get family() { return st.family; },
    get serverRecord() { return st.rec ? { ...st.rec } : null; },
    get carrier() { return st.carrier; },
    encrypt: (recordId, data) => translate(() => sealRecord(c, noteKey, recordId, data)),
    decrypt: <T extends VaultData = VaultData>(recordId: string, blob: string) =>
      translate(() => openRecord(c, noteKey, recordId, blob)) as Promise<T>,
    changePassphrase: (newPassphrase, opts) => translate(async () => {
      checkPassphrase(newPassphrase);
      let pin: string | null;
      if (opts?.pin === undefined) {
        if (st.family && specOf(st.family).dual) throw new VaultError('ERR_VAULT_PIN_REQUIRED');
        pin = null;
      } else {
        pin = opts.pin;
      }
      if (pin !== null) { checkPin(pin); checkDualWritable(c); }
      await ensure();
      const w = await wrapCurrent(c, noteKey, newPassphrase, pin);
      st.rec = w.rec;
      st.family = w.family;
      return { ...w.rec };
    }),
    needsUpgrade: () => st.family !== null && !specOf(st.family).current,
    upgrade: (passphrase, opts) => translate(async () => {
      if (!st.rec || !st.family) throw new VaultError('ERR_VAULT_BAD_RECORD', 'no server record (recovered vault: use changePassphrase)');
      if (specOf(st.family).current) return { ...st.rec };
      checkPassphrase(passphrase);
      const f = specOf(st.family);
      const pin = f.dual ? opts?.pin : undefined;
      if (f.dual) {
        if (pin === undefined) throw new VaultError('ERR_VAULT_PIN_REQUIRED');
        checkPin(pin);
        checkDualWritable(c);
      }
      await ensure(); // 寫面恆 Argon（jr4）；讀驗證面 jr3 亦 Argon
      const check = await unwrapOrThrow(f, c, st.rec, passphrase, pin ?? '');
      if (!(await sameKey(check, noteKey))) throw new VaultError('ERR_VAULT_WRAP_MISMATCH', 'different noteKey');
      const w = await wrapCurrent(c, noteKey, passphrase, f.dual ? pin! : null);
      st.rec = w.rec;
      st.family = w.family;
      return { ...w.rec };
    }),
  };
}

// ── 入口 ────────────────────────────────────────────────────────────────────

/** 新 vault：隨機 noteKey＋最新家族包裹（pin＝jr4d.，否則 jr4w.）＋選配復原套件（jr1r.）。 */
export function createVault(passphrase: string, opts: VaultOptions): Promise<{
  vault: VaultHandle;
  serverRecord: VaultServerRecord;
  recovery: VaultRecoveryKit | null;
}> {
  return translate(async () => {
    validateConfig(opts);
    checkPassphrase(passphrase);
    const pin = opts.pin === undefined ? null : opts.pin;
    if (pin !== null) { checkPin(pin); checkDualWritable(opts); }
    const carrier = await ensureArgonCarrier(opts.carrier);
    const noteKey = await generateNoteKey();
    const w = await wrapCurrent(opts, noteKey, passphrase, pin);
    let recovery: VaultRecoveryKit | null = null;
    if (opts.recovery) {
      const recToken = generateRecToken();
      // identity 不入 HKDF 世代 KEK（identity-free by design）——空字串僅滿足簽名。
      const wrappedRec = await wrapNoteKeyWithRecToken(recoveryCfg(opts), noteKey, recToken, '');
      recovery = { recToken, wrappedRec, recTokenHash: await recTokenHash(recToken) };
    }
    const vault = makeHandle(opts, noteKey, { rec: w.rec, family: w.family, carrier }, opts.carrier);
    return { vault, serverRecord: { ...w.rec }, recovery };
  });
}

/** 解鎖：serverRecord（wrapped＋salt 成對）按前綴辨識家族（新→舊次序），舊世代照解；
 *  needsUpgrade() 為真時呼叫端可於同一動線 upgrade(passphrase) 靜默重包（Argon 遷移契約同構）。 */
export function unlockVault(passphrase: string, serverRecord: VaultServerRecord, opts: VaultOptions): Promise<VaultHandle> {
  return translate(async () => {
    validateConfig(opts);
    const r = serverRecord as Partial<VaultServerRecord> | null | undefined;
    if (!r || typeof r !== 'object' || !nonEmpty(r.wrapped) || typeof r.salt !== 'string' || !HEX32_RE.test(r.salt)) {
      throw new VaultError('ERR_VAULT_BAD_RECORD');
    }
    checkPassphrase(passphrase);
    const rec: VaultServerRecord = { wrapped: r.wrapped, salt: r.salt };
    const f = detectFamily(opts, rec.wrapped);
    if (!f) throw new VaultError('ERR_VAULT_WRAP_UNKNOWN');
    if (f.dual) {
      if (opts.pin === undefined) throw new VaultError('ERR_VAULT_PIN_REQUIRED');
      checkPin(opts.pin);
    }
    const carrier = f.argon ? await ensureArgonCarrier(opts.carrier) : null;
    const noteKey = await unwrapOrThrow(f, opts, rec, passphrase, opts.pin ?? '');
    return makeHandle(opts, noteKey, { rec, family: f.family, carrier }, opts.carrier);
  });
}

/** 復原：recToken（hex64）＋wrappedRec（jr1r.）→ handle（無包裹欄——呼叫端隨即 changePassphrase 設新密語）。 */
export function recoverVault(recToken: string, wrappedRec: string, opts: VaultOptions): Promise<VaultHandle> {
  return translate(async () => {
    validateConfig(opts);
    if (!opts.recovery) throw new VaultError('ERR_VAULT_CONFIG', 'recovery');
    if (typeof recToken !== 'string' || !HEX64_RE.test(recToken)) throw new VaultError('ERR_VAULT_RECOVERY', 'recToken');
    if (typeof wrappedRec !== 'string' || !wrappedRec.startsWith(opts.recovery.wrapRec)) throw new VaultError('ERR_VAULT_RECOVERY', 'wrappedRec prefix');
    const noteKey = await unwrapNoteKeyWithRecToken(recoveryCfg(opts), wrappedRec, recToken, '');
    if (!noteKey) throw new VaultError('ERR_VAULT_RECOVERY');
    return makeHandle(opts, noteKey, { rec: null, family: null, carrier: null }, opts.carrier);
  });
}
