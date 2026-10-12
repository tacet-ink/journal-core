/**
 * vault.ts — 高階 Vault API：createVault／unlockVault／recoverVault → VaultHandle＋零設定前綴推導 resolver。
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
  derivePh1ArgonV3,
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

/** 復原套件規格形（= 既顯式物件形；resolver 對 app 推導同形輸出——名稱是接線層措語，型別零新增）。 */
export type VaultRecoverySpec = { wrapRec: string; recKekHkdf: string; recKekSalt?: string };

/**
 * resolveVaultConfig(input)：零設定前綴推導（resolver）。
 * 輸入 `{ app, ...任意顯式欄位 }`，輸出完整 VaultConfig＋defaulted 旗標：
 * `defaulted`＝真時 cipher/argon/legacy/recovery 四組**整組**由 app 決定性推導（10 欄，recovery opt-in 時含）——
 * 命名自定（語意＝resolveVaultConfig：`{app}`＋零設定前綴推導）：前綴零手填、家族尾碼恆固定（契約三要素 app＋尾碼＋佈局；
 * 帶內版本化：尾碼代即版本代，升級＝新尾碼；家族佈局不隨字面——README 前綴契約節同源）。
 * `defaulted`＝假時輸入即顯式全配置（回歸 diff 恆 0——validateConfig 逐對檢查照守）。
 *
 * 推導表（app 契約 `^[A-Za-z0-9_-]+$`——前綴字面＝線上 ASCII 契約；**契約閘＝零設定（推導）路徑專載**：
 * 零設定路徑上 app 在場但含契約外字元＝ERR_VAULT_CONFIG fail-closed 不猜；顯式全配置路徑
 * app 字面照 0.3.3 既有契約零驗形（非 ASCII／帶點 app 走顯式全配置照舊）——契約閘不跨路徑加寬）：
 *   cipher='foo1v.'／wrap4='foo4w.'／wrapDual4='foo4d.'／pinSalt3Prefix='foo3s:'（鹽域 ':' 同 tacet 形）
 *   wrap3='foo3w.'／wrapDual3='foo3d.'／legacy wrap='foo1w.'／wrapDual='foo2w.'／pinSaltPrefix='foo1s.'
 *   recovery（`recovery: true` 時）wrapRec='foo1r.'／recKekHkdf='fookek1'（KEK info 域帶 k 代——刻意
 *   異於 wrapRec 字面：HKDF info 域與前綴域恆非前綴關係，鹽外置 payload 邊界不重疊）；
 *   wrap3／wrapDual3 舊世代讀面同由 app 推導（`app + '3w.'`／`app + '3d.'`——app 族半顯式 legacy 槽的推導殘部）。
 *   `foo`＝示例形；任兩推導值互不為前綴（startsWith 唯一性前提）；尾碼代＝家族表 README 行。
 *
 * 顯式路徑判別：`argon` 或 `cipher` 任一在場＝顯式全配置路徑（resolver 不再推導任何欄位——
 * 顯式欄位優先、缺欄照 validateConfig 拒＝opt-in 母型；app 契約閘不跨路徑加寬——**契約閘＝
 * 零設定路徑專載**（顯式全配置路徑 app 字面照 0.3.3 契約零驗；`resolveVaultConfig(opts)`
 * 三入口單點接線共用）。
 * recovery 物件形同判（呼叫端自管面）。半顯式態（argon 組推導＋legacy 物件槽顯式欄位共存）：
 * 推導值與顯式值同進前綴互斥檢查（validateConfig——例 `legacy: { wrap: 'foo4w.bait' }` 與推導
 * wrap4 'foo4w.' 互為前綴＝CONFIG 拒；歧義配置不猜。
 */
export function resolveVaultConfig(input: VaultOptions | VaultConfigInput): { config: VaultConfig; defaulted: boolean } {
  if (!input || typeof input !== 'object') throw new VaultError('ERR_VAULT_CONFIG', 'input missing');
  const appIn = (input as { app?: unknown }).app;
  const opts = input as Partial<VaultOptions> & { legacy?: VaultConfig['legacy'] | boolean };
  const explicit = opts.argon !== undefined || opts.cipher !== undefined
    || (opts.recovery !== undefined && typeof opts.recovery === 'object');
  if (explicit) return { config: input as VaultConfig, defaulted: false };
  // app 契約閘＝零設定（推導）路徑專載——契約閘不跨路徑加寬（顯式全配置路徑 app 字面照 0.3.3
  // 既有契約零驗；非契約 app 誤入零設定＝推導值帶契約外字元入前綴域＝fail-closed 不猜）。
  if (typeof appIn !== 'string' || !APP_RE.test(appIn)) {
    throw new VaultError('ERR_VAULT_CONFIG', 'app contract (^[A-Za-z0-9_-]+$)');
  }
  const app = appIn;
  let legacy: NonNullable<VaultConfig['legacy']>;
  if (opts.legacy === true) {
    legacy = { wrap: app + '1w.', wrapDual: app + '2w.', pinSaltPrefix: app + '1s.' };
  } else if (opts.legacy === undefined || opts.legacy === false) {
    legacy = { wrap: false };
  } else {
    const l = opts.legacy;
    legacy = {
      wrap: l.wrap === undefined ? app + '1w.' : l.wrap,
      wrapDual: l.wrapDual ?? app + '2w.',
      pinSaltPrefix: l.pinSaltPrefix ?? app + '1s.',
    };
  }
  const recovery = opts.recovery === true ? { wrapRec: app + '1r.', recKekHkdf: app + 'kek1' } : undefined;
  return {
    config: {
      app,
      cipher: app + '1v.',
      argon: { wrap4: app + '4w.', wrapDual4: app + '4d.', pinSalt3Prefix: app + '3s:', wrap3: app + '3w.', wrapDual3: app + '3d.' },
      legacy,
      recovery,
    },
    defaulted: true,
  };
}

// ── 型別 ────────────────────────────────────────────────────────────────────

export interface VaultConfig {
  /** 應用域（AAD 前段）：記錄密文 AAD＝`<app>:<recordId>`。必填非空。 */
  app: string;
  /** 記錄密文前綴（如 'jr1v.'）。必填非空，且與所有包裹前綴互不為前綴。 */
  cipher: string;
  /** Argon2id 家族前綴：`wrap4` 必填（寫面）；`wrapDual4`＋`pinSalt3Prefix`＝PIN 寫面；
   *  `wrap3`／`wrapDual3`＝舊世代讀面（unlock＋upgrade 來源）。`wrapShare3` 本 API 不用。 */
  argon: Argon3Config;
  /** PBKDF2 舊世代讀面（jr1w.＝`wrap`；jr2w.＝`wrapDual`＋`pinSaltPrefix`）。只讀不寫。
   *  `wrap: false`＝舊契約回落腿關閉（零設定 vault 預設語意——identity 綁域的 jr1w. 復原套件不屬本 API）。 */
  legacy?: { wrap?: string | false; wrapDual?: string; pinSaltPrefix?: string };
  /** 復原套件（jr1r. HKDF 世代；兩欄一體）。物件形＝顯式（呼叫端自管前綴與鹽域）；
   *  true＝opt-in 零設定（wrapRec／recKekHkdf 由 resolver 以 app 推導；recKekSalt 未指定＝零鹽契約）；
   *  false／undefined＝不產生復原套件（recoverVault 拒）。 */
  recovery?: VaultRecoverySpec | boolean;
}

/** VaultConfigInput：resolveVaultConfig 輸入形（三入口共用——零設定 `{app}` 與顯式全配置同形進位；
 *  pin／carrier＝入口進位欄，resolver 不消費）。 */
export interface VaultConfigInput {
  /** app 契約 `^[A-Za-z0-9_-]+$`：零設定路徑 fail-closed（缺 app 亦拒——推導無從）；顯式路徑放行顯式全配置。 */
  app?: string;
  /** 顯式記錄密文前綴（在場＝顯式全配置路徑——resolver 不推導）。 */
  cipher?: string;
  /** 顯式 Argon3 家族前綴組（在場＝顯式全配置路徑）。 */
  argon?: Argon3Config;
  /** 舊世代讀面 opt-in：true＝全推導；false／undefined＝falsable 預設 `{ wrap: false }`（wrap 舊契約回落腿關閉）；
   *  物件形＝顯式欄位優先、缺欄由 app 推導（`wrap: false` 原樣保留）。 */
  legacy?: VaultConfig['legacy'] | boolean;
  /** 復原套件 opt-in：true＝resolver 推導（wrapRec＝`<app>1r.`、recKekHkdf＝`<app>kek1`、零鹽契約）；
   *  物件形＝顯式（呼叫端自管前綴與鹽域——＝顯式路徑判別）；false／undefined＝無（recoverVault 拒）。 */
  recovery?: VaultRecoverySpec | boolean;
  /** PIN 第二因子（入口進位欄——resolver 不消費；VaultOptions 同欄）。 */
  pin?: string;
  /** Argon2id 載體選項（入口進位欄——resolver 不消費；VaultOptions 同欄）。 */
  carrier?: ArgonCarrierOptions;
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
/** app 契約（前綴字面＝線上 ASCII 契約）：字母／數字／底線／減號。 */
const APP_RE = /^[A-Za-z0-9_-]+$/;

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
  { family: 'wrap', dual: false, current: false, argon: false, prefix: (c) => (c.legacy?.wrap === false ? undefined : c.legacy?.wrap) },
  { family: 'wrapDual', dual: true, current: false, argon: false, prefix: (c) => (c.legacy?.wrap === false ? undefined : (c.legacy?.pinSaltPrefix ? c.legacy?.wrapDual : undefined)) },
];

function specOf(family: VaultWrapFamily): FamilySpec {
  return FAMILIES.find((f) => f.family === family)!;
}

function validateConfig(c: VaultConfig): void {
  if (!c || typeof c !== 'object') throw new VaultError('ERR_VAULT_CONFIG', 'config missing');
  if (!nonEmpty(c.app)) throw new VaultError('ERR_VAULT_CONFIG', 'app');
  if (!nonEmpty(c.cipher)) throw new VaultError('ERR_VAULT_CONFIG', 'cipher');
  if (!c.argon || !nonEmpty(c.argon.wrap4)) throw new VaultError('ERR_VAULT_CONFIG', 'argon.wrap4');
  if (c.legacy !== undefined) {
    if (typeof c.legacy !== 'object' || Array.isArray(c.legacy)) throw new VaultError('ERR_VAULT_CONFIG', 'legacy');
    const lv = c.legacy as { wrap?: string | false; wrapDual?: string; pinSaltPrefix?: string };
    if (lv.wrap !== undefined && lv.wrap !== false && !nonEmpty(lv.wrap)) throw new VaultError('ERR_VAULT_CONFIG', 'legacy.wrap');
    if (lv.wrapDual !== undefined && !nonEmpty(lv.wrapDual)) throw new VaultError('ERR_VAULT_CONFIG', 'legacy.wrapDual');
    if (lv.pinSaltPrefix !== undefined && !nonEmpty(lv.pinSaltPrefix)) throw new VaultError('ERR_VAULT_CONFIG', 'legacy.pinSaltPrefix');
  }
  const prefixes: string[] = [c.cipher];
  for (const f of FAMILIES) {
    const p = f.prefix(c);
    if (p !== undefined && p !== '') prefixes.push(p);
  }
  if (c.recovery !== undefined) {
    // 物件形契約（resolver `recovery: true` opt-in 推導前的原始形＝boolean 進位——顯式路徑直通時 true/false 恆拒：
    // true＝推導語意非顯式規格；false＝「無復原」語意不入 validateConfig 面）。
    if (c.recovery === true || c.recovery === false || typeof c.recovery !== 'object' || Array.isArray(c.recovery)) {
      throw new VaultError('ERR_VAULT_CONFIG', 'recovery');
    }
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
  const lw = c.legacy?.wrap === false ? '' : c.legacy?.wrap ?? '';
  return {
    guestKdfPrefix: '',
    recSaltPrefix: '',
    cipherBound: c.cipher,
    wrap: lw,
    wrapDual: c.legacy?.wrapDual,
    pinSaltPrefix: c.legacy?.pinSaltPrefix,
    store: NO_STORE,
  };
}

/** 復原面專用 cfg：wrap='' ＝舊契約回落腿關閉（identity 綁域的 jr1w. 復原套件不屬本 API）。
 *  呼叫端先收口：boolean 形 recovery 已由 validateConfig 拒（createVault）／recoverVault 入口拒——本函式唯物件形。 */
function recoveryCfg(c: VaultConfig): NoteCryptoConfig {
  const r = c.recovery as VaultRecoverySpec;
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

/**
 * deriveVaultPh1(passphrase, ph1Salt)：高階 Vault API 的 PH1 登入憑證派生（hex64）。
 * 本體委派 `derivePh1ArgonV3(pass, ph1Salt)`（PH1 v3：Argon2id(normalizePassphrase(pass), 鹽, m=64MiB, t=3, p=1)→hex64）
 * ——語意單一真相同在 argon2.ts，本函式只是 vault 子路徑的入口收口位（呼叫端免跨 import argon2）。
 *
 * ⚠️ 契約三行（README PH1 節同款）：
 * 1. 鹽一經選定恆固定（per-product）——PH2 UNIQUE 約束：同一密語必須恆生同一 PH2；
 *    per-user 鹽會摧毀它。改鹽＝帶內版本化換鹽尾碼重遷移，禁原地改語意。
 * 2. `PH1_V3_SALT`（'tacet-ph1-v2'）禁當 saltArg 餵 v2 派生面 `derivePh1Argon`——
 *    反之亦然：同鹽域值跨面餵入＝NFKC-effective 密語與 v2 raw 密語同值撞 PH2（鹽撞位警告）。
 * 3. 其他產品用自有鹽域——禁硬編 tacet 鹽當預設；必須顯式帶入 `ph1Salt`。
 */
export async function deriveVaultPh1(passphrase: string, ph1Salt: Uint8Array): Promise<string> {
  return derivePh1ArgonV3(passphrase, ph1Salt);
}

/** 新 vault：隨機 noteKey＋最新家族包裹（pin＝<app>4d.，否則 <app>4w.）＋選配復原套件（<app>1r.）。
 *  前綴零手填態（resolver）：`{ app }` 最小設定——全前綴由 app 決定性推導（resolveVaultConfig；
 *  `recovery: true` opt-in、PIN 帶值＝同族尾碼推導 <app>4d. 不拒）；顯式 `argon`／`cipher` 在場
 *  ＝顯式全配置路徑（零設定語意退出——缺欄照 validateConfig 拒）。輸入形 VaultOptions | VaultConfigInput。 */
export function createVault(passphrase: string, opts: VaultOptions | VaultConfigInput): Promise<{
  vault: VaultHandle;
  serverRecord: VaultServerRecord;
  recovery: VaultRecoveryKit | null;
}> {
  return translate(async () => {
    const o = resolveVaultConfig(opts);
    const cfg = o.config;
    validateConfig(cfg);
    checkPassphrase(passphrase);
    const pin = opts.pin === undefined ? null : opts.pin;
    if (pin !== null) { checkPin(pin); checkDualWritable(cfg); }
    const carrier = await ensureArgonCarrier(opts.carrier);
    const noteKey = await generateNoteKey();
    const w = await wrapCurrent(cfg, noteKey, passphrase, pin);
    let recovery: VaultRecoveryKit | null = null;
    if (opts.recovery) {
      const recToken = generateRecToken();
      // identity 不入 HKDF 世代 KEK（identity-free by design）——空字串僅滿足簽名。
      const wrappedRec = await wrapNoteKeyWithRecToken(recoveryCfg(cfg), noteKey, recToken, '');
      recovery = { recToken, wrappedRec, recTokenHash: await recTokenHash(recToken) };
    }
    const vault = makeHandle(cfg, noteKey, { rec: w.rec, family: w.family, carrier }, opts.carrier);
    return { vault, serverRecord: { ...w.rec }, recovery };
  });
}

/** 解鎖：serverRecord（wrapped＋salt 成對）按前綴辨識家族（新→舊次序），舊世代照解；
 *  前綴零手填態（resolver）：整組前綴缺省＝全前綴由 app 推導（resolveVaultConfig）；顯式欄位
 *  在場＝顯式全配置路徑（零推導）。needsUpgrade() 為真時呼叫端可於同一動線
 *  upgrade(passphrase) 靜默重包（Argon 遷移契約同構）。輸入形 VaultOptions | VaultConfigInput。 */
export function unlockVault(passphrase: string, serverRecord: VaultServerRecord, opts: VaultOptions | VaultConfigInput): Promise<VaultHandle> {
  return translate(async () => {
    const o = resolveVaultConfig(opts);
    const cfg = o.config;
    validateConfig(cfg);
    const r = serverRecord as Partial<VaultServerRecord> | null | undefined;
    if (!r || typeof r !== 'object' || !nonEmpty(r.wrapped) || typeof r.salt !== 'string' || !HEX32_RE.test(r.salt)) {
      throw new VaultError('ERR_VAULT_BAD_RECORD');
    }
    checkPassphrase(passphrase);
    const rec: VaultServerRecord = { wrapped: r.wrapped, salt: r.salt };
    const f = detectFamily(cfg, rec.wrapped);
    if (!f) throw new VaultError('ERR_VAULT_WRAP_UNKNOWN');
    if (f.dual) {
      if (opts.pin === undefined) throw new VaultError('ERR_VAULT_PIN_REQUIRED');
      checkPin(opts.pin);
    }
    const carrier = f.argon ? await ensureArgonCarrier(opts.carrier) : null;
    const noteKey = await unwrapOrThrow(f, cfg, rec, passphrase, opts.pin ?? '');
    return makeHandle(cfg, noteKey, { rec, family: f.family, carrier }, opts.carrier);
  });
}

/** 復原：recToken（hex64）＋wrappedRec（<app>1r.）→ handle（無包裹欄——呼叫端隨即 changePassphrase 設新密語）。
 *  前綴零手填態同上：recovery 未配置＝ERR_VAULT_CONFIG（零鹽選擇不可靜默——opt-in 鐵律；resolver 對
 *  `recovery: true` 推導零鹽契約、物件形＝顯式零動）。輸入形 VaultOptions | VaultConfigInput。 */
export function recoverVault(recToken: string, wrappedRec: string, opts: VaultOptions | VaultConfigInput): Promise<VaultHandle> {
  return translate(async () => {
    const o = resolveVaultConfig(opts);
    const cfg = o.config;
    validateConfig(cfg);
    if (!cfg.recovery || cfg.recovery === true) throw new VaultError('ERR_VAULT_CONFIG', 'recovery'); // true＝resolver opt-in 形——顯式路徑（argon/cipher 在場）未推導＝與未配置同拒
    if (typeof recToken !== 'string' || !HEX64_RE.test(recToken)) throw new VaultError('ERR_VAULT_RECOVERY', 'recToken');
    if (typeof wrappedRec !== 'string' || !wrappedRec.startsWith(cfg.recovery.wrapRec)) throw new VaultError('ERR_VAULT_RECOVERY', 'wrappedRec prefix');
    const noteKey = await unwrapNoteKeyWithRecToken(recoveryCfg(cfg), wrappedRec, recToken, '');
    if (!noteKey) throw new VaultError('ERR_VAULT_RECOVERY');
    return makeHandle(cfg, noteKey, { rec: null, family: null, carrier: null }, opts.carrier);
  });
}
