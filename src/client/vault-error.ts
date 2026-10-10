/**
 * vault-error.ts — 高階 Vault API 的型別化錯誤家族（0.3.1 批 A3）。
 *
 * 低階原語面不動（throw 'ERR_*' 字串錯誤＋unwrap 恆 null 的混態照舊）——只在 vault.ts／
 * argon-auto.ts 邊界轉譯：高階 API 一律 throw VaultError，呼叫端以 `code` 分流，不比對 message。
 * 失敗面刻意不細分「密語錯」與「密文竄改」（同一 GCM 失敗——細分＝oracle）。
 */

export type VaultErrorCode =
  /** 配置缺欄／畸形（app、cipher、argon.wrap4、recovery 兩欄一體…）——opt-in 未配置即拒。 */
  | 'ERR_VAULT_CONFIG'
  /** serverRecord 缺 wrapped/salt 欄或形不符（不猜）。 */
  | 'ERR_VAULT_BAD_RECORD'
  /** wrapped 前綴不屬任何已配置家族（未知世代／他產品前綴）。 */
  | 'ERR_VAULT_WRAP_UNKNOWN'
  /** 家族辨識成功但解包失敗：密語／PIN 錯或包裹竄改（刻意不分）。 */
  | 'ERR_VAULT_WRAP_MISMATCH'
  /** 雙因子家族（jr2w./jr3d./jr4d.）缺 PIN。 */
  | 'ERR_VAULT_PIN_REQUIRED'
  /** 密語空值／非字串。 */
  | 'ERR_VAULT_BAD_PASSPHRASE'
  /** PIN 正規化後為空。 */
  | 'ERR_VAULT_BAD_PIN'
  /** Argon2id 載體缺席或失效（zero-fallback：禁 PBKDF2／zeros 兜底）。 */
  | 'ERR_VAULT_KDF_UNSUPPORTED'
  /** recordId 非字串或空。 */
  | 'ERR_VAULT_BAD_RECORD_ID'
  /** encrypt 資料形不支援（undefined、BigInt、循環 JSON、非 Uint8Array 的 ArrayBuffer 族…）。 */
  | 'ERR_VAULT_BAD_DATA'
  /** 密文 blob 形不符（前綴／base64／長度／型別標記）。 */
  | 'ERR_VAULT_BAD_BLOB'
  /** 密文解密失敗：recordId（AAD）不符、金鑰不符或密文竄改（刻意不分）。 */
  | 'ERR_VAULT_DECRYPT'
  /** 復原套件形不符（recToken 非 hex64、wrappedRec 前綴不符）或解包失敗。 */
  | 'ERR_VAULT_RECOVERY'
  /** 未預期的低階錯誤（cause 帶原錯）。 */
  | 'ERR_VAULT_INTERNAL';

export class VaultError extends Error {
  readonly code: VaultErrorCode;
  constructor(code: VaultErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ? code + ': ' + message : code, options);
    this.name = 'VaultError';
    this.code = code;
  }
}

/** 型別守衛：`isVaultError(e)` 或指定碼 `isVaultError(e, 'ERR_VAULT_DECRYPT')`。 */
export function isVaultError(e: unknown, code?: VaultErrorCode): e is VaultError {
  return e instanceof VaultError && (code === undefined || e.code === code);
}
