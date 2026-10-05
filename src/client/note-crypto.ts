/**
 * note-crypto.ts — 自由書寫 e2e 加密，品牌參數化核心。
 *
 * 血統：抽取自姊妹專案的日記加密模組（37 斷言驗證閘母型）；
 * fork diff 已證實：除品牌前綴（guest KDF 前綴、密文前綴家族、KDF salt 前綴）
 * 與產品附加機制外，密碼學本體在多個產品間完全一致——本檔收編該本體。
 *
 * 兩時代金鑰模型（不變量，勿破壞）：
 *   時代 1（未綁定 guest）：K_u = SHA-256(guestKdfPrefix ‖ identity) — 純客戶端派生，混淆級
 *   時代 2（綁定後）：隨機 256-bit noteKey；日常加解密只用 noteKey，passphrase 以
 *     KEK = PBKDF2(pass, salt, 600000, SHA-256) 包裹成 wrapped 上傳；復原套件 wrappedRec
 *     = 同款包裹在 KEK_rec = PBKDF2(recToken, salt = recSaltPrefix ‖ identity) 下。
 *     passphrase 從此不過線：線上憑證送 PH1（雜湊形，派生方式由各產品自定義），伺服器存 PH2。
 *     復原套件 v0.2.0 世代（卡D 議題二搭車案）：前綴專用化（wrapRec=jr1r.）＋KEK_rec 派生
 *     世代化（recKekHkdf 配置＝HKDF-SHA256，info='journal-kek-rec-v1:'+recKekHkdf）＋
 *     AAD 帶內切換（'notekey'→'notekey-rec'）；新世代讀舊寫新——unwrap 新面先行、回落
 *     舊契約面（PBKDF2＋AAD 'notekey'）雙試（r3 過渡保護承諾：舊 blob 永遠可解；摘雙試
 *     時點＝遷移率裁定非日曆）。
 *
 * 前綴全部可配置（帶內版本化：升級 KDF 參數 = 換新前綴）。AAD 由呼叫端傳入——
 * 例如綁 `noteId`（跨列搬移必解密失敗）、`lifeId:day`（逐日日記）或留言綁 `tst:<lifeId>`。
 *
 * ⚠️ extractable 鐵律：所有要被 exportKey/wrap 的 key，
 * import 當下就必須 extractable=true。noteKey 全部產生路徑（generate/unwrap×3）
 * 一律顯式 true；KEK/guest key 保持 nonextractable（只加解密、永不 export）。
 */

// ── 配置 ────────────────────────────────────────────────────────────────────

export interface NoteCryptoConfig {
  /** guest 時代 KDF 前綴，如 'journal-note-u1'。 */
  guestKdfPrefix: string;
  /** 復原包裹 KDF salt 前綴，如 'journal-note-rec1:'。 */
  recSaltPrefix: string;
  /** 密文前綴：guest 時代，如 'jr1g.'。未配置 = guest API 拒絕（未配置行為不變；2026-09-19 選配收編）。 */
  cipherGuest?: string;
  /** 密文前綴：綁定時代，如 'jr1b.'。 */
  cipherBound: string;
  /** 金鑰包裹前綴，如 'jr1w.'。 */
  wrap: string;
  /** 本機包裹前綴（jr1l.，v0.2.0 批卡③：本機包裹不再借用 cfg.wrap——「一個前綴一份契約」
   *  的第二違例收口）。未配置 = storeLocalWrap/loadLocalWrap 退場（無寫入／讀取照走
   *  舊形回落——cipherLocal opt-in 母型；寫面功能退場——v1 可用者升級後需配置 wrapLocal
   *  才保留本機包裹寫入）。 */
  wrapLocal?: string;
  /** 復原套件專用前綴（jr1r.，v0.2.0 批卡⑤：wrappedRec 不再借用 cfg.wrap——同前例收口）。
   *  AAD 亦帶內切換 'notekey'→'notekey-rec'（共用 AAD 收口）。與 recKekHkdf **兩欄一體**
   *  （同缺同在；部分配置＝ERR_REC_CFG_PARTIAL 拒寫——世代配對門，fail-closed 禁寫出
   *  「前綴面 jr1r.×派生面 PBKDF2」跨契約 blob）。兩欄皆缺席 = wrap/unwrap 復原套件面
   *  照走舊契約（cfg.wrap＋PBKDF2＋AAD 'notekey'）＝行為不變態（r3 承諾面：配置形正確
   *  時舊 wrappedRec blob 永遠可解——HKDF 腿誤配拋點整面 fail-closed 既有契約）。 */
  wrapRec?: string;
  /** 復原套件「KEK 派生」世代開關（v0.2.0 批卡⑤）：KEK_rec = HKDF-SHA256(
   *  ikm = recToken（256-bit 實體因子）， salt = recKekSalt？:16B hex（未配置＝零鹽），
   *  info = 'journal-kek-rec-v1:' + recKekHkdf, L = 32 )——info 合成名沿 argon2 家族
   *  慣例（呼叫端帶入；KEK 派生世代空間由前綴＋info 承載）。HKDF 世代 identity 不入
   *  KEK（identity-free by design——256-bit 實體因子足綁，卡D 議題二；identity 綁域由
   *  舊契約面 recSaltPrefix‖identity 專屬承載，兩世代綁域刻意分離）。與 wrapRec 兩欄
   *  一體（同缺同在；部分配置＝ERR_REC_CFG_PARTIAL 拒寫）。未配置 = PBKDF2 舊世代
   *  （卡D 議題二裁定：HKDF 強化搭車 v0.2.0；強度差異對 256-bit recToken 無意義，
   *  收的是「派生域＋前綴契約面分離」的語意收口）。 */
  recKekHkdf?: string;
  /** HKDF salt（v0.2.0 批卡⑤）：16B hex 專屬鹽域（與 PBKDF2 面 recSaltPrefix 前綴域分離
   *  ——KEK 派生世代鹽）。未配置 = HKDF 零鹽（HKDF salt 欄位本就 optional；語意不變，
   *  域由 info 承載）。 */
  recKekSalt?: string;
  /** 雙因子合鑰包裹前綴（jr2w.，PIN 第二因子）。未配置 = dual API 拒絕（未配置行為不變）。 */
  wrapDual?: string;
  /** 雙因子 pin 段 PBKDF2 salt 前綴，如 'journal-note-pin1:'（pinSalt 內嵌 payload 後拼接）。 */
  pinSaltPrefix?: string;
  /** 分享包裹前綴（jrsw.，單篇分享連結 V1）。未配置 = share API 拒絕（未配置行為不變）。 */
  wrapShare?: string;
  /** 附件密文前綴（jr1c.，image attachments）。未配置 = attach API 拒絕（未配置行為不變）。 */
  cipherAttach?: string;
  /** 本機 IDB 密文前綴（jr1d.，notes store stored 形）。未配置 = local API 拒絕（未配置行為不變）。 */
  cipherLocal?: string;
  /** localStorage key store（品牌前綴由 keys.ts 管理）。 */
  store: import('./keys').KeyStore;
}

export const PBKDF2_ITERATIONS = 600_000; // OWASP 2023 建議值
export const PIN_PBKDF2_ITERATIONS = 2_000_000; // 雙因子 pin 段（設計 v2：6 位數字也要扛離線爆破）
export const IV_LEN = 12;

const HEX32_RE = /^[0-9a-f]{32}$/; // 16-byte salt hex
/**
 * hex 合法性（fail-closed 目標 #2）：大小寫正規化後長度恰 2n（n bytes＝2 hex digits×n）＋
 * 每雙位元組真 hex。
 */
const HEX_RE = /^([0-9a-f][0-9a-f])+$/;

// ── 基礎工具（export 供 argon2.ts 等同檔模組複用；語意不變） ─────────────────

export function b64(bytes: Uint8Array): string {
  // 分塊 String.fromCharCode.apply（t_7361b68c 目標 2：review 實測瀏覽器 4MiB 222ms→27ms；
  // node 端分塊形 132-181ms→18ms，與閘執行帳同源——review 的 Node-only toBase64 1ms 帳是
  // 不同形，非本體帳：round 2 MINOR-2 對齊）。瀏覽器端恆走本形——core 是 isomorphic TS
  // 源碼發行，不引入 Node-only
  // toBase64 分支（卡面否決案）。apply 參數上限安全窗 8192；輸出 byte 等價
  // （驗證閘 [14] 有 0/1/7/8191/8192/8193/65539 邊界逐位元組對照＋unb64 roundtrip）。
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192) as unknown as number[]);
  }
  return btoa(binary);
}

export function unb64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  // fail-closed（目標 #2）：非法字元靜默歸零是 unwrap 家族的假金鑰生產器——
  // 拋 ERR_BAD_HEX（呼叫端 unwrap 全部 try/catch 回 null；非 catch 端僅 bip39
  // HEX64_RE 前置自守）。奇數長度、非 hex、空字串皆拒；大小寫/全形 NFKC 收容。
  // 測與 parse 同一（正規化後）真相——round 1 審查 MINOR-4：形檢吃正規化串、
  // parseInt 吃原始串＝全形 hex digit NaN 歸零殘形（README 例外契約自穿透），收口殲滅。
  // NFKC 寬容＝設計面刻意（round 2 NIT 記錄 t_580f9c54）：'⑩'→'10' 等相容字元收容後是真 hex
  // 值（⑩→[16] 實帳），非缺陷形（NaN 歸零已殲滅＝輸出恆數學等值）；rawHex 檢查同式（HEX_RE 同行後置
  // ＝rawHex 前置守衛）；鹽欄同為同行後置（note-crypto/argon2 各 unwrap 面鹽欄形檢——行號帳不寫死，
  // 新增段推移行號＝註解行號帳漂移，NIT-a 同病禁再犯）。
  // 行為恆 null（純註解）；正式輸入面形檢在場，公開原語只保證「正規化後真 hex 恆等值、垃圾恆拒」。
  // 若要 ASCII-only 收緊＝帶內版本化（換前綴），禁原地改語意。
  const norm = hex.normalize('NFKC').toLowerCase();
  if (!HEX_RE.test(norm)) {
    throw new Error('ERR_BAD_HEX');
  }
  return new Uint8Array((norm.match(/.{2}/g) ?? []).map(h => parseInt(h, 16)));
}

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(new Uint8Array(d));
}

/** SHA-256 hex（分享定位鍵雜湊等呼叫端雜湊用；與伺服器端 sha256Hex 同構）。 */
export function sha256HexExport(text: string): Promise<string> {
  return sha256Hex(text);
}

export async function importAesGcm(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  // extractable 預設 false（最小權限）；唯一需要 true 的是 noteKey。
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

export async function deriveGuestKey(cfg: NoteCryptoConfig, identity: string): Promise<CryptoKey> {
  const material = new TextEncoder().encode(cfg.guestKdfPrefix + identity);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  return importAesGcm(digest);
}

async function deriveKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  // 這裡的 importKey 是 deriveKey 用途集——與 derivePbkdf2Bits 的 deriveBits 面不是同一形，
  // 禁共用 importKeyRawForKdf（usage 不符＝InvalidAccessError；t_7361b68c probe 實證）。
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password) as BufferSource, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** raw → PBKDF2 import（僅供 deriveBits 用途；與 deriveKek 的 deriveKey 用途分行）。 */
async function importKeyRawForKdf(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(password) as BufferSource, 'PBKDF2', false, ['deriveBits']);
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

/**
 * 密語正規化契約 v3（v0.2.0 批卡①；卡D 裁定 NFKC-only）：NFKC——**大小寫摺疊禁絕：區分大小寫
 * （大小寫差＝不同 KEK/ph2）＋首尾空白保留（不 trim）**。
 * 消費面只有 v3 世代：jr4w./jr4d. 包裹家族與 PH1 v3（derivePh1ArgonV3）——
 * 舊前綴家族（jr1w./jr3w./jr2w./jr3d.）契約面永不變（raw pass 派生，帶內版本化＝
 * KEK 輸入契約改變＝換新前綴，禁原地改語意），禁把本函式接進舊家族入口。
 * 與 normalizePin 契約並存不混（NFKC→trim→lowercase，pinlock/dual 面不動）：
 * 兩函式是正交契約，閘有「同輸入不同輸出」行為向量承載分離。
 * 三面單一真相：本體（此處）＋README 家族表＋驗證閘 [15] 行為向量——改 NFKC 語意＝帶內版本化（換世代），禁原地改。
 */
export function normalizePassphrase(passphrase: string): string {
  return passphrase.normalize('NFKC');
}

async function derivePbkdf2Bits(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const km = await importKeyRawForKdf(password);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, km, 256);
  return new Uint8Array(bits);
}

async function deriveKek2(cfg: NoteCryptoConfig, passphrase: string, pin: string, salt1: Uint8Array, pinSalt: Uint8Array): Promise<CryptoKey> {
  // pass 段與 pin 段 PBKDF2 相互獨立（不同 salt/密碼不同鹽源）＝可並行（t_7361b68c 目標 1）。
  // ⚠️ 瀏覽器 hash-wasm Argon2（jr3d. 對應形 deriveKek2Argon）禁並行——純 wasm Argon2id
  // 共享記憶體池、兩實例並行在部分引擎靜態直 throw，卡面 review 明示；並行只收 PBKDF2 家族。
  // 兩段各自 importKeyRawForKdf（round 2 NIT-2：keyMat 參數化退場——pass/pin 段絕不共享 PBKDF2 基材）。
  // 輸出序＝ikm 組裝序＝passBits@0 ‖ pinBits@32（與原串行逐位一致）；閘錨綁左手側 destructure，
  // 對調滑接＝既有 jr2w. 帳戶全不可解（round 2 MAJOR-1 reviewer rev-harm 一手實證）。
  const [passBits, pinBits] = await Promise.all([
    derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS),
    derivePbkdf2Bits(pin, new TextEncoder().encode(cfg.pinSaltPrefix + toHex(pinSalt)), PIN_PBKDF2_ITERATIONS),
  ]);
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
  if (!pinNorm) throw new Error('ERR_PIN_EMPTY'); // 空 PIN ≠ 未配置（t_7710c766 語意分離）
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
    if (salt1.length !== 16 || !HEX32_RE.test(salt1Hex)) return null;
    const payload = unb64(wrapped.slice(cfg.wrapDual.length));
    // 嚴格長度：pinSalt(16) + iv(12) + ct(hex 字串 64B + GCM tag 16B) = 108B 固定；rawHex hex 形為本函式自有檢查（鹽內嵌族不經 openNoteKey 本體）
    if (payload.length !== DUAL_SALT_LEN + DUAL_IV_LEN + 80) return null;
    const pinSalt = payload.slice(0, DUAL_SALT_LEN);
    const ivPrefixedCt = payload.slice(DUAL_SALT_LEN); // decryptWithKey 契約：payload = iv[12] ‖ ct
    const pinNorm = normalizePin(pin);
    if (!pinNorm) return null;
    const kek2 = await deriveKek2(cfg, passphrase, pinNorm, salt1, pinSalt);
    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');
    if (!rawHex || rawHex.length !== 64 || !/^[0-9a-f]+$/.test(rawHex)) return null;
    return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹（鐵律）
  } catch {
    return null;
  }
}

// ── 對稱核心：encrypt / decrypt（AAD 由呼叫端指定） ──────────────────────────

export async function encryptWithKey(key: CryptoKey, plaintext: string, aad: string): Promise<string> {
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

export async function decryptWithKey(key: CryptoKey, payload: Uint8Array, aad: string): Promise<string | null> {
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

// ── 附件密文（jr1c.，image attachments；金鑰由呼叫端決定） ────────────────────
//
// 附件用既有 noteKey（綁定後）或 guest key（Era 0 純本地），零新金鑰管理；
// AAD 帶 'jr1a:<note_id>:<attachment_id>'（綁篇＋綁附件，跨列搬移必失敗）。
// 前綴 cfg opt-in（未配置即拒）：兄弟 fork 不配置＝API 拒絕，行為不變。

export async function encryptAttach(cfg: NoteCryptoConfig, key: CryptoKey, plaintext: string, aad: string): Promise<string> {
  if (!cfg.cipherAttach) throw new Error('ERR_ATTACH_NOT_CONFIGURED');
  return cfg.cipherAttach + await encryptWithKey(key, plaintext, aad);
}

export async function decryptAttach(cfg: NoteCryptoConfig, key: CryptoKey, cipher: string, aad: string): Promise<string | null> {
  try {
    if (!cfg.cipherAttach) return null;
    if (!cipher.startsWith(cfg.cipherAttach)) return null;
    return await decryptWithKey(key, unb64(cipher.slice(cfg.cipherAttach.length)), aad);
  } catch {
    return null;
  }
}

// ── 本機 IDB 密文（jr1d.，notes store stored 形；金鑰由呼叫端決定） ──────────
//
// IDB 持久形密文：bound 態＝held noteKey、Era 0＝guest key（兩者皆由呼叫端注入；
// 鑰匙狀態機在呼叫端 store 層，core 只承載前綴與對稱本體）。payload 自帶 {v:1,...}
// 版本欄（呼叫端 JSON 面），前綴即可辨識；AAD 綁 note_id（呼叫端契約，跨列搬移必失敗）。
// 前綴 cfg opt-in（未配置即拒）：兄弟 fork 不配置＝API 拒絕，行為不變。

export async function encryptLocal(cfg: NoteCryptoConfig, key: CryptoKey, plaintext: string, aad: string): Promise<string> {
  if (!cfg.cipherLocal) throw new Error('ERR_LOCAL_NOT_CONFIGURED');
  return cfg.cipherLocal + await encryptWithKey(key, plaintext, aad);
}

export async function decryptLocal(cfg: NoteCryptoConfig, key: CryptoKey, cipher: string, aad: string): Promise<string | null> {
  try {
    if (!cfg.cipherLocal) return null;
    if (!cipher.startsWith(cfg.cipherLocal)) return null;
    return await decryptWithKey(key, unb64(cipher.slice(cfg.cipherLocal.length)), aad);
  } catch {
    return null;
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

/** noteKey raw hex 長度（hex(noteKey) 64B ＝ payload ct 面 80B 契約的一半）。 */
const NOTEKEY_HEX_LEN = 64;

/**
 * 共用包裹核心（目標 #1 收口）：prefix + b64(iv[12] ‖ GCM(KEK, hex(noteKey), aad))。
 * 鹽外置家族字首家系清點（v0.2.0 批卡③④同步——七呼叫端）：jr1w.（wrapNoteKey）/jrsw.
 *（wrapNoteKeyShare）/jr3w.（wrapNoteKey3）/jr4w.（wrapNoteKey4）/jr3s.
 *（wrapNoteKeyShare3）/jr1l.（storeLocalWrap）/jr1r.＋jr1w.（wrapNoteKeyWithRecToken——
 * HKDF 世代專用前綴＋AAD 'notekey-rec'、未配置世代 legacy 面＝cfg.wrap＋AAD 'notekey'）
 * 同一本體；KDF 差異在呼叫端 KEK、payload 形狀（salt 外置 vs 內嵌）由各家族維持。
 * prefix null/undefined＝未配置拒絕（呼叫端亦可先行拒絕，帶自家錯誤碼形；雙防線）。
 */
export async function sealNoteKey(prefix: string | null | undefined, noteKey: CryptoKey, kek: CryptoKey, aad: string): Promise<string> {
  if (!prefix) throw new Error('ERR_WRAP_NOT_CONFIGURED');
  const raw = await crypto.subtle.exportKey('raw', noteKey);
  if (raw.byteLength !== 32) throw new Error('ERR_WRAPTAMPER_LEN32');
  return prefix + await encryptWithKey(kek, toHex(new Uint8Array(raw)), aad);
}

/**
 * 共用解包核心（目標 #1 收口）：任何不符——前綴、base64 形、payload 長度、
 * GCM（金鑰/AAD/密文損壞）、rawHex 長度/hex 形——恆回 null 不拋。
 * round 1 審查 MINOR-5：atob 對非法字元會拋、原 docstring「不拋」與實作不符——
 * 本體吞收 null（公開原語誠實契約；呼叫端 unwrap 家族 try/catch 是雙防線非依賴面）。
 * 家族嚴格度收口實況（round 1 審查 MINOR-2 校正＋r2 MINOR-1 殘餘校正 t_580f9c54；
 * 七呼叫端帳同步 v0.2.0 批卡③④——鹽外置家族字首家系清點，6 點帳已過期）：
 * 本體嚴格 92B 終結七呼叫端＝note-crypto 四點（unwrapNoteKey＝jr1w／
 * unwrapNoteKeyShare＝jrsw／unwrapNoteKeyWithRecToken（legacy 面 jr1w.／HKDF 面 jr1r.）
 * ／loadLocalWrap＝jr1l.）
 * ＋argon2 三點（unwrapNoteKey3＝jr3w／unwrapNoteKey4＝jr4w／unwrapNoteKeyShare3＝jr3s；
 * own 92B 檢已隨收口摘除）；
 * 鹽內嵌 3 點（jr2w/jr3d/jr1p）own 108B＋rawHex 形檢——與本體同嚴格度、刻意不經本體
 * （pinSalt 前綴不在鹽外置形契約內）。維護本體時鹽內嵌三族不隨行。
 */
export async function openNoteKey(wrapped: string, kek: CryptoKey, aad: string, prefix: string): Promise<CryptoKey | null> {
  if (!wrapped.startsWith(prefix)) return null;
  let payload: Uint8Array;
  try {
    payload = unb64(wrapped.slice(prefix.length)); // atob 非法字元拋點吞收 null（公開原語全 null 契約）
  } catch {
    return null; // 壞 base64＝任何不符面之一（行為閘有壞 b64 向量承載）
  }
  if (payload.length !== IV_LEN + 80) return null; // 嚴格 92B：iv 12＋ct 80（hex64 字串編碼 64B＋tag 16）
  const rawHex = await decryptWithKey(kek, payload, aad);
  if (!rawHex || rawHex.length !== NOTEKEY_HEX_LEN || !HEX_RE.test(rawHex)) return null;
  return importAesGcm(hexToBytes(rawHex), true); // extractable=true：要能再包裹/解密（鐵律）
}

/** passphrase 包裹：salt 隨機 16 bytes（hex 存於 users.salt）。 */
export async function wrapNoteKey(cfg: NoteCryptoConfig, noteKey: CryptoKey, passphrase: string): Promise<{ wrapped: string; salt: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  if (!cfg.wrap) throw new Error('ERR_WRAP_NOT_CONFIGURED');
  const kek = await deriveKek(passphrase, salt);
  const wrapped = await sealNoteKey(cfg.wrap, noteKey, kek, 'notekey');
  return { wrapped, salt: toHex(salt) };
}

export async function unwrapNoteKey(cfg: NoteCryptoConfig, wrapped: string, passphrase: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrap) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== 16 || !HEX32_RE.test(saltHex)) return null;
    const kek = await deriveKek(passphrase, salt);
    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap);
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
  const wrapped = await sealNoteKey(cfg.wrapShare, noteKey, kek, 'notekey-share');
  return { wrapped, salt: toHex(salt) };
}

/** 分享解包：salt 取自 GET /shares/:hash 回應（與 jr1w 同形）；任何不符回 null，不拋。 */
export async function unwrapNoteKeyShare(cfg: NoteCryptoConfig, wrapped: string, sharePass: string, saltHex: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrapShare) return null;
    const salt = hexToBytes(saltHex);
    if (salt.length !== 16 || !HEX32_RE.test(saltHex)) return null;
    const kek = await deriveKek(sharePass, salt);
    return await openNoteKey(wrapped, kek, 'notekey-share', cfg.wrapShare);
  } catch {
    return null;
  }
}

/** 復原套件 KEK 派生（v0.2.0 批卡⑤）：HKDF 專責（本體只承載 recKekHkdf 配置世代——
 *  呼叫端須先過世代配對門）。KEK_rec = HKDF-SHA256(
 *    ikm = recToken（TextEncoder UTF-8；recToken 恆 hex64 256-bit 實體因子），
 *    salt = recKekSalt？(16B hex → 16 raw bytes；未配置＝零鹽)，
 *    info = 'journal-kek-rec-v1:' + recKekHkdf, L = 32 )——輸出 AES-GCM 256 nonextractable。
 *  HKDF 世代 identity 不入 KEK（identity-free by design——256-bit 實體因子足綁，卡D 議題二；
 *  identity 綁域由舊契約面 recSaltPrefix‖identity 專屬承載，兩世代綁域刻意分離）。
 *  強度語意（卡D 議題二文字）：recToken 256-bit 實體因子，KDF 強度無意義——收的是
 *  派生域（HKDF info）＋前綴契約面（jr1r.）的世代分離；非防爆破強化帳。
 *  鹽域二分（t_7710c766 鹽家族）：HKDF salt 屬「派生面內嵌 cfg、payload 零內嵌」——
 *  92B 帳純粹來自 hex(noteKey) 64B＋iv 12＋tag 16（pinSalt 內嵌 payload 是 jr2w./jr3d.
 *  鹽內嵌族的事，不入此帳）。PBKDF2 舊世代派生＝deriveRecLegacyKek（單一本體，修正輪
 *  收口：deriveRecKek 禁 PBKDF2 fallback——派生源雙模＝C2 缺口形）。 */
async function deriveRecKek(cfg: NoteCryptoConfig, recToken: string): Promise<CryptoKey> {
  const hkdfTail = cfg.recKekHkdf as string;
  const info = 'journal-kek-rec-v1:' + hkdfTail;
  if (cfg.recKekSalt && !HEX32_RE.test(cfg.recKekSalt)) throw new Error('ERR_REC_KEK_SALT');
  const salt = cfg.recKekSalt ? hexToBytes(cfg.recKekSalt) : new Uint8Array(0);
  const hkdfBase = await crypto.subtle.importKey('raw', new TextEncoder().encode(recToken) as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(info) as BufferSource },
    hkdfBase,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, noteKey: CryptoKey, recToken: string, identity: string): Promise<string> {
  // 世代配對門（v0.2.0 批卡⑤修正輪——reviewer C1/C2 收口）：一前綴一份契約補完。
  // 禁寫面＝「前綴面 jr1r.×派生面 PBKDF2」（wrapRec-only，C1：寫得出讀不回）與
  // 「前綴面 jr1w.×派生面 HKDF」（HKDF-only，C2：借 jr1w. 前綴 carrying 第二派生、
  // 升級即失資料）——兩面都由部分配置自然接線產生，門 fail-closed 拒寫。
  if (cfg.wrapRec || cfg.recKekHkdf) {
    if (!cfg.wrapRec || !cfg.recKekHkdf) throw new Error('ERR_REC_CFG_PARTIAL');
    const kek = await deriveRecKek(cfg, recToken);
    return sealNoteKey(cfg.wrapRec, noteKey, kek, 'notekey-rec');
  }
  // 未配置世代（兩欄皆缺席＝legacy 契約面永不變）：cfg.wrap＋PBKDF2＋AAD 'notekey'
  //（既有向量 byte 不變；cfg.wrap 缺席由 sealNoteKey 守衛承載——雙防線）。
  const kek = await deriveRecLegacyKek(cfg, recToken, identity);
  return sealNoteKey(cfg.wrap, noteKey, kek, 'notekey');
}

export async function unwrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, wrapped: string, recToken: string, identity: string): Promise<CryptoKey | null> {
  try {
    // 次序契約：jr1r. 面只在兩欄齊備時試（HKDF 專責派生——cfg.wrap 面零 HKDF 腿，
    // jr1w. 前綴只 carrying passphrase-PBKDF2 派生：「一個前綴一份契約」第二違例收口）。
    if (cfg.wrapRec && cfg.recKekHkdf) {
      const recKek = await deriveRecKek(cfg, recToken);
      const fresh = await openNoteKey(wrapped, recKek, 'notekey-rec', cfg.wrapRec);
      if (fresh) return fresh;
    }
    // 舊面回落（r3 過渡保護）：cfg.wrap 在場即試（部分配置讀面照走——寫面已被配對門
    // 拒，讀面寬容＝舊 blob 永遠可解的承載面）。
    if (!cfg.wrap) return null;
    const legacyKek = await deriveRecLegacyKek(cfg, recToken, identity);
    return await openNoteKey(wrapped, legacyKek, 'notekey', cfg.wrap);
  } catch {
    return null;
  }
}

/** 舊契約派生本體（v0.2.0 批卡⑤修正輪：legacy 派生全案單一本體）：PBKDF2(recToken,
 *  salt = recSaltPrefix ‖ identity)——永不變（r3 承諾面：配置形正確時既有 wrappedRec
 *  blob 逐位可解）。寫面未配置世代與讀面回落同源呼叫本體；deriveRecKek 改 HKDF 專責
 *  （修正輪 C2 收口：HKDF 派生禁借 cfg.wrap 前綴面，派生源不再雙模）。 */
async function deriveRecLegacyKek(cfg: NoteCryptoConfig, recToken: string, identity: string): Promise<CryptoKey> {
  return deriveKek(recToken, new TextEncoder().encode(cfg.recSaltPrefix + identity));
}

/**
 * 綁定請求的金鑰包裹三件套（bind 用）+ recovery_token_hash。
 * 兩段 600k PBKDF2 相互獨立（pass 鹽隨機、rec 鹽=recSaltPrefix‖identity 定值）＝並行
 *（t_7361b68c 目標 1：node 實測 133-152ms→68-84ms，與閘執行帳同源——round 2 MINOR-2 對齊）。
 * AES-GCM derive 佔 600k 迴圈 99%，兩段 wrapped 各自隨機 iv（pass 段另隨機鹽 16B；rec 腿
 * KEK 鹽定值、回傳 salt 來自 pass 腿 w1——round 2 MINOR-2 措辭修正）——逐位等值帳由
 * 「兩段各自與 wrapNoteKey 直呼相等」承載。
 */
export async function buildBindPayload(
  cfg: NoteCryptoConfig,
  noteKey: CryptoKey,
  passphrase: string,
  recToken: string,
  identity: string,
): Promise<{ wrapped: string; salt: string; wrappedRec: string; recTokenHash: string }> {
  const [w1, wrappedRec] = await Promise.all([
    wrapNoteKey(cfg, noteKey, passphrase),
    wrapNoteKeyWithRecToken(cfg, noteKey, recToken, identity),
  ]);
  return {
    wrapped: w1.wrapped,
    salt: w1.salt,
    wrappedRec,
    recTokenHash: await recTokenHash(recToken),
  };
}

// ── 本機包裹（PWA session 期免重打密語） ─────────────────────────────────────

/**
 * 本機包裹（v0.2.0 批卡③）：KEK = deriveGuestKey（identity 派生、passphrase-free——
 * session 期免重打密語的機制原樣），payload 改走專用前綴 cfg.wrapLocal（jr1l.）。
 * 舊實作借用 cfg.wrap（jr1w. passphrase 包裹前綴）寫本機包裹＝「一個前綴一份契約」
 * 的第二違例（wrappedRec 專用前綴歸卡①批面）：本機包裹的 KDF 與 caller 不同、
 * 儲存面（localStorage）不同、生命週期不同（clearLocalWrap 隨時摘除）——共前綴讓
 * 「本機字串是否可能誤入 server 包裹欄」對帳失真。新前綴＝讀舊寫新自癒：
 * loadLocalWrap 先試 jr1l.（本體嚴格面），命中舊形（jr1w.）回落解密後即重包
 * cfg.wrapLocal 回寫（自癒一次），寫入恆 jr1l.。
 */
export async function storeLocalWrap(cfg: NoteCryptoConfig, identity: string, noteKey: CryptoKey): Promise<void> {
  try {
    // 寫入恆專用前綴 cfg.wrapLocal（jr1l.；未配置＝無寫入退場，讀取面照走舊形回落——
    // 行為不變態）。單一真相：loadLocalWrap 自癒腿經本函式回寫（前綴契約不二寫）。
    if (!cfg.wrapLocal) return;
    const guest = await deriveGuestKey(cfg, identity);
    const wrapped = await sealNoteKey(cfg.wrapLocal, noteKey, guest, 'notekey-local');
    cfg.store.set(cfg.store.noteKeyWrap(identity), wrapped);
  } catch { /* private mode：不阻擋主流程 */ }
}

async function loadLocalWrap(cfg: NoteCryptoConfig, identity: string): Promise<CryptoKey | null> {
  try {
    const stored = cfg.store.get(cfg.store.noteKeyWrap(identity));
    if (!stored) return null;
    const guest = await deriveGuestKey(cfg, identity);
    // 次序契約：新形必先於舊形試——新形 blob 在舊前綴面恆拒（family isolation）；先新後舊
    // 仍是要件（新形命中即不跑舊解包），但兩前綴互斥 startsWith 下單一三元只有一腿成立，
    // 實際次序不可觀察。
    const fresh = cfg.wrapLocal
      ? await openNoteKey(stored, guest, 'notekey-local', cfg.wrapLocal) // 本體嚴格面（92B＋rawHex hex 形）
      : null;
    if (fresh) return fresh;
    const legacy = cfg.wrap
      ? await openNoteKey(stored, guest, 'notekey-local', cfg.wrap)
      : null;
    if (legacy) {
      await storeLocalWrap(cfg, identity, legacy);
      return legacy;
    }
    return null;
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
  /** 當前身份字串（guest 派生與本機包裹的命名空間，如 account_id）。 */
  current(): string;
}

/** 加密一則：綁定時代持有 noteKey → cipherBound；否則 guest key → cipherGuest
 *  （guest 前綴選配：未配置＝ERR_GUEST_NOT_CONFIGURED，bound 路徑不受牽連）。
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
  if (!cfg.cipherGuest) throw new Error('ERR_GUEST_NOT_CONFIGURED'); // guest 路徑選配：未配置即拒（bound 路徑不受牽連）
  // 空 identity 拒絕（t_7710c766 目標 3）：K_u = SHA-256(prefix ‖ '') 仍可派生（sha256 不拋），
  // 靜默產出「空帳號金鑰」＝可解同樣空 identity 的任何 guest 密文（對稱面誤配）。fail-closed。
  const identity = idp.current();
  if (!identity) throw new Error('ERR_NO_IDENTITY');
  const guest = await deriveGuestKey(cfg, identity);
  return cfg.cipherGuest + await encryptWithKey(guest, plaintext, aad);
}

/** 解密一則：按前綴選鑰匙；無前綴 = 舊版明文（相容層）原樣返回（guest 前綴未配置時
 *  不明字串一律 null＝guest 家族整面拒絕，跨前綴鐵律不降級）；失敗回 null。 */
export async function decryptNote(
  cfg: NoteCryptoConfig,
  held: HeldKey,
  cipher: string,
  aad: string,
  idp: IdentityProvider,
): Promise<string | null> {
  try {
    // guest 前綴正規化（follow-up ②，t_44239f5f）：畸形配置 ''（空字串）會讓
    // startsWith('') 恆真＝bound 列誤導 guest 分支回 null（解密面整列滅失）。
    // falsy 一律收斂為 undefined，與加密面「未配置即拒」truthiness 對稱。
    const guestPrefix = cfg.cipherGuest || undefined;
    const isGuest = guestPrefix !== undefined && cipher.startsWith(guestPrefix);
    const isBound = cipher.startsWith(cfg.cipherBound);
    if (!isGuest && !isBound) {
      // 舊版明文（相容層）原樣返回；guest 前綴未配置＝guest 家族整面拒絕（不明字串
      // 一律 null——跨前綴鐵律「回 null 不降級」，避免他家族殘列被當明文顯示）。
      return guestPrefix === undefined ? null : cipher;
    }
    if (isGuest) {
      // 空 identity 拒絕（t_7710c766 目標 3，對稱面）：guest 密文在 identity 缺席時必 null
      //（K_u 仍可派生但「空帳號金鑰」不是該密文作者的 intent；誤配下兩態皆 fail-closed）。
      const identity = idp.current();
      if (!identity) return null;
      const guest = await deriveGuestKey(cfg, identity);
      return await decryptWithKey(guest, unb64(cipher.slice(guestPrefix!.length)), aad);
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