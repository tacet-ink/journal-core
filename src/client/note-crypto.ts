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
  // 值（⑩→[16] 實帳），非缺陷形（NaN 歸零已殲滅＝輸出恆數學等值）；正式輸入面（unwrap/鹽欄）
  // 皆有 ASCII regex 前置守衛攔截，公開原語只保證「正規化後真 hex 恆等值、垃圾恆拒」。
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
 * 全家族單因子包裹（jr1w./jrsw./jr3w./jr3s.）與復原套件（wrappedRec，前綴共用 cfg.wrap）
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
 * 家族嚴格度收口實況（round 1 審查 MINOR-2 校正＋r2 MINOR-1 殘餘校正 t_580f9c54）：
 * 鹽外置 6 點由本體嚴格 92B 終結——note-crypto 四點（unwrapNoteKey＝jr1w／
 * unwrapNoteKeyShare＝jrsw／unwrapNoteKeyWithRecToken＝jr1wRec 同本體／loadLocalWrap）
 * ＋argon2 兩點（unwrapNoteKey3＝jr3w／unwrapNoteKeyShare3＝jr3s；own 92B 檢已隨收口摘除）；
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

/** 復原套件包裹：KEK_rec = PBKDF2(recToken, salt = recSaltPrefix ‖ identity)。 */
async function deriveRecKek(cfg: NoteCryptoConfig, recToken: string, identity: string): Promise<CryptoKey> {
  return deriveKek(recToken, new TextEncoder().encode(cfg.recSaltPrefix + identity));
}

export async function wrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, noteKey: CryptoKey, recToken: string, identity: string): Promise<string> {
  const kek = await deriveRecKek(cfg, recToken, identity);
  return sealNoteKey(cfg.wrap, noteKey, kek, 'notekey');
}

export async function unwrapNoteKeyWithRecToken(cfg: NoteCryptoConfig, wrapped: string, recToken: string, identity: string): Promise<CryptoKey | null> {
  try {
    if (!cfg.wrap) return null;
    const kek = await deriveRecKek(cfg, recToken, identity);
    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap);
  } catch {
    return null;
  }
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

export async function storeLocalWrap(cfg: NoteCryptoConfig, identity: string, noteKey: CryptoKey): Promise<void> {
  try {
    if (!cfg.wrap) throw new Error('ERR_WRAP_NOT_CONFIGURED');
    const guest = await deriveGuestKey(cfg, identity);
    const wrapped = await sealNoteKey(cfg.wrap, noteKey, guest, 'notekey-local');
    cfg.store.set(cfg.store.noteKeyWrap(identity), wrapped);
  } catch { /* private mode：不阻擋主流程 */ }
}

async function loadLocalWrap(cfg: NoteCryptoConfig, identity: string): Promise<CryptoKey | null> {
  try {
    const stored = cfg.store.get(cfg.store.noteKeyWrap(identity));
    if (!stored || !cfg.wrap) return null;
    const guest = await deriveGuestKey(cfg, identity);
    return await openNoteKey(stored, guest, 'notekey-local', cfg.wrap);
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