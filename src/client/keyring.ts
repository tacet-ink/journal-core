/**
 * keyring.ts — 主鑰輪替金鑰環原語族（rotateNoteKey 設計 §3；docs/rotation-design.md）。
 *
 * 定位：ring 是「過渡期雙鑰併存」的 client 資料模型——server 端存 opaque blob
 *（client 序列化 ring JSON 的 base64，server 不解析金鑰/密文）＋kid/stage 明文欄
 *（kid 非秘密 §3.1；R6 裁定）。本模組承載 client 側 ring 的形狀、上限、冪等面：
 * - kid 契約（§3.1）＝note-crypto.ts 單一真相（generateKeyId/isValidKid——本檔 re-export，
 *   不設第二份 kid 形檢）；
 * - ring 兩 entry 恆（active＋至多 1 個待退場）：超限 `ERR_RING_FULL`（先退場再加，
 *   輪替是串行動作、並行輪替禁）；
 * - 現行主鑰（綁定時產生、無 kid）佔保留位 `kid='legacy'`；
 * - 序列化：`serializeKeyRing` → base64(JSON)（server blob 形，定長序＝同 ring 恆同字面）；
 *   `parseKeyRing` 任何畸形回 null 不拋（fail-closed——ring 是解鑰路徑索引，
 *   畸形 ring 不得靜默降級成假解鑰面）。
 * - 帶內版本化（rotation-design §12）：0.7.0（外審 2026-11-07 #3 ring 回滾面）——`RingMacConfig`
 *   選配 v2 形（未配置＝v1 形 byte-identical；配置＝v1 兩欄原樣＋頂層 `epoch`/`mac`：client 側
 *   HMAC＋單調 epoch，server 仍是 opaque blob 搬運者）；0.8.0（外審 2026-11-10 N1/N2）——v2 面擴：
 *   `accountId`（MAC 輸入帳號域）＋`mk` 尾欄（macKey 雙包承載、受 MAC 覆蓋）＋`requireMac`
 *   （legacy face 恆拒選配）。blob 是 client 自描述 JSON，無 server 前綴面＝版本化落在 blob 內
 *   結構欄位（非新前綴）。
 *
 * ⚠️ PIN 形包裹不入 ring（M-D 鐵）：KeyEntry 僅 passphrase 形（wrappedForms 含
 * wrapped/salt/wrappedRec?）——jr1p./jr2p. 只以獨立本機 LS key 存在（§5.1 雙包裹動線、§7.1/§7.3）。
 * ⚠️ ring entry 的包裹面恆為該 entry 鑰自包（明文禁反向捷徑：新鑰不得以
 *「legacy 包存 server ring」取得——J1/J4 止血失效，§5.1）。
 * ⚠️ ring 是 index 不是秘密：kid/前綴/包裹字面皆非秘密（安全靠 GCM＋KDF，不靠隱匿）。
 * ⚠️ ring MAC 的 key（0.8.0 起）：macKey 恆 32B `crypto.getRandomValues`（`generateRingMacKey`
 *   單一真相；禁從 noteKey/密語派生）；本體由呼叫端本地持有＝**可共享**——密語 KEK＋復原 KEK
 *   雙包承載（`RingMacConfig.macKeyWrapped`，WrappedForms 同構）內嵌 blob `mk` 欄隨 server 儲存、
 *   受 MAC 覆蓋＝server 零知識不變（server 見密文）；第二裝置由 `mk` 欄解包（`keyRingWrappedMacKey`
 *   → 呼叫端既有包裹族 unwrap → `ringMacKeyHexOf`）完成 MAC 驗證（寫出即全裝置可驗）。
 *   MAC 只證「blob 出自持 key 的 client」，**不證新鮮度**——回推舊合法 blob 由單調 epoch
 *  （變換即推進＋呼叫端高水 epoch+mac 紀錄 `keyRingMeetsHighWater`）承載；本機紀錄缺席
 *  （新裝置）＝首見即信（§12 殘餘界線）。
 *
 * 與「held map」的分工（§5.1）：ring（本模組）＝**持久化**面（server blob＋LS 鏡像，
 * 存包裹字面＋salt）；held map（`Record<kid, CryptoKey>`）＝**運行期**面（ring 兩 entry
 * 各解一次包裹後載入的 kid 對址鑰表）。decrypt 路由（note-crypto.ts decryptNote2 族）
 * 消費的是 held map，非本模組的 KeyRing——本模組不持 CryptoKey（ring 只存包裹）。
 */

import { generateKeyId, isValidKid } from './note-crypto.ts';

export { generateKeyId, isValidKid };

/** kid 保留位：綁定時主鑰（無 kid 標記、`jr1b.` 密文世代）在 ring 中的編址。 */
export const KEYRING_LEGACY_KID = 'legacy';

/** 8 位小寫 hex kid 形（[0-9a-f]{8}；§3.1）。ring 內部形檢用（與 note-crypto 同字面）。 */
const KID_RE = /^[0-9a-f]{8}$/;

/**
 * 包裹面（§3.3 KeyEntry.wrappedForms）：與舊鑰同款全包裹面（§4.2），至少含——
 * `wrapped`（passphrase 形包裹前綴，如 jr4w./jr4d.，＋salt）／`salt`（16B hex）／
 * `wrappedRec?`（復原套件包裹，有套件時）。PIN 形**不入**此結構（M-D）。
 */
export interface WrappedForms {
  /** passphrase 形包裹（該 entry 鑰自包）：前綴由帳戶現行世代決定，server 零知識只驗 b64 形。 */
  wrapped: string;
  /** 包裹 salt（16B hex；users.salt 同形）。 */
  salt: string;
  /** 復原套件包裹（有套件時；R9 重發面＝finish 時以新/同 recToken 重包）。 */
  wrappedRec?: string;
}

export interface KeyEntry {
  /** 該 entry 鑰的包裹面（§3.3：`wrappedForms` 巢狀）。 */
  wrappedForms: WrappedForms;
}

export interface KeyRing {
  /** 'legacy'（初態）或 8 位 hex kid。 */
  activeKid: string;
  /** kid → entry；kid ∈ 'legacy' ∪ [0-9a-f]{8}；恆 ≤2 entries。 */
  entries: Record<string, KeyEntry>;
  /** 單調 epoch（0.7.0；安全非負整數）：v2 blob 必帶且 **≥ 1**（`ep<epoch>:` 入 MAC 輸入；
   *  floor＝配置態寫/讀面 epoch 缺席或 <1 恆拋/null——「epoch ≥ 1 ⇔ MAC 已驗」不變式）；
   *  v1 blob 不寫不讀（legacy face parse 恆回 epoch=0）。變換即推進（0.8.0 N2）：帶 epoch ring 的
   *  addEntry/retire 自動 +1；`keyRingBumpEpoch` 保留相容（顯式 +1）。 */
  epoch?: number;
  /** blob mac hex64（0.8.0）：parseKeyRing v2 成功面帶回——呼叫端高水紀錄 epoch+mac 同存承載；
   *  serialize 恆重算、本欄不消（禁重放舊簽）。 */
  mac?: string;
}

/**
 * ring MAC 配置（0.7.0 選配律：未配置＝v1 形 byte-identical，兄弟 fork 零影響）。
 * MAC 鑰＝HKDF-SHA256(ikm=macKey 32B, salt=∅, info=`macAad`)→HMAC-SHA256；MAC 輸入＝
 * `ep<epoch>:<accountId>:<canonical>`（0.8.0 起帶帳號域；canonical＝v1 兩欄定長序 JSON、`mk` 在場時附
 * mk 嚴格三欄子集）。macKey 本體＝`generateRingMacKey()`（32B getRandomValues → hex64），以
 * serialize/parse 第三參傳入；不以明文入 blob——僅以 `macKeyWrapped` 雙包密文形走 `mk` 欄（0.8.0）。
 */
export interface RingMacConfig {
  /** ring MAC 的 AAD 域（HKDF info 混域；非空）。server 不解析 blob——字串由 host app 配置
   *  （如 `'tacet-keyring-mac'`）；同 key 異域＝異 MAC 鑰（fork 間域分離）。 */
  macAad: string;
  /** 帳號域（0.8.0）：MAC 輸入必帶——`ep<epoch>:<accountId>:<canonical>`；可共享 macKey 後
   *  server 端對調兩帳 ring 面收口（同 key 異帳恆異 MAC）。形：非空字串、禁 `':'`、≤256 字元；
   *  違例＝serialize 拋 ERR_RING_MAC_ACC_BAD／parse 經 MAC 計算路徑 throw→null。 */
  accountId: string;
  /** legacy blob 恆拒（0.8.0 選配）：無 mac 欄 blob → parse null（殲 K1e 剝欄回滾面）。未設/false
   *  ＝0.7.0 行為（legacy 照讀 epoch 0）。開啟時機＝消費端遷移完成裁定（權不在本模組）。 */
  requireMac?: boolean;
  /** macKey 包裹面（0.8.0；WrappedForms 同構——密語 KEK 包裹＋復原 KEK 包裹雙包慣例）：serialize
   *  時內嵌 blob 頂層 `mk` 欄（受 MAC 覆蓋、隨 blob 上 server＝server 零知識）；parse 不消費本欄
   *  （macKey 由呼叫端攜入——本地 key 或 `keyRingWrappedMacKey` 讀 blob mk 欄後經既有包裹族解包）。 */
  macKeyWrapped?: WrappedForms;
}

/** ring 上限（§3.3）：active＋至多 1 個待退場。 */
export const KEYRING_MAX_ENTRIES = 2;

/** ring 初值（新綁定／ring 未輪替）：activeKid='legacy'＋單 entry（無 kid 的 legacy 位）。
 *  本函式只在「ring 從零建立」面用（client LS 鏡像初始化）——server 側初值＝欄 NULL。 */
export function initKeyRing(wrapped: string, salt: string, wrappedRec?: string): KeyRing {
  const wf: WrappedForms = { wrapped, salt };
  if (wrappedRec) wf.wrappedRec = wrappedRec;
  return { activeKid: KEYRING_LEGACY_KID, entries: { [KEYRING_LEGACY_KID]: { wrappedForms: wf } } };
}

/** 取 entry；缺席＝null（呼叫端 fail-closed——解鑰路由「缺席＝null，不盲試」§3.2）。
 *  runtime proto-pollution 面（0.5.3 J4）：取值走 `Object.hasOwn`——kid='__proto__'／'constructor'
 *  等原型鏈鍵不回 entry（舊形 `?? null` 會回 Object.prototype／函式物件）。序列化入口
 *  `parseKeyRing` 走 JSON.parse 產純 object 且 kid 形檢已拒非 legacy/8-hex 鍵，本面只防 runtime
 *  以非 ring 自有鍵查表的攻擊面；自有鍵回值零變。 */
export function keyRingGet(ring: KeyRing, kid: string): KeyEntry | null {
  return Object.hasOwn(ring.entries, kid) ? ring.entries[kid] : null;
}

/** ring 是否已輪替（activeKid 為 8 位 hex）——決定寫入面走 `jr2b.<kid>.` 或裸 `jr1b.`（§3.2）。 */
export function keyRingIsRotated(ring: KeyRing): boolean {
  return isValidKid(ring.activeKid);
}

/**
 * 輪替階段 A（rotate_start 後 client 側 ring 形）：新 kid entry 加入、active 切換、legacy 保留。
 * 冪等（§4.2 階段 A）：同 kid 重發＝同值覆寫（同 input 恆同輸出，無副作用）。
 * 超限（已有 2 entry 且新 kid 缺席）＝throw `ERR_RING_FULL`（server 側同形 `ERR_ROTATION_IN_PROGRESS`）。
 * @throws ERR_KID_BAD（kid 形非 8 位 hex）/ ERR_RING_FULL
 *   （ring 滿＋新 kid 缺席——正常動線是「先退場舊鑰再加新鑰」，未退場即加＝並行輪替/漂移態，fail-closed）
 */
export function keyRingAddEntry(ring: KeyRing, kid: string, wrappedForms: WrappedForms): KeyRing {
  if (!isValidKid(kid)) throw new Error('ERR_KID_BAD');
  const entries = { ...ring.entries };
  const existing = entries[kid];
  if (existing) {
    // 同 kid 在場＝冪等覆寫（同值覆寫面）：覆寫同址、active 維持/切換到本 kid。
    entries[kid] = { wrappedForms: { ...wrappedForms } };
    return withEpochOf(ring, { activeKid: kid, entries });
  }
  if (Object.keys(entries).length >= KEYRING_MAX_ENTRIES) {
    throw new Error('ERR_RING_FULL');
  }
  entries[kid] = { wrappedForms: { ...wrappedForms } };
  return withEpochOf(ring, { activeKid: kid, entries });
}

/**
 * 輪替階段 B（rotate_finish）：退場指定 entry（首輪＝legacy）、ring 收斂。
 * 冪等：kid 已缺席＝原样回傳（finish 重發零副作用）。
 * 多輪參數化：退場 kid 集＝ring 內非 active 位（形＝`jr2?.<退場kid集>.` 拒收面對齊 §4.2）。
 * @throws ERR_KID_BAD（kid 形非 8 位 hex）/ ERR_RING_EMPTY（退場後無 entry——正常動線不觸發）
 */
export function keyRingRetire(ring: KeyRing, kid: string): KeyRing {
  if (kid !== KEYRING_LEGACY_KID && !isValidKid(kid)) throw new Error('ERR_KID_BAD');
  if (!ring.entries[kid]) return ring; // 冪等：已缺席＝原样（finish 重發零副作用）
  const entries = { ...ring.entries };
  delete entries[kid];
  if (Object.keys(entries).length === 0) throw new Error('ERR_RING_EMPTY');
  return withEpochOf(ring, { activeKid: ring.activeKid, entries });
}

/** 退場 kid 集（ring 內非 active 位；server 拒收面參數化輸入，§4.2 MINOR-6）。 */
export function keyRingRetiredKids(ring: KeyRing): string[] {
  return Object.keys(ring.entries).filter(k => k !== ring.activeKid).sort();
}

/** epoch 形（安全非負整數）——serialize 寫面／parse 讀面／bump 正規化共用判準。 */
function isRingEpoch(x: unknown): x is number {
  return Number.isSafeInteger(x) && (x as number) >= 0;
}

/** ring 變換攜帶 epoch：帶 epoch ring 變換即推進（0.8.0 N2——addEntry/retire 任一變換自動 +1，
 *  serialize 恆可出恆推進後 epoch——「同 epoch 改寫」面收口）；v1 形（epoch 缺席）零漂移不讀
 *  （0.6.x byte-identical 契約不變）。冪等已缺席面（retire 原样返回）不經本函式＝零推進。 */
function withEpochOf(src: KeyRing, out: KeyRing): KeyRing {
  if (src.epoch === undefined) return out; // v1 形零漂移（epoch 缺席變換後仍無 epoch 鍵）
  out.epoch = (isRingEpoch(src.epoch) ? src.epoch : 0) + 1; // 變換即推進（0.8.0 N2）：K2a/K2c 同 epoch serialize 殲；keyRingBumpEpoch 顯式保留相容
  return out;
}

/** epoch +1（純函式；禁 throw）：缺席／非法 epoch（非安全非負整數）視 0。activeKid/entries 原值帶出。
 *  0.8.0 起變換即推進——本原語保留相容：v1 緣起 ring（epoch 缺席）首配置態首寫仍以本函式遞增；
 *  v2 緣起 ring 變換恆自推進、顯式 bump 為冗餘正確操作（多推進只進帳——單調面：client 本機記錄最高
 *  已見 epoch＋mac，拒低版／同 epoch 異 mac，見 `keyRingMeetsHighWater`）。 */
export function keyRingBumpEpoch(ring: KeyRing): KeyRing {
  const cur = isRingEpoch(ring.epoch) ? ring.epoch : 0;
  return { activeKid: ring.activeKid, entries: ring.entries, epoch: cur + 1 };
}

/** v1 定長序物件（activeKid＋entries 按 key 排序）：其 JSON＝v1 blob 本體＝v2 MAC 輸入的 canonical 部分。
 *  serialize（ring）與 parse（blob 原 JSON 的 activeKid/entries）共用本 helper＝同字面重組。 */
function stableRing(activeKid: unknown, entries: Record<string, unknown>): { activeKid: unknown; entries: Record<string, unknown> } {
  return {
    activeKid,
    entries: Object.fromEntries(Object.keys(entries).sort().map(k => [k, entries[k]])),
  };
}

const MAC_KEY_RE = /^[0-9a-f]{64}$/;

/** accountId 形（0.8.0）：非空字串、禁 ':'（`ep<epoch>:<accountId>:<canonical>` 分隔保留位）、≤256。 */
function isRingAccountId(x: unknown): x is string {
  return typeof x === 'string' && x.length > 0 && x.length <= 256 && !x.includes(':');
}

function wrapBad(): never { throw new Error('ERR_RING_MAC_KEY_WRAP_BAD'); }

/** macKey 包裹面形檢＋嚴格三欄子集重建（0.8.0）：{wrapped, salt, wrappedRec?} 同 WrappedForms；
 *  形廢＝拋 ERR_RING_MAC_KEY_WRAP_BAD（serialize 面）；parse 面由呼叫端 catch→null。
 *  子集重建＝serialize 內嵌與 parse 重建共用同一 canonical（額外鍵剝除——MAC 覆蓋面零漂移）。 */
function macKeyWrapChecked(v: unknown): WrappedForms {
  const o = v as Record<string, unknown> | null;
  if (typeof o !== 'object' || o === null || Array.isArray(o)) wrapBad();
  const wrapped = o.wrapped;
  const salt = o.salt;
  if (typeof wrapped !== 'string' || wrapped === '') wrapBad();
  if (typeof salt !== 'string' || salt === '') wrapBad();
  const forms: WrappedForms = { wrapped, salt };
  if (o.wrappedRec !== undefined) {
    if (typeof o.wrappedRec !== 'string') wrapBad();
    forms.wrappedRec = o.wrappedRec;
  }
  return forms;
}

/** ring MAC（hex64）：kek＝HKDF-SHA256(ikm=macKey 32B, salt=∅, info=macAad)→HMAC-SHA256(kek, `ep<epoch>:<accountId>:<canonical>`)
 *  （0.8.0 起 MAC 輸入帶帳號域——同 key 異帳恆異 MAC）。
 *  只用 crypto.subtle（HKDF/HMAC；瀏覽器/Workers/node 同形——禁 node:crypto）。
 *  @throws ERR_RING_MAC_AAD_BAD（macAad 非字串／空）／ERR_RING_MAC_ACC_BAD（accountId 形廢）／
 *    ERR_RING_MAC_KEY_BAD（macKey 非 64 位小寫 hex） */
async function ringMacHex(macCfg: RingMacConfig, macKeyHex: string | undefined, epoch: number, canonical: string): Promise<string> {
  if (typeof macCfg.macAad !== 'string' || macCfg.macAad === '') throw new Error('ERR_RING_MAC_AAD_BAD');
  if (!isRingAccountId(macCfg.accountId)) throw new Error('ERR_RING_MAC_ACC_BAD'); // 帳號域形檢（0.8.0——MAC 輸入必帶帳號 ID，N1 修法 4）
  if (typeof macKeyHex !== 'string' || !MAC_KEY_RE.test(macKeyHex)) throw new Error('ERR_RING_MAC_KEY_BAD');
  const raw = new Uint8Array(32);
  for (let i = 0; i < 32; i++) raw[i] = parseInt(macKeyHex.slice(i * 2, i * 2 + 2), 16);
  const te = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', raw as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0) as BufferSource, info: te.encode(macCfg.macAad) as BufferSource },
    base,
    256,
  );
  const kek = await crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', kek, te.encode('ep' + epoch + ':' + macCfg.accountId + ':' + canonical) as BufferSource)); // 帳號域入 MAC 輸入（0.8.0——同 key 異帳恆異 MAC，server 對調兩帳 ring 面收口）
  return Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** MAC 比對（常數時間形——禁 `===` 直咬 hex，時序旁路面）：以期望值全長逐位 XOR fold，
 *  長度差先併入 diff（不等長也走完整 fold、不提前返回）；越界位 charCodeAt＝NaN→按位運算視 0。 */
function ringMacEqual(got: string, expected: string): boolean {
  let diff = got.length ^ expected.length;
  for (let i = 0; i < expected.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/** b64 → bytes（serializeKeyRing 分塊 b64 的逆操作；parseKeyRing／keyRingWrappedMacKey 共用）。
 *  非法 b64＝atob 拋——呼叫端 catch→null。 */
function unb64Ring(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** ring 序列化（server blob 形）：JSON 定長序（activeKid＋entries 按 key 排序）→ base64。
 *  定長序＝同 ring 恆同字面（冪等覆寫「同值」面；server 端字面覆寫零漂移）。
 *  - 未配置 `macCfg`＝v1 形 **byte-identical**（0.6.x 現行字面；`ring.epoch`／`macKeyHex` 不讀）。
 *  - 配置＝v2 形：v1 兩欄原樣＋頂層 `epoch`（安全非負整數且 **≥ 1**——缺席/<1 恆拋）＋`mac`
 *    （hex64，見 `ringMacHex`）＋`macCfg.macKeyWrapped` 提供時尾欄 `mk`（macKey 雙包面，嚴格三欄子集；
 *    未提供＝0.7.0 四欄形）。MAC 輸入＝`ep<epoch>:<accountId>:<canonical>`（canonical＝定長序 v1 兩欄、
 *    mk 在場時附 mk 子集欄＝MAC 覆蓋 mk——包裹面竄改恆攔）；HMAC 確定性＝同 ring/key/epoch/帳域/mk
 *    恆同字面（定長序契約延伸）。`macKeyHex` 不入輸出；`ring.mac` 不消（恆重算）。
 *  - epoch floor：v1 緣起（epoch 缺席）首配置態 serialize 恆拋（ERR_RING_EPOCH_BAD——首寫前顯式
 *    `keyRingBumpEpoch`）；v2 緣起（epoch 帶位）serialize 恆可出恆帶推進後 epoch——變換即推進
 *    （0.8.0 N2），`keyRingBumpEpoch` 為相容保留的顯式遞增。
 *  @throws ERR_RING_EPOCH_BAD（配置態 epoch 非安全非負整數或缺席/<1——floor 不變式「epoch ≥ 1 ⇔
 *    MAC 已驗」；自寫不可讀 blob 禁出廠）／ERR_RING_MAC_KEY_BAD／ERR_RING_MAC_AAD_BAD／
 *    ERR_RING_MAC_ACC_BAD（配置態 key/域/帳域畸形）／ERR_RING_MAC_KEY_WRAP_BAD（macKeyWrapped 形廢） */
export async function serializeKeyRing(ring: KeyRing, macCfg?: RingMacConfig, macKeyHex?: string): Promise<string> {
  const stable = stableRing(ring.activeKid, ring.entries);
  const canonical = JSON.stringify(stable);
  let json = canonical;
  if (macCfg) {
    const epoch = ring.epoch;
    if (!isRingEpoch(epoch) || epoch < 1) throw new Error('ERR_RING_EPOCH_BAD'); // epoch floor（r2 MAJOR-1：配置態 epoch 缺席/<1 恆拋——「epoch ≥ 1 ⇔ MAC 已驗」不變式，遞增只經 keyRingBumpEpoch 禁靜默代值）
    let mkObj: WrappedForms | undefined;
    if (macCfg.macKeyWrapped !== undefined) mkObj = macKeyWrapChecked(macCfg.macKeyWrapped); // mk 欄形檢（寫面 fail-closed——自寫不可讀 blob 禁出廠）
    const mac = await ringMacHex(macCfg, macKeyHex, epoch, mkObj ? JSON.stringify({ ...stable, mk: mkObj }) : canonical);
    json = JSON.stringify(mkObj ? { ...stable, epoch, mac, mk: mkObj } : { ...stable, epoch, mac }); // v2：v1 兩欄逐字在前、epoch/mac 恆位、mk 尾欄（v1 reader 照 parse、欄位不審）
  }
  const bytes = new TextEncoder().encode(json);
  // b64（core 同式分塊——browsers/node 雙端）
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192) as unknown as number[]);
  }
  return btoa(binary);
}

/** ring 反序列化（client LS 鏡像／server blob 回讀）：任何畸形回 null 不拋（fail-closed）。
 *  形狀門（§3.3）：activeKid ∈ 'legacy' ∪ [0-9a-f]{8}；entries 1..2；每 entry 為
 *  `{ wrappedForms: { wrapped, salt, wrappedRec? } }`——wrapped/salt 非空字串、
 *  wrappedRec 在場必字串；entry key 形檢；activeKid 必在 entries 內（ring 自洽——
 *  active 位缺席＝ring 腐敗，禁靜默降級）。
 *  帶內版本化分派（形狀門之後）：
 *  - 未配置 `macCfg`＝現行行為 byte-identical：mac/epoch/mk 欄**不審不拒**（升級兼容窗——v2 blob 對
 *    未升級 reader 照 parse；拒多餘欄＝鏡像清空事故），回傳無 epoch 鍵。
 *  - 配置＋mac 欄缺席＝legacy（v1）blob：照 parse、epoch=0（mk 欄不審＝升級兼容窗）；
 *    `requireMac:true`（0.8.0）→ null（legacy face 恆拒——K1e 剝欄回滾殲）；epoch 單欄在場（無 mac）
 *    → null（未認證 epoch 禁採信——剝 mac 抬 epoch＝單調面繞道）。
 *  - 配置＋mac 欄在場＝v2 claim：epoch 必在場且安全非負整數且 **≥ 1**（floor——epoch-0 恆 null：
 *    不給「真 v2 epoch-0 blob」與「legacy face 兩欄同摘/replay 舊 v1」indistinguishable 面＝
 *    單調 downgrade/replay 訊號，r2 MAJOR-1）；mac 必字串；`mk` 在場必合形（嚴格三欄子集——形廢
 *    null，MAC 前 fail-closed）；key/域/帳域可用；HMAC 必符（輸入 `ep<epoch>:<accountId>:<canonical>`，
 *    mk 在場入 canonical）——任一不過 → null（聲明了驗證就禁跳過：key 缺≠降級 legacy 讀）。
 *    成功面帶回 `mac`（KeyRing.mac——呼叫端高水紀錄 epoch+mac 同存承載）；mk 欄不消費（macKey 由
 *    呼叫端攜入——裝置 B 以 `keyRingWrappedMacKey` 讀 mk 後經既有包裹族解包）。 */
export async function parseKeyRing(b64: string, macCfg?: RingMacConfig, macKeyHex?: string): Promise<KeyRing | null> {
  try {
    const obj = JSON.parse(new TextDecoder().decode(unb64Ring(b64))) as unknown;
    if (typeof obj !== 'object' || obj === null) return null;
    const o = obj as { activeKid?: unknown; entries?: unknown; epoch?: unknown; mac?: unknown; mk?: unknown };
    if (typeof o.activeKid !== 'string') return null;
    const kidOk = o.activeKid === KEYRING_LEGACY_KID || KID_RE.test(o.activeKid);
    if (!kidOk) return null;
    if (typeof o.entries !== 'object' || o.entries === null || Array.isArray(o.entries)) return null;
    const entries = o.entries as Record<string, unknown>;
    const keys = Object.keys(entries);
    if (keys.length === 0 || keys.length > KEYRING_MAX_ENTRIES) return null;
    const out: Record<string, KeyEntry> = {};
    for (const k of keys) {
      if (k !== KEYRING_LEGACY_KID && !KID_RE.test(k)) return null;
      const e = entries[k] as Record<string, unknown> | null;
      if (typeof e !== 'object' || e === null) return null;
      const wf = e.wrappedForms as Record<string, unknown> | null;
      if (typeof wf !== 'object' || wf === null) return null;
      if (typeof wf.wrapped !== 'string' || wf.wrapped === '') return null;
      if (typeof wf.salt !== 'string' || wf.salt === '') return null;
      const forms: WrappedForms = { wrapped: wf.wrapped, salt: wf.salt };
      if (wf.wrappedRec !== undefined) {
        if (typeof wf.wrappedRec !== 'string') return null;
        forms.wrappedRec = wf.wrappedRec;
      }
      out[k] = { wrappedForms: forms };
    }
    if (!out[o.activeKid]) return null;
    if (!macCfg) return { activeKid: o.activeKid, entries: out };
    if (o.mac === undefined) {
      if (o.epoch !== undefined) return null; // 半 v2 形（epoch 在場、mac 缺席）：未認證 epoch 禁採信
      if (macCfg.requireMac === true) return null; // requireMac（0.8.0）：legacy blob（無 mac 欄）恆拒——K1e 剝欄回滾殲（開啟時機＝消費端遷移完成裁定）
      return { activeKid: o.activeKid, entries: out, epoch: 0 }; // legacy blob：照讀（帶內兼容）
    }
    if (o.epoch === undefined) return null; // v2 形必帶 epoch
    if (!isRingEpoch(o.epoch)) return null; // epoch 形檢（安全非負整數——"3"/[3] 字串化同 `ep3:` 的型別混淆面唯一防線）
    if (o.epoch < 1) return null; // epoch floor（r2 MAJOR-1：v2 面 epoch ≥ 1 ⇔ MAC 已驗——epoch-0 恆 null，與 legacy face（恆 epoch 0）自然可分辨）
    if (typeof o.mac !== 'string') return null;
    let mkForms: WrappedForms | undefined;
    if (o.mk !== undefined) { try { mkForms = macKeyWrapChecked(o.mk); } catch { return null; } } // mk 欄形檢（0.8.0——包裹面形廢恆 null，MAC 前 fail-closed）
    const canonical = mkForms !== undefined
      ? JSON.stringify({ ...stableRing(o.activeKid, entries), mk: mkForms })
      : JSON.stringify(stableRing(o.activeKid, entries)); // 與 serialize 同真相（mk 子集重建＝MAC 覆蓋面零漂移）
    const expected = await ringMacHex(macCfg, macKeyHex, o.epoch, canonical); // key/域/帳域畸形＝拋→null
    if (!ringMacEqual(o.mac, expected)) return null; // MAC 驗證（常數時間形）
    return { activeKid: o.activeKid, entries: out, epoch: o.epoch, mac: o.mac }; // mac 帶回＝高水紀錄承載
  } catch {
    return null;
  }
}

/** macKey 生成（0.8.0 單一真相）：32B crypto.getRandomValues → hex64（MAC_KEY_RE 同形）。
 *  禁從 noteKey/密語派生——輪替前提＝舊鑰可能外流，取得舊鑰者不得能偽造任意 epoch MAC。 */
export function generateRingMacKey(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** ring MAC key 的 CryptoKey→hex64 轉出面（0.8.0）：裝置 B 由 mk 欄解包（既有包裹族 unwrapNoteKey/
 *  unwrapNoteKeyWithRecToken 等回傳 CryptoKey）後轉 hex64 餵 parseKeyRing。32B raw 恆回 hex64；
 *  非 32B／不可 export（non-extractable）→ null（fail-closed 不拋）。 */
export async function ringMacKeyHexOf(key: CryptoKey): Promise<string | null> {
  try {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const hex64 = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
    return raw.byteLength === 32 ? hex64 : null;
  } catch {
    return null;
  }
}

/** blob `mk` 欄讀取（0.8.0 裝置 B 形態）：任何 blob（免 cfg）讀出 macKey 包裹面（嚴格三欄子集形檢）
 *  —macKeyWrapped 缺席／形廢／非合法 b64 JSON → null。本讀取面不驗 MAC：解包所得 key 只在
 *  parseKeyRing MAC 驗證成功時生效（mk 欄受 MAC 覆蓋＝竄改包裹面恆攔）。 */
export function keyRingWrappedMacKey(b64: string): WrappedForms | null {
  try {
    const obj = JSON.parse(new TextDecoder().decode(unb64Ring(b64))) as { mk?: unknown };
    if (obj === null || typeof obj !== 'object' || obj.mk === undefined) return null;
    return macKeyWrapChecked(obj.mk);
  } catch {
    return null;
  }
}

/** 高水紀錄（0.8.0）：epoch＋mac（同存——同 epoch 異 mac＝分叉/改寫訊號）。parseKeyRing v2 成功面
 *  帶回 KeyRing.mac 以承載；v1 face 無 mac 欄（undefined）。 */
export interface RingHighWater {
  epoch: number;
  mac?: string;
}

/** 高水比對 helper（0.8.0 N2）：呼叫端以本機最高已見 {epoch, mac} 對候選 blob 判準——
 *  - incoming null（parse 失敗）→ false（fail-closed）；
 *  - seen null → true（首見即信——§12 殘餘界線：新裝置無本地紀錄＝單調 epoch 本質界線）；
 *  - epoch 較低 → false（回推舊版）；epoch 相同但 mac 不同 → false（同 epoch 改寫/對調面）；
 *  - epoch 形廢（非安全非負整數）→ false；其餘（較高、同 epoch 同 mac 冪等重見）→ true。 */
export function keyRingMeetsHighWater(seen: RingHighWater | null, incoming: RingHighWater | null): boolean {
  if (!incoming || !isRingEpoch(incoming.epoch)) return false;
  if (seen === null) return true; // 首見即信（§12 殘餘界線誠實面——非驗證面）
  if (!isRingEpoch(seen.epoch)) return false; // seen 形廢＝帳面腐敗恆拒（fail-closed）
  if (incoming.epoch < seen.epoch) return false; // 回推舊版＝拒
  if (incoming.epoch === seen.epoch && incoming.mac !== seen.mac) return false; // 同 epoch 異 mac＝分叉/改寫（K2b 殲——高水紀錄需同存 mac）
  return true;
}
