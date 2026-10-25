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
 *
 * ⚠️ PIN 形包裹不入 ring（M-D 鐵）：KeyEntry 僅 passphrase 形（wrappedForms 含
 * wrapped/salt/wrappedRec?）——jr1p./jr2p. 只以獨立本機 LS key 存在（§5.1 雙包裹動線、§7.1/§7.3）。
 * ⚠️ ring entry 的包裹面恆為該 entry 鑰自包（明文禁反向捷徑：新鑰不得以
 *「legacy 包存 server ring」取得——J1/J4 止血失效，§5.1）。
 * ⚠️ ring 是 index 不是秘密：kid/前綴/包裹字面皆非秘密（安全靠 GCM＋KDF，不靠隱匿）。
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

/** 取 entry；缺席＝null（呼叫端 fail-closed——解鑰路由「缺席＝null，不盲試」§3.2）。 */
export function keyRingGet(ring: KeyRing, kid: string): KeyEntry | null {
  return ring.entries[kid] ?? null;
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
    return { activeKid: kid, entries };
  }
  if (Object.keys(entries).length >= KEYRING_MAX_ENTRIES) {
    throw new Error('ERR_RING_FULL');
  }
  entries[kid] = { wrappedForms: { ...wrappedForms } };
  return { activeKid: kid, entries };
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
  return { activeKid: ring.activeKid, entries };
}

/** 退場 kid 集（ring 內非 active 位；server 拒收面參數化輸入，§4.2 MINOR-6）。 */
export function keyRingRetiredKids(ring: KeyRing): string[] {
  return Object.keys(ring.entries).filter(k => k !== ring.activeKid).sort();
}

/** ring 序列化（server blob 形）：JSON 定長序（activeKid＋entries 按 key 排序）→ base64。
 *  定長序＝同 ring 恆同字面（冪等覆寫「同值」面；server 端字面覆寫零漂移）。 */
export function serializeKeyRing(ring: KeyRing): string {
  const stable = {
    activeKid: ring.activeKid,
    entries: Object.fromEntries(Object.keys(ring.entries).sort().map(k => [k, ring.entries[k]])),
  };
  const json = JSON.stringify(stable);
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
 *  active 位缺席＝ring 腐敗，禁靜默降級）。 */
export function parseKeyRing(b64: string): KeyRing | null {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const obj = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (typeof obj !== 'object' || obj === null) return null;
    const o = obj as { activeKid?: unknown; entries?: unknown };
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
    return { activeKid: o.activeKid, entries: out };
  } catch {
    return null;
  }
}
