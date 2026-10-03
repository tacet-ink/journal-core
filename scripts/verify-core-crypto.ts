/**
 * verify-core-crypto.ts — core 抽取的驗證閘（對真模組，禁鏡像——extractable 教訓）。
 * 執行：node --experimental-strip-types scripts/verify-core-crypto.ts
 * 全綠輸出 CORE-CRYPTO-OK；任何失敗 exit 1。
 */

// 對真模組（禁鏡像重寫金鑰邏輯——鏡像驗證抓不到真模組 bug 的生產教訓）
import {
  makeHeldKey,
  PBKDF2_ITERATIONS,
  ph1Of,
  decryptNote,
  encryptNote,
  generateNoteKey,
  generateRecToken,
  storeLocalWrap,
  clearLocalWrap,
  buildBindPayload,
  openNoteKey,
  unwrapNoteKey,
  unwrapNoteKeyWithRecToken,
  wrapNoteKey,
  wrapNoteKeyWithRecToken,
  wrapNoteKeyShare,
  unwrapNoteKeyShare,
  recTokenHash,
  wrapNoteKeyDual,
  unwrapNoteKeyDual,
  normalizePin,
  encryptAttach,
  decryptAttach,
  encryptLocal,
  decryptLocal,
  hexToBytes,
  encryptWithKey,
  decryptWithKey,
} from '../src/client/note-crypto.ts';
import {
  verifyArgonKat,
  wrapNoteKey3,
  unwrapNoteKey3,
  wrapNoteKeyDual3,
  unwrapNoteKeyDual3,
  ARGON_MEMORY_KIB,
  ARGON_ITERATIONS,
  ARGON_PARALLELISM,
  ARGON_TAG_LEN,
  derivePh1Argon,
  PH1_V2_SALT,
  type Argon3Config,
} from '../src/client/argon2.ts';
import { makeKeyStore } from '../src/client/keys.ts';
import type { NoteCryptoConfig } from '../src/client/note-crypto.ts';
import {
  wrapNoteKeyPinLock,
  unwrapNoteKeyPinLock,
  type PinLockConfig,
} from '../src/client/pinlock.ts';
import {
  makeInboundCipher,
  isCipherFor,
  validWrappedKey,
  validHash64,
  validSalt,
  pickKeyPackage,
  AUTH_RATE,
  type CipherFormats,
} from '../src/server/auth.ts';
import { checkRate, isRateAllowed, SQL_RATE_BUMP, type RateWindow } from '../src/server/ratelimit.ts';
import { generateSessionToken, timingSafeEq } from '../src/server/hash.ts';

const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text))));
}

// ── 日記應用前綴（jr1 家族）＋ 對照組（sn1 家族，驗證品牌參數化） ──────────────

const store = makeKeyStore({ brand: 'tacet' });

const TACET: NoteCryptoConfig = {
  guestKdfPrefix: 'tacet-note-u1',
  recSaltPrefix: 'tacet-note-rec1:',
  cipherGuest: 'jr1g.',
  cipherBound: 'jr1b.',
  wrap: 'jr1w.',
  store,
};

let passed = 0;
const failures: string[] = [];
async function A(name: string, cond: boolean | Promise<boolean>, detail = ''): Promise<void> {
  const ok = cond instanceof Promise ? await cond : cond;
  if (ok) { passed++; console.log(`  ✓ ${name}`); }
  else { failures.push(name); console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ── 1. 基礎向量 ─────────────────────────────────────────────────────────────

console.log('\n[1] PH1 / PBKDF2 / hash-ladder 基礎');
await A('PH1 = SHA-256(pass) 穩定', (await ph1Of('test-pass-123')) === (await ph1Of('test-pass-123')));
await A('PH1 hex64 格式', /^[0-9a-f]{64}$/.test(await ph1Of('x')));
await A('PBKDF2_ITERATIONS = 600k', PBKDF2_ITERATIONS === 600_000);

// ── 2. roundtrip（guest 時代 + 綁定時代，AAD 由呼叫端） ───────────────────────

console.log('\n[2] roundtrip / AAD 防搬移');
const note = '今天寫了一點東西。';
const identityA = 'acct-aaaaaaaaaaaaaaaa';
const guest = await crypto.subtle.importKey('raw', enc.encode('seed').slice(0), 'PBKDF2', false, ['deriveKey']); // 型別哨兵：guest 非此路徑
void guest;
const held = makeHeldKey();
const cipherGuest = await encryptNote(TACET, held, note, 'noteId:n1', { current: () => identityA });
await A('guest 時代前綴 jr1g.', cipherGuest.startsWith('jr1g.'));
await A('guest roundtrip', (await decryptNote(TACET, held, cipherGuest, 'noteId:n1', { current: () => identityA })) === note);

const noteKey = await generateNoteKey();
held.set(noteKey);
const cipherBound = await encryptNote(TACET, held, note, 'noteId:n1', { current: () => identityA });
await A('綁定時代前綴 jr1b.', cipherBound.startsWith('jr1b.'));
await A('綁定 roundtrip', (await decryptNote(TACET, held, cipherBound, 'noteId:n1', { current: () => identityA })) === note);

// AAD 防搬移：AAD 不符 → null（不拋、不降級成別列內容）
await A('AAD 防搬移：跨 noteId 解密失敗回 null',
  (await decryptNote(TACET, held, cipherBound, 'noteId:n2', { current: () => identityA })) === null);
await A('AAD 防搬移：跨身份 guest 解密失敗回 null',
  (await decryptNote(TACET, held, cipherGuest, 'noteId:n1', { current: () => 'acct-bbbbbbbbbbbbbbbb' })) === null);

// 舊版明文相容層：無前綴 = 原樣返回
await A('舊明文原樣返回', (await decryptNote(TACET, held, '純舊明文', 'x', { current: () => identityA })) === '純舊明文');

// ── 3. 包裹三件套（pass / rec / 本機） ───────────────────────────────────────

console.log('\n[3] 金鑰包裹（passphrase / 復原 / 本機）');
const pass = 'correct-horse-battery-staple-42';
const recToken = generateRecToken();
const { wrapped, salt } = await wrapNoteKey(TACET, noteKey, pass);
const wrappedRec = await (await import('../src/client/note-crypto.ts')).wrapNoteKeyWithRecToken(TACET, noteKey, recToken, identityA);
const recTokenHashValue = await recTokenHash(recToken);
await A('wrapped 前綴 jr1w.', wrapped.startsWith('jr1w.'));
await A('salt = 16B hex', /^[0-9a-f]{32}$/.test(salt));
await A('wrappedRec 前綴 jr1w.', wrappedRec.startsWith('jr1w.'));
await A('recTokenHash hex64', /^[0-9a-f]{64}$/.test(recTokenHashValue));

const unwrapped = await unwrapNoteKey(TACET, wrapped, pass, salt);
await A('pass unwrap 救回 noteKey（同 pass 同 salt）',
  unwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped))) ===
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))));
await A('錯誤 pass unwrap → null', (await unwrapNoteKey(TACET, wrapped, 'wrong-pass', salt)) === null);

const recUnwrapped = await unwrapNoteKeyWithRecToken(TACET, wrappedRec, recToken, identityA);
await A('rec unwrap 救回 noteKey',
  recUnwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', recUnwrapped))) ===
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))));
await A('錯誤 recToken unwrap → null',
  (await unwrapNoteKeyWithRecToken(TACET, wrappedRec, generateRecToken(), identityA)) === null);

// 改密語 O(1)：解開舊包裹 → 新密語重包裹；密文零重加密
const { wrapped: rewrapped, salt: newSalt } = await wrapNoteKey(TACET, noteKey, 'new-pass-99');
await A('改密語：新包裹解得回同 noteKey',
  (await unwrapNoteKey(TACET, rewrapped, 'new-pass-99', newSalt)) !== null &&
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', (await unwrapNoteKey(TACET, rewrapped, 'new-pass-99', newSalt))!))) ===
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))));

// 本機包裹
const localIdentity = 'acct-localwrap-test';
const heldLocal = makeHeldKey();
heldLocal.set(noteKey);
await storeLocalWrap(TACET, localIdentity, noteKey);

// ── 4. extractable 鐵律（2026-09-06 iOS 實機炸點回歸） ────────────────────────

console.log('\n[4] noteKey extractable 鐵律');
const rawNote = crypto.getRandomValues(new Uint8Array(32));
const nonExtractable = await crypto.subtle.importKey('raw', rawNote, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
let threwNotExtractable = false;
try { await crypto.subtle.exportKey('raw', nonExtractable); } catch (e) {
  // 鐵律：錯誤名稱跨引擎不同（iOS Safari = InvalidAccessElement、Node 26 = InvalidAccessError），
  // 斷言「有擲且訊息指明 extractable」，不綁單一瀏覽器錯誤名——對真模組驗證抓的是契約不是品牌。
  const msg = (e as Error).message ?? '';
  threwNotExtractable = /extractable/i.test(msg) || /extractable/i.test((e as Error).name);
}
await A('病徵重現：nonextractable exportKey 拋 not-extractable 類錯誤', threwNotExtractable);
const extractable = await crypto.subtle.importKey('raw', rawNote, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
await A('修法機制：extractable key exportKey 等值 roundtrip',
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', extractable))) === hex(rawNote));
// unwrap 出的 key（全部三路徑）都要能再包裹：與 noteKey 原值比對（非 rawNote——那是本段新建隨機值）
const origRaw = hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
await A('unwrap 出的 noteKey 可再 exportKey（等值 noteKey）',
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped!))) === origRaw);
await A('rec unwrap 出的 noteKey 可再 exportKey（等值 noteKey）',
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', recUnwrapped!))) === origRaw);

// ── 5. 時代隔離：guest 與 bound 前綴互不誤判 ─────────────────────────────────

console.log('\n[5] 時代隔離');
await A('guest cipher 不以 jr1b. 開頭', !cipherGuest.startsWith('jr1b.'));
await A('bound cipher 不以 jr1g. 開頭', !cipherBound.startsWith('jr1g.'));
await A('無 held key 的 bound 解密 → null',
  (await decryptNote(TACET, makeHeldKey(), cipherBound, 'noteId:n1', { current: () => identityA })) === null);

// ── 6. 雙因子合鑰（jr2w.，2026-09-09 PIN 第二因子） ─────────────────────────

console.log('\n[6] 雙因子合鑰 KEK2（jr2w.）');
const TACET2: NoteCryptoConfig = { ...TACET, wrapDual: 'jr2w.', pinSaltPrefix: 'tacet-note-pin1:' };
const passD = 'dual-factor-passphrase-42';
const pinD = '2580ab';
const dual = await wrapNoteKeyDual(TACET2, noteKey, passD, pinD);
await A('wrapped2 前綴 jr2w.', dual.wrapped.startsWith('jr2w.'));
await A('dual salt1 = 16B hex', /^[0-9a-f]{32}$/.test(dual.salt));
const unwrapped2 = await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, pinD, dual.salt);
await A('dual unwrap 等值 noteKey（extractable 再 export）',
  unwrapped2 !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped2))) ===
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))));
await A('錯 PIN → null', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, '999999', dual.salt)) === null);
await A('錯 pass → null', (await unwrapNoteKeyDual(TACET2, dual.wrapped, 'wrong-passphrase', pinD, dual.salt)) === null);
await A('缺 PIN → null', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, '', dual.salt)) === null);
await A('錯 pass 與錯 PIN 回傳同形（皆 null 不拋）',
  (await unwrapNoteKeyDual(TACET2, dual.wrapped, 'wrong', 'bad!!', dual.salt)) === null);
await A('jr1w unwrapNoteKey 拒收 jr2w 字串', (await unwrapNoteKey(TACET2, dual.wrapped, passD, dual.salt)) === null);
await A('dual unwrapNoteKeyDual 拒收 jr1w 字串', (await unwrapNoteKeyDual(TACET2, wrapped, pass, pinD, dual.salt)) === null);
await A('既有 jr1w 包裹不受 dual 並存影響', (await unwrapNoteKey(TACET2, wrapped, pass, salt)) !== null);

// payload 竄改 → 一律 null（自描述完整性：pinSalt/hksalt/iv/ct 任一區）
function unb64(text: string): Uint8Array {
  const bin = atob(text);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
const payload2 = unb64(dual.wrapped.slice('jr2w.'.length));
const tamperedAt = async (idx: number): Promise<boolean> => {
  const copy = payload2.slice();
  copy[idx] ^= 0x01;
  let bin = '';
  for (let i = 0; i < copy.byteLength; i++) bin += String.fromCharCode(copy[i]);
  const tampered = 'jr2w.' + btoa(bin);
  return (await unwrapNoteKeyDual(TACET2, tampered, passD, pinD, dual.salt)) === null;
};
await A('payload 竄改 pinSalt 區 → null', await tamperedAt(3));
await A('payload 竄改 hksalt 區 → null', await tamperedAt(20));
await A('payload 竄改 iv 區 → null', await tamperedAt(36));
await A('payload 竄改 ct 尾 → null', await tamperedAt(payload2.length - 1));

// PIN 正規化（NFKC → trim → lowercase）：wrap/unwrap 同一正規化路徑
await A('PIN 大小寫不敏感', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, '2580AB', dual.salt)) !== null);
await A('PIN 兩端空白容忍', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, ' 2580ab ', dual.salt)) !== null);
await A('PIN 全形 NFKC 等價', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, '２５８０ＡＢ', dual.salt)) !== null);
const dualNorm = await wrapNoteKeyDual(TACET2, noteKey, passD, ' ２５８０Ab ');
await A('wrap 端同一正規化（正規化後等價 unwrap）',
  (await unwrapNoteKeyDual(TACET2, dualNorm.wrapped, passD, '2580ab', dualNorm.salt)) !== null);
await A('normalizePin 契約', normalizePin(' ２５８０Ab ') === '2580ab');
await A('未配置 wrapDual 拒絕 dual 包裹', (await unwrapNoteKeyDual(TACET, dual.wrapped, passD, pinD, '')) === null);

// ── 7. Argon2id 包裹（jr3w./jr3d.，2026-09-14 安全路線第 2 步） ───────────────
//
// 離線 oracle 中和：login 回應的 wrapped+salt 是戰利品，PBKDF2 對 GPU 友善，
// Argon2id 記憶體困難（64MiB）使每猜成本上升 1-2 個數量級。遷移契約 = 成功 unwrap
// 後客戶端靜默 re-wrap，舊前綴照解（下面有並存斷言）。

console.log('\n[7] Argon2id 包裹（jr3w./jr3d.）');
const TACET3: Argon3Config = { wrap3: 'jr3w.', wrapDual3: 'jr3d.', pinSalt3Prefix: 'tacet-note-pin3:' };
await A('RFC 9106 無 secret/ad 標準向量（當前載體正確性）', await verifyArgonKat());
await A('Argon 參數契約 m=64MiB t=3 p=1 tag=32',
  ARGON_MEMORY_KIB === 65536 && ARGON_ITERATIONS === 3 && ARGON_PARALLELISM === 1 && ARGON_TAG_LEN === 32);

const w3 = await wrapNoteKey3(TACET3, noteKey, pass);
await A('wrapped 前綴 jr3w.', w3.wrapped.startsWith('jr3w.'));
await A('jr3w salt = 16B hex', /^[0-9a-f]{32}$/.test(w3.salt));
const unwrapped3 = await unwrapNoteKey3(TACET3, w3.wrapped, pass, w3.salt);
await A('jr3w unwrap 等值 noteKey（extractable 再 export）',
  unwrapped3 !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped3))) === origRaw);
await A('jr3w 錯 pass → null', (await unwrapNoteKey3(TACET3, w3.wrapped, 'wrong-passphrase', w3.salt)) === null);
await A('jr3w 錯 salt → null', (await unwrapNoteKey3(TACET3, w3.wrapped, pass, 'ab'.repeat(16))) === null);
await A('jr3w unwrap 拒收 jr1w 字串', (await unwrapNoteKey3(TACET3, wrapped, pass, salt)) === null);
await A('jr1w unwrapNoteKey 拒收 jr3w 字串', (await unwrapNoteKey(TACET2, w3.wrapped, pass, w3.salt)) === null);
await A('既有 jr1w 包裹照解（遷移契約：舊前綴不解散）', (await unwrapNoteKey(TACET2, wrapped, pass, salt)) !== null);
// jr3w payload 竄改 → GCM 驗證失敗 → null
const payload3 = unb64(w3.wrapped.slice('jr3w.'.length));
const tampered3 = async (idx: number): Promise<boolean> => {
  const copy = payload3.slice();
  copy[idx] ^= 0x01;
  let bin = '';
  for (let i = 0; i < copy.byteLength; i++) bin += String.fromCharCode(copy[i]);
  return (await unwrapNoteKey3(TACET3, 'jr3w.' + btoa(bin), pass, w3.salt)) === null;
};
await A('jr3w payload 竄改 iv 區 → null', await tampered3(3));
await A('jr3w payload 竄改 ct 尾 → null', await tampered3(payload3.length - 1));

// jr3d 雙因子（PIN 第二因子，Argon2id 版）
const dual3 = await wrapNoteKeyDual3(TACET3, noteKey, passD, pinD);
await A('dual3 前綴 jr3d.', dual3.wrapped.startsWith('jr3d.'));
await A('dual3 salt1 = 16B hex', /^[0-9a-f]{32}$/.test(dual3.salt));
const unwrappedD3 = await unwrapNoteKeyDual3(TACET3, dual3.wrapped, passD, pinD, dual3.salt);
await A('dual3 unwrap 等值 noteKey（extractable 再 export）',
  unwrappedD3 !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrappedD3))) === origRaw);
await A('dual3 錯 PIN → null', (await unwrapNoteKeyDual3(TACET3, dual3.wrapped, passD, '999999', dual3.salt)) === null);
await A('dual3 缺 PIN → null', (await unwrapNoteKeyDual3(TACET3, dual3.wrapped, passD, '', dual3.salt)) === null);
await A('dual3 錯 pass → null', (await unwrapNoteKeyDual3(TACET3, dual3.wrapped, 'wrong-passphrase', pinD, dual3.salt)) === null);
await A('dual3 PIN 大小寫不敏感', (await unwrapNoteKeyDual3(TACET3, dual3.wrapped, passD, '2580AB', dual3.salt)) !== null);
await A('dual3 PIN 全形 NFKC 等價', (await unwrapNoteKeyDual3(TACET3, dual3.wrapped, passD, '２５８０ＡＢ', dual3.salt)) !== null);

// 跨家族隔離：jr3d payload 餵 jr2w 路徑、jr2w 餵 jr3d、jr3w 餵 jr1w、單因子交叉，全部 null
// （HKDF info 同名但 KDF bits 不同 → KEK2 值天然互斥；GCM tag 保證不會假成功）
await A('jr3d payload 餵 jr2w 路徑 → null（家族隔離）',
  (await unwrapNoteKeyDual(TACET2, dual3.wrapped, passD, pinD, dual3.salt)) === null);
await A('jr2w payload 餵 jr3d 路徑 → null（家族隔離）',
  (await unwrapNoteKeyDual3(TACET3, dual.wrapped, passD, pinD, dual.salt)) === null);
await A('jr3w unwrap 拒收 jr3d 字串', (await unwrapNoteKey3(TACET3, dual3.wrapped, passD, dual3.salt)) === null);
await A('jr3d unwrap 拒收 jr3w 字串', (await unwrapNoteKeyDual3(TACET3, w3.wrapped, pass, pinD, w3.salt)) === null);

// 未配置拒絕（兄弟 fork 行為不變）
const throwsJr3w = async (): Promise<boolean> => { try { await wrapNoteKey3({}, noteKey, pass); return false; } catch { return true; } };
const throwsJr3d = async (): Promise<boolean> => { try { await wrapNoteKeyDual3({}, noteKey, pass, pinD); return false; } catch { return true; } };
await A('未配置 wrap3 → wrapNoteKey3 拒絕', await throwsJr3w());
await A('未配置 wrapDual3 → wrapNoteKeyDual3 拒絕', await throwsJr3d());
await A('未配置 wrapDual3 → unwrap 拒收 jr3d',
  (await unwrapNoteKeyDual3({ wrap3: 'jr3w.' }, dual3.wrapped, passD, pinD, dual3.salt)) === null);

// ── 8. PH1 v2（登入憑證 Argon2id 派生，2026-09-10 安全路線）──────────────────
//
// 動機（安全路線第 4 步分析）：DB 全洩後 ph2 = sha256(ph1) 是離線爆破讀日記的最後一個
// 快雜湊面——攻擊者拿候選密語重算 sha256(sha256(g)) 對 ph2 命中即 g 就是密語，
// 再以 DB salt1 算 Argon2id(g, salt1) 解 wrapped＝日記全開。ph1 改 Argon2id 派生後
// 每猜成本從 ~ns（SHA-256×2）升到 ~0.1-0.18s CPU＝×10⁴-10⁶。
// 固定域鹽是被迫設計（per-user 鹽會摧毀 PH2 UNIQUE＝幽靈帳號機制基礎）；改參數 = 換鹽尾碼（v2/v3）重遷移。

console.log('\n[8] PH1 v2（登入憑證 Argon2id 派生）');
await A('RFC 9106 KAT 先行（載體正確性，本節所有 Argon 斷言的前提）', await verifyArgonKat());
const ph1v2a = await derivePh1Argon('probe-determinism-pass-42');
await A('ph1v2 確定性（同 pass 兩跑逐位元同）', ph1v2a === (await derivePh1Argon('probe-determinism-pass-42')));
await A('ph1v2 hex64 形（validHash64 可收）', /^[0-9a-f]{64}$/.test(ph1v2a));
// 與 legacy ph1（SHA-256 形）必然不同值＝雙查表兩鍵語意成立
await A('ph1v2 ≠ legacy ph1（SHA-256 形）', ph1v2a !== (await ph1Of('probe-determinism-pass-42')));
// 鹽用途隔離：PH1_V2_SALT 不等於任何包裹鹽前綴（固定鹽專用域，與 jr3w. per-user 隨機鹽分流）
await A('PH1_V2_SALT = "tacet-ph1-v1"（12B 專用域，與包裹鹽前綴無重疊）',
  PH1_V2_SALT === 'tacet-ph1-v1' && !PH1_V2_SALT.startsWith('tacet-note') && !PH1_V2_SALT.startsWith('tacet-pinlock'));
// 不同 pass 零碰撞（抽 50 組，兩兩相異）
{
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) seen.add(await derivePh1Argon(`collision-probe-${i}-random-${crypto.randomUUID()}`));
  await A('不同 pass 零碰撞（50 組兩兩相異）', seen.size === 50, `unique=${seen.size}`);
}
// 參數常數同源（單一碼路：ph1 v2 沿 jr3w. 同一組 Argon 參數常數）
await A('ph1v2 參數與 jr3w. 家族常數同源（m=64MiB t=3 p=1）',
  ARGON_MEMORY_KIB === 65536 && ARGON_ITERATIONS === 3 && ARGON_PARALLELISM === 1 && ARGON_TAG_LEN === 32);
// 錯誤密語 ≠ 正確密語輸出（形狀面 sanity：非恆等映射）
await A('ph1v2 非恆等（pass ≠ 輸出）', ph1v2a !== 'probe-determinism-pass-42');

// ── 9. BIP39 復原套件契約（words↔hex64 轉寫層；線上契約 recToken hex64 不變） ──

console.log('\n[9] BIP39 復原套件（24 詞 ⇄ entropy 32B ⇄ hex64）');
const bip = await import('../src/client/bip39.ts');
const wl = await import('../src/client/wordlist.ts');

const kitWords = await bip.generateBip39Words();
await A('24 詞', kitWords.length === 24);
await A('全在詞表', kitWords.every(w => wl.wordlist.includes(w)));
await A('詞表 2048 詞', wl.wordlist.length === 2048);
await A('詞全小寫字母（轉寫容錯面）', wl.wordlist.every(w => /^[a-z]+$/.test(w)));

const kitHex64 = await bip.wordsToRecToken(kitWords);
await A('words→hex64 格式', kitHex64 !== null && /^[0-9a-f]{64}$/.test(kitHex64));
await A('words→hex64 roundtrip（同詞同值）', (await bip.wordsToRecToken(kitWords)) === kitHex64);
await A('不同套件不同 hex64', (await bip.wordsToRecToken(await bip.generateBip39Words())) !== kitHex64);

// hex64 舊套件 ⇄ 詞轉換雙向（相容層：舊紙本照走現行鏈）
const hexToWords = await bip.recTokenToWords(kitHex64!);
await A('hex64→24 詞 roundtrip', hexToWords !== null && (await bip.wordsToRecToken(hexToWords)) === kitHex64);
await A('舊 hex64（generateRecToken 產物）可轉詞',
  (await bip.recTokenToWords(generateRecToken())) !== null);

// normalize 容錯：大寫/全形空格/換行/多空白
const messy = kitWords.map((w, i) => (i % 2 ? w.toUpperCase() : w)).join('　');
await A('全形空格＋大寫容錯', (await bip.wordsToRecToken(messy)) === kitHex64);
await A('換行＋多空白容錯', (await bip.wordsToRecToken(kitWords.join('\n  '))) === kitHex64);

// 失敗面統一 null（不洩漏哪類錯）
await A('23 詞 → null', (await bip.wordsToRecToken(kitWords.slice(0, 23).join(' '))) === null);
await A('25 詞 → null', (await bip.wordsToRecToken([...kitWords, kitWords[0]].join(' '))) === null);
await A('詞表外 → null', (await bip.wordsToRecToken(kitWords.slice(0, 23).concat('notaword').join(' '))) === null);

// checksum 面：錯一詞（詞表內不同詞）→ 幾乎必被 checksum 抓；固定種子 64 樣本全抓。
// （t_d1cf3846：真隨機取樣時 P(漏 ≥2)≈0.4%＝偶發 62/64 flake 實證——改 xorshift 常數
// 種子樣本集（bip39.seededSampleBytes），向量可重放、閘輸出逐輪恆定；種子窗 1..64
// 經五窗 320 樣本探針驗證全抓後採用，非挑窗）
const wlArr: readonly string[] = wl.wordlist;
let checksumCaught = 0;
for (let t = 0; t < 64; t++) {
  const ws = [...(await bip.generateBip39Words(bip.seededSampleBytes(1 + t)))];
  const idx = t % 24;
  let alt = wlArr[(wlArr.indexOf(ws[idx]) + 1 + t) % 2048];
  if (alt === ws[idx]) alt = wlArr[(wlArr.indexOf(ws[idx]) + 1) % 2048];
  ws[idx] = alt;
  if ((await bip.wordsToRecToken(ws.join(' '))) === null) checksumCaught++;
}
await A('錯一詞固定種子 64 樣本全抓（checksum 8-bit；flake 歸零）', checksumCaught === 64, `caught=${checksumCaught}/64`);
const detA = await bip.generateBip39Words(bip.seededSampleBytes(20260919));
const detB = await bip.generateBip39Words(bip.seededSampleBytes(20260919));
const detC = await bip.generateBip39Words(bip.seededSampleBytes(20260920));
await A('種子樣本確定性（同 seed 逐字同詞、異 seed 異詞；產品面無參數真隨機不變）',
  detA.join(' ') === detB.join(' ') && detA.join(' ') !== detC.join(' '));

// spot-check 抽驗索引
const picks = bip.spotCheckIndexes();
await A('抽驗 4 位置', picks.length === 4);
await A('位置 0-23 不重複', new Set(picks).size === 4 && picks.every(p => p >= 0 && p <= 23));
await A('抽驗索引排序（顯示穩定）', picks.every((p, i) => i === 0 || picks[i - 1] < p));

// 參照實作對照（@scure/bip39 devDependencies，僅本閘用；產品碼零依賴）
try {
  const scureMod = await import('@scure/bip39');
  const scureWl = (await import('@scure/bip39/wordlists/english.js')).wordlist;
  const { entropyToMnemonic, mnemonicToEntropy } = scureMod;
  let refOk = true;
  for (let t = 0; t < 200; t++) {
    const ent = crypto.getRandomValues(new Uint8Array(32));
    const refWords: string[] = entropyToMnemonic(ent, scureWl).split(' ');
    const ours = await bip.recTokenToWords(hex(new Uint8Array(ent)));
    if (!ours || ours.join(' ') !== refWords.join(' ')) { refOk = false; break; }
    if ((await bip.wordsToRecToken(refWords)) !== hex(new Uint8Array(mnemonicToEntropy(refWords.join(' '), scureWl)))) { refOk = false; break; }
  }
  await A('與 @scure/bip39 參照 200 組雙向一致', refOk);
} catch {
  await A('與 @scure/bip39 參照 200 組雙向一致', false, '參照套件未安裝（devDependencies @scure/bip39）');
}

// 與現行包裹鏈相容：words 造的 hex64 走 recTokenHash/wrapNoteKeyWithRecToken 原樣
const kitHexAsToken = (await bip.wordsToRecToken(kitWords))!;
const kitWrapped = await wrapNoteKeyWithRecToken(TACET, noteKey, kitHexAsToken, identityA);
await A('words 派生 hex64 包裹前綴 jr1w.', kitWrapped.startsWith('jr1w.'));
await A('words 派生 hex64 unwrap 救回 noteKey',
  (await unwrapNoteKeyWithRecToken(TACET, kitWrapped, kitHexAsToken, identityA)) !== null);

// ── 10. 附件密文（jr1c.，image attachments；opt-in 未配置即拒） ───────────────

console.log('\n[10] 附件密文（jr1c. cipherAttach opt-in）');
const bareCfgAttach: NoteCryptoConfig = { ...TACET }; // 無 cipherAttach 欄
let attachCfgThrow = '';
try { await encryptAttach(bareCfgAttach, noteKey, '{"v":1}', 'jr1a:n1:a1'); } catch (e) { attachCfgThrow = (e as Error).message; }
await A('未配置 cipherAttach → encryptAttach throw', attachCfgThrow === 'ERR_ATTACH_NOT_CONFIGURED', attachCfgThrow);

const TACET_ATTACH: NoteCryptoConfig = { ...TACET, cipherAttach: 'jr1c.' };
const attachAad = 'jr1a:note-abc:att-001';
const attachPayload = JSON.stringify({ v: 1, kind: 'img', mime: 'image/jpeg', w: 2048, h: 1365, b64: b64(new Uint8Array(2048)) });
const attachCt = await encryptAttach(TACET_ATTACH, noteKey, attachPayload, attachAad);
await A('附件前綴 jr1c.', attachCt.startsWith('jr1c.'));
await A('附件 roundtrip（顯式 noteKey）',
  (await decryptAttach(TACET_ATTACH, noteKey, attachCt, attachAad)) === attachPayload);
await A('附件 AAD 防搬移：錯 attachment_id → null',
  (await decryptAttach(TACET_ATTACH, noteKey, attachCt, 'jr1a:note-abc:att-999')) === null);
await A('附件錯鑰匙 → null',
  (await decryptAttach(TACET_ATTACH, await generateNoteKey(), attachCt, attachAad)) === null);

// ── 11. 本機 IDB 密文（jr1d. cipherLocal opt-in）＋ guest 選配拒絕面 ──────────

console.log('\n[11] 本機 IDB 密文（jr1d. cipherLocal opt-in）＋ guest 選配拒絕面');
// 分享包裹（jrsw.，wrapShare 選配）＋ jr3s. roundtrip（t_7710c766 目標 8：閘本有 roundtrip 斷言缺席）
const TACET_SHARE: NoteCryptoConfig = { ...TACET, wrapShare: 'jrsw.' };
const shareWrapped = await wrapNoteKeyShare(TACET_SHARE, noteKey, 'share-pass-42');
await A('分享包裹前綴 jrsw.', shareWrapped.wrapped.startsWith('jrsw.'));
await A('分享 salt = 16B hex', /^[0-9a-f]{32}$/.test(shareWrapped.salt));
const shareUnwrapped = await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'share-pass-42', shareWrapped.salt);
await A('jrsw unwrap 等值 noteKey（extractable 再 export）',
  shareUnwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', shareUnwrapped))) === origRaw);
await A('分享錯密語 → null', (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'wrong-share-pass', shareWrapped.salt)) === null);
await A('分享錯 salt → null', (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'share-pass-42', 'zz'.repeat(16))) === null);
await A('分享 malformed salt（zz 字元）→ null（t_7710c766：salt1 hex 形檢查）',
  (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'share-pass-42', '0'.repeat(31) + 'z')) === null);
await A('分享 payload 長度不符 → null',
  (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped.slice(0, -3) + 'abc', 'share-pass-42', shareWrapped.salt)) === null);
await A('未配置 wrapShare → 分享解包 null（opt-in 拒絕面）',
  (await unwrapNoteKeyShare(TACET, shareWrapped.wrapped, 'share-pass-42', shareWrapped.salt)) === null);
await A('本機包裹 roundtrip 經 loadLocalWrap 通路（clearLocalWrap 在場面）',
  (async () => { await storeLocalWrap(TACET, localIdentity, noteKey); return true; })());
await A('clearLocalWrap 摘除本機包裹', (() => { clearLocalWrap(TACET, localIdentity); return TACET.store.get(TACET.store.noteKeyWrap(localIdentity)) === null; })());
await A('buildBindPayload 四件套輸出面（wrapped/wrappedRec/recTokenHash 同 wrapNoteKey 直呼）',
  (async () => {
    const p = await buildBindPayload(TACET, noteKey, pass, recToken, identityA);
    return p.wrapped.startsWith('jr1w.') && p.wrappedRec.startsWith('jr1w.') &&
      /^[0-9a-f]{32}$/.test(p.salt) && /^[0-9a-f]{64}$/.test(p.recTokenHash);
  })());
await A('buildBindPayload unwrap 等值 noteKey（wrapped 面救得回）',
  (async () => {
    const p = await buildBindPayload(TACET, noteKey, pass, recToken, identityA);
    const k = await unwrapNoteKey(TACET, p.wrapped, pass, p.salt);
    return k !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === origRaw;
  })());
const bareCfgLocal: NoteCryptoConfig = { ...TACET }; // 無 cipherLocal 欄
let localCfgThrow = '';
try { await encryptLocal(bareCfgLocal, noteKey, '{}', 'jr1:n1'); } catch (e) { localCfgThrow = (e as Error).message; }
await A('未配置 cipherLocal → encryptLocal throw', localCfgThrow === 'ERR_LOCAL_NOT_CONFIGURED', localCfgThrow);

const TACET_LOCAL: NoteCryptoConfig = { ...TACET, cipherLocal: 'jr1d.' };
const localAad = 'jr1:note-abc';
const localPayload = JSON.stringify({ v: 1, text: '今天寫了一點東西。', title: '標題' });
const localCt = await encryptLocal(TACET_LOCAL, noteKey, localPayload, localAad);
await A('本機前綴 jr1d.', localCt.startsWith('jr1d.'));
await A('本機 roundtrip（bound noteKey）', (await decryptLocal(TACET_LOCAL, noteKey, localCt, localAad)) === localPayload);
await A('本機 AAD 防搬移：錯 note_id → null', (await decryptLocal(TACET_LOCAL, noteKey, localCt, 'jr1:note-zzz')) === null);
await A('本機錯鑰匙 → null', (await decryptLocal(TACET_LOCAL, await generateNoteKey(), localCt, localAad)) === null);

// Era 0 形：guest key（呼叫端派生注入，與 IDB store 層同構）
const localGuest = await (async () => {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('tacet-note-u1' + identityA)));
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
})();
const localCtGuest = await encryptLocal(TACET_LOCAL, localGuest, localPayload, localAad);
await A('本機 roundtrip（Era 0 guest key）', (await decryptLocal(TACET_LOCAL, localGuest, localCtGuest, localAad)) === localPayload);

// 跨前綴隔離：jr1d. 非 jr1c./jr1b./jr1u.；他家族入口不吃本機密文
await A('本機密文非附件/筆記前綴',
  !localCt.startsWith('jr1c.') && !localCt.startsWith('jr1b.') && !localCt.startsWith('jr1u.'));
await A('decryptAttach 拒收 jr1d.', (await decryptAttach(TACET_ATTACH, noteKey, localCt, localAad)) === null);
await A('decryptLocal 拒收 jr1c.', (await decryptLocal(TACET_LOCAL, noteKey, attachCt, attachAad)) === null);
await A('decryptNote 對未配置的 jr1d.＝未知前綴相容層原樣（不誤判不誤解）',
  (await decryptNote({ ...TACET }, makeHeldKey(), localCt, localAad, { current: () => identityA })) === localCt);

// payload 竄改 → GCM 驗證失敗 → null（iv 區 byte 3／ct 尾最後一位元組；索引以解碼後
// 位元組面計——b64 字串索引會越界靜默 no-op＝假紅，閘毒化同族教訓）
const tamperLocal = async (byteIdx: number): Promise<boolean> => {
  const bin = atob(localCt.slice('jr1d.'.length));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  if (byteIdx < 0 || byteIdx >= bytes.length) return false; // 索引自守衛：越界即顯性失敗
  bytes[byteIdx] ^= 0x01;
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) out += String.fromCharCode(bytes[i]);
  return (await decryptLocal(TACET_LOCAL, noteKey, 'jr1d.' + btoa(out), localAad)) === null;
};
await A('本機 payload 竄改 iv 區 → null', await tamperLocal(3));
await A('篡改索引越界＝顯性失敗（runner 自檢：靜默 no-op 即假紅）', await tamperLocal(-1) === false);
await A('本機 payload 竄改 ct 尾 → null', await tamperLocal(59));

// guest 選配未配置拒絕面（2026-09-19 收編：cipherGuest 轉選配；未配置即拒鐵律）
const TACET_NOGUEST: NoteCryptoConfig = { ...TACET, cipherGuest: undefined };
const guestThrowsMsg = async (): Promise<string | null> => {
  try { await encryptNote(TACET_NOGUEST, makeHeldKey(), note, 'noteId:n1', { current: () => identityA }); return null; }
  catch (e) { return (e as Error).message; }
};
await A('未配置 cipherGuest → encryptNote guest 路徑 throw ERR_GUEST_NOT_CONFIGURED',
  (await guestThrowsMsg()) === 'ERR_GUEST_NOT_CONFIGURED');
const heldBound = makeHeldKey();
heldBound.set(noteKey);
await A('未配置 guest 的 bound 加密不受牽連',
  (await encryptNote(TACET_NOGUEST, heldBound, note, 'noteId:n1', { current: () => identityA })).startsWith('jr1b.'));
await A('未配置 guest → decryptNote guest 密文 null',
  (await decryptNote(TACET_NOGUEST, makeHeldKey(), cipherGuest, 'noteId:n1', { current: () => identityA })) === null);
await A('未配置 guest → decryptNote 不明字串 null（guest 家族整面拒絕、不當明文顯示）',
  (await decryptNote(TACET_NOGUEST, makeHeldKey(), 'jr9x.somestring', 'x', { current: () => identityA })) === null);
await A('配置 guest → decryptNote 舊明文相容層原樣（既有契約不變）',
  (await decryptNote(TACET, makeHeldKey(), '純舊明文', 'x', { current: () => identityA })) === '純舊明文');
await A('既有 guest 配置 roundtrip 不受選配收編影響',
  (await decryptNote(TACET, makeHeldKey(), cipherGuest, 'noteId:n1', { current: () => identityA })) === note);

// guest 空 identity 拒絕面（t_7710c766 目標 3）：K_u = SHA-256(prefix ‖ '') 靜默產出「空帳號金鑰」是誤配炸彈
const TACET_GUESTOK: NoteCryptoConfig = { ...TACET }; // cipherGuest='jr1g.' 在場，專測 identity 面
const emptyIdp = { current: () => '' };
let emptyIdMsg: string | null = null;
try { await encryptNote(TACET_GUESTOK, makeHeldKey(), note, 'noteId:n1', emptyIdp); } catch (e) { emptyIdMsg = (e as Error).message; }
await A("guest 加密面空 identity → throw ERR_NO_IDENTITY（falsy 一體：空字串/undefined/null）",
  emptyIdMsg === 'ERR_NO_IDENTITY');
// 空白 '  ' 是 truthy：K_u 照派生＝加密面照常（呼叫端責任面）；誠實界線＝「非 falsy 不擋」的行為證據
let wsCipher = '';
try { wsCipher = await encryptNote(TACET_GUESTOK, makeHeldKey(), note, 'noteId:n1', { current: () => '  ' }); } catch { /* 不該發生 */ }
await A('guest 空白 identity 是 truthy → 照派生不擋（非 falsy 不拒的誠實界線；行為面）', wsCipher.startsWith('jr1g.'));
await A('guest 解密面空 identity → null（對稱面 fail-closed）',
  (await decryptNote(TACET_GUESTOK, makeHeldKey(), cipherGuest, 'noteId:n1', emptyIdp)) === null);
await A('guest 空 identity 的既有 roundtrip 恆正常（identity 在場零新拒絕面）',
  (await decryptNote(TACET_GUESTOK, makeHeldKey(), cipherGuest, 'noteId:n1', { current: () => identityA })) === note);

// 畸形配置 ''（空字串）正規化面（follow-up ②，t_44239f5f）：空字串前綴＝startsWith('') 恆真，
// bound 列會被誤導 guest 分支回 null。正規化後：加密面與未配置同拒、解密面 bound 照解、
// guest 密文（他家族形）null——與「未配置」行為完全同構。
const TACET_EMPTYGUEST: NoteCryptoConfig = { ...TACET, cipherGuest: '' };
await A("畸形 guest 前綴 '' → encryptNote guest 路徑同 ERR_GUEST_NOT_CONFIGURED（truthiness 對稱）",
  (await (async () => { try { await encryptNote(TACET_EMPTYGUEST, makeHeldKey(), note, 'noteId:n1', { current: () => identityA }); return null; } catch (e) { return (e as Error).message; } })()) === 'ERR_GUEST_NOT_CONFIGURED');
await A("畸形 guest 前綴 '' → decryptNote bound 密文照解（不誤導 guest 分支回 null）",
  (await decryptNote(TACET_EMPTYGUEST, heldBound, cipherBound, 'noteId:n1', { current: () => identityA })) === note);
await A("畸形 guest 前綴 '' → decryptNote guest 密文 null（guest 家族整面拒絕）",
  (await decryptNote(TACET_EMPTYGUEST, makeHeldKey(), cipherGuest, 'noteId:n1', { current: () => identityA })) === null);
await A("畸形 guest 前綴 '' → decryptNote 舊明文相容層同「未配置」形（null，不當明文）",
  (await decryptNote(TACET_EMPTYGUEST, makeHeldKey(), '純舊明文', 'x', { current: () => identityA })) === null);

// ── 12. 伺服器端原語（t_7710c766 目標 8：makeInboundCipher/validWrappedKey/pickKeyPackage/
//         checkRate/timingSafeEq）＋ 本機鎖定全函式（pinlock jr1p.，目標 8） ──────────

console.log('\n[12] 伺服器端原語（auth/ratelimit/hash）＋ 本機鎖定（pinlock）');
// ratelimit 行為面（t_b91ed07f）：真 node:sqlite 直載 UPSERT…RETURNING 單句對真實
// SQLite 引擎全三態驗證（D1 同為 SQLite；D1 實測另有 wrangler dev 探針回帶 results——
// 見卡 comments）。表名直插 SQL＝注入面驗證；放行判準 count<=max 單一真相。
type RateRow = { ip: string; window_start: number; count: number };
const makeRateDb = (): {
  db: unknown;
  allowed: (ip: string, windowStart: number, cutoff: number, max: number) => boolean;
  row: (ip: string) => RateRow | undefined;
  runRaw: (sql: string) => void;
} => {
  const { DatabaseSync } = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { DatabaseSync?: unknown } };
  }).process?.getBuiltinModule?.('node:sqlite') ?? {};
  if (!DatabaseSync) throw new Error('ERR_SQLITE_UNAVAILABLE');
  const db = new (DatabaseSync as new (p: string) => {
    exec: (s: string) => void;
    prepare: (s: string) => { all: (...p: unknown[]) => Array<Record<string, unknown>>; get: (...p: unknown[]) => Record<string, unknown> | undefined };
  })(':memory:');
  db.exec('CREATE TABLE login_rate (ip TEXT PRIMARY KEY, window_start INTEGER, count INTEGER)');
  const bump = db.prepare(SQL_RATE_BUMP.replaceAll('{table}', 'login_rate'));
  const sel = db.prepare('SELECT * FROM login_rate WHERE ip = ?');
  return {
    db,
    allowed: (ip, windowStart, cutoff, max) =>
      isRateAllowed((bump.all(ip, windowStart, cutoff)[0]?.n as number) ?? NaN, max),
    row: (ip) => sel.get(ip) as RateRow | undefined,
    runRaw: (sql) => db.exec(sql),
  };
};
const RATE: RateWindow = { table: 'login_rate', windowMs: 60_000, max: 3 };
await A('rate：窗內首發 pass（RETURNING n=1）', await (async () => {
  const r = makeRateDb(); return r.allowed('ip-1', 1000, 900, RATE.max) === true && JSON.stringify(r.row('ip-1'))?.includes('"count":1');
})());
await A('rate：同 IP 三發連續 pass、第四發 reject（放行判準 count<=max）', await (async () => {
  const r = makeRateDb();
  const seq = [r.allowed('ip-1', 1000, 900, RATE.max), r.allowed('ip-1', 1000, 900, RATE.max), r.allowed('ip-1', 1000, 900, RATE.max), r.allowed('ip-1', 1000, 900, RATE.max)];
  return seq[0] && seq[1] && seq[2] && seq[3] === false;
})());
await A('rate：併發首發不 undercount（原 INSERT/輸家競態面——單句原子後兩發計數 1→2）', await (async () => {
  const r = makeRateDb();
  r.allowed('ip-c', 1000, 900, RATE.max); r.allowed('ip-c', 1000, 900, RATE.max);
  return r.row('ip-c')?.count === 2;
})());
await A('rate：窗口過期整窗重置（count 歸 1＋window_start 換新）', await (async () => {
  const r = makeRateDb();
  for (let i = 0; i < RATE.max + 2; i++) r.allowed('ip-w', 1000, 900, RATE.max);
  r.allowed('ip-w', 2000000, 1940000, RATE.max); // 過期窗：window_start 1000 <= cutoff 1940000 → 重置
  const row = r.row('ip-w');
  return row?.count === 1 && row?.window_start === 2000000;
})());
await A('rate：同一發內過期重置＋立即放行（重置發回 n=1 不吃 max 帽）', await (async () => {
  const r = makeRateDb();
  for (let i = 0; i < RATE.max + 1; i++) r.allowed('ip-x', 3000000, 2940000, RATE.max); // 已滿窗
  return r.allowed('ip-x', 4000000, 3940000, RATE.max) === true; // 過期後首發放行
})());
await A('rate：count 不封頂（超額發照實累計 5、6——審計可見非靜默吞）', await (async () => {
  const r = makeRateDb();
  for (let i = 0; i < 6; i++) r.allowed('ip-m', 1000, 900, RATE.max);
  return r.row('ip-m')?.count === 6;
})());
await A('rate：checkRate 呼叫端形（env.DB.prepare→bind→run；D1 results 回帶）fail-open', await (async () => {
  const calls: string[] = [];
  const env12 = { DB: {
    prepare: (sql: string) => ({
      bind: (..._p: unknown[]) => ({ run: async () => { calls.push(sql.slice(0, 30)); throw new Error('D1_DOWN'); } }),
    }),
  } };
  const ok = await checkRate(env12 as unknown as Parameters<typeof checkRate>[0], RATE, 'ip-fail');
  return ok === true && calls.length === 1 && calls[0].startsWith('INSERT INTO');
})());
await A('rate：表名注入拒絕（直插 SQL 面）', await (async () => {
  try { await checkRate({ DB: { prepare: () => { throw new Error('SHOULD_NOT_PREPARE'); } } } as unknown as Parameters<typeof checkRate>[0], { table: 'x; DROP TABLE users--', windowMs: 1000, max: 3 }, 'ip'); return false; }
  catch (e) { return String((e as Error).message).startsWith('ERR_RATE_TABLE_NAME'); }
})());
await A('rate：表名 \w 合法（字母數字底線）', await (async () => {
  try { await checkRate({ DB: { prepare: () => { throw new Error('D1_DOWN_FAILOPEN'); } } } as unknown as Parameters<typeof checkRate>[0], { table: 'login_rate_2', windowMs: 1000, max: 3 }, 'ip'); return true; }
  catch (e) { return String((e as Error).message).startsWith('ERR_RATE_TABLE_NAME') === false && String((e as Error).message).includes('D1_DOWN_FAILOPEN'); }
})());
await A('rate：SQL_RATE_BUMP 常數形（UPSERT…RETURNING…count AS n；{table} 佔位）',
  /^INSERT INTO \{table\} \(ip, window_start, count\) VALUES \(\?1, \?2, 1\)\n\s+ON CONFLICT\(ip\) DO UPDATE SET\n\s+count\s+= CASE WHEN window_start <= \?3 THEN 1 ELSE count \+ 1 END,\n\s+window_start = CASE WHEN window_start <= \?3 THEN \?2 ELSE window_start END\n\s+RETURNING count AS n$/.test(SQL_RATE_BUMP));
await A('AUTH_RATE 契約（60s 窗 max 10）', AUTH_RATE.windowMs === 60_000 && AUTH_RATE.max === 10);
const sessA = generateSessionToken();
const sessB = generateSessionToken();
await A('generateSessionToken hex64', /^[0-9a-f]{64}$/.test(sessA));
await A('generateSessionToken 兩次相異', sessA !== sessB);
await A('timingSafeEq 等值 true', timingSafeEq(sessA, sessA));
await A('timingSafeEq 異值 false', timingSafeEq(sessA, sessB) === false);
await A('timingSafeEq 長度異 false', timingSafeEq(sessA, sessA.slice(0, 32)) === false);
await A('timingSafeEq 空串等值', timingSafeEq('', ''));
await A('timingSafeEq 空串異值 false', !timingSafeEq('', 'x'));

const formats: CipherFormats = { cipherPrefixes: ['jr1u.', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 5000 };
const inbound = makeInboundCipher(formats);
await A('inboundCipher：前綴密文原樣入庫', inbound('jr1b.' + b64(new Uint8Array(32))) === 'jr1b.' + b64(new Uint8Array(32)));
await A('inboundCipher：超限密文丟棄（截斷必壞）', inbound('jr1b.' + b64(new Uint8Array(4000))) === null);
await A('inboundCipher：超限明文截到上限照收', inbound('字'.repeat(7000))?.length === 5000);
await A('inboundCipher：b64 慣例照收', inbound(b64(new Uint8Array(64))) !== null);
await A('inboundCipher：控制字元垃圾丟棄', inbound('bad\x00junk') === null);
await A('inboundCipher：真明文照收', inbound('純明文') === '純明文');
await A('inboundCipher：非字串 null', inbound(42) === null);
await A('isCipherFor：家族前綴 true／非家族 false',
  isCipherFor('jr1b.abc', formats) && isCipherFor('jr1u.abc', formats) && !isCipherFor('jr2x.abc', formats));
await A('makeInboundCipher regex 跳脫全字面（P2.5 行為面：舊碼 .replace 單點跳脫讓 c() 誤判密文——>max 丟棄 vs 明文截斷兩路分岔）',
  (() => {
    // 前綴字面含 regex 符號（可建構形——裸 '(' 形舊碼建構即 throw）：'a.b|c()'
    const f: CipherFormats = { cipherPrefixes: ['a.b|c(' + String.fromCharCode(41), 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 500 };
    const m = makeInboundCipher(f);
    // 'c()' + 600 chars > max：舊碼 regex 的 c\(\) 誤分支咬住 → 密文丟棄 null；
    // 正碼全字面跳脫 → 非家族前綴 → 明文截斷照收。
    const probe = 'c()' + 'A'.repeat(600);
    return m(probe) === probe.slice(0, 500) && m('a.b|c()Zm9v') === 'a.b|c()Zm9v';
  })());
await A('validWrappedKey：合法包裹 true／超長 null／非法前綴 null',
  validWrappedKey('jr1w.' + b64(new Uint8Array(32)), 'jr1w.') !== null &&
  validWrappedKey('jr1w.' + b64(new Uint8Array(300)), 'jr1w.') === null &&
  validWrappedKey('jr9x.' + b64(new Uint8Array(32)), 'jr1w.') === null);
await A('validHash64／validSalt 形狀', validHash64('a'.repeat(64)) !== null && validHash64('zz') === null && validSalt('a'.repeat(32)) !== null && validSalt('zz') === null);
const pkgOk = pickKeyPackage({ wrapped: 'jr1w.' + b64(new Uint8Array(32)), salt: 'a'.repeat(32) }, 'jr1w.');
await A('pickKeyPackage：成對成立', pkgOk.wrapped !== null && pkgOk.salt !== null);
await A('pickKeyPackage：缺 salt 整組放棄',
  (() => { const p = pickKeyPackage({ wrapped: 'jr1w.' + b64(new Uint8Array(32)) }, 'jr1w.'); return p.wrapped === null && p.salt === null; })());
await A('pickKeyPackage：缺 wrapped 整組放棄',
  (() => { const p = pickKeyPackage({ salt: 'a'.repeat(32) }, 'jr1w.'); return p.wrapped === null && p.salt === null; })());
await A('pickKeyPackage：錯前綴整組放棄',
  (() => { const p = pickKeyPackage({ wrapped: 'jr9x.' + b64(new Uint8Array(32)), salt: 'a'.repeat(32) }, 'jr1w.'); return p.wrapped === null; })());

// 本機鎖定（jr1p.）：全函式 roundtrip＋嚴格檢查面（t_7710c766：pinlock 閘本有斷言缺席）
const PINLOCK: PinLockConfig = { pinLock: 'jr1p.', pinLockSaltPrefix: 'tacet-pinlock-v1:', pinLockAad: 'notekey-pinlock' };
const pinWrapped = await wrapNoteKeyPinLock(PINLOCK, noteKey, '2580ab');
await A('jr1p 包裹前綴 jr1p.', pinWrapped.startsWith('jr1p.'));
const pinUnwrapped = await unwrapNoteKeyPinLock(PINLOCK, pinWrapped, '2580ab');
await A('jr1p unwrap 等值 noteKey（extractable 再 export）',
  pinUnwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', pinUnwrapped))) === origRaw);
await A('jr1p 錯 PIN → null', (await unwrapNoteKeyPinLock(PINLOCK, pinWrapped, '999999')) === null);
await A('jr1p 空 PIN unwrap → null（解包面誠實拒絕）', (await unwrapNoteKeyPinLock(PINLOCK, pinWrapped, '  ')) === null);
await A('jr1p PIN 大小寫/空白正規化等價', (await unwrapNoteKeyPinLock(PINLOCK, pinWrapped, ' ２５８０ＡＢ ')) !== null);
await A('jr1p 空_PIN wrap 拒絕形', await (async () => {
  try { await wrapNoteKeyPinLock(PINLOCK, noteKey, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PINLOCK_EMPTY'; }
})());
await A('jr1p 未配置 cfg → wrap 拒絕（opt-in 律）', await (async () => {
  try { await wrapNoteKeyPinLock({}, noteKey, '2580ab'); return false; } catch { return true; }
})());
await A('jr1p 未配置 cfg → unwrap null',
  (await unwrapNoteKeyPinLock({ pinLock: 'jr1p.' }, pinWrapped, '2580ab')) === null);
await A('jr1p payload 竄改 pinSalt 區 → null（自描述完整性）', await (async () => {
  const bytes = unb64(pinWrapped.slice('jr1p.'.length)); bytes[3] ^= 0x01;
  return (await unwrapNoteKeyPinLock(PINLOCK, 'jr1p.' + b64(bytes), '2580ab')) === null;
})());
await A('jr1p payload 竄改 ct 尾 → null', await (async () => {
  const bytes = unb64(pinWrapped.slice('jr1p.'.length)); bytes[bytes.length - 1] ^= 0x01;
  return (await unwrapNoteKeyPinLock(PINLOCK, 'jr1p.' + b64(bytes), '2580ab')) === null;
})());
await A('jr1p 跨家族：jr1w. 字串餵 pinlock → null',
  (await unwrapNoteKeyPinLock(PINLOCK, wrapped, '2580ab')) === null);
await A('jr1p 跨家族：jr1p. 字串餵 jr1w unwrap → null',
  (await unwrapNoteKey(TACET2, pinWrapped, pass, salt)) === null);

// ── 13. 新契約面（t_7710c766：hex fail-closed／salt hex 形收口／PH1 鹽注入／錯誤碼語意分離） ──

console.log('\n[13] unwrap 驗證統一新契約（fail-closed ＋ 語意分離）');
// hexToBytes fail-closed（目標 #2；note-crypto 與 bip39 同步——bip39 面是 HEX64_RE 前置自守）
await A('hexToBytes 合法輸出不變（舊碼同值；新向量）', hexToBytes('00ff10').join(',') === '0,255,16');
await A('hexToBytes 大小寫正規化（新行為，舊碼同值）', (() => { const a = Array.from(hexToBytes('AB')); const b = Array.from(hexToBytes('ab')); return a.length === b.length && a.every((v, i) => v === b[i]); })());
await A("hexToBytes 非法字元 'zz' → throw ERR_BAD_HEX", await (async () => {
  try { hexToBytes('zz'); return false; } catch (e) { return (e as Error).message === 'ERR_BAD_HEX'; }
})());
await A('hexToBytes 奇數長度 → throw', await (async () => {
  try { hexToBytes('abc'); return false; } catch (e) { return (e as Error).message === 'ERR_BAD_HEX'; }
})());
await A('hexToBytes 空字串 → throw', await (async () => {
  try { hexToBytes(''); return false; } catch (e) { return (e as Error).message === 'ERR_BAD_HEX'; }
})());
await A(`hexToBytes 全形正規化（'${'ｆｆ'}'）→ Bytes [255] 等值`, (() => { try { return Array.from(hexToBytes('ｆｆ')).join(',') === '255'; } catch { return false; } })());
await A(`hexToBytes 全形數字（'２ｆ'）→ Bytes 等值（NFKC 窗殲滅——round 1 MINOR-4：parse 原始串 NaN 歸零殘形）`, (() => { try { return Array.from(hexToBytes('２ｆ')).join(',') === '47'; } catch { return false; } })());
await A('bip39 hexToBytes 同步（HEX64_RE 自守前提下的舊向量不變）', (await bip.recTokenToWords('ab'.repeat(32)))?.length === 24);
await A('unwrap：鹽 hex 非法字元 → 假錯誤誘餌面 null（原碼靜默歸零會錯誤炸出成功路徑）',
  (await unwrapNoteKey(TACET2, dual.wrapped, passD, 'a'.repeat(31) + 'z')) === null);
await A('unwrapNoteKeyDual：salt1 hex 非法字元 ' + 'z' + ' → null（鹽內嵌族 own 檢查照舊——收口本體=鹽外置族）',
  (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, pinD, 'a'.repeat(31) + 'z')) === null);
await A('unwrapNoteKeyDual：salt1 hex 奇數長 → null', (await unwrapNoteKeyDual(TACET2, dual.wrapped, passD, pinD, 'a'.repeat(31))) === null);
await A('unwrapNoteKey3：salt hex 形檢查照舊（既有契約不變）',
  (await unwrapNoteKey3(TACET3, w3.wrapped, pass, 'a'.repeat(31) + 'z')) === null);
// 鍛造面（格式嚴格契約的可觀察承載；毒化前提）：KEK 已知者可造任意形 payload——
// 舊碼（無 rawHex 長度/形檢）下 32-hex 假 noteKey 與 'zz' 前綴零化 hex 皆 NON-NULL＝假金鑰生產器。
const craftKek = (async (): Promise<CryptoKey> => {
  // deriveKek 鏡像（未匯出）：PBKDF2-SHA256(pass, salt, 600k) → AES-GCM-256。
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: hexToBytes(salt) as BufferSource, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
})();
// 鍛造面（格式嚴格契約的可觀察承載；毒化前提）：KEK 已知者可造任意形 payload——
// 舊碼（無 rawHex 長度/形檢）下 'zz' 前綴零化 hex 非 null＝假金鑰生產器。
// round 1 審查 MAJOR-1 校正：鍛造 encrypt 必帶 additionalData('notekey')＝與 decryptWithKey
// 同 AAD——缺 AAD 的鍛造 GCM 層恆拒＝rawHex 形檢從未執行（斷言空轉）。
// craftKek 鏡像真 deriveKek（同 pass 同 salt 同 600k）＝鍛造鏈與真 unwrap 同 KEK：
// 有效形鍛造真解開（NON-NULL 自證鏈活）、畸形形由各檢查點拒——機制面直接可觀察。
const F_AAD: BufferSource = enc.encode('notekey');
await A('MAJOR-1 機制面：帶 AAD 鍛造 ct 可解回 rawHex（形檢層可達＝斷言活）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('zz' + 'a'.repeat(62)) as BufferSource));
  return (await decryptWithKey(kekC, new Uint8Array([...ivC, ...ctC]), 'notekey')) === 'zz' + 'a'.repeat(62);
})());
await A('MAJOR-1 空轉形：同 payload 無 AAD 鍛造 → decryptWithKey null（GCM 層恆拒＝round 1 空轉病理）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC }, kekC, enc.encode('zz' + 'a'.repeat(62)) as BufferSource));
  return (await decryptWithKey(kekC, new Uint8Array([...ivC, ...ctC]), 'notekey')) === null;
})());
await A('鍛造有效形 92B payload（64-hex 假 noteKey）→ NON-NULL（鍛造鏈自證：真解到 importAesGcm＝假金鑰真產出）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('ab'.repeat(32)) as BufferSource));
  const p = new Uint8Array(12 + ctC.byteLength); p.set(ivC, 0); p.set(ctC, 12);
  const k = await unwrapNoteKey(TACET, 'jr1w.' + b64(p), pass, salt);
  if (k === null) return false;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', k));
  return raw.length === 32 && raw.every((b: number) => b === 0xab);
})());
await A('鍛造 92B payload 的零化 hex rawHex（zz 前綴）→ null（rawHex HEX_RE 形檢查；帶 AAD 真解後形檢拒）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('zz' + 'a'.repeat(62)) as BufferSource));
  const p = new Uint8Array(12 + ctC.byteLength); p.set(ivC, 0); p.set(ctC, 12);
  return (await unwrapNoteKey(TACET, 'jr1w.' + b64(p), pass, salt)) === null;
})());
// 短 payload 鍛造（60B：iv+ct(hex32假 noteKey)）→ null：openNoteKey 嚴格長度檢的可觀察承載
//（僅 hexToBytes fail-closed 擋不住「合法 hex 的假 32B 金鑰」——長度檢獨立承載）。
await A('鍛造 60B payload（合法 hex 32B 假 noteKey，帶 AAD）→ null（openNoteKey 嚴格 92B 長度檢先行）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('ab'.repeat(16)) as BufferSource));
  const p = new Uint8Array(12 + ctC.byteLength); p.set(ivC, 0); p.set(ctC, 12);
  return (await unwrapNoteKey(TACET, 'jr1w.' + b64(p), pass, salt)) === null;
})());
await A('encryptWithKey 產物餵 unwrap（長度恆不符 60B）→ null（短 payload 鍛造面對照）', await (async () => {
  const kekC = await craftKek;
  const short = await encryptWithKey(kekC, 'ab'.repeat(16), 'notekey'); // iv12+ct48 = 60B ≠ 92B
  return (await unwrapNoteKey(TACET, 'jr1w.' + short, pass, salt)) === null;
})());
// guest 空 identity 自洽密文面（P5 的行為承載）：手工以 K_u(prefix‖'') 造密文——
// 舊碼（守衛缺席）下 deriveGuestKey('')＝同一把「空帳號金鑰」→ 解開＝NON-NULL 假相；
// 新契約下解密面守衛先擋＝null。這是解密面守衛唯一真咬的行為向量。
await A('guest 空 identity 自洽密文 → decryptNote null（「空帳號金鑰」整族拒絕＝解密面守衛承載）', await (async () => {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('tacet-note-u1')));
  const kuEmpty = await crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const cipherEmpty = 'jr1g.' + await encryptWithKey(kuEmpty, note, 'noteId:n1');
  return (await decryptNote(TACET_GUESTOK, makeHeldKey(), cipherEmpty, 'noteId:n1', emptyIdp)) === null;
})());
// 錯誤碼語意分離（目標 6）：空 PIN ≠ 未配置；jr3d 兩 case 同碼分流
await A('wrapNoteKeyDual 空 PIN → ERR_PIN_EMPTY（非 NOT_CONFIGURED）', await (async () => {
  try { await wrapNoteKeyDual(TACET2, noteKey, passD, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual 空 PIN 全形空白正規化後 → ERR_PIN_EMPTY', await (async () => {
  try { await wrapNoteKeyDual(TACET2, noteKey, passD, '　'); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual 未配置 wrapDual → ERR_DUAL_NOT_CONFIGURED（契約不變）', await (async () => {
  try { await wrapNoteKeyDual(TACET, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_DUAL_NOT_CONFIGURED'; }
})());
await A('wrapNoteKeyDual3 空 PIN → ERR_PIN_EMPTY（t_7710c766：兩 case 同碼分流）', await (async () => {
  try { await wrapNoteKeyDual3(TACET3, noteKey, passD, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual3 未配置 wrapDual3 → ERR_JR3W_NOT_CONFIGURED（契約不變）', await (async () => {
  try { await wrapNoteKeyDual3({}, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_JR3W_NOT_CONFIGURED'; }
})());
// PH1 鹽注入（目標 4）：預設舊值零行為變更
await A('derivePh1Argon 預設鹽零行為變更（同 pass 同值）',
  (await derivePh1Argon('probe-determinism-pass-42')) === ph1v2a);
async function srcOf(rel: string): Promise<string> {
  // node 內建模組動態存取（structured type，零 node types 依賴——argon2.ts getBuiltinModule 母型同構；
  // TS2591 types 帽下 import('node:fs') 靜態/動態皆炸＝此繞法）
  const fs = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { readFileSync?: (p: string, enc: string) => string } | undefined };
  }).process?.getBuiltinModule?.('node:fs');
  if (!fs?.readFileSync) throw new Error('ERR_FS_UNAVAILABLE');
  return fs.readFileSync(new URL(rel, import.meta.url).pathname, 'utf8');
}
await A('derivePh1Argon 預設分支源碼面 = encode(PH1_V2_SALT)（鹽預設單一真相錨；同-pass 同值斷言對預設值漂移無承載力）',
  /saltArg \?\? new TextEncoder\(\)\.encode\(PH1_V2_SALT\)/.test(await srcOf('../src/client/argon2.ts')));
await A('derivePh1Argon 自選鹽 → 不同派生值', (await derivePh1Argon('probe-determinism-pass-42', new Uint8Array(12))) !== ph1v2a);
await A('derivePh1Argon 自選鹽 hex64 形', /^[0-9a-f]{64}$/.test(await derivePh1Argon('x', new Uint8Array(12))));
await A('PH1_V2_SALT re-export 在場（index barrel；其他產品可見可注入同源鹽）', PH1_V2_SALT === 'tacet-ph1-v1');
// index barrel 新匯出（目標 5）：clearLocalWrap/buildBindPayload（review「缺匯出」條誤差已校正＝本卡以閘承載）
await A('index barrel 匯出 clearLocalWrap/buildBindPayload', await (async () => {
  const src = await import('../src/index.ts');
  return typeof src.clearLocalWrap === 'function' && typeof src.buildBindPayload === 'function';
})());
// PinLockConfig 死欄退場（t_7710c766）：型別面真齒＝excess-property 探針（round 1 審查 MINOR-3：
// 舊形 typeof cfg==='object' 恆真空轉）——dead 欄復活（毒化輪補回 noteKeyExtractable）即 TS2353 紅；
// 本面綠態＝core+tacet 摘欄後編譯綠。@ts-expect-error 只入毒化形（pristine 待位錯誤＝TS2578 自擋）。
const _cfgProbe: PinLockConfig = { pinLock: 'jr1p.', pinLockSaltPrefix: 'p:', pinLockAad: 'notekey-pinlock' };
// 壞 b64 面向量（openNoteKey 誠實契約「任何不符恆回 null 不拋」的可觀察承載——round 1 MINOR-5）：
await A('鍛造壞 base64 面字符 → unwrapNoteKey null（openNoteKey unb64 拋點吞收＝不拋契約）',
  (await unwrapNoteKey(TACET, 'jr1w.' + '!!not-base64!!', pass, salt)) === null);
await A('openNoteKey 直接呼叫：壞 base64 → null 不拋（本體吞收點）', await (async () => {
  const kekC = await craftKek;
  return (await openNoteKey('jr1w.' + '!!not-base64!!', kekC, 'notekey', 'jr1w.')) === null;
})());

// ── 決議 ────────────────────────────────────────────────────────────────────

console.log(`\n${passed} 斷言全綠` + (failures.length ? `；${failures.length} 失敗` : ''));
if (failures.length) {
  console.error('失敗項：', failures);
  process.exit(1);
}
console.log('CORE-CRYPTO-VERIFY-OK');