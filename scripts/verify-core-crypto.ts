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
  normalizePassphrase,
  encryptAttach,
  decryptAttach,
  encryptLocal,
  decryptLocal,
  hexToBytes,
  encryptWithKey,
  decryptWithKey,
  b64 as modB64,
  unb64 as unb64Mod,
  deriveGuestKey,
  sealNoteKey,
  importAesGcm,
} from '../src/client/note-crypto.ts';
import {
  verifyArgonKat,
  wrapNoteKey3,
  unwrapNoteKey3,
  wrapNoteKeyDual3,
  unwrapNoteKeyDual3,
  wrapNoteKey4,
  unwrapNoteKey4,
  wrapNoteKeyDual4,
  unwrapNoteKeyDual4,
  ARGON_MEMORY_KIB,
  ARGON_ITERATIONS,
  ARGON_PARALLELISM,
  ARGON_TAG_LEN,
  derivePh1Argon,
  derivePh1ArgonV3,
  PH1_V2_SALT,
  PH1_V3_SALT,
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
import { CORS_HEADERS, corsResponse } from '../src/server/cors.ts';

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

// ── 3. 包裹三件套（pass / rec / 本機；2026-09-24 效能審查節——buildBindPayload 兩段
//      PBKDF2 600k 已由卡C t_7361b68c 收 Promise.all 並行，node 實測 133-152ms→68-84ms） ──

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
// 卡C 收口：本地複製退場、直呼模組 unb64（單一真相；t_7361b68c [14] 導入面；
// round 2 NIT-5：轉手 wrapper 本身退場——呼叫端直用模組 unb64）。
const payload2 = unb64Mod(dual.wrapped.slice('jr2w.'.length));
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
const payload3 = unb64Mod(w3.wrapped.slice('jr3w.'.length));
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
const bindPayloadProbe = await buildBindPayload(TACET, noteKey, pass, recToken, identityA);
await A('[14] buildBindPayload wrappedRec 去重帳（p.wrappedRec ≠ p.wrapped＋rec 套件 unwrapNoteKeyWithRecToken 救回 origRaw）',
  (async () => {
    if (bindPayloadProbe.wrappedRec === bindPayloadProbe.wrapped) return false;
    const kRec = await unwrapNoteKeyWithRecToken(TACET, bindPayloadProbe.wrappedRec, recToken, identityA);
    return kRec !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', kRec))) === origRaw;
  })());
await A('[14] buildBindPayload recTokenHash 去重帳（p.recTokenHash === recTokenHash(recToken) 恆等；錯綁 passphrase 即 RED）',
  bindPayloadProbe.recTokenHash === (await recTokenHash(recToken)) && bindPayloadProbe.recTokenHash !== (await recTokenHash(pass)));
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
// ratelimit 行為面（t_b91ed07f；r2 MAJOR-2 收口）：真 node:sqlite 直載 UPSERT…RETURNING 單句，
// 行為斷言全數「真生產函式 checkRate 直驅」——D1 形 shim 包 node:sqlite 只做 D1 run() 的
// {results} 回帶形，無測試端 glue 副本。表名直插 SQL＝注入面驗證；放行判準 count<=max
// 單一真相。同 IP 真併發不 undercount 的 D1 活線證據見卡 comments（wrangler dev 探針：
// UPSERT…RETURNING 於 wrangler 4.129.0 workerd 逐發回真值；併發首發兩發計數 1→2）。
type RateRow = { ip: string; window_start: number; count: number };
const RATE: RateWindow = { table: 'login_rate', windowMs: 60_000, max: 3 };
const makeRateDb = (): {
  db: {
    exec: (s: string) => void;
    prepare: (s: string) => { all: (...p: unknown[]) => Array<Record<string, unknown>>; get: (...p: unknown[]) => Record<string, unknown> | undefined };
  };
  row: (ip: string) => RateRow | undefined;
  runRaw: (sql: string) => void;
  check: (ip: string) => Promise<boolean>;
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
  return {
    db,
    row: (ip: string) =>
      db.prepare('SELECT * FROM login_rate WHERE ip = ?').get(ip) as RateRow | undefined,
  runRaw: (sql) => db.exec(sql),
    // 真 checkRate 直驅：?1/?2/?3 有名參數語意在 node:sqlite 與 workerd 一致（端對端探針實證，見卡 comments）。
    check: (ip) =>
      checkRate(
        {
          DB: {
            prepare: (sql: string) => ({
              bind: (...p: unknown[]) => ({
                run: async () => ({ results: db.prepare(sql).all(...p), meta: {} }),
              }),
            }),
          },
        } as unknown as Parameters<typeof checkRate>[0],
        RATE,
        ip,
      ),
  };
};
await A('rate：真 checkRate 窗內首發 pass（D1-shim 直驅；RETURNING n=1）', await (async () => {
  const r = makeRateDb();
  return (await r.check('ip-1')) === true && JSON.stringify(r.row('ip-1'))?.includes('"count":1');
})());
await A('rate：同 IP 連發衝突臂計數 1→2（UPSERT 單句原子——同鍵衝突逐發累計不 undercount；真併發面由 D1 活線探針承載見卡 comments）', await (async () => {
  const r = makeRateDb();
  return (await r.check('ip-c')) === true && (await r.check('ip-c')) === true && r.row('ip-c')?.count === 2;
})());
await A('rate：同 IP 三發 pass、第四發 reject（真 checkRate；放行判準 count<=max）', await (async () => {
  const r = makeRateDb();
  const seq = [await r.check('ip-3'), await r.check('ip-3'), await r.check('ip-3'), await r.check('ip-3')];
  return seq[0] === true && seq[1] === true && seq[2] === true && seq[3] === false;
})());
await A('rate：真 checkRate 窗口過期整窗重置（舊窗 seed→重置發放行且 n=1 不吃 max 帽；window_start 換新至真時鐘）', await (async () => {
  const r = makeRateDb();
  r.runRaw("INSERT INTO login_rate (ip, window_start, count) VALUES ('ip-w', 1000, 99)");
  const ok = (await r.check('ip-w')) === true;
  const row = r.row('ip-w');
  return ok && row?.count === 1 && (row?.window_start ?? 0) > 1_700_000_000_000;
})());
await A('rate：真 checkRate count 不封頂（超額發照實累計 6——審計可見非靜默吞）', await (async () => {
  const r = makeRateDb();
  for (let i = 0; i < 6; i++) await r.check('ip-m');
  return r.row('ip-m')?.count === 6;
})());
await A('rate：真 checkRate 他 IP 隔離（計數互不干擾）', await (async () => {
  const r = makeRateDb();
  await r.check('ip-a');
  await r.check('ip-b'); await r.check('ip-b');
  return r.row('ip-a')?.count === 1 && r.row('ip-b')?.count === 2;
})());
await A('rate：checkRate 呼叫端形（env.DB.prepare→bind→run；餵 D1 的 SQL 直插面）＋fail-open', await (async () => {
  const calls: string[] = [];
  const env12 = { DB: {
    prepare: (sql: string) => ({
      bind: (..._p: unknown[]) => ({ run: async () => { calls.push(sql); throw new Error('D1_DOWN'); } }),
    }),
  } };
  const ok = await checkRate(env12 as unknown as Parameters<typeof checkRate>[0], RATE, 'ip-fail');
  return ok === true && calls.length === 1 && calls[0].startsWith('INSERT INTO') && calls[0].includes('RETURNING');
})());
await A('rate：表名注入拒絕（直插 SQL 面）', await (async () => {
  try { await checkRate({ DB: { prepare: () => { throw new Error('SHOULD_NOT_PREPARE'); } } } as unknown as Parameters<typeof checkRate>[0], { table: 'x; DROP TABLE users--', windowMs: 1000, max: 3 }, 'ip'); return false; }
  catch (e) { return String((e as Error).message).startsWith('ERR_RATE_TABLE_NAME'); }
})());
await A('rate：表名 \\w 合法（字母數字底線）', await (async () => {
  try { await checkRate({ DB: { prepare: () => { throw new Error('D1_DOWN_FAILOPEN'); } } } as unknown as Parameters<typeof checkRate>[0], { table: 'login_rate_2', windowMs: 1000, max: 3 }, 'ip'); return true; }
  catch (e) { return String((e as Error).message).startsWith('ERR_RATE_TABLE_NAME') === false && String((e as Error).message).includes('D1_DOWN_FAILOPEN'); }
})());
await A('rate：RETURNING 異形回應守衛 fail-open（results 空／alias 斷裂——與儲存故障同向，r2 MINOR-3 不反向 deny）', await (async () => {
  const mkEnv = (run: () => Promise<unknown>) =>
    ({ DB: { prepare: () => ({ bind: () => ({ run }) }) } } as unknown as Parameters<typeof checkRate>[0]);
  const empty = await checkRate(mkEnv(async () => ({ results: [] })), RATE, 'ip');
  const alias = await checkRate(mkEnv(async () => ({ results: [{ m: 1 }] })), RATE, 'ip');
  return empty === true && alias === true;
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
await A('isCipherFor 空字首組態 → false（\x27\x27 態 startsWith(\x27\x27) 恆真 accept-all——run 574 MINOR-3：cipherPrefixRe 守衛不覆蓋直讀 tuple 面，同向收口；非字串 false 契約照舊）',
  (() => {
    const emptyTuple: CipherFormats = { cipherPrefixes: ['', ''], wrapPrefix: 'jr1w.', cipherMax: 5000 };
    const mixed: CipherFormats = { cipherPrefixes: ['', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 5000 };
    return isCipherFor('jr1g.abc', emptyTuple) === false && isCipherFor('純明文', emptyTuple) === false &&
      isCipherFor('jr1g.abc', mixed) === false && // 混合形：空槽摘除、真前綴面承載
      isCipherFor('jr1b.abc', mixed) === true && // 真前綴面零誤傷
      isCipherFor(null, formats) === false; // 非字串 false 面（typed 形合法態；運行時 typeof 守衛承載 unknown 呼叫端）
  })());
await A('makeInboundCipher regex 跳脫全字面（r2 MAJOR-1 辨別形重推——探針新舊碼輸出一手實測，兩向分歧各一）',
  (() => {
    // 舊碼 .replace('.','\\.') 只跳第一個點，前綴含 regex 符號（| ( )）時家族 regex 失真，
    // 兩方向輸出分歧（一手對照探針帳面：tmp probe-d1.cjs，main 舊碼 vs 分支新碼）：
    // ①完整前綴形『a.b|c()』+A*600（真家族密文標記）：正碼辨得前綴 → >max 密文丟棄 null；
    //   舊碼 regex 辨不出自家前綴 → 誤落明文截斷（>max 密文截半損毀＝舊碼 slice(0,500)）。
    // ②點前截形『a.b』+A*600：舊碼 a\.b 殘臂（從頭起 b64 全程）誤咬 → 丟棄 null；
    //   正碼前綴不完整非家族 → 明文截斷照收 slice(0,500)。兩形缺一即探針無齒（r1 教訓）。
    const f: CipherFormats = { cipherPrefixes: ['a.b|c()', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 500 };
    const m = makeInboundCipher(f);
    const full = 'a.b|c()' + 'A'.repeat(600);
    const dotHead = 'a.b' + 'A'.repeat(600);
    return m(full) === null && m(dotHead) === dotHead.slice(0, 500);
  })());
// N-7（t_580f9c54）：cipherPrefixRe 空字首組態毒形——never-match 守衛的行為面。
// run 574 r2 校正（新舊碼組裝對照一手實測 /tmp/t580f9c54-r2/n7-corrected-probe.mjs）：舊碼
// `[]` 與 `['']` 組裝出 byte-identical `^()[A-Za-z0-9+/]+={0,2}$`（join('|') 同為空串），
// `['','']` 僅多空首選交替 `^(|)…`＝同面——真洞＝無點純 b64 串（≤200）在舊碼
// validWrappedKey/pickKeyPackage 放行（NON-NULL）；帶點前綴向量（'jr1w.'+b64）舊碼本就 null
// （'.' 在 b64 charset 外）＝帳面無承載。r1 版敘事（charset 恆假自帶防線／空槽首選交替洞）經
// run 574 一手實證俱誤——本段已按實測帳重寫（revert-poison 案為守衛還原面的直接承載）。
// 守衛後（usable 過濾＋never-match）：家族/re 面整面拒絕；inboundCipher 輸出面 zero delta
// （家族路摘除後長路徑 b64≤max 短路進 legacy 慣例層、超限丟棄、明文相容層照收——出口與舊碼
// RE 路徑恆等，probe 33 組合實證）；混合『['','jr1b.']』形只摘空槽、真前綴家族面照活（降級非全拒）。
await A('N-7 真洞還原面：無點純 b64 ≤200 空字首組態 → null（cipherPrefixRe never-match——守衛摘除即翻紅；三組態）',
  (() => {
    const pureB64 = b64(new Uint8Array(32)); // 無點 b64（44 字符）——舊碼本就放行＝真洞載體（帶點向量舊碼本就 null，無承載）
    const emptyTuple = ['', ''];
    return validWrappedKey(pureB64, []) === null &&
      validWrappedKey(pureB64, emptyTuple) === null &&
      validWrappedKey(pureB64, '') === null; // string 形空前綴同面
  })());
await A('N-7 pickKeyPackage 空字首組態 → 整組放棄（validWrappedKey never-match 傳播——wrapped/salt 同 null）',
  (() => {
    const p = pickKeyPackage({ wrapped: b64(new Uint8Array(32)), salt: 'a'.repeat(32) }, ['', '']);
    return p.wrapped === null && p.salt === null;
  })());
await A('inboundCipher 空字首組態：輸出面 zero delta（family RE 摘除後長路徑 b64≤max 落 legacy 慣例層、超限丟棄、明文相容層照收——probe 33 組合實證舊≡新，僅路徑歸層從家族 RE 移到 b64 慣例層）',
  (() => {
    const mEmpty = makeInboundCipher({ cipherPrefixes: ['', ''], wrapPrefix: 'jr1w.', cipherMax: 500 });
    const mOneEmpty = makeInboundCipher({ cipherPrefixes: ['', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 500 });
    const plain = '純明文日記內容';
    const pureB64 = b64(new Uint8Array(32)); // 44 字符 >40＝legacy b64 慣例面（家族路拒絕後的唯一去處）
    return mEmpty(plain) === plain.slice(0, 500) && // 明文相容層照收（家族守衛不誤傷 prefix 無關面）
      mEmpty(pureB64) === pureB64 && // 家族路摘除後 b64 落 legacy 慣例層（與舊碼 RE+慣例短路出口恆等）
      mOneEmpty('jr1b.' + b64(new Uint8Array(32))) === 'jr1b.' + b64(new Uint8Array(32)) && // 混合形只摘空槽——真前綴家族面照活
      mOneEmpty(plain) === plain.slice(0, 500);
  })()); // 真前綴放行面對照＝下兩案「validWrappedKey：合法包裹／pickKeyPackage：成對成立」（同體放行帳，不另立重複案）
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
  const bytes = unb64Mod(pinWrapped.slice('jr1p.'.length)); bytes[3] ^= 0x01;
  return (await unwrapNoteKeyPinLock(PINLOCK, 'jr1p.' + b64(bytes), '2580ab')) === null;
})());
await A('jr1p payload 竄改 ct 尾 → null', await (async () => {
  const bytes = unb64Mod(pinWrapped.slice('jr1p.'.length)); bytes[bytes.length - 1] ^= 0x01;
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
// 舊碼（無 rawHex 長度/形檢）下 32-hex 假 noteKey 與 'zz' 前綴零化 hex 皆 NON-NULL＝假金鑰生產器。
const craftKek = (async (): Promise<CryptoKey> => {
  // deriveKek 鏡像（未匯出）：PBKDF2-SHA256(pass, salt, 600k) → AES-GCM-256。
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: hexToBytes(salt) as BufferSource, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
})();
// 鍛造面（格式嚴格契約的可觀察承載；毒化前提）：KEK 已知者可造任意形 payload——
// 舊碼（無 rawHex 長度/形檢）下 'zz' 前綴零化 hex 與 32-hex 假 noteKey 皆 NON-NULL＝假金鑰生產器。
// round 1 審查 MAJOR-1 校正：鍛造 encrypt 必帶 additionalData('notekey')＝與 decryptWithKey
// 同 AAD——缺 AAD 的鍛造 GCM 層恆拒＝rawHex 形檢從未執行（斷言空轉）。
// craftKek 鏡像真 deriveKek（同 pass 同 salt 同 600k）＝鍛造鏈與真 unwrap 同 KEK：
// 有效形鍛造真解開（NON-NULL 自證鏈活）、畸形形由各檢查點拒——機制面直接可觀察。
// AAD 單一化（r2 NIT-a）：F_AAD 是四鍛造向量唯一 AAD 源（對 decryptWithKey 同 AAD 律的 helper 收口）。
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
await A('鍛造 92B payload 的零化 hex rawHex（zz 前綴）→ null（rawHex HEX_RE 形檢＋hexToBytes fail-closed 雙層——單摘任一被次層接住，P2 同摘 6F 才翻；帶 AAD 真解後形檢拒）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('zz' + 'a'.repeat(62)) as BufferSource));
  const p = new Uint8Array(12 + ctC.byteLength); p.set(ivC, 0); p.set(ctC, 12);
  return (await unwrapNoteKey(TACET, 'jr1w.' + b64(p), pass, salt)) === null;
})());
// 短 payload 鍛造（60B：iv+ct(hex32假 noteKey)）→ null：openNoteKey 嚴格長度檢的可觀察承載
//（僅 hexToBytes fail-closed 擋不住「合法 hex 的假 32B 金鑰」——長度檢獨立承載）。
await A('鍛造 60B payload（合法 hex 32B 假 noteKey，帶 AAD）→ null（openNoteKey 嚴格 92B 長度檢＋rawHex 64B 長度雙層——P1b 同摘才翻）', await (async () => {
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
// 舊形 typeof cfg==='object' 恆真空轉）。r2 MINOR-2 實測校正（t_580f9c54；行號帳由 P12 毒化 tsc 輸出承載
// 而非註解寫死——新增段推移行號＝註解行號帳漂移，NIT-a 同病禁再犯）：required 復活形＝TS2741（PINLOCK
// 常數面）＋TS2345（未配置兩案），optional 復活形＝舊形探針未帶該欄＝excess-property 檢照不到＝tsc 0 綠——robust 形＝pristine 就在探針字面量帶 `noteKeyExtractable:
// undefined as never`＋前置 @ts-expect-error：欄位復活任何形（required/optional/false 字面量）都多出待位錯誤＝TS2578 紅；
// pristine 態錯誤恰由 expect-error 吸收＝全 repo tsc 0 綠（探針字面量缺 false 形欄不另生錯＝零加值面除名）。
// 本面綠態＝core+tacet 摘欄後編譯綠。@ts-expect-error 常駐在場（robust 形，見上註）；pristine 態恰由其吸收。
// @ts-expect-error — 死欄退場待位錯誤面（pristine 恰此一待位錯由本指令吸收；欄位復活任何形＝本指令反噬 TS2578＝P12 案紅）
const _cfgProbe: PinLockConfig = { pinLock: 'jr1p.', pinLockSaltPrefix: 'p:', pinLockAad: 'notekey-pinlock', noteKeyExtractable: undefined as never };
void _cfgProbe;
// 壞 b64 面向量（openNoteKey 誠實契約「任何不符恆回 null 不拋」的可觀察承載——round 1 MINOR-5）：
await A('鍛造壞 base64 面字符 → unwrapNoteKey null（openNoteKey unb64 拋點吞收＝不拋契約；家族面毒化形＝頂層 crash，本面包 try/catch 收乾淨 ✗）', await (async () => {
  try {
    return (await unwrapNoteKey(TACET, 'jr1w.' + '!!not-base64!!', pass, salt)) === null;
  } catch { return false; } // 吞收契約破形（本體或呼叫端漏 catch）＝本面 false 紅，非 runner crash
})());
await A('openNoteKey 直接呼叫：壞 base64 → null 不拋（本體吞收點）', await (async () => {
  const kekC = await craftKek;
  return (await openNoteKey('jr1w.' + '!!not-base64!!', kekC, 'notekey', 'jr1w.')) === null;
})());

// ── 14. 效能形契約（卡C t_7361b68c：零行為變更——輸出 byte 等價是合約；錨面咬「形」） ──
//
// 效能批的閘承載物理：執行時間不能進閘（機器相依）——咬「並行形在場＋串行殘留歸零」
// 靜態錨＋「Argon 串行刻意保留」負向＋b64 輸出等價行為面＋Max-Age/sideEffects 字面＋
// ikm 組裝序行為向量（KAT14 凍結 blob）。執行帳（node 26.8.1 實測，2026-10-04）：
// buildBindPayload 串行 133-152ms→並行 68-84ms；dual 串行 234→並行 179ms median；
// b64 4MiB 132-181ms→18ms。瀏覽器帳=review 222ms→27ms。

console.log('\n[14] 效能形契約（buildBindPayload 並行／b64 分塊／argon 禁並行／CORS Max-Age／sideEffects）');

const noteCryptoSrc14 = await srcOf('../src/client/note-crypto.ts');
const argon2Src14 = await srcOf('../src/client/argon2.ts');
const corsSrc14 = await srcOf('../src/server/cors.ts');
await A('[14] buildBindPayload 兩段共用 Promise.all 並行錨（wrapNoteKey＋wrapNoteKeyWithRecToken）',
  /await Promise\.all\(\[\r?\n\s*wrapNoteKey\(cfg, noteKey, passphrase\),\r?\n\s*wrapNoteKeyWithRecToken\(cfg, noteKey, recToken, identity\)/.test(noteCryptoSrc14));
await A('[14] deriveKek2 輸入順序錨（pass 段 raw 收口形＋Promise.all 相鄰形——O2 毒形即本錨翻面）',
  /await Promise\.all\(\[\r?\n\s*derivePbkdf2Bits\(passphrase, salt1, PBKDF2_ITERATIONS\),\r?\n\s*derivePbkdf2Bits\(pin,/.test(noteCryptoSrc14));
await A('[14] deriveKek2Argon 正向串行錨（pass/pin 兩段 deriveArgon2id 串行在場）',
  /const passBits = await deriveArgon2id\(/.test(argon2Src14) && /const pinBits = await deriveArgon2id\(/.test(argon2Src14));
await A('[14] argon2 destructure 並行形歸零（舊串行面對稱收口——r2 MAJOR-1 防逆向回歸）',
  argon2Src14.split('const [passBits, pinBits] = await Promise.all([').length === 1);
await A('[14] buildBindPayload 舊串行形歸零（await wrapNoteKeyWithRecToken 串行殘留）',
  !noteCryptoSrc14.includes('await wrapNoteKeyWithRecToken'));
await A('[14] deriveKek2 舊串行形歸零（串行 passBits 殘留）',
  !/const passBits = await derivePbkdf2Bits/.test(noteCryptoSrc14));
// r2 MAJOR-1：並行錨升左手側——destructure 與 Promise.all 相鄰形恰一，對調滑接（pin‖pass）
// 即 RED（RHS 指令序不變＝原本體並行錨不動，兩錨分工：RHS 面／組件序面）。
await A('[14] deriveKek2 destructure 左手側恰一（const [passBits, pinBits] ＋ Promise.all 相鄰形——swap 滑接即 RED）',
  noteCryptoSrc14.split('const [passBits, pinBits] = await Promise.all([').length === 2);
// MAJOR-1 行為面：bea6ab8 逐值凍結 jr2w. blob（手工 pristine 組裝＝passBits@0‖pinBits@32 序）——
// destructure 對調滑接產 pin‖pass ikm＝本 blob 不可解（reviewer rev-harm 雙向一手：pristine 自解
// true／互解 null；r2 樹 A/C/B/D/E/F 六腿同帳，探針存證 kanban 工作區）。凍結定值自足：
// salt1 'a1'×16／pinSalt 0xb2+i×16／iv 0x44+i×12／raw 'c3'×32／pass/pin 明寫——重放＝按定值
// 重建 KEK2（HKDF info 'journal-kek2-v1:jr2w.'、aad 'notekey2'）比對 unwrap=raw。
const KAT14 = {
  blob: 'jr2w.srO0tba3uLm6u7y9vr/AwURFRkdISUpLTE1OTy8+hmx+AhMYCgPVBH1Q1q1UnjPF9uvN/ie4DoYqh4LGkMTHvHDy/Sku/lMRvoRWfuqSuIlX0rEpVU8HfMajsaYtzaz1zHFQELEIuzTsM6+S',
  salt1: 'a1'.repeat(16),
  pass: 'correct-horse-battery-staple-42',
  pin: '482913',
  raw: 'c3'.repeat(32), // 計算式構造（手打對數面禁止——r2 首跑 1 FAIL 即手打 raw 對數錯的實證）
};
await A('[14] jr2w. ikm 組裝序行為向量（bea6ab8 凍結 blob unwrap=raw——destructure 對調滑接不可解）',
  (async () => {
    const k = await unwrapNoteKeyDual(TACET2, KAT14.blob, KAT14.pass, KAT14.pin, KAT14.salt1);
    if (k === null) return false;
    return hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === KAT14.raw;
  })());
await A('[14] argon 側禁並行警示在場（deriveKek2Argon 串行刻意——hash-wasm 共享記憶體池）',
  /禁並行/.test(argon2Src14) && !argon2Src14.includes('await Promise.all'));
await A('[14] b64 分塊 apply 錨＋舊逐位元組形歸零（fromCharCode(bytes[i]) 殘留）',
  noteCryptoSrc14.includes('String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)') &&
  !noteCryptoSrc14.includes('String.fromCharCode(bytes[i])'));
// b64 行為面：分塊後輸出必逐位元組等價（本閘起手 b64 是獨立複製＝黃金對照）；邊界尺寸
//（0/1/7/8191/8192/8193）咬窗緣、65539 非 8192 倍數咬長尾、4MiB 咬分塊多輪＋unb64 全往返。
const b64Ref14 = (bytes: Uint8Array): string => {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};
{
  let boundsEq = true;
  for (const size of [0, 1, 7, 8191, 8192, 8193]) {
    const buf = new Uint8Array(size);
    for (let i = 0; i < size; i++) buf[i] = (i * 7 + 3) & 0xff;
    if (modB64(buf) !== b64Ref14(buf)) boundsEq = false;
  }
  await A('[14] b64 輸出等價：邊界尺寸 0/1/7/8191/8192/8193 逐位元組對照', boundsEq);
}
await A('[14] b64 輸出等價：65539（非 8192 倍數長尾）逐位元組對照', (() => {
  const buf = new Uint8Array(65539);
  for (let i = 0; i < buf.length; i++) buf[i] = (i * 13 + 5) & 0xff;
  return modB64(buf) === b64Ref14(buf);
})());
await A('[14] b64 輸出等價：4MiB 多區塊＋unb64 roundtrip 逐位元組',
  (() => {
    const buf = new Uint8Array(4 * 1024 * 1024);
    for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
    const s = modB64(buf);
    if (s !== b64Ref14(buf)) return false;
    const back = unb64Mod(s);
    if (back.byteLength !== buf.byteLength) return false;
    for (let i = 0; i < buf.length; i++) if (back[i] !== buf[i]) return false;
    return true;
  })());
await A('[14] CORS_HEADERS 帶 Access-Control-Max-Age（preflight 快取 86400）',
  CORS_HEADERS['Access-Control-Max-Age'] === '86400' && /'Access-Control-Max-Age': '86400'/.test(corsSrc14));
await A('[14] CORS 其餘三頭零變（ACAO *／Methods GET, POST, OPTIONS／Headers Content-Type, Authorization）',
  CORS_HEADERS['Access-Control-Allow-Origin'] === '*' &&
  CORS_HEADERS['Access-Control-Allow-Methods'] === 'GET, POST, OPTIONS' &&
  CORS_HEADERS['Access-Control-Allow-Headers'] === 'Content-Type, Authorization');
await A('[14] corsResponse 仍完整轉發四頭（corsResponse 面帶 Max-Age）',
  (() => {
    const h = new Headers({ 'x-probe': '1' });
    const out = corsResponse(new Response('ok', { headers: h }));
    return Object.entries(CORS_HEADERS).every(([k, v]) => out.headers.get(k) === v) && out.headers.get('x-probe') === '1';
  })());
{
  const fsPkg14 = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { readFileSync?: (p: string, enc: string) => string } | undefined };
  }).process?.getBuiltinModule?.('node:fs');
  const pkg14 = JSON.parse(fsPkg14!.readFileSync!(new URL('../package.json', import.meta.url).pathname, 'utf8')) as { sideEffects?: boolean; version: string };
  await A('[14] package.json sideEffects:false（tree-shake server 模組＋BIP39 詞表）', pkg14.sideEffects === false);
  // sideEffects 前提（round 2 MINOR-1 升級）：src 標目 **遞迴** 枚舉（硬編碼清單退場——新模組
  // 自動入掃），頂層語句白名單化＋**宣告行初始化式呼叫面檢查**（const x = fn() 形＝執行點；
  // Object.freeze(...)/純常數結構白名單——wordlist.ts:7 即此形）。
  await A('[14] sideEffects 前提：src 頂層零副作用語句＋宣告行初始化式零裸呼叫（Object.freeze 白名單）',
    await (async () => {
      const fs14 = (globalThis as unknown as {
        process?: { getBuiltinModule?: (id: string) => { readFileSync?: (p: string, enc: string) => string; readdirSync?: (p: string) => string[] } | undefined };
      }).process?.getBuiltinModule?.('node:fs');
      if (!fs14?.readFileSync || !fs14?.readdirSync) return false;
      const urlOf = (p: string) => new URL(`../${p}`, import.meta.url).pathname;
      const listTs = (dir: string): string[] => fs14.readdirSync!(urlOf(dir)).flatMap((e: string) => {
        const full = `${dir}/${e}`;
        let isDir = false;
        try { fs14.readdirSync!(urlOf(full)); isDir = true; } catch { isDir = false; }
        if (isDir) return listTs(full);
        return e.endsWith('.ts') ? [full] : [];
      });
      const files = listTs('src');
      if (files.length < 12) return false; // 枚舉自守衛：src 樹不該少於既有 12 模組
      let offenders = 0;
      for (const f of files) {
        const lines = fs14.readFileSync!(urlOf(f), 'utf8').split('\n');
        for (const line of lines) {
          if (/^[a-zA-Z(/{\[]/.test(line)) {
            // 頂層語句白名單：import/export＋註解＋純宣告（const/let/var/function/async/
            // interface/type/enum/class/declare）——其餘字母開頭頂層＝執行面 side effect。
            if (/^(import\b|export\b|\/\*\*|\*|\/\/|const\b|let\b|var\b|function\b|async\b|interface\b|type\b|enum\b|class\b|declare\b)/.test(line)) {
              // 宣告行初始化面：const x = <呼叫形>()＝模組載入即執行（NIT MINOR-1 缺口）。
              // 白名單：Object.freeze（純凍結常數）。其餘呼叫形初始化＝offender。
              if (/^(const\b|let\b|var\b|export const\b).*=.*\b[A-Za-z_$][\w$]*\(\s*[^)]/.test(line) &&
                  !/Object\.freeze\(/.test(line)) offenders++;
            } else offenders++;
          }
        }
      }
      return offenders === 0;
    })());
}

// ── 15. 密語正規化 v3 世代（v0.2.0 批卡①：normalizePassphrase＋jr4w./jr4d.＋PH1 v3） ──
//
// 帶內版本化母型實例：密語 KEK 輸入契約改變（raw → normalizePassphrase NFKC-only）＝新前綴。
// 命名兩軸分離：卡D 文案「v3 家族」＝PH1 規格代（derivePh1ArgonV3）；前綴數字軸 jr4w./jr4d.
// ＝KDF 世代代（jr1w→jr2w→jr3w→jr4w，README 家族表對照）。舊家族（jr1w./jr2w./jr3w./jr3d.）
// 函式體零改＝raw 契約永久不變——本節同字面雙家族對照向量（ＰＡＳＳ１２x／PASS12x）就是
// 「免換前綴合約證明」的承載面：同組字串在舊家族恆異 KEK（raw 直派生）、在 v3 家族恆同 KEK（NFKC 收容）。

console.log('\n[15] 密語正規化 v3 世代（normalizePassphrase／jr4w.／jr4d.／PH1 v3）');

const noteCryptoSrc15 = await srcOf('../src/client/note-crypto.ts');
const argon2Src15 = await srcOf('../src/client/argon2.ts');
const TACET4: Argon3Config = { wrap4: 'jr4w.', wrapDual4: 'jr4d.', pinSalt3Prefix: 'tacet-note-pin3:' };
const pass4 = 'v3-generation-passphrase-42';
const passD4 = 'ｄｕａｌ－ｆａｃｔｏｒ－ｐａｓｓｐｈｒａｓｅ－４２'; // NFKC → passD 的全形形
const passD4_NFKC = normalizePassphrase(passD4); // 與 passD 恆等（NFKC 收容）——P2 毒化翻面本體（r2 CRITICAL-1：毒形即收口形計數錨翻＋毒翻 = NFKC-effective 帳面翻，雙承載）

// 函式契約面（單一真相本體：normalizePassphrase 與 normalizePin 並存不混）
await A('normalizePassphrase NFKC 契約：全形收容（ｐａｓｓ=pass）', normalizePassphrase('ｐａｓｓ') === 'pass');
await A('normalizePassphrase NFKC 契約：結合序列合成（カ+U+3099=ガ——NFD/NFC 裝置差收容）',
  normalizePassphrase('カ\u3099x') === 'ガx');
await A('normalizePassphrase 分離向量一：不 trim（首尾空白保留）', normalizePassphrase(' pass ') === ' pass ');
await A('normalizePassphrase 分離向量二：大小寫恆異（大小寫摺疊禁絕——大小寫差＝不同 KEK/ph2）',
  normalizePassphrase('PaSs') === 'PaSs' && normalizePassphrase('PaSs') !== normalizePassphrase('pass') && normalizePassphrase('PaSs') !== normalizePassphrase('PASS'));
await A('normalizePassphrase 與 normalizePin 契約並存不混（同輸入兩形＝兩輸出）',
  normalizePin(' Ｐｉｎ42 ') === 'pin42' && normalizePassphrase(' Ｐｉｎ42 ') === ' Pin42 ');

// jr4w. 單因子（v3 密語）roundtrip
const w4 = await wrapNoteKey4(TACET4, noteKey, pass4);
await A('wrapped 前綴 jr4w.', w4.wrapped.startsWith('jr4w.'));
await A('jr4w salt = 16B hex', /^[0-9a-f]{32}$/.test(w4.salt));
const unwrapped4 = await unwrapNoteKey4(TACET4, w4.wrapped, pass4, w4.salt);
await A('jr4w unwrap 等值 noteKey（extractable 再 export）',
  unwrapped4 !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped4))) === origRaw);
await A('jr4w 正規化等價：ASCII wrap → 全形 unwrap（unwrap 入口 NFKC 承載）', (await unwrapNoteKey4(TACET4, w4.wrapped, 'ｖ３－ｇｅｎｅｒａｔｉｏｎ－ｐａｓｓｐｈｒａｓｅ－４２', w4.salt)) !== null);
const w4Nfd = await wrapNoteKey4(TACET4, noteKey, 'カ\u3099ｘｙ');
await A('jr4w NFKC 等價：NFD 形 wrap → NFC 形 unwrap', (await unwrapNoteKey4(TACET4, w4Nfd.wrapped, 'ガxy', w4Nfd.salt)) !== null);
const w4Case = await wrapNoteKey4(TACET4, noteKey, 'V3-Generation-Pass-42');
await A('jr4w raw 大小寫不折疊（v3 契約只收容寫法差，不收大小寫差）',
  (await unwrapNoteKey4(TACET4, w4Case.wrapped, 'v3-generation-pass-42', w4Case.salt)) === null);
const w4Sp = await wrapNoteKey4(TACET4, noteKey, ' spaced pass ');
await A('jr4w raw 首尾空白為不同密語（不 trim 契約家族面）',
  (await unwrapNoteKey4(TACET4, w4Sp.wrapped, 'spaced pass', w4Sp.salt)) === null);
await A('jr4w 錯 pass → null', (await unwrapNoteKey4(TACET4, w4.wrapped, 'wrong-passphrase', w4.salt)) === null);
await A('jr4w 錯 salt → null', (await unwrapNoteKey4(TACET4, w4.wrapped, pass4, 'ab'.repeat(16))) === null);

// jr4d. 雙因子（v3 密語＋PIN 照舊）——wrap 端吃全形（NFKC 載體），unwrap 端兩向都咬
const dual4 = await wrapNoteKeyDual4(TACET4, noteKey, passD4, pinD); // 全形 wrap＝NFKC 載體（cp1=0xFF44——ASCII 化即本面 RED）
await A('dual4 前綴 jr4d.', dual4.wrapped.startsWith('jr4d.'));
await A('dual4 salt1 = 16B hex', /^[0-9a-f]{32}$/.test(dual4.salt));
const unwrappedD4 = await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, pinD, dual4.salt);
const dual4NfkEq = unwrappedD4 !== null
  && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrappedD4))) === origRaw; // 全形 wrap → NFKC 形：unwrap 真救回（null 恆 false＝normalize 摘除不可藏）
await A('dual4 unwrap 等值 noteKey（extractable 再 export；全形 wrap 面 NFKC 等價自證——not-null 恆 false 恆真盲區免疫）', dual4NfkEq);
const dual4a = await wrapNoteKeyDual4(TACET4, noteKey, passD, pinD); // ASCII NFKC 慣用形 wrap（passD＝passD4 的 NFKC 位——上式自證）
const dual4NfkRev = dual4a !== null && (await unwrapNoteKeyDual4(TACET4, dual4a.wrapped, passD4, pinD, dual4a.salt)) !== null; // ASCII 包 → 全形解（MAJOR-1 修真向：feed passD4；無 NFKC 即 null）
await A('dual4 pass 段 NFKC 反向等價（ASCII wrap → 全形 unwrap；PIN 段契約不動）', dual4NfkRev === true);
await A('dual4 PIN 大小寫不敏感（normalizePin 契約 v3 世代照舊）', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '2580AB', dual4.salt)) !== null);
await A('dual4 PIN 全形 NFKC 等價', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '２５８０ＡＢ', dual4.salt)) !== null);
await A('dual4 錯 PIN → null', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '999999', dual4.salt)) === null);
await A('dual4 空 PIN → null（unwrap 面）', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '', dual4.salt)) === null);
await A('wrapNoteKeyDual4 空 PIN → ERR_PIN_EMPTY（非 NOT_CONFIGURED——t_7710c766 分流 v3 世代照舊）', await (async () => {
  try { await wrapNoteKeyDual4(TACET4, noteKey, passD, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('dual4 payload 嚴格 108B（截短 → null——鹽內嵌族 own 檢查在場）', await (async () => {
  try {
    const short = new Uint8Array(107);
    crypto.getRandomValues(short);
    let bin = '';
    for (let i = 0; i < short.byteLength; i++) bin += String.fromCharCode(short[i]);
    return (await unwrapNoteKeyDual4(TACET4, 'jr4d.' + btoa(bin), passD, pinD, dual4.salt)) === null;
  } catch { return false; }
})());
await A('dual4 pass 段大小寫與空白恆異（不摺疊不 trim——v3 契約 unwrap 側真行為面）',
  (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, 'DUAL-FACTOR-PASSPHRASE-42', pinD, dual4.salt)) === null
  && (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD + ' ', pinD, dual4.salt)) === null);
await A('jr4d unwrap 配置面 {wrapDual4 有、pinSalt3Prefix 無} → null（家族守衛雙腿各自承載）',
  (await unwrapNoteKeyDual4({ wrapDual4: 'jr4d.' }, dual4.wrapped, passD, pinD, dual4.salt)) === null);

// 同字面兩家族對照（帶內版本化本質向量）：ＰＡＳＳ１２x／PASS12x
const fwPass15 = 'ＰＡＳＳ１２x';
const asciiPass15 = 'PASS12x';
await A('[15] NFKC 契約向量（fwPass15 ＝ asciiPass15 的 NFKC-effective 全形——self-proving 錨：字面漂移即本面 RED）',
  normalizePassphrase(fwPass15) === asciiPass15);
const w4fw = await wrapNoteKey4(TACET4, noteKey, fwPass15);
await A('jr4w 全形/ASCII 同密語（NFKC 收容）', (await unwrapNoteKey4(TACET4, w4fw.wrapped, asciiPass15, w4fw.salt)) !== null);
const w3fw = await wrapNoteKey3(TACET3, noteKey, fwPass15); // 舊家族 raw 對照組（同字面）
await A('jr3w 全形 wrap 照解（舊家族 raw 契約——全形字面恆可解）', (await unwrapNoteKey3(TACET3, w3fw.wrapped, fwPass15, w3fw.salt)) !== null);
await A('jr3w 拒收 normalized 慣用形（舊家族零正規化——帶內版本化「契約面永不變」承載）', (await unwrapNoteKey3(TACET3, w3fw.wrapped, asciiPass15, w3fw.salt)) === null);
await A('jr4w unwrap 拒收 jr3w 字串（家族隔離；wrap3 未配置面）', (await unwrapNoteKey4(TACET4, w3.wrapped, pass, w3.salt)) === null);
await A('jr3w unwrap 拒收 jr4w 字串（家族隔離——wrap3 在場、payload 前綴不符恆 null）',
  (await unwrapNoteKey3(TACET3, w4.wrapped, pass4, w4.salt)) === null);
await A('jr3d payload 餵 jr4d 路徑 → null（家族隔離）', (await unwrapNoteKeyDual4(TACET4, dual3.wrapped, passD, pinD, dual3.salt)) === null);
await A('jr4d payload 餵 jr3d 路徑 → null（家族隔離）', (await unwrapNoteKeyDual3(TACET3, dual4.wrapped, passD, pinD, dual4.salt)) === null);

// 跨前綴隔離：jr4w.↔jr1w. 双向（PBKDF2 族面——鹽外置同構家族跨世代隔離；jr3↔jr4 面在下方 jr3d/jr4d 兩案）
await A('jr4w unwrap 拒收 jr1w 字串（家族隔離——raw 世代 payload 餵 v3 路徑）',
  (await unwrapNoteKey4(TACET4, wrapped, pass, salt)) === null);
await A('jr1w unwrapNoteKey 拒收 jr4w 字串（家族隔離——v3 payload 餵 raw 世代路徑）',
  (await unwrapNoteKey(TACET2, w4.wrapped, pass4, w4.salt)) === null);

// 舊家族凍結向量（PBKDF2 族面）：jr1w./jr2w. 契約面永不變——全形字面 raw 恆解、normalized 慣用形恆拒
//（帶內版本化承載與 jr3w. 對照組同構；jr3 面雙案在上方 fwPass15 三案）
const old1fw = await wrapNoteKey(TACET, noteKey, fwPass15);
await A('jr1w 凍結（raw 契約）：全形 wrap 照解（raw 字面恆可解）',
  (await unwrapNoteKey(TACET, old1fw.wrapped, fwPass15, old1fw.salt)) !== null);
await A('jr1w 凍結：normalized 慣用形解 → null（不隨 v3 正規化——帶內版本化）',
  (await unwrapNoteKey(TACET, old1fw.wrapped, asciiPass15, old1fw.salt)) === null);
const old2fw = await wrapNoteKeyDual(TACET2, noteKey, fwPass15, pinD);
await A('jr2w 凍結（pass 段 raw 契約）：normalized 解 → null（pin 段 normalizePin 契約不動）',
  (await unwrapNoteKeyDual(TACET2, old2fw.wrapped, asciiPass15, pinD, old2fw.salt)) === null);
await A('jr2w 凍結：全形 wrap 照解（raw 字面恆可解）',
  (await unwrapNoteKeyDual(TACET2, old2fw.wrapped, fwPass15, pinD, old2fw.salt)) !== null);
// 未配置拒絕（opt-in 鐵律 v3 世代照舊）
await A('未配置 wrap4 → wrapNoteKey4 拒絕', await (async () => { try { await wrapNoteKey4({}, noteKey, pass4); return false; } catch (e) { return (e as Error).message === 'ERR_JR4W_NOT_CONFIGURED'; } })());
await A('未配置 wrapDual4 → wrapNoteKeyDual4 拒絕（ERR_JR4D_NOT_CONFIGURED——語意分離同 t_7710c766）', await (async () => { try { await wrapNoteKeyDual4({}, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_JR4D_NOT_CONFIGURED'; } })());
await A('未配置 wrap4 → unwrap 拒收 jr4w', (await unwrapNoteKey4({ wrapDual4: 'jr4d.' }, w4.wrapped, pass4, w4.salt)) === null);

// PH1 v3（normalizePassphrase 派生＋新鹽域）
const ph1v3a = await derivePh1ArgonV3('probe-v3-pass-42');
await A('ph1v3 確定性（同 pass 兩跑逐位元同）', ph1v3a === (await derivePh1ArgonV3('probe-v3-pass-42')));
await A('ph1v3 hex64 形', /^[0-9a-f]{64}$/.test(ph1v3a));
await A('ph1v3 NFKC 等價（全形=NFKC 形同 ph2——PH2 UNIQUE 契約面）', (await derivePh1ArgonV3('ｐｒｏｂｅ－ｖ３－ｐａｓｓ－４２')) === ph1v3a);
await A('ph1v3 大小寫恆異（不分大小寫＝不同 ph2）', (await derivePh1ArgonV3('PROBE-V3-PASS-42')) !== ph1v3a);
await A('ph1v3 空白恆異（不 trim＝不同 ph2）', (await derivePh1ArgonV3(' probe-v3-pass-42 ')) !== ph1v3a);
await A('ph1v3 ≠ v2 形（同字面不同值——鹽域世代分離）', ph1v3a !== (await derivePh1Argon('probe-v3-pass-42')));
await A('PH1_V3_SALT = "tacet-ph1-v2"（鹽域值代沿 PH1_V2_SALT 先例；與 v2 鹽域及包裹鹽前綴零重疊）',
  PH1_V3_SALT === 'tacet-ph1-v2' && (PH1_V3_SALT as string) !== PH1_V2_SALT && !PH1_V3_SALT.startsWith('tacet-note') && !PH1_V3_SALT.startsWith('tacet-pinlock'));
await A('derivePh1ArgonV3 預設分支源碼面 = encode(PH1_V3_SALT)（鹽預設單一真相錨；同 v2 母型）',
  /saltArg \?\? new TextEncoder\(\)\.encode\(PH1_V3_SALT\)/.test(argon2Src15));
await A('derivePh1ArgonV3 自選鹽 → 不同派生值（卡A #4 saltArg 慣例）',
  (await derivePh1ArgonV3('probe-v3-pass-42', new Uint8Array(12))) !== ph1v3a);
await A('derivePh1Argon v2 預設零動（raw 契約——舊世代派生面零變更）', (await derivePh1Argon('probe-determinism-pass-42')) === ph1v2a);

// 源碼結構面（帶內版本化「舊家族零改」的錨）
await A('[15] normalizePassphrase 本體＝單行 NFKC（三面單一真相——函式體禁夾帶 trim/toLowerCase）',
  /export function normalizePassphrase\(passphrase: string\): string \{\r?\n  return passphrase\.normalize\('NFKC'\);\r?\n\}/.test(noteCryptoSrc15));
await A('[15] 舊家族 KEK 派生 raw 面守衛（deriveKekArgon(passphrase 恰 2＝jr3w wrap/unwrap；deriveInput 形恰 2＝jr4w 兩面）',
  argon2Src15.split('deriveKekArgon(passphrase, salt)').length === 3
  && argon2Src15.split('deriveKekArgon(deriveInput(passphrase)').length === 3);
await A('[15] deriveKek2Argon 零改（共用派生本體不吃 normalize——kekk2Argon 簽名與 body 兩錨在場）',
  /async function deriveKek2Argon\(/.test(argon2Src15) && /const passBits = await deriveArgon2id\(passphrase,/.test(argon2Src15));
await A('[15] jr4w/jr4d 入口 normalize 走 deriveInput 收口（兩面恰 2——normalize 形歸零非旁路；正規化禁進共用本體）',
  argon2Src15.split('deriveKek2Argon(cfg, deriveInput(passphrase)').length === 3
  && argon2Src15.split('deriveKekArgon(deriveInput(passphrase)').length === 3
  && argon2Src15.split('deriveArgon2id(\n    deriveInput(passphrase)').length === 2
  && !argon2Src15.includes('deriveKekArgon(normalizePassphrase(passphrase'));
await A('[15] deriveKek2Argon HKDF info 參數化（jr3d/jr4d 域由呼叫端帶入——本體 hardcoded info 域殘留=0）',
  /hkdfInfo: string,/.test(argon2Src15)
  && argon2Src15.split("deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual3)").length === 3
  && argon2Src15.split("deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4)").length === 3
  && !argon2Src15.includes("encode('journal-kek2-v1:' + cfg.wrapDual3)"));

// barrel 匯出面
await A('index barrel 匯出 v3 世代七識別字（normalizePassphrase／jr4 家族四／derivePh1ArgonV3／PH1_V3_SALT）', await (async () => {
  const src = await import('../src/index.ts');
  return typeof src.normalizePassphrase === 'function' && typeof src.wrapNoteKey4 === 'function'
    && typeof src.unwrapNoteKey4 === 'function' && typeof src.wrapNoteKeyDual4 === 'function'
    && typeof src.unwrapNoteKeyDual4 === 'function' && typeof src.derivePh1ArgonV3 === 'function'
    && src.PH1_V3_SALT === 'tacet-ph1-v2';
})());

// ── 決議 ────────────────────────────────────────────────────────────────────

// ── 16. 常駐毒化矩陣（v0.2.0 批卡①自帶——對真模組行為斷言的毒化證據隨每執行重建） ──
//
// 母型（t_0ab6e760 閘常駐毒化面）：對 /tmp 拷貝樹做突變後重跑同一組行為斷言——
// 「毒化態恰翻面」meta 斷言承載外部 poison runner 的證據；毒化跑在拷貝樹＝本 repo 樹零接觸。
// 期望值每毒型真跑實測（r2 本 run /tmp 拷貝樹一手實測，見各案 comment 歸屬帳）；還原面由
// /tmp 樹的出生即棄承載（本 repo 樹 byte 不動）。每案還原後重跑回綠（還原正確性的行為帳）。
//
// 案期望值（r2 修正後程式碼上 /tmp 毒化重測，本 run 一手帳——還原後重跑回綠帶）：
//   P1 摘 jr4w unwrap 入口 normalize → nfail=4 帳（正規化等價面＋KAT 慣用形帳面＋兩 [15] 錨跟隨）
//   P2 本體夾帶 lowercase → nfail=11 帳（NFKC-effective 帳面翻面集；P3/P4/P5 針毒形零匹配＝全格向量化）
//   P3 摘 derivePh1ArgonV3 入口 normalize → nfail=2 帳（ph1v3 NFKC 等價面＋[15] 收口形錨）
//   P4 摘 jr4w wrap 入口 normalize → nfail=4 帳（NFD 收容面＋全形/ASCII 同密語面＋兩 [15] 錨）
//   P5 摘 jr4d wrap 入口 normalize → nfail=5 帳（dual4 等值面＋PIN 兩面＋兩 [15] 錨）
//   O1 jr3w.wrap 入口接 normalize（禁手）→ nfail=4 帳（jr3w 凍結兩面＋兩 [15] 錨）
//   O2 deriveKek2 pass 段接 normalize（禁手）→ nfail=2 帳（[14] 輸入順序錨＋jr2w 凍結 normalized 面）
//   O3 normalizePin 摘 trim/lowercase → nfail=9 帳（>=帽——MINOR-3 韌性；PIN 契約毒化真 RED）
//   O4 摘 jr4d unwrap 入口 normalize（反拉禁手）→ nfail=4 帳（NFKC 反向等價面＋KAT 慣用形帳面＋兩 [15] 錨）
//   O1-src/O2-src/O4-src 源碼計數錨（[15] 同形複寫——防單點誤删，NIT-3）：
//   v3 家族入口 normalize 收口形恰 3×3＋PBKDF2 raw 恰 1——毒化形即計數變異，本 repo 樹直接斷言。
// 每案結束後還原／清樹（出生即棄）；designated 面帳寫在案例名內。

console.log('\n[16] 常駐毒化矩陣（v3 家族語意毒＋舊家族不變毒）');
{
  const getBuiltin = (id: string): unknown =>
    (globalThis as unknown as { process?: { getBuiltinModule?: (i: string) => unknown } }).process?.getBuiltinModule?.(id);
  const cpMod = getBuiltin('node:child_process') as { execFileSync?: (cmd: string, args: string[], opts: { cwd: string; encoding: string; stdio: unknown[]; env?: Record<string, string> }) => string } | undefined;
  const osMod = getBuiltin('node:os') as { tmpdir?: () => string } | undefined;
  const nodeEnvOk = !!cpMod?.execFileSync && !!osMod?.tmpdir && typeof (globalThis as unknown as { process?: { getBuiltinModule?: unknown } }).process?.getBuiltinModule === 'function';
  const processMod = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process;
  const inner16 = processMod?.env?.POISON_GATE_INNER === '1';
  if (!nodeEnvOk || inner16) {
    await A('[16] 毒化矩陣載體就緒（node 內建模組在場；內層遞迴由 sentinel 跳過＝正常；缺席＝顯性 FAIL）', inner16, 'env unavailable AND not inner');
  } else {
    const exec16 = cpMod!.execFileSync!;
    const path16 = {
      join: (...parts: string[]): string => parts.join('/').replace(/\/{2,}/g, '/'),
      resolve: (...parts: string[]): string => parts.join('/').replace(/\/\.(?=\/|$)/g, '').replace(/\/{2,}/g, '/'),
    };
    const fs16 = getBuiltin('node:fs') as {
      rmSync?: (p: string, o?: { recursive: boolean; force: boolean }) => void;
      cpSync?: (a: string, b: string, o?: { recursive: boolean; dereference?: boolean; filter?: (src: string) => boolean }) => void;
      readFileSync?: (p: string, e?: string) => string;
      writeFileSync?: (p: string, c: string, e?: string) => void;
      mkdtempSync?: (p: string) => string;
      existsSync?: (p: string) => boolean;
    } | undefined;
    if (!fs16?.mkdtempSync || !fs16.cpSync || !fs16.readFileSync || !fs16.writeFileSync) {
      await A('[16] node:fs 原語在場（mkdtemp/cp/read/write）', false);
    } else {
      const treePaths16: string[] = []; // MINOR-2 修正：殘留判準只看本 run 喚出的 tree16 路徑（跨執行/跨 host 零耦合）
      const tmpdir16 = osMod!.tmpdir!();
      const coreNM = path16.resolve(new URL('.', import.meta.url).pathname, '../node_modules');
      const repoRoot16 = path16.resolve(new URL('.', import.meta.url).pathname, '..'); // MINOR-4：repo root 錨定（禁 cwd 依賴——自 repo 外呼叫 cp 樹也恆真）
      const gitIgnoreSkip = (src: string): boolean => src === '.git' || src.endsWith('/.git') || src.includes('/.git/') || src === 'node_modules' || src.endsWith('/node_modules') || src.includes('/node_modules/');
      let tree16 = '';
      const mkTree = (): void => {
        fs16!.rmSync!(tree16, { recursive: true, force: true });
        tree16 = fs16!.mkdtempSync!(path16.join(tmpdir16, 'core-poison-'));
        treePaths16.push(tree16); // 本 run 喚出記帳（MINOR-2：收尾殘留判準的封閉集）
        fs16!.cpSync!(repoRoot16, tree16, { recursive: true, filter: (src: string) => !gitIgnoreSkip(src) }); // MINOR-6＋r2 MINOR-4：零 .git/零 node_modules 實拷（repo root 錨定——非 cwd；CI 冷複製成本歸零——毒化樹 node_modules 走下方 symlink）
        fs16!.rmSync!(path16.join(tree16, 'node_modules'), { recursive: true, force: true });
        // node_modules 走 symlink（worktree 慣例 cp 語意不跟隨）：本閘執行樹一定有 node_modules
        //（@scure 對照組＋typescript）——毒化樹補 symlink 即可；缺席環境（bare npm ci 後無 install）
        // 本閘自己在主樹就跑不起來，不是毒化矩陣的責任面。
        exec16('ln', ['-s', nodeEnvOk ? coreNM : '', path16.join(tree16, 'node_modules')], { cwd: tree16, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      };
      const runGate16 = (): { rc: number; out: string } => {
        // 內層 gate 執行帶 POISON_GATE_INNER=1 sentinel——[16] 矩陣在內層自我跳過＝遞迴防線
        //（拷貝樹的閘檔含本節全文；無 sentinel 會自拷貝再自跑＝18+ 連鎖行程實證）。
        try { return { rc: 0, out: exec16('node', ['--experimental-strip-types', 'scripts/verify-core-crypto.ts'], { cwd: tree16, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...(processMod?.env ?? {}), POISON_GATE_INNER: '1' } }) }; }
        catch (e: unknown) {
          const err = e as { stdout?: string; stderr?: string; status?: number };
          return { rc: err.status ?? 1, out: (err.stdout ?? '') + (err.stderr ?? '') };
        }
      };
      const poison16 = (rel: string, needle: string, replacement: string): { applied: boolean; restore: () => void } => {
        const p = path16.join(tree16, rel);
        const before = fs16!.readFileSync!(p, 'utf8');
        const cnt = before.split(needle).length - 1;
        fs16!.writeFileSync!(p, before.split(needle).join(replacement), 'utf8');
        return { applied: cnt > 0 && !(fs16!.readFileSync!(p, 'utf8').includes(needle)), restore: (): void => fs16!.writeFileSync!(p, before, 'utf8') };
      };
      const realFails = (out: string): string[] => out.split('\n').filter((l: string) => l.trimStart().startsWith('✗')).map((l: string) => l.trim());
      const nfail = (out: string): number => realFails(out).length;
      mkTree();
      const pristine = runGate16();

      await A('[16] 基準：拷貝樹 pristine = 全綠（毒化矩陣前提；rc=1 即環境病非本節）', pristine.rc === 0, 'rc=' + pristine.rc + (pristine.rc === 0 ? '' : ' | stderr tail: ' + pristine.out.split('\n').filter((l: string) => l.trim()).slice(-3).join(' ;; ').slice(0, 220)));

      // P1 摘 jr4w unwrap 入口 normalize → 行為翻 4 面帳（本 run 毒化重測：jr4w 正規化等價面＋[15] raw
      // 守衛錨＋[15] 收口形錨＋[17] jr4w NFKC 慣用形帳面）——名單面 designated＝正規化等價面＋dual4 等值面（案內檢）。
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "    const kek = await deriveKekArgon(deriveInput(passphrase), salt);\n    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap4);",
          "    const kek = await deriveKekArgon(passphrase, salt);\n    return await openNoteKey(wrapped, kek, 'notekey', cfg.wrap4);");
        const g = runGate16();
        // P1 名單面 designated（r2 MAJOR-2，本 run 重測帳）：jr4w 正規化等價面＋[17] jr4w NFKC 慣用形
        // 帳面兩面真翻——摘除 unwrap 入口 normalize 時 normalized 形失去收容（dual4 等值面不翻＝wrap 端
        // normalize 仍承載，P1 針只咬 unwrap 面——P5 已咬 wrap 面；兩針分工面帳）。
        const p1eqRed = g.out.split('\n').some((l: string) => l.includes('jr4w 正規化等價') && l.trimStart().startsWith('✗'));
        const p1katRed = g.out.split('\n').some((l: string) => l.includes('NFKC-effective 全形 unwrap = 原始 noteKey（v3 契約收容自己——全形 wrap 的 KAT 慣用形）') && l.trimStart().startsWith('✗'));
        const red = mut.applied && g.rc === 1 && nfail(g.out) >= 2 && p1eqRed && p1katRed;
        await A('[16] P1 摘 jr4w unwrap 入口 normalize → 正規化等價面＋KAT 慣用形帳面真翻（nfail=4 帳——非錨影）', red, 'nfail=' + nfail(g.out));
        mut.restore();
        const g2 = runGate16();
        fs16!.rmSync!(tree16, { recursive: true, force: true });
        await A('[16] P1 還原回綠（出生即棄樹上還原；P2 共樹後不可達案由出生即棄承載）', g2.rc === 0, String(g2.rc));
      }
      // P2 本體夾帶 lowercase → NFKC-effective 行為翻面集（r2 CRITICAL-1 重測：nfail=11 帳——非 crash 形）
      {
        mkTree();
        const mut = poison16('src/client/note-crypto.ts',
          "export function normalizePassphrase(passphrase: string): string {\n  return passphrase.normalize('NFKC');\n}",
          "export function normalizePassphrase(passphrase: string): string {\n  return passphrase.normalize('NFKC').toLowerCase();\n}");
        const g = runGate16();
        // P2 名單面 designated（r2 CRITICAL-1 重測帳）：NFKC-effective 帳面翻面集（分離向量二＋並存不混＋jr4w
        // raw 大小寫不折疊＋dual4 case/space＋[15] NFKC 契約向量＋ph1v3 大小寫恆異＋[17] 大寫兩形 null 四面＋本體
        // 單行形錨）＝11 面帳；同 P3/P4/P5 毒形零匹配（全格向量化——毒化矩陣單點真值面）。
        const p2normRed = g.out.split('\n').some((l: string) => l.includes('分離向量二') && l.trimStart().startsWith('✗'));
        await A('[16] P2 本體夾帶 lowercase → NFKC-effective 帳面翻面集（nfail>=11 帳＋分離向量二名單面）', mut.applied && g.rc === 1 && nfail(g.out) >= 11 && p2normRed, 'rc=' + g.rc + ' nfail=' + nfail(g.out));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // P3 摘 derivePh1ArgonV3 入口 normalize → 行為翻 2 面帳（本 run 毒化重測：ph1v3 NFKC 等價面＋[15] 收口形
      // 錨跟隨）——名單面 designated＝ph1v3 NFKC 等價面（案內檢）；P3 毒形＝derivePh1Argon v2 名同型不匹配（全格向量化）。
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "    deriveInput(passphrase),\n    saltArg ?? new TextEncoder().encode(PH1_V3_SALT),",
          "    passphrase,\n    saltArg ?? new TextEncoder().encode(PH1_V3_SALT),");
        const g = runGate16();
        // P3 名單面 designated（r2 MAJOR-2）：ph1v3 NFKC 等價面（全形 vs ASCII 同 ph2）真翻。
        const p3red = g.out.split('\n').some((l: string) => l.includes('ph1v3 NFKC 等價') && l.trimStart().startsWith('✗'));
        await A('[16] P3 摘 derivePh1ArgonV3 入口 normalize → ph1v3 NFKC 等價面真翻（名單級承載）', mut.applied && g.rc === 1 && nfail(g.out) >= 1 && p3red, 'nfail=' + nfail(g.out));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // P4 摘 jr4w wrap 入口 normalize → 行為翻 4 面帳（本 run 毒化重測：NFD wrap→NFC unwrap 面＋全形/ASCII 同
      // 密語面＋[15] raw 守衛錨＋[15] 收口形錨）——名單面 designated＝全形/ASCII 同密語面（案內檢）。
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "  const kek = await deriveKekArgon(deriveInput(passphrase), salt);\n  const wrapped = await sealNoteKey(cfg.wrap4, noteKey, kek, 'notekey');",
          "  const kek = await deriveKekArgon(passphrase, salt);\n  const wrapped = await sealNoteKey(cfg.wrap4, noteKey, kek, 'notekey');");
        const g = runGate16();
        // P4 名單面 designated（r2 MAJOR-2）：jr4w 全形/ASCII 同密語面（全形 wrap 的 NFKC 收容）真翻。
        const p4red = g.out.split('\n').some((l: string) => l.includes('jr4w 全形/ASCII 同密語') && l.trimStart().startsWith('✗'));
        await A('[16] P4 摘 jr4w wrap 入口 normalize → 全形/ASCII 同密語面真翻（名單級承載）', mut.applied && g.rc === 1 && nfail(g.out) >= 1 && p4red, 'nfail=' + nfail(g.out));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // P5 摘 jr4d wrap 入口 normalize → 行為翻 5 面帳（本 run 毒化重測：dual4 等值面＋PIN 兩面＋[15] 收口形
      // 錨＋[15] HKDF info 錨）——名單面 designated＝dual4 等值面（dual4red 檈）；PIN 兩面翻＝毒化 wrap 端
      // normalize 摘除的帳面（wrap 端 NFKC-effective 面倒灌 PIN 段）。
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "  const kek2 = await deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n  const iv = crypto.getRandomValues(new Uint8Array(DUAL_IV_LEN));\n  const ct = new Uint8Array(await crypto.subtle.encrypt(",
          "  const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n  const iv = crypto.getRandomValues(new Uint8Array(DUAL_IV_LEN));\n  const ct = new Uint8Array(await crypto.subtle.encrypt(");
        const g = runGate16();
        const dual4red = g.out.split('\n').some((l: string) => l.includes('dual4 unwrap 等值') && l.trimStart().startsWith('✗'));
        await A('[16] P5 摘 jr4d wrap 入口 normalize → dual4 self-proving 面翻（帳面 ✗ 計數免疫——✓-line 內嵌 ✗ 標記不入計）', mut.applied && g.rc === 1 && dual4red, 'rc=' + g.rc);
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O3 normalizePin 本體摘 trim/lowercase → 行為翻 ≥9 面（外部探針帳實值）
      {
        mkTree();
        const mut = poison16('src/client/note-crypto.ts',
          '  return pin.normalize(\'NFKC\').trim().toLowerCase();',
          '  return pin.toLowerCase();');
        const g = runGate16();
        await A('[16] O3 normalizePin 本體摘 trim/lowercase → 行為翻 9 面（PIN 契約毒化承載）', mut.applied && g.rc === 1 && nfail(g.out) >= 9, 'nfail=' + nfail(g.out) + ' want >=9');
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O2 deriveKek2 pass 段接 normalize（禁手形）→ 真翻面案（r2 MAJOR-2 名單級承載；本 run 重測帳＝
      // [14] 輸入順序錨翻＋jr2w 凍結 normalized 面翻，恰 2 面——兩面各自 designated，帳寫在案斷言內）。
      {
        mkTree();
        const mut = poison16('src/client/note-crypto.ts',
          "  const [passBits, pinBits] = await Promise.all([\n    derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS),",
          "  const [passBits, pinBits] = await Promise.all([\n    derivePbkdf2Bits(normalizePassphrase(passphrase), salt1, PBKDF2_ITERATIONS),");
        const g = runGate16();
        // O2 行為翻 2 面帳（本 run 毒化重測）：[14] 輸入順序錨（毒形不匹配 raw 收口形恰-1 形）＋jr2w 凍結
        // normalized 解翻面（毒化 wrap 也 normalize → ascii 形同 KEK）——名單級承載＝[14] 輸入順序錨面（案內檢）；
        // nfail 精確 2 帳＝P5/P1 形的錨翻面恰補位（姊妹卡新增 PIN/dual 覆蓋時 >= 帽韌性——MINOR-3）。
        const o2rawRed = g.out.split('\n').some((l: string) => l.includes('[14] deriveKek2 輸入順序錨') && l.trimStart().startsWith('✗'));
        await A('[16] O2 deriveKek2 pass 段接 normalize（禁手形）→ raw 收口形錨翻＋jr2w 凍結面翻（nfail>=2；名單級承載）',
          mut.applied && g.rc === 1 && nfail(g.out) >= 2 && o2rawRed, 'rc=' + g.rc + ' nfail=' + nfail(g.out) + ' fails=' + realFails(g.out).map(s => s.slice(0, 44)).join(';;'));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O1 jr3w.wrap 入口接 normalize（禁手形）→ 行為翻 4 面帳（本 run 毒化重測：jr3w 全形照解面翻＋normalized
      // 恆拒面翻＋[15] raw 守衛錨＋[15] 收口形錨）——行為 designated＝凍結兩面（raw 入口契約復活即翻）。
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "  const kek = await deriveKekArgon(passphrase, salt);\n  const wrapped = await sealNoteKey(cfg.wrap3, noteKey, kek, 'notekey');",
          "  const kek = await deriveKekArgon(deriveInput(passphrase), salt);\n  const wrapped = await sealNoteKey(cfg.wrap3, noteKey, kek, 'notekey');");
        const g = runGate16();
        // O1 名單面 designated（r2 MAJOR-2，本 run 重測帳）：jr3w 凍結兩面（全形照解面翻＋normalized 恆拒
        // 面翻）＝raw 入口契約復活的行為齒；4 面帳＝兩行為面＋兩 [15] 錨跟隨。
        const o1fwRed = g.out.split('\n').some((l: string) => l.includes('jr3w 全形 wrap 照解') && l.trimStart().startsWith('✗'));
        const o1normRed = g.out.split('\n').some((l: string) => l.includes('jr3w 拒收 normalized 慣用形') && l.trimStart().startsWith('✗'));
        await A('[16] O1 jr3w.wrap 入口接 normalize（禁手形）→ 凍結兩面真翻（nfail=4 帳；名單級承載）',
          mut.applied && g.rc === 1 && nfail(g.out) >= 2 && o1fwRed && o1normRed, 'rc=' + g.rc + ' nfail=' + nfail(g.out) + ' fails=' + realFails(g.out).map(s => s.slice(0, 44)).join(';;'));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O4 unwrapNoteKeyDual4 入口接 raw（v3 反拉形）→ 「毒態」行為面翻轉樣本（MAJOR-2 面修正後真有齒）
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "    const kek2 = await deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');",
          "    const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');");
        const g = runGate16();
        // O4 名單面 designated（r2 MAJOR-2，本 run 重測帳）：dual4 pass 段 NFKC 反向等價面（MAJOR-1 修正後
        // unwrap 餵 passD4 的真反向）＋[17] jr4d NFKC 慣用形帳面——反拉 normalize 時 unwrap 餵 normalized 形
        // 失去收容 = 該面 null = 行為齒（非只 rc 計數）；行為翻 4 面帳＝反向等價面＋兩 [15] 錨＋[17] 帳面。
        const o4red = g.out.split('\n').some((l: string) => l.includes('dual4 pass 段 NFKC 反向等價') && l.trimStart().startsWith('✗'));
        const o4katRed = g.out.split('\n').some((l: string) => l.includes('NFKC-effective 全形 unwrap = 原始 noteKey（v3 契約收容自己；info=jr4d 域）') && l.trimStart().startsWith('✗'));
        await A('[16] O4 unwrapNoteKeyDual4 入口接 raw（反拉禁手形）→ NFKC 反向等價面＋KAT 慣用形帳面真翻（nfail=4 帳）',
          mut.applied && g.rc === 1 && nfail(g.out) >= 2 && o4red && o4katRed, 'rc=' + g.rc + ' nfail=' + nfail(g.out) + ' fails=' + realFails(g.out).map(s => s.slice(0, 44)).join(';;'));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O1/O2/O4 的真防線＝源碼計數錨（normalize 收口形恰 3／raw 形恰 2——毒化形即計數變異，本 repo
      // 樹直接斷言＝毒化態「本節自身」翻而不是只翻拷貝樹）：
      {
        const argonSrcNow = await srcOf('../src/client/argon2.ts');
        const ncSrcNow = await srcOf('../src/client/note-crypto.ts');
        // 與 [15] 同形計數錨＝「複寫防單點誤删」（NIT-3：[16] 內層保留 O-案源碼錨——[15] 錨被未來誤删時本段仍咬）。
        await A('[16] O1-src 計數錨（[15] 同形複寫——防單點誤删）：argon2 normalize 收口入口形恰 3（禁手形任何復活＝計數變異即 RED）',
          argonSrcNow.split('deriveKekArgon(deriveInput(passphrase)').length === 3
            && argonSrcNow.split('deriveArgon2id(\n    deriveInput(passphrase)').length === 2
            && argonSrcNow.split('deriveKek2Argon(cfg, deriveInput(passphrase)').length === 3);
        await A('[16] O2-src 計數錨：note-crypto PBKDF2 家族 pass 段 raw 形恰 1 處（deriveKek2；接 normalize 即 RED——raw 錨 length 2）',
          ncSrcNow.split('derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS)').length === 2);
        await A('[16] O4-src 計數錨（[15] 同形複寫）：jr4d unwrap 入口 normalize 形恰 2（wrap/unwrap 對稱；摘除或反拉即變異）',
          argonSrcNow.split('deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm').length === 3);
      }
      // 收尾：毒化樹清理自證（MINOR-2 修正：封閉集——只核對本 run 喚出的 tree16 路徑；跨執行/
      // 並行/host 殘留零耦合——其他 core-poison-* 不入本判準）；每棵出生即棄 rmSync 強制在場。
      {
        const exists16 = fs16!.existsSync!;
        let residual = 0;
        for (const t of treePaths16) if (exists16(t)) residual++;
        await A('[16] 毒化樹零殘留（本 run 喚出 ' + treePaths16.length + ' 棵全清——封閉集判準）',
          treePaths16.length >= 10 && residual === 0, 'trees=' + treePaths16.length + ' residual=' + residual);
      }
    }
  }
}

// ── 17. KAT 凍結向量：HKDF info 域世代分離（CRITICAL-1 修正承載面） ──────────────
//
// 凍結常數計算式構造（t_7361b68c KAT14 母型——raw 'c3'.repeat(32) 寫 c3x32 帳面）：
// jr3w./jr3d.＝舊 raw 族凍結 blob（全形字面 RAW 派生承載；normalized 慣用形恆拒）；
// jr4w./jr4d.＝v3 族凍結 blob（KEK 輸入契約＝normalizePassphrase：normalized 慣用形可解、
// raw 全形形恆拒）。KDF 派生輸入正規化收口（v3）：入口 deriveInput(pass)＝normalizePassphrase
// 本體同語意（NFKC-only：不 trim、不分大小寫——大小寫摺疊禁絕，大小寫差＝不同 KEK/ph2）；
// 正規化禁進共用派生本體（舊家族 raw 契約永不變）。
// jr4d. 的 KEK2 HKDF info 域＝'journal-kek2-v1:' + cfg.wrapDual4（呼叫端帶入）——
// NFKC-effective 密語下 jr3d/jr4d 兩入參數同輸入（bits 段同值），域分離由 info 承載：
// 兩 blob 互解 null（下方案）＋各自 ASCII/全形 unwrap=raw＝KDF 域世代的真行為承載。
// 凍結值：fixed rawKey 'c3'×32；jr3w/jr3d＝全形 RAW 樣本 blob（舊族 raw 承載）；jr4w/jr4d＝
// 全形 NFKC 載體 blob（v3 契約收容態）；pin '2580ab'；salt/pinSalt 逐值自 baked 資料（外探針實測入冊）。
// 大小寫摺疊禁絕帳：ASCII 大寫與全形大寫兩形 → null（全形面上限非 NFKC-only 帳面缺口——大小寫
// 摺疊是另一禁絕面，兩形各自承載）。凍結 blob 逐字面恆定（非動態重演）——驗證期重放＝以 unwrap 端
// KEK 派生（凍結參數）比對 blob 內 baked 密文；「重放」語意＝派生確定性重驗，blob 本體恆凍結。
const KAT17_PASS_NORM = pass4; // v3 段 ASCII 慣用形（NFKC-effective：normalizePassphrase(pass4)==pass4）
const KAT17 = {
  raw: 'c3'.repeat(32),
  // 舊族全形凍結樣本由 ASCII 源計算式派生（同 KAT14 母型「凍結常數計算式構造」——
  // 帶 confusable 字面直接入冊曾實證漂移：gate literal 與真全形一位點碼差＝KAT 靜默拒解）。
  pass3Raw: Array.from('PASS12x').map((c) => String.fromCodePoint(c.codePointAt(0)! + 0xfee0)).join(''),
  pass4fw: Array.from(pass4).map((c) => String.fromCodePoint(c.codePointAt(0)! + 0xfee0)).join(''),
  passDbRaw: Array.from(passD).map((c) => String.fromCodePoint(c.codePointAt(0)! + 0xfee0)).join(''),
  jr3w: 'jr3w.BeQ8F6s3DdJWY853l2jRv5dHtVEMd+tjJ3XuIisu2ymuK7IInuqIvxtwPD3WzhTkEtCRr+h7KOfWo5FM6ELGjPxwxHAp5LtM5zcEg8hmCqH3dMX9iHF7IOQl3Ak=',
  s3: 'f6a511fb29b131869d282d89f9eaa90a',
  jr3d: 'jr3d.nOB7P29euSEa+LM8qMSTRe6r32TbBX7nS2R/WyRJ7N1NO+mqXuW5u9HLiLzYObKHq3NURwiEaxD9qwli646qDoG4/5wlHD7UE9nBT485oUeEx/vYIkmOu4muJQ42avl8zX9M1PSgaP+Bk+R9',
  sd3: 'a06bd4b1f293b8c8ebff4b6a02f13a34',
  jr4w: 'jr4w.x6cZmk7UVUAf8abE3mLps22+BLTdWGTDOZpTs4DqHFUDUcz5p5VpdIqYub/9r+sE2/hYE1fPb68ABSCdDeEvJVXlGOsbDr9L//xsdFcZZYlRtrMO3APSwJQBrv0=',
  s4: '31a8d4ae616ccc0a6def28a9b0db4860',
  jr4d: 'jr4d.Dz8wgY5Lphif69Fh5fE+54J4YBlUJgfVLHBeM7RGr3HUmplys5FpcIK/AZT8zstvsUSpox2mwnpo4eQA9eqtbRK3kTowaWRyAEjTfx4kJS9eMoPQEWsr+GRRYgtdINlgAoVJxyi/NaCNqhDR',
  sd4: 'd6ebccb6c9bb3a0d13905183d2b2977d',
  pin: pinD,
};
  {
    const katRawUnlock = async (key: CryptoKey | null): Promise<boolean> =>
      key !== null && (await hex(new Uint8Array(await crypto.subtle.exportKey('raw', key)))) === KAT17.raw;
    console.log('\n[17] KAT 凍結向量：HKDF info 域世代分離＋v3/raw 入口契約（jr3w./jr3d./jr4w./jr4d. 四 blob）');
    await A('[17] jr3w 凍結 blob：全形 RAW unwrap = 原始 noteKey（舊家族 raw 契約——KAT 承載）',
      katRawUnlock(await unwrapNoteKey3(TACET3, KAT17.jr3w, KAT17.pass3Raw, KAT17.s3)));
    await A('[17] jr3w 凍結 blob：normalized 慣用形 → null（normalized 面恆拒——raw 族零正規化承載）',
      (await unwrapNoteKey3(TACET3, KAT17.jr3w, KAT17_PASS_NORM, KAT17.s3)) === null);
    await A('[17] jr3d 凍結 blob：全形 RAW unwrap = 原始 noteKey（舊家族 raw 契約——KAT 承載；info=jr3d 域）',
      katRawUnlock(await unwrapNoteKeyDual3(TACET3, KAT17.jr3d, KAT17.passDbRaw, KAT17.pin, KAT17.sd3)));
    await A('[17] jr3d 凍結 blob：normalized 慣用形 → null（normalized 面恆拒——鹽內嵌 raw 契約；info=jr3d 域）',
      (await unwrapNoteKeyDual3(TACET3, KAT17.jr3d, passD, KAT17.pin, KAT17.sd3)) === null);
    await A('[17] jr4w 凍結 blob：normalized 慣用形 unwrap = 原始 noteKey（v3 契約——KAT 承載）',
      katRawUnlock(await unwrapNoteKey4(TACET4, KAT17.jr4w, KAT17_PASS_NORM, KAT17.s4)));
    await A('[17] jr4w 凍結 blob：NFKC-effective 全形 unwrap = 原始 noteKey（v3 契約收容自己——全形 wrap 的 KAT 慣用形）',
      katRawUnlock(await unwrapNoteKey4(TACET4, KAT17.jr4w, KAT17.pass4fw, KAT17.s4)));
    await A('[17] jr4w 凍結 blob：fw 大寫形 → null（大小寫差＝不同 KEK——全形載體面上的摺疊禁絕）',
      (await unwrapNoteKey4(TACET4, KAT17.jr4w, KAT17.pass4fw.toUpperCase(), KAT17.s4)) === null);
    await A('[17] jr4w 凍結 blob：ASCII 大寫形 → null（大小寫差＝不同 KEK，v3 契約）',
      (await unwrapNoteKey4(TACET4, KAT17.jr4w, KAT17_PASS_NORM.toUpperCase(), KAT17.s4)) === null);
    await A('[17] jr4d 凍結 blob：normalized 慣用形 unwrap = 原始 noteKey（v3 契約；KEK2 info=jr4d 自有域）',
      katRawUnlock(await unwrapNoteKeyDual4(TACET4, KAT17.jr4d, passD, KAT17.pin, KAT17.sd4)));
    await A('[17] jr4d 凍結 blob：NFKC-effective 全形 unwrap = 原始 noteKey（v3 契約收容自己；info=jr4d 域）',
      katRawUnlock(await unwrapNoteKeyDual4(TACET4, KAT17.jr4d, KAT17.passDbRaw, KAT17.pin, KAT17.sd4)));
    await A('[17] jr4d 凍結 blob：fw 大寫形 → null（大小寫差＝不同 KEK——全形載體面上的摺疊禁絕）',
      (await unwrapNoteKeyDual4(TACET4, KAT17.jr4d, KAT17.passDbRaw.toUpperCase(), KAT17.pin, KAT17.sd4)) === null);
    await A('[17] jr4d 凍結 blob：ASCII 大寫形 → null（大小寫差＝不同 KEK，v3 契約）',
      (await unwrapNoteKeyDual4(TACET4, KAT17.jr4d, passD.toUpperCase(), KAT17.pin, KAT17.sd4)) === null);
    await A('[17] family isolation：jr4d blob 餵 jr3d 路徑 → null（HKDF info 域對不上——域世代分離）',
      (await unwrapNoteKeyDual3(TACET3, KAT17.jr4d, passD, KAT17.pin, KAT17.sd4)) === null);
    await A('[17] family isolation：jr3d blob 餵 jr4d 路徑 → null（KEK2 info 域分離對稱面）',
      (await unwrapNoteKeyDual4(TACET4, KAT17.jr3d, passD, KAT17.pin, KAT17.sd3)) === null);
  }

// ── 18. 本機包裹專用前綴（v0.2.0 批卡③：wrapLocal opt-in＋讀舊寫新自癒；jr1l.） ──
//
// 舊實作借用 cfg.wrap（jr1w. passphrase 包裹前綴）寫本機包裹＝「一個前綴一份契約」的第二
// 違例（wrappedRec 專用前綴歸卡①批面）。收口三面：
//   ①寫面專用前綴：storeLocalWrap 寫入恆 cfg.wrapLocal（jr1l.）；未配置＝退場無寫入
//     （cipherLocal opt-in 母型——未配置面零寫入零拋）。
//   ②讀舊寫新自癒：loadLocalWrap 先試新前綴（本體嚴格面）；命中舊形（借用期 jr1w. blob）
//     回落解密後重包 cfg.wrapLocal 回寫（自癒恰一次）；解不回（損壞/他機搬來）誠實 null
//     不硬遷移。
//   ③未配置態讀取面：照走舊形 cfg.wrap（行為不變），且不自癒重寫（heal 綁在新前綴面）。
// KEK 不動＝deriveGuestKey（identity 派生、passphrase-free——session 期免重打密語的機制
// 原樣）；本卡只界「前綴」面（payload 布局的 KDF/prefix 契約由前綴界定——帶內版本化母型）。
console.log('\n[18] 本機包裹專用前綴（wrapLocal=jr1l. opt-in＋讀舊寫新自癒）');
{
  // section 專用 Map store：node 端 localStorage 死位（keys.ts try/catch 恆 null）——stored 面
  // 行為斷言要可觀察可重放，結構 KeyStore 注入（同 cfg 注入母型；TACET 基座 fixture 不動）。
  const mapS18 = (() => { const m = new Map<string, string>(); return {
    get: (k: string): string | null => (m.has(k) ? m.get(k)! : null),
    set: (k: string, v: string): void => { m.set(k, v); },
    remove: (k: string): void => { m.delete(k); },
    noteKeyWrap: (soul: string): string => 't18_notekey:' + soul,
  }; })();
  const TACET_L18 = { ...TACET, wrapLocal: 'jr1l.', store: mapS18 };
  const { wrapLocal: _omit18, ...restN18 } = TACET_L18;
  const TACET18_NOLOCAL: NoteCryptoConfig = restN18; // wrap 帶、wrapLocal 無（行為不變態）
  const { wrap: _omitw18, ...restW18 } = TACET_L18;
  const TACET18_NOWRAP = restW18 as unknown as NoteCryptoConfig; // wrapLocal 帶、wrap 無（回落守衛態）

  const RAW18 = hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const eqNoteKey18 = async (k: CryptoKey | null): Promise<boolean> =>
    k !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === RAW18;
  const storedOf18 = (c: NoteCryptoConfig, id: string): string | null => c.store.get(c.store.noteKeyWrap(id));
  const guestOf18 = async (c: NoteCryptoConfig, id: string): Promise<CryptoKey> => deriveGuestKey(c, id);

  // 舊形向量＝借用期工件真本體：sealNoteKey(cfg.wrap, key, guest, 'notekey-local') 形直呼
  //（PRE 樹一對照實測：舊碼 storeLocalWrap 產出即此形——92B 嚴格面（hex64 字串 payload））。
  const guestL18 = await guestOf18(TACET_L18, 'acct-l2');
  const legacyL18 = await sealNoteKey(TACET.wrap, noteKey, guestL18, 'notekey-local');
  await A('[18] 舊形向量自洽錨：回落前直解 jr1w. blob = 原 noteKey（樣本可重放）',
    eqNoteKey18(await openNoteKey(legacyL18, guestL18, 'notekey-local', TACET.wrap)));

  // ── P1 寫面：寫入恆新前綴；未配置退場 ──
  await storeLocalWrap(TACET_L18, 'acct-l2', noteKey);
  const freshL18 = storedOf18(TACET_L18, 'acct-l2');
  await A('[18] 寫前綴 jr1l.（store 契約——借用 cfg.wrap 舊形＝反）', !!freshL18 && freshL18!.startsWith('jr1l.'));
  await A('[18] 寫入 payload unwrap = 原 noteKey（KEK=deriveGuestKey 原樣——本體 92B 嚴格面）',
    freshL18 !== null && eqNoteKey18(await openNoteKey(freshL18!, guestL18, 'notekey-local', TACET_L18.wrapLocal!)));
  await A('[18] 未配置 wrapLocal store 退場（noop——stored 殘留零，opt-in 母型）',
    (async () => { await storeLocalWrap(TACET18_NOLOCAL, 'acct-l1', noteKey); return storedOf18(TACET18_NOLOCAL, 'acct-l1') === null; })());

  // ── P1b 讀面通路（loadLocalWrap 唯一消費點：encryptNote/decryptNote 的 held 設值面） ──
  const heldB18 = makeHeldKey(); heldB18.set(noteKey);
  const ctB18 = await encryptNote(TACET_L18, heldB18, 'plain-read-18', 'aad-18b', { current: () => 'acct-l3' });
  await A('[18] 樣本自洽：bound 密文前綴 jr1b.（held 預置面）', ctB18.startsWith('jr1b.'));
  await storeLocalWrap(TACET_L18, 'acct-l3r', noteKey);
  await A('[18] 空-held decrypt 經本機包裹通路 = 原文（read 通路行為面）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l3r' })) === 'plain-read-18');
  await A('[18] 該 identity 無 stored → null（通路不無中生有）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l3x' })) === null);

  // ── P2 舊形回落＋自癒回寫（讀舊寫新） ──
  TACET_L18.store.set(TACET_L18.store.noteKeyWrap('acct-l2'), legacyL18);
  await A('[18] 舊形（借用期 jr1w. blob）讀回 = 解密成立（回落面行為）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l2' })) === 'plain-read-18');
  const healedL18 = storedOf18(TACET_L18, 'acct-l2');
  await A('[18] 自癒回寫恆新前綴（stored 舊形摘除——v1 借用面行為翻轉）', !!healedL18 && healedL18!.startsWith(TACET_L18.wrapLocal!));
  await A('[18] 自癒 blob unwrap 等值（同一 guest KEK 重包）',
    healedL18 !== null && eqNoteKey18(await openNoteKey(healedL18!, guestL18, 'notekey-local', TACET_L18.wrapLocal!)));
  await A('[18] 自癒 blob 舊形恆拒（新形不落舊前綴——家族隔離）',
    (await openNoteKey(healedL18!, guestL18, 'notekey-local', TACET.wrap)) === null);
  const beforeRe18 = storedOf18(TACET_L18, 'acct-l2');
  await A('[18] 自癒後二次讀回（fresh face 通路承載）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l2' })) === 'plain-read-18');
  await A('[18] 二次讀不自癒二次（byte-identical——自癒恰一次）', storedOf18(TACET_L18, 'acct-l2') === beforeRe18);

  // ── P2b/P3 垃圾面：回落解不回＝誠實 null 零回寫；他家族/明文殘留零 crash ──
  const guestB18 = await guestOf18(TACET_L18, 'acct-l2b');
  const brokenL18 = (await sealNoteKey(TACET.wrap, noteKey, guestB18, 'notekey-local')).slice(0, -8) + 'AAAABBBB';
  TACET_L18.store.set(TACET_L18.store.noteKeyWrap('acct-l2b'), brokenL18);
  const blobBeforeBf18 = storedOf18(TACET_L18, 'acct-l2b');
  const heldT18 = makeHeldKey(); heldT18.set(noteKey);
  const ctT18 = await encryptNote(TACET_L18, heldT18, 'plain-bf-18', 'aad-18t', { current: () => 'acct-l2t' });
  await A('[18] 壞舊形（ct 竄改）讀回 → null（誠實降級非拋）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctT18, 'aad-18t', { current: () => 'acct-l2b' })) === null);
  await A('[18] 壞舊形零回寫（自癒條款面：解不回不遷移）', storedOf18(TACET_L18, 'acct-l2b') === blobBeforeBf18);
  const otherK18 = await importAesGcm(crypto.getRandomValues(new Uint8Array(32)), false);
  TACET_L18.store.set(TACET_L18.store.noteKeyWrap('acct-l2c'), 'jr3d.' + await encryptWithKey(otherK18, 'y'.repeat(50), 'x'));
  await A('[18] 他家族 blob（鹽內嵌形）讀回 → null（前綴路由不串家族）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctT18, 'aad-18t', { current: () => 'acct-l2c' })) === null);
  TACET_L18.store.set(TACET_L18.store.noteKeyWrap('acct-l2p'), 'plain-leftover-18');
  await A('[18] 明文殘留讀回 → null（零 crash——舊資料層不進包裹通路）',
    (await decryptNote(TACET_L18, makeHeldKey(), ctT18, 'aad-18t', { current: () => 'acct-l2p' })) === null);

  // ── P3d cfg.wrap 缺席態（回落守衛面：無舊形可解，wrapLocal 帶著也不硬寫） ──
  const guestW18 = await guestOf18(TACET18_NOWRAP, 'acct-l2w');
  const legacyW18 = await sealNoteKey('jr1w.', noteKey, guestW18, 'notekey-local');
  TACET18_NOWRAP.store.set(TACET18_NOWRAP.store.noteKeyWrap('acct-l2w'), legacyW18);
  const blobBeforeW18 = storedOf18(TACET18_NOWRAP, 'acct-l2w');
  await A('[18] cfg.wrap 缺席讀舊形 → null（回落守衛面）',
    (await decryptNote(TACET18_NOWRAP, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l2w' })) === null);
  await A('[18] 守衛面 stored 不變（零硬寫）', storedOf18(TACET18_NOWRAP, 'acct-l2w') === blobBeforeW18);

  // ── P5 未配置態讀取面（wrap 帶、wrapLocal 無——v1 行為不變且不自癒） ──
  const guestN18 = await guestOf18(TACET18_NOLOCAL, 'acct-l2n');
  const legacyN18 = await sealNoteKey(TACET18_NOLOCAL.wrap, noteKey, guestN18, 'notekey-local');
  TACET18_NOLOCAL.store.set(TACET18_NOLOCAL.store.noteKeyWrap('acct-l2n'), legacyN18);
  const blobBeforeN18 = storedOf18(TACET18_NOLOCAL, 'acct-l2n');
  await A('[18] 未配置態讀舊形 = 解密成立（v1 行為不變——讀取面回落照走）',
    (await decryptNote(TACET18_NOLOCAL, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l2n' })) === 'plain-read-18');
  await A('[18] 未配置態讀取不自癒重寫（heal 綁在新前綴面）', storedOf18(TACET18_NOLOCAL, 'acct-l2n') === blobBeforeN18);

  // ── P6/P7 分離面＋fail-open（私隱模式） ──
  const gCt18 = await encryptNote(TACET_L18, makeHeldKey(), 'guest-note-18', 'aad-18g', { current: () => 'acct-l5' });
  await A('[18] guest 期零本機觸碰（stored 殘留零＋前綴 jr1g. 分離面）',
    storedOf18(TACET_L18, 'acct-l5') === null && gCt18.startsWith('jr1g.'));
  const FIXQ18 = { get: (): string | null => { throw new Error('LS_GET_DENIED'); }, set: (): void => { throw new Error('LS_SET_DENIED'); }, remove: (): void => { throw new Error('LS_RM_DENIED'); }, noteKeyWrap: (soul: string): string => 't18q_notekey:' + soul };
  const TACET_Q18: NoteCryptoConfig = { ...TACET_L18, store: FIXQ18 };
  await A('[18] 私隱模式 store 拋錯不外拋：empty-held encrypt 降級 guest 面（fail-open）',
    (await encryptNote(TACET_Q18, makeHeldKey(), 'plain-q-18', 'aad-18q', { current: () => 'acct-l4q' })).startsWith('jr1g.'));
  await A('[18] 私隱模式 get 拋錯 decrypt → null（誠實降級非外拋）',
    (await decryptNote(TACET_Q18, makeHeldKey(), ctB18, 'aad-18b', { current: () => 'acct-l4q' })) === null);
  await A('[18] guest 分支零 store 依賴（私隱模式 guest 密文照解）',
    (await decryptNote(TACET_Q18, makeHeldKey(), gCt18, 'aad-18g', { current: () => 'acct-l5' })) === 'guest-note-18');

  // ── clearLocalWrap 契約原樣 ──
  await A('[18] clearLocalWrap 摘除面（契約原樣）', (async () => {
    await storeLocalWrap(TACET_L18, 'acct-l6', noteKey);
    const had = storedOf18(TACET_L18, 'acct-l6') !== null;
    clearLocalWrap(TACET_L18, 'acct-l6');
    return had && storedOf18(TACET_L18, 'acct-l6') === null;
  })());

  // ── 源碼窗靜態錨（本地段結構——毒化形即計數/窗錨變異） ──
  const ncSrc18 = await srcOf('../src/client/note-crypto.ts');
  const localWin18 = ncSrc18.slice(ncSrc18.indexOf('── 本機包裹'), ncSrc18.indexOf('── 日記密文入口'));
  await A('[18] 源碼窗：本機段零 throw 面（ERR_WRAP_NOT_CONFIGURED 退場——未配置＝無寫入無拋）',
    localWin18.length > 1900 && !localWin18.includes('ERR_WRAP_NOT_CONFIGURED'));
  await A('[18] 源碼窗：寫面唯 cfg.wrapLocal seal＋舊借形零殘留（v1 借用面復活即反）',
    localWin18.split('sealNoteKey(cfg.wrapLocal').length === 2 && !localWin18.includes('sealNoteKey(cfg.wrap,'));
  await A('[18] 源碼窗：回落三元恰 1（收口形——自癒腿與未配置態同走單一 cfg.wrap 面；借用形復活即 2+）＋自癒接線（if legacy → storeLocalWrap identity legacy 恰 1）',
    localWin18.split('openNoteKey(stored, guest, \'notekey-local\', cfg.wrap)').length === 2
    && localWin18.split('await storeLocalWrap(cfg, identity, legacy)').length === 2
    && /if \(legacy\) \{\s*await storeLocalWrap\(cfg, identity, legacy\);/.test(localWin18));
  await A('[18] 界面欄：wrapLocal? 宣告恰 1（note-crypto 全檔——NoteCryptoConfig 選配欄）',
    ncSrc18.split('wrapLocal?: string;').length === 2);
  // ── [18] 常駐毒化矩陣（本機段結構毒三案——母型 [16]：/tmp 拷貝突變＋fresh import＋出生即棄） ──
  {
    const getBuiltin18 = (id: string): unknown =>
      (globalThis as unknown as { process?: { getBuiltinModule?: (i: string) => unknown } }).process?.getBuiltinModule?.(id);
    const os18 = getBuiltin18('node:os') as { tmpdir?: () => string } | undefined;
    const fs18 = getBuiltin18('node:fs') as {
      rmSync?: (p: string, o?: { recursive: boolean; force: boolean }) => void;
      cpSync?: (a: string, b: string, o?: { recursive: boolean; filter?: (src: string) => boolean }) => void;
      readFileSync?: (p: string, e?: string) => string;
      writeFileSync?: (p: string, c: string, e?: string) => void;
      mkdtempSync?: (p: string) => string;
    } | undefined;
    const inner18 = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env?.POISON_GATE_INNER === '1';
    const ready18 = !!os18?.tmpdir && !!fs18?.mkdtempSync && !!fs18?.cpSync && !!fs18?.readFileSync && !!fs18?.writeFileSync && !!fs18?.rmSync;
    if (inner18 || !ready18) {
      await A('[18] 毒化矩陣載體就緒（node 內建模組在場；內層遞迴由 sentinel 跳過＝正常；缺席＝顯性 FAIL）', inner18 && !ready18 ? false : inner18, 'env unavailable AND not inner');
    } else {
      const repoRoot18 = new URL('..', import.meta.url).pathname;
      const skip18 = (s: string): boolean => s.endsWith('/.git') || s.includes('/.git/') || s.includes('/node_modules') || s.split('/').pop() === 'node_modules';
      const needlePA18 = "\n    const fresh = cfg.wrapLocal\n      ? await openNoteKey(stored, guest, 'notekey-local', cfg.wrapLocal) // 本體嚴格面（92B＋rawHex hex 形）\n      : null;\n    if (fresh) return fresh;";
      const needlePB18 = "      await storeLocalWrap(cfg, identity, legacy);\n      return legacy;";
      const needlePC18 = "sealNoteKey(cfg.wrapLocal,";
      const existsSync18 = (p: string): boolean => {
        const fsx18 = getBuiltin18('node:fs') as { existsSync?: (p: string) => boolean } | undefined;
        return typeof fsx18?.existsSync === 'function' ? fsx18.existsSync(p) : false;
      };
      const trees18: string[] = [];
      const withPoison18 = async (applyS: (s: string) => string, restoreS: (s: string) => string, probe: (dir: string) => Promise<void>): Promise<void> => {
        const dir = fs18!.mkdtempSync!(os18!.tmpdir!() + '/t18-lw-')!;
        trees18.push(dir);
        try {
          fs18!.cpSync!(repoRoot18, dir, { recursive: true, filter: (s: string) => !skip18(s) });
          const p = dir + '/src/client/note-crypto.ts';
          const s0 = fs18!.readFileSync!(p, 'utf8');
          fs18!.writeFileSync!(p, applyS(s0), 'utf8');
          await probe(dir);
        } finally {
          fs18!.rmSync!(dir, { recursive: true, force: true });
        }
      };
      const freshImport18 = async (dir: string): Promise<Record<string, unknown>> => await import('file://' + dir + '/src/client/note-crypto.ts') as Record<string, unknown>;
      const mapStore18 = () => { const m = new Map<string, string>(); return {
        get: (k: string): string | null => (m.has(k) ? m.get(k)! : null),
        set: (k: string, v: string): void => { m.set(k, v); },
        remove: (k: string): void => { m.delete(k); },
        noteKeyWrap: (soul: string): string => 't18p_notekey:' + soul,
      }; };
      const baseCfg18 = (store: ReturnType<typeof mapStore18>): NoteCryptoConfig => ({ ...TACET, wrapLocal: 'jr1l.', store: store as unknown as NoteCryptoConfig['store'] });

      // P18 摘 fresh-face（三元→null）→ stored jr1l. blob 通路讀死＋自癒腿（舊形服務）仍活
      await withPoison18(
        (s: string) => s.replace(needlePA18, '\n    const fresh = null;'),
        (s: string) => s.replace('\n    const fresh = null;', needlePA18),
        async (dir: string) => {
          const mod = (await freshImport18(dir)) as typeof import('../src/client/note-crypto.ts');
          const FIX = mapStore18(); const CFG = baseCfg18(FIX);
          const nk = await mod.generateNoteKey();
          await mod.storeLocalWrap(CFG, 'acca2', nk);
          const hp = mod.makeHeldKey(); hp.set(nk);
          const ct = await mod.encryptNote(CFG, hp, 'plain-ct-18', 'aadz', { current: () => 'acca2y' });
          const back = await mod.decryptNote(CFG, mod.makeHeldKey(), ct, 'aadz', { current: () => 'acca2' });
          await A('[18] 毒化 P18 摘 fresh-face → 本機通路讀死（blob 不可讀——designated）', back === null, String(back));
          const guestA = await mod.deriveGuestKey(CFG, 'acca2');
          CFG.store.set(CFG.store.noteKeyWrap('acca2'), await mod.sealNoteKey('jr1w.', nk, guestA, 'notekey-local'));
          const lback = await mod.decryptNote(CFG, mod.makeHeldKey(), ct, 'aadz', { current: () => 'acca2' });
          await A('[18] 毒化 P18 自癒腿仍活（舊形 blob 照服務——單面隔離非互毀）', lback !== null, String(lback));
        });
      // P18b 摘自癒回寫 → 舊形讀回照解＋stored 殘留 jr1w.（零重寫）
      await withPoison18(
        (s: string) => s.replace(needlePB18, '      return legacy;'),
        (s: string) => s.replace('      return legacy;', needlePB18),
        async (dir: string) => {
          const mod = (await freshImport18(dir)) as typeof import('../src/client/note-crypto.ts');
          const FIX = mapStore18(); const CFG = baseCfg18(FIX);
          const nk = await mod.generateNoteKey();
          const guest = await mod.deriveGuestKey(CFG, 'accb2');
          const legacy = await mod.sealNoteKey('jr1w.', nk, guest, 'notekey-local');
          CFG.store.set(CFG.store.noteKeyWrap('accb2'), legacy);
          const hp = mod.makeHeldKey(); hp.set(nk);
          const ct = await mod.encryptNote(CFG, hp, 'plain-ct-18', 'aadz', { current: () => 'accb2y' });
          const back = await mod.decryptNote(CFG, mod.makeHeldKey(), ct, 'aadz', { current: () => 'accb2' });
          await A('[18] 毒化 P18b 摘自癒回寫 → 舊形讀回照解（讀面不依賴回寫線）', back !== null, String(back));
          await A('[18] 毒化 P18b stored 殘留 jr1w.（零重寫——heal 條款面是唯一重寫者）',
            typeof legacy === 'string' && legacy.startsWith('jr1w.') && (CFG.store.get(CFG.store.noteKeyWrap('accb2')) ?? '') === legacy);
        });
      // P18c 寫面接回借用形（禁手）→ 寫面 fallback jr1w.（v1 借用面復活的行為翻轉）
      await withPoison18(
        (s: string) => s.replace(needlePC18, 'sealNoteKey(cfg.wrap,'),
        (s: string) => s.replace('sealNoteKey(cfg.wrap,', needlePC18),
        async (dir: string) => {
          const mod = (await freshImport18(dir)) as typeof import('../src/client/note-crypto.ts');
          const FIX = mapStore18(); const CFG = baseCfg18(FIX);
          const nk = await mod.generateNoteKey();
          await mod.storeLocalWrap(CFG, 'accc2', nk);
          const blob = CFG.store.get(CFG.store.noteKeyWrap('accc2'));
          await A('[18] 毒化 P18c 寫面接回借用形 → 寫面 fallback jr1w.（designated——寫面契約行為翻轉）',
            typeof blob === 'string' && blob.startsWith('jr1w.'), String(blob ?? '').slice(0, 8));
        });
      // 還原自證：真樹 needle 計數在所有毒化後仍恰 1×3（byte-exact 還原的行程帳）
      const srcAfter18 = await srcOf('../src/client/note-crypto.ts');
      await A('[18] 毒化還原自證（真樹 needle 恰 1×3——毒化零殘留本樹）',
        srcAfter18.split(needlePA18).length === 2 && srcAfter18.split(needlePB18).length === 2 && srcAfter18.split(needlePC18).length === 2);
      await A('[18] 毒化樹零殘留（本 run 喚出 ' + trees18.length + ' 棵全清——封閉集判準）',
        trees18.length === 3 && trees18.every((t) => !fs18!.rmSync || !existsSync18(t)));
    }
  }
}
console.log(`\n${passed} 斷言全綠` + (failures.length ? `；${failures.length} 失敗` : ''));
if (failures.length) {
  console.error('失敗項：', failures);
  process.exit(1);
}

console.log('CORE-CRYPTO-VERIFY-OK');