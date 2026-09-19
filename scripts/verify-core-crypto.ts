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
  unwrapNoteKey,
  unwrapNoteKeyWithRecToken,
  wrapNoteKey,
  wrapNoteKeyWithRecToken,
  recTokenHash,
  wrapNoteKeyDual,
  unwrapNoteKeyDual,
  normalizePin,
  encryptAttach,
  decryptAttach,
  encryptLocal,
  decryptLocal,
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

console.log('\n[11] 本機 IDB 密文（jr1d. cipherLocal opt-in）＋ guest 選配');
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

// ── 決議 ────────────────────────────────────────────────────────────────────

console.log(`\n${passed} 斷言全綠` + (failures.length ? `；${failures.length} 失敗` : ''));
if (failures.length) {
  console.error('失敗項：', failures);
  process.exit(1);
}
console.log('CORE-CRYPTO-VERIFY-OK');