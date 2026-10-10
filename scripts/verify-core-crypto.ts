/**
 * verify-core-crypto.ts — core 抽取的驗證閘（對真模組，禁鏡像——extractable 教訓）。
 * 執行：node --experimental-strip-types scripts/verify-core-crypto.ts
 * 全綠輸出 CORE-CRYPTO-VERIFY-OK(N assertions)（整行＝唯一消費錨——下游驗收條款禁前綴子字串
 * 比對，防段數漂移誤判；--only 態改 CORE-CRYPTO-VERIFY-OK(N assertions)(--ONLY 16-18) 顯形）；任何失敗 exit 1。
 * [24] 段級運行（2026-10-09）：`--only 16,17,18`／`--only 16-18`（或混形）＝只跑指定段；setup（頂層向量群＋段標記行）恆跑；
 * 段依賴常數由 setup 重生（無跨段狀態依賴——各段消費自己的區塊常數）。省時是這卡的真價值：審查輪重跑 [16]-[18] 不再等 KDF 群全套。
 *
 * 2026-10-09（0.2.4）：[23] loginRouteCore ladder 查表守衛段（外審 #8 幽靈帳）——真 node:sqlite
 * shim 直驅七情境（現值 hit／ladder hit 回舊帳／兩面 miss 建幽靈／未配置單查零變／fail-open）
 * ＋拷貝樹毒化 in-gate（接線摘除 → ladder hit 翻建幽靈）。POISON_GATE_INNER 內層跑份自我跳過。
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
  wrapNoteKeyShare3,
  unwrapNoteKeyShare3,
  wrapNoteKeyDual3,
  unwrapNoteKeyDual3,
  wrapNoteKey4,
  unwrapNoteKey4,
  wrapNoteKeyDual4,
  unwrapNoteKeyDual4,
  unwrapNoteKeyDual4WithSalt,
  ARGON_MEMORY_KIB,
  ARGON_ITERATIONS,
  ARGON_PARALLELISM,
  ARGON_TAG_LEN,
  derivePh1Argon,
  derivePh1ArgonV3,
  PH1_V2_SALT,
  PH1_V3_SALT,
  ARGON_RFC9106_EXPECTED,
  setArgonLoader,
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
import {
  PH2_LADDER_TABLE,
  PH2_LADDER_KIND_LEGACY,
  PH2_LADDER_KIND_V2,
  makePh2LadderStore,
} from '../src/server/ladder.ts';
import {
  createVault,
  unlockVault,
  recoverVault,
  VaultError,
  isVaultError,
  currentArgonCarrier,
  resetArgonCarrier,
  argonWorkerSource,
  type VaultOptions,
  type ArgonWorkerLike,
} from '../src/client/vault.ts';
import { hashWasmArgon2Factory, HASH_WASM_ARGON2_SHA256, HASH_WASM_VERSION } from '../src/client/vendor/hash-wasm-argon2.ts';

type Row19 = { account_id: string; ph2_kind: string };
type Env19 = { DB: { prepare(sql: string): { bind(...params: unknown[]): { first(): Promise<Row19 | null>; run(): Promise<void> } } } };

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
  if (ok) { passed++; secRan.set(secCur, (secRan.get(secCur) ?? 0) + 1); console.log(`  ✓ ${name}`); }
  else { failures.push(name); secRan.set(secCur, (secRan.get(secCur) ?? 0) + 1); console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ── [24] runner：段級 --only 運行（2026-10-09，t_3ec0936e）——段號語法契約＋帳面誠實契約的主場 ──
// 語法契約（[24] parse 面自證）：--only <CSV>｜<a-b>｜<混形>；輸出單調遞增去重（16,17,18 ≡ 16-18）；
// 空值／非數字／未定段／倒序範圍＝ERR_ONLY_* fail-closed exit 1。--only 缺席＝預設恆全跑（CI/deploy 契約不動）。
// 帳面契約：--only 態總帳顯形「本輪 X/選段帳 N（N 案非本輪載）」＋OK 標記帶 (--ONLY …) 尾碼；skip 段帳面恆列「未跑非通過」；[24]/[25] runner 自證段隨每輪在場。
// 段標記 helper（secOpen）：全跑態輸出位元組恆等原 console.log('\n[N] …')；--only 態僅選中段輸出段頭。
// 毒化矩陣內層 rerun（execFileSync＋POISON_GATE_INNER=1）不傳遞 --only＝內層恆全帳（POISON_GATE_INNER 語意不變）。
// 段帳＝執行帳（healthy-repo 全跑 runtime 真值，2026-10-10 實測 506——A3 [27] +14）；帳面語意契約（逐段「案 X/帳」
// 對 secRan 執行值顯形）：執行 < 帳 的段＝本環境條件態未行使（非 skip 態），--only 期望算術對齊本帳。
// [23] 執行 18 帳 21＝[23]④ lookup 未配置（0.2.3 單查恆等）／[23]⑤ fail-open（表缺席）兩情境
// 在本機樹由 [8]（登入憑證 Argon2id 派生）內登入 lane 的訊號面真行使（try/catch 異常面）——車道分流非帳面虛報。
// secEnter 跑行為脫鉤 secCases；secCases 鍵只承載段存在／帳面／--only 判準的登記義務
//（secOpen(22,…) 無段標記行＝慣例 skip 段）。缺帳防線（teeth）：secRan 實跑段必已登記——
// for (const [k] of secRan) if (!secCases[k] && k !== 22) FAIL（負向斷言本體在 [25] 段
//——secCases 全摘即 RED）；反向缺席段＝帳面誠實「案 0/N · skip」。
// secCases 載體三群：[24]/[25] self-account＋--only 段存在面＋teeth（段帳由 secRan 執行自記）。
const secCases: Record<number, number> = { 1: 3, 2: 7, 3: 9, 4: 4, 5: 3, 6: 20, 7: 27, 8: 8, 9: 22, 10: 5, 11: 41, 12: 50, 13: 39, 14: 18, 15: 59, 16: 15, 17: 14, 18: 39, 19: 17, 20: 47, 21: 10, 23: 18, 24: 5, 25: 4, 26: 8, 27: 14 };
function parseOnly(spec: string): { err: string | null; set: number[] } {
  const set = new Set<number>();
  const specStr = spec.trim();
  if (specStr === '') return { err: 'ERR_ONLY_SPEC_EMPTY', set: [] };
  for (const rawPart of specStr.split(',')) {
    const part = rawPart.trim();
    if (part === '') return { err: 'ERR_ONLY_SPEC_EMPTY_TOKEN', set: [] };
    const span = part.match(/^([0-9]+)-([0-9]+)$/);
    if (span) {
      const lo = Number(span[1]); const hi = Number(span[2]);
      if (!(hi >= lo) || !secCases[lo] || !secCases[hi]) return { err: 'ERR_ONLY_SPEC_RANGE', set: [] };
      for (let s = lo; s <= hi; s++) if (secCases[s]) set.add(s);
      continue;
    }
    if (!/^[0-9]+$/.test(part)) return { err: 'ERR_ONLY_SPEC_TOKEN', set: [] };
    const num = Number(part);
    if (!secCases[num]) return { err: 'ERR_ONLY_SPEC_UNKNOWN_SEC', set: [] };
    set.add(num);
  }
  return { err: null, set: [...set].sort((a, b) => a - b) };
}
const argvArr = (globalThis as unknown as { process?: { argv?: string[] } }).process?.argv ?? [];
const argvOnlyIdx = argvArr.indexOf('--only');
const onlySpecRaw = argvOnlyIdx >= 0 ? argvArr[argvOnlyIdx + 1] ?? '' : null;
const onlyParsed = onlySpecRaw !== null ? parseOnly(onlySpecRaw) : null;
if (onlyParsed?.err) {
  console.error('FAIL: ' + onlyParsed.err + ' — --only 段號語法契約：--only 16,17,18（CSV）／--only 16-18（範圍）／混形 16,17-19；--only 缺席＝全跑。');
  process.exit(1);
}
const onlySet = new Set<number>(onlyParsed?.set ?? []);
const onlyMode = (): boolean => onlySet.size > 0;
// runner 自證段（24/25）隨每輪在場（毫秒級；only 態帳面顯形契約的行使面——非選段制）。
// 全跑態 secEnter 恆 true（n ≥1 且 n ≠ 22——secOpen 行在場即實段；secCases 人工帳冊退役＝
// 靜默不跑面收口：新段只加 secOpen 即跑，段帳由 secRan 自記）。22＝慣例 skip 段（bannerless
// 斷言群帳入 [13]的慣例面；[24] 契約明文在案）；n < 1＝非法（非段位）。--only 態照選段集＋自證段。
const secEnter = (n: number): boolean =>
  (!onlyMode() ? (n >= 1 && n !== 22) : (onlySet.has(n) || n === 24 || n === 25));
const onlySpecDisp = (): string => (onlyMode() ? (onlyParsed?.set ?? []).join(',') : '');
const rangeCompress = (nums: number[]): string => {
  const out: string[] = [];
  let i = 0;
  while (i < nums.length) {
    let j = i;
    while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
    out.push(nums[i] === nums[j] ? String(nums[i]) : nums[i] + '-' + nums[j]);
    i = j + 1;
  }
  return out.join(',');
};
const onlyTag = (): string => (onlyMode() ? '(--ONLY ' + rangeCompress(onlyParsed?.set ?? []) + ')' : '');
let secCur = 0;
const secRan = new Map<number, number>();
const secOpen = (n: number, text: string): void => {
  secCur = n;
  if (onlyMode() ? onlySet.has(n) : true) console.log(onlyMode() ? text : '\n' + text);
};

// ── setup 恆跑向量群（--only 態也重生——跨段消費常數上移；值與原段位逐位等值，僅求值時點上移）──
// 依賴帳（--only 分段的承載面——每行原段位標註）：note/identityA/held/noteKey/cipherGuest/cipherBound ←[2]；
// pass/recToken/wrapped/salt/wrappedRec/unwrapped/recUnwrapped/localIdentity ←[3]；origRaw ←[4]；
// TACET2/passD/pinD/dual ←[6]；TACET3/w3/dual3 ←[7]；ph1v2a ←[8]；bip ←[9]；
// TACET_ATTACH/attachAad/attachPayload/attachCt ←[10]；TACET4/pass4/passD4 ←[15]（[17]KAT17/[19] 跨段消費）。
const note = '今天寫了一點東西。';
const identityA = 'acct-aaaaaaaaaaaaaaaa';
const held = makeHeldKey();
const noteKey = await generateNoteKey();
const cipherGuest = await encryptNote(TACET, held, note, 'noteId:n1', { current: () => identityA }); // held 空態＝guest 時代（原 [2] 順序——guest 密文先於 held 設值）
held.set(noteKey);
const cipherBound = await encryptNote(TACET, held, note, 'noteId:n1', { current: () => identityA });
const pass = 'correct-horse-battery-staple-42';
const recToken = generateRecToken();
const { wrapped, salt } = await wrapNoteKey(TACET, noteKey, pass);
const wrappedRec = await (await import('../src/client/note-crypto.ts')).wrapNoteKeyWithRecToken(TACET, noteKey, recToken, identityA);
const unwrapped = await unwrapNoteKey(TACET, wrapped, pass, salt);
const recUnwrapped = await unwrapNoteKeyWithRecToken(TACET, wrappedRec, recToken, identityA);
const origRaw = hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
const localIdentity = 'acct-localwrap-test';
const TACET2: NoteCryptoConfig = { ...TACET, wrapDual: 'jr2w.', pinSaltPrefix: 'tacet-note-pin1:' };
const passD = 'dual-factor-passphrase-42';
const pinD = '2580ab';
const dual = await wrapNoteKeyDual(TACET2, noteKey, passD, pinD);
const TACET3: Argon3Config = { wrap3: 'jr3w.', wrapDual3: 'jr3d.', pinSalt3Prefix: 'tacet-note-pin3:' };
const w3 = await wrapNoteKey3(TACET3, noteKey, pass);
const dual3 = await wrapNoteKeyDual3(TACET3, noteKey, passD, pinD);
const ph1v2a = await derivePh1Argon('probe-determinism-pass-42');
const bip = await import('../src/client/bip39.ts');
const TACET_ATTACH: NoteCryptoConfig = { ...TACET, cipherAttach: 'jr1c.' };
const attachAad = 'jr1a:note-abc:att-001';
const attachPayload = JSON.stringify({ v: 1, kind: 'img', mime: 'image/jpeg', w: 2048, h: 1365, b64: b64(new Uint8Array(2048)) });
const attachCt = await encryptAttach(TACET_ATTACH, noteKey, attachPayload, attachAad);
const TACET4: Argon3Config = { wrap4: 'jr4w.', wrapDual4: 'jr4d.', pinSalt3Prefix: 'tacet-note-pin3:' };
const guest = await crypto.subtle.importKey('raw', enc.encode('seed').slice(0), 'PBKDF2', false, ['deriveKey']); // 型別哨兵：guest 非此路徑——跨段消費（[5]/[11]/[13]/[18]）
void guest;
const pass4 = 'v3-generation-passphrase-42';
const passD4 = 'ｄｕａｌ－ｆａｃｔｏｒ－ｐａｓｓｐｈｒａｓｅ－４２'; // NFKC → passD 的全形形
// srcOf：源碼窗讀取 helper（原 [13] 段內宣告——跨 [14]-[23] 消費＝setup 恆跑群；2026-10-09 段級化揚升）
async function srcOf(rel: string): Promise<string> {
  // node 內建模組動態存取（structured type，零 node types 依賴——argon2.ts getBuiltinModule 母型同構；
  // TS2591 types 帽下 import('node:fs') 靜態/動態皆炸＝此繞法）
  const fs = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { readFileSync?: (p: string | URL, enc: string) => string } | undefined };
  }).process?.getBuiltinModule?.('node:fs');
  if (!fs?.readFileSync) throw new Error('ERR_FS_UNAVAILABLE');
  return fs.readFileSync(new URL(rel, import.meta.url), 'utf8');
}

const TACET_GUESTOK: NoteCryptoConfig = { ...TACET }; // cipherGuest='jr1g.' 在場，專測 identity 面
const emptyIdp = { current: () => '' };
const dual4 = await wrapNoteKeyDual4(TACET4, noteKey, passD4, pinD); // 全形 wrap＝NFKC 載體（cp1=0xFF44——ASCII 化即本面 RED）
// ── 1. 基礎向量 ─────────────────────────────────────────────────────────────

secOpen(1, '[1] PH1 / PBKDF2 / hash-ladder 基礎'); if (secEnter(1)) {
await A('PH1 = SHA-256(pass) 穩定', (await ph1Of('test-pass-123')) === (await ph1Of('test-pass-123')));
await A('PH1 hex64 格式', /^[0-9a-f]{64}$/.test(await ph1Of('x')));
await A('PBKDF2_ITERATIONS = 600k', PBKDF2_ITERATIONS === 600_000);

// ── 2. roundtrip（guest 時代 + 綁定時代，AAD 由呼叫端） ───────────────────────

};
secOpen(2, '[2] roundtrip / AAD 防搬移'); if (secEnter(2)) {
await A('guest 時代前綴 jr1g.', cipherGuest.startsWith('jr1g.'));
await A('guest roundtrip', (await decryptNote(TACET, held, cipherGuest, 'noteId:n1', { current: () => identityA })) === note);

await A('綁定時代前綴 jr1b.', cipherBound.startsWith('jr1b.'));
await A('綁定 roundtrip', (await decryptNote(TACET, held, cipherBound, 'noteId:n1', { current: () => identityA })) === note);

// AAD 防搬移：AAD 不符 → null（不拋、不降級成別列內容）
await A('AAD 防搬移：跨 noteId 解密失敗回 null',
  (await decryptNote(TACET, held, cipherBound, 'noteId:n2', { current: () => identityA })) === null);
await A('AAD 防搬移：跨身份 guest 解密失敗回 null',
  (await decryptNote(TACET, held, cipherGuest, 'noteId:n1', { current: () => 'acct-bbbbbbbbbbbbbbbb' })) === null);

// 舊版明文相容層：無前綴 = 原樣返回
await A('舊明文原樣返回', (await decryptNote(TACET, held, '純舊明文', 'x', { current: () => identityA })) === '純舊明文');

// ── 3. 包裹三件套（pass / rec / 本機；2026-09-24 效能節——buildBindPayload 兩段
//      PBKDF2 600k 已收 Promise.all 並行，node 實測 133-152ms→68-84ms） ──

};
secOpen(3, '[3] 金鑰包裹（passphrase / 復原 / 本機）'); if (secEnter(3)) {
const recTokenHashValue = await recTokenHash(recToken);
await A('wrapped 前綴 jr1w.', wrapped.startsWith('jr1w.'));
await A('salt = 16B hex', /^[0-9a-f]{32}$/.test(salt));
await A('wrappedRec 前綴 jr1w.', wrappedRec.startsWith('jr1w.'));
await A('recTokenHash hex64', /^[0-9a-f]{64}$/.test(recTokenHashValue));

await A('pass unwrap 救回 noteKey（同 pass 同 salt）',
  unwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped))) ===
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))));
await A('錯誤 pass unwrap → null', (await unwrapNoteKey(TACET, wrapped, 'wrong-pass', salt)) === null);

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
const heldLocal = makeHeldKey();
heldLocal.set(noteKey);
await storeLocalWrap(TACET, localIdentity, noteKey);

// ── 4. extractable 鐵律（2026-09-06 iOS 實機炸點回歸） ────────────────────────

};
secOpen(4, '[4] noteKey extractable 鐵律'); if (secEnter(4)) {
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
await A('unwrap 出的 noteKey 可再 exportKey（等值 noteKey）',
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped!))) === origRaw);
await A('rec unwrap 出的 noteKey 可再 exportKey（等值 noteKey）',
  hex(new Uint8Array(await crypto.subtle.exportKey('raw', recUnwrapped!))) === origRaw);

// ── 5. 時代隔離：guest 與 bound 前綴互不誤判 ─────────────────────────────────

};
secOpen(5, '[5] 時代隔離'); if (secEnter(5)) {
await A('guest cipher 不以 jr1b. 開頭', !cipherGuest.startsWith('jr1b.'));
await A('bound cipher 不以 jr1g. 開頭', !cipherBound.startsWith('jr1g.'));
await A('無 held key 的 bound 解密 → null',
  (await decryptNote(TACET, makeHeldKey(), cipherBound, 'noteId:n1', { current: () => identityA })) === null);

// ── 6. 雙因子合鑰（jr2w.，2026-09-09 PIN 第二因子） ─────────────────────────

};
secOpen(6, '[6] 雙因子合鑰 KEK2（jr2w.）'); if (secEnter(6)) {
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
// 收口：本地複製退場、直呼模組 unb64（單一真相；[14] 導入面；
// 轉手 wrapper 本身退場——呼叫端直用模組 unb64）。
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

};
secOpen(7, '[7] Argon2id 包裹（jr3w./jr3d.）'); if (secEnter(7)) {
await A('RFC 9106 無 secret/ad 標準向量（當前載體正確性）', await verifyArgonKat());
await A('Argon 參數契約 m=64MiB t=3 p=1 tag=32',
  ARGON_MEMORY_KIB === 65536 && ARGON_ITERATIONS === 3 && ARGON_PARALLELISM === 1 && ARGON_TAG_LEN === 32);

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

};
secOpen(8, '[8] PH1 v2（登入憑證 Argon2id 派生）'); if (secEnter(8)) {
await A('RFC 9106 KAT 先行（載體正確性，本節所有 Argon 斷言的前提）', await verifyArgonKat());
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

};
secOpen(9, '[9] BIP39 復原套件（24 詞 ⇄ entropy 32B ⇄ hex64）'); if (secEnter(9)) {
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
// （真隨機取樣時 P(漏 ≥2)≈0.4%＝偶發 62/64 flake 實證——改 xorshift 常數
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
  // 斷鏈（symlink 落空）與真缺席要分流：裸 npm ci 環境的確定性病是「參照組斷鏈」——
  // 訊息指向 vendor 修復（prepare-core-pkg.cjs），不是泛化「未安裝」（對斷鏈態毫無作用＝誤導指示）。
  // 路徑錨定 repo root（t_87ef62dd NIT-1）：裸 '@scure/bip39' 是 CWD 相對——他 cwd 跑閘
  // （如 scripts/ 子目錄）會把斷鏈態誤報「未安裝」；錨 import.meta.url 起手＝CWD 無關恆真。
  const fsMod = (globalThis as unknown as { process?: { getBuiltinModule?: (id: string) => { lstatSync?: (p: string) => { isSymbolicLink(): boolean }; existsSync?: (p: string) => boolean } | undefined } }).process?.getBuiltinModule?.('node:fs');
  const repoRootRef = new URL('../node_modules/@scure/bip39', import.meta.url).pathname.replace(/\/$/, '');
  const isBrokenLink = !!fsMod?.lstatSync && !!fsMod.existsSync && (() => {
    try {
      return fsMod.lstatSync(repoRootRef).isSymbolicLink() && !fsMod.existsSync(repoRootRef);
    } catch { return false; } // ENOENT＝真缺席（未安裝），不是斷鏈
  })();
  await A('與 @scure/bip39 參照 200 組雙向一致', false,
    isBrokenLink
      ? '參照套件斷鏈（@scure/bip39 symlink realpath 不存在）——重跑 npm ci（plain）再跑 scripts/prepare-core-pkg.cjs vendor 修復'
      : '參照套件未安裝（devDependencies @scure/bip39）');
}

// 與現行包裹鏈相容：words 造的 hex64 走 recTokenHash/wrapNoteKeyWithRecToken 原樣
const kitHexAsToken = (await bip.wordsToRecToken(kitWords))!;
const kitWrapped = await wrapNoteKeyWithRecToken(TACET, noteKey, kitHexAsToken, identityA);
await A('words 派生 hex64 包裹前綴 jr1w.', kitWrapped.startsWith('jr1w.'));
await A('words 派生 hex64 unwrap 救回 noteKey',
  (await unwrapNoteKeyWithRecToken(TACET, kitWrapped, kitHexAsToken, identityA)) !== null);

// ── 10. 附件密文（jr1c.，image attachments；opt-in 未配置即拒） ───────────────

};
secOpen(10, '[10] 附件密文（jr1c. cipherAttach opt-in）'); if (secEnter(10)) {
const bareCfgAttach: NoteCryptoConfig = { ...TACET }; // 無 cipherAttach 欄
let attachCfgThrow = '';
try { await encryptAttach(bareCfgAttach, noteKey, '{"v":1}', 'jr1a:n1:a1'); } catch (e) { attachCfgThrow = (e as Error).message; }
await A('未配置 cipherAttach → encryptAttach throw', attachCfgThrow === 'ERR_ATTACH_NOT_CONFIGURED', attachCfgThrow);

await A('附件前綴 jr1c.', attachCt.startsWith('jr1c.'));
await A('附件 roundtrip（顯式 noteKey）',
  (await decryptAttach(TACET_ATTACH, noteKey, attachCt, attachAad)) === attachPayload);
await A('附件 AAD 防搬移：錯 attachment_id → null',
  (await decryptAttach(TACET_ATTACH, noteKey, attachCt, 'jr1a:note-abc:att-999')) === null);
await A('附件錯鑰匙 → null',
  (await decryptAttach(TACET_ATTACH, await generateNoteKey(), attachCt, attachAad)) === null);

// ── 11. 本機 IDB 密文（jr1d. cipherLocal opt-in）＋ guest 選配拒絕面 ──────────

};
secOpen(11, '[11] 本機 IDB 密文（jr1d. cipherLocal opt-in）＋ guest 選配拒絕面'); if (secEnter(11)) {
// 分享包裹（jrsw.，wrapShare 選配）＋ jr3s. roundtrip（閘本有 roundtrip 斷言缺席）
const TACET_SHARE: NoteCryptoConfig = { ...TACET, wrapShare: 'jrsw.' };
const shareWrapped = await wrapNoteKeyShare(TACET_SHARE, noteKey, 'share-pass-42');
await A('分享包裹前綴 jrsw.', shareWrapped.wrapped.startsWith('jrsw.'));
await A('分享 salt = 16B hex', /^[0-9a-f]{32}$/.test(shareWrapped.salt));
const shareUnwrapped = await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'share-pass-42', shareWrapped.salt);
await A('jrsw unwrap 等值 noteKey（extractable 再 export）',
  shareUnwrapped !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', shareUnwrapped))) === origRaw);
await A('分享錯密語 → null', (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'wrong-share-pass', shareWrapped.salt)) === null);
await A('分享錯 salt → null', (await unwrapNoteKeyShare(TACET_SHARE, shareWrapped.wrapped, 'share-pass-42', 'zz'.repeat(16))) === null);
await A('分享 malformed salt（zz 字元）→ null（salt1 hex 形檢查）',
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

// guest 選配未配置拒絕面（2026-09-19 定案：cipherGuest 轉選配；未配置即拒鐵律）
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
await A('既有 guest 配置 roundtrip 不受選配化影響',
  (await decryptNote(TACET, makeHeldKey(), cipherGuest, 'noteId:n1', { current: () => identityA })) === note);

// guest 空 identity 拒絕面：K_u = SHA-256(prefix ‖ '') 靜默產出「空帳號金鑰」是誤配炸彈
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

// 畸形配置 ''（空字串）正規化面：空字串前綴＝startsWith('') 恆真，
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

// ── 12. 伺服器端原語（makeInboundCipher/validWrappedKey/pickKeyPackage/
//         checkRate/timingSafeEq）＋ 本機鎖定全函式（pinlock jr1p.） ──────────

};
secOpen(12, '[12] 伺服器端原語（auth/ratelimit/hash）＋ 本機鎖定（pinlock）'); if (secEnter(12)) {
// ratelimit 行為面（UPSERT…RETURNING 單句設計收口）：真 node:sqlite 直載 UPSERT…RETURNING 單句，
// 行為斷言全數「真生產函式 checkRate 直驅」——D1 形 shim 包 node:sqlite 只做 D1 run() 的
// {results} 回帶形，無測試端 glue 副本。表名直插 SQL＝注入面驗證；放行判準 count<=max
// 單一真相。同 IP 真併發不 undercount 的 D1 活線證據由 wrangler dev 探針承載（
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
await A('rate：RETURNING 異形回應守衛 fail-open（results 空／alias 斷裂——與儲存故障同向，異形不反向 deny）', await (async () => {
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
await A('isCipherFor 空字首組態 → false（\x27\x27 態 startsWith(\x27\x27) 恆真 accept-all——cipherPrefixRe 守衛不覆蓋直讀 tuple 面，同向收口；非字串 false 契約照舊）',
  (() => {
    const emptyTuple: CipherFormats = { cipherPrefixes: ['', ''], wrapPrefix: 'jr1w.', cipherMax: 5000 };
    const mixed: CipherFormats = { cipherPrefixes: ['', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 5000 };
    return isCipherFor('jr1g.abc', emptyTuple) === false && isCipherFor('純明文', emptyTuple) === false &&
      isCipherFor('jr1g.abc', mixed) === false && // 混合形：空槽摘除、真前綴面承載
      isCipherFor('jr1b.abc', mixed) === true && // 真前綴面零誤傷
      isCipherFor(null, formats) === false; // 非字串 false 面（typed 形合法態；運行時 typeof 守衛承載 unknown 呼叫端）
  })());
await A('makeInboundCipher regex 跳脫全字面（辨別形重推——探針新舊碼輸出一手實測，兩向分歧各一）',
  (() => {
    // 舊碼 .replace('.','\\.') 只跳第一個點，前綴含 regex 符號（| ( )）時家族 regex 失真，
    // 兩方向輸出分歧（一手對照探針帳面：tmp probe-d1.cjs，main 舊碼 vs 分支新碼）：
    // ①完整前綴形『a.b|c()』+A*600（真家族密文標記）：正碼辨得前綴 → >max 密文丟棄 null；
    //   舊碼 regex 辨不出自家前綴 → 誤落明文截斷（>max 密文截半損毀＝舊碼 slice(0,500)）。
    // ②點前截形『a.b』+A*600：舊碼 a\.b 殘臂（從頭起 b64 全程）誤咬 → 丟棄 null；
    //   正碼前綴不完整非家族 → 明文截斷照收 slice(0,500)。兩形缺一即探針無齒。
    const f: CipherFormats = { cipherPrefixes: ['a.b|c()', 'jr1b.'], wrapPrefix: 'jr1w.', cipherMax: 500 };
    const m = makeInboundCipher(f);
    const full = 'a.b|c()' + 'A'.repeat(600);
    const dotHead = 'a.b' + 'A'.repeat(600);
    return m(full) === null && m(dotHead) === dotHead.slice(0, 500);
  })());
// 空字首組態毒形防線：cipherPrefixRe never-match 守衛的行為面。
// 校正（新舊碼組裝對照一手實測）：舊碼
// `[]` 與 `['']` 組裝出 byte-identical `^()[A-Za-z0-9+/]+={0,2}$`（join('|') 同為空串），
// `['','']` 僅多空首選交替 `^(|)…`＝同面——真洞＝無點純 b64 串（≤200）在舊碼
// validWrappedKey/pickKeyPackage 放行（NON-NULL）；帶點前綴向量（'jr1w.'+b64）舊碼本就 null
// （'.' 在 b64 charset 外）＝帳面無承載。初版敘事（charset 恆假自帶防線／空槽首選交替洞）經
// 一手實證俱誤——本段已按實測帳重寫（revert-poison 案為守衛還原面的直接承載）。
// 守衛後（usable 過濾＋never-match）：家族/re 面整面拒絕；inboundCipher 輸出面 zero delta
// （家族路摘除後長路徑 b64≤max 短路進 legacy 慣例層、超限丟棄、明文相容層照收——出口與舊碼
// RE 路徑恆等，probe 33 組合實證）；混合『['','jr1b.']』形只摘空槽、真前綴家族面照活（降級非全拒）。
await A('空字首真洞還原面：無點純 b64 ≤200 空字首組態 → null（cipherPrefixRe never-match——守衛摘除即翻紅；三組態）',
  (() => {
    const pureB64 = b64(new Uint8Array(32)); // 無點 b64（44 字符）——舊碼本就放行＝真洞載體（帶點向量舊碼本就 null，無承載）
    const emptyTuple = ['', ''];
    return validWrappedKey(pureB64, []) === null &&
      validWrappedKey(pureB64, emptyTuple) === null &&
      validWrappedKey(pureB64, '') === null; // string 形空前綴同面
  })());
await A('空字首組態 pickKeyPackage → 整組放棄（validWrappedKey never-match 傳播——wrapped/salt 同 null）',
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

// 本機鎖定（jr1p.）：全函式 roundtrip＋嚴格檢查面（閘本有斷言缺席）
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

// ── 13. 新契約面（hex fail-closed／salt hex 形收口／PH1 鹽注入／錯誤碼語意分離） ──

};
secOpen(13, '[13] unwrap 驗證統一新契約（fail-closed ＋ 語意分離）'); if (secEnter(13)) {
// hexToBytes fail-closed（note-crypto 與 bip39 同步——bip39 面是 HEX64_RE 前置自守）
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
await A(`hexToBytes 全形數字（'２ｆ'）→ Bytes 等值（NFKC 窗殲滅——parse 原始串 NaN 歸零殘形）`, (() => { try { return Array.from(hexToBytes('２ｆ')).join(',') === '47'; } catch { return false; } })());
await A('bip39 hexToBytes 同步（HEX64_RE 自守前提下的舊向量不變）', (await bip.recTokenToWords('ab'.repeat(32)))?.length === 24);
await A('unwrap：鹽 hex 非法字元 → 假錯誤誘餌面 null（原碼靜默歸零會錯誤炸出成功路徑）',
  (await unwrapNoteKey(TACET2, dual.wrapped, passD, 'a'.repeat(31) + 'z')) === null);
// ── 13-2. 包裹前綴快檢上移（t_87ef62dd，外審 #2）：錯前綴 junk 在 KDF 派生前即 null——
// 母型 unwrapNoteKey4 入口快檢（argon2.ts）；五入口（jr1w./jrsw./jr3w./jr3s.＋recToken 兩腿）
// 行為恆 null 不拋（快檢同向 null＝契約零變——錯前綴本就由 openNoteKey:417 拒）；
// 收益面＝錯前綴試探不再付 600k PBKDF2／64MiB Argon2id KDF 成本（計時面對真 KDF 斷言）。
{
  const junkPrefix = 'jr9w.' + wrapped.slice('jr1w.'.length); // 真形 payload 錯前綴（junk 前綴面）
  const t0Junk = performance.now();
  const junkRc = [
    await unwrapNoteKey(TACET, junkPrefix, pass, salt),
    await unwrapNoteKeyShare(TACET, junkPrefix, pass, salt),
    await unwrapNoteKey3(TACET3, junkPrefix, pass, salt),
    await unwrapNoteKey3(TACET3, junkPrefix, 'wrong-passphrase', salt),
    await unwrapNoteKeyShare3(TACET3, junkPrefix, pass, salt),
  ];
  const tJunkMs = performance.now() - t0Junk;
  await A('錯前綴 junk 試探（真 payload 錯前綴面）五入口恆 null 不拋（快檢同向 null＝契約零變）', junkRc.every(r => r === null), JSON.stringify(junkRc.map(r => r === null)));
  // 行為承載面（KDF 未走即 null）：PBKDF2 600k ≈ 60-150ms／Argon2id 64MiB ≈ 120-150ms——
  // 任一入口真付 KDF 即超帽；快檢落地後五次試探總計 ≪1ms（實測 <1ms；帽 30ms＝數量級餘裕）。
  // 結構面（真防線）＝下方源碼計數錨＋接線形——計時帽是行為輔助面（未來快機 PBKDF2 縮水時
  // 計數錨仍承載）；對照組只承載「正確前綴快檢後仍真 unwrap」＝零變更契約行為面（不計時——
  // 絕對時距對照在快慢機間是 flake 源，tacet-dev runner 母型）。
  await A('錯前綴 junk 試探五入口計時帽 ≪ KDF 成本（快檢在 deriveKek/deriveKekArgon 前——真付 KDF 即超帽）', tJunkMs < 30, 'junk5=' + tJunkMs.toFixed(2) + 'ms');
  const t2Legacy = performance.now();
  const legacyBack = await unwrapNoteKey(TACET, wrapped, pass, salt);
  await A('對照組：正確前綴 unwrap 真付 KDF 且救回 noteKey（快檢零變更契約——正確路徑行為面）',
    legacyBack !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', legacyBack))) ===
    hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey))), 'elapsed=' + (performance.now() - t2Legacy).toFixed(2) + 'ms');
  // 源碼計數錨（快檢五點＋recToken 雙腿接線＝tacet-dev「條款與接線分離」）：五入口 startsWith 快檢
  // 恰 5（摘任一＝計數變異）；recToken 雙腿錨——jr1r. 面在 deriveRecKek 前、cfg.wrap 面在
  // deriveRecLegacyKek 前的相鄰形（錯位接線——快檢搬進 KDF 之後＝形變異即 RED）。
  const ncSrc132 = await srcOf('../src/client/note-crypto.ts');
  const arSrc132 = await srcOf('../src/client/argon2.ts');
  const qcNc = (ncSrc132.match(/if \(!wrapped\.startsWith\(cfg\.(wrap|wrapShare|wrapRec|wrap)\)\) return null;/g) ?? []).length;
  const scNc = ncSrc132.split('wrapped.startsWith(cfg.wrapRec)').length - 1; // jr1r. 腿條件面（跳過形）
  const qcAr = (arSrc132.match(/if \(!wrapped\.startsWith\(cfg\.(wrap3|wrapShare3)\)\) return null;/g) ?? []).length;
  await A('源碼計數錨：startsWith 快檢恰 6 條（note-crypto 4＝jr1w./jrsw./舊腿終面/jr1r. 條件面＋argon2 2；錯前綴試探防線——摘任一條即計數變異 RED）',
    qcNc === 3 && scNc === 1 && qcAr === 2, 'nc=' + qcNc + ' sc=' + scNc + ' ar=' + qcAr);
  await A('源碼計數錨：recToken 雙腿快檢接線形（jr1r. 腿條件面在 deriveRecKek 前——禁 return null 短路雙試；舊面終面接線在 deriveRecLegacyKek 前）',
    /if \(cfg\.wrapRec && cfg\.recKekHkdf && wrapped\.startsWith\(cfg\.wrapRec\)\) \{\n {6}const recKek = await deriveRecKek\(/.test(ncSrc132)
    && /if \(!cfg\.wrap\) return null;\n {4}if \(!wrapped\.startsWith\(cfg\.wrap\)\) return null; \/\/ 快速前綴快檢：錯前綴 junk 免付 600k PBKDF2 成本\n {4}const legacyKek = await deriveRecLegacyKek\(/.test(ncSrc132));
  // 毒化錨前綴自檢（錨窗同字面點數——毒化矩陣 Q 案的錯位防線；jr1w./舊腿兩行同註解開頭——
  // 錨帶全註解頭消歧：『（t_87ef62dd）』＝jr1w. 面、『：錯前綴』＝舊腿終面）
  await A('快檢錨前綴自檢：五錨各恰 1（split 計數帳）',
    ncSrc132.split('if (!wrapped.startsWith(cfg.wrap)) return null; // 快速前綴快檢（t_87ef62dd）').length === 2
    && ncSrc132.split('if (!wrapped.startsWith(cfg.wrap)) return null; // 快速前綴快檢：').length === 2
    && ncSrc132.split('if (!wrapped.startsWith(cfg.wrapShare)) return null; // 快速前綴快檢').length === 2
    && ncSrc132.split('if (cfg.wrapRec && cfg.recKekHkdf && wrapped.startsWith(cfg.wrapRec)) {').length === 2
    && arSrc132.split('if (!wrapped.startsWith(cfg.wrap3)) return null;').length === 2
    && arSrc132.split('if (!wrapped.startsWith(cfg.wrapShare3)) return null;').length === 2);
}
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
// 鍛造校正：encrypt 必帶 additionalData('notekey')＝與 decryptWithKey
// 同 AAD——缺 AAD 的鍛造 GCM 層恆拒＝rawHex 形檢從未執行（斷言空轉）。
// craftKek 鏡像真 deriveKek（同 pass 同 salt 同 600k）＝鍛造鏈與真 unwrap 同 KEK：
// 有效形鍛造真解開（NON-NULL 自證鏈活）、畸形形由各檢查點拒——機制面直接可觀察。
// AAD 單一化：F_AAD 是四鍛造向量唯一 AAD 源（對 decryptWithKey 同 AAD 律的 helper 收口）。
const F_AAD: BufferSource = enc.encode('notekey');
await A('鍛造機制面：帶 AAD 鍛造 ct 可解回 rawHex（形檢層可達＝斷言活）', await (async () => {
  const kekC = await craftKek;
  const ivC = crypto.getRandomValues(new Uint8Array(12));
  const ctC = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivC, additionalData: F_AAD }, kekC, enc.encode('zz' + 'a'.repeat(62)) as BufferSource));
  return (await decryptWithKey(kekC, new Uint8Array([...ivC, ...ctC]), 'notekey')) === 'zz' + 'a'.repeat(62);
})());
await A('鍛造空轉形：同 payload 無 AAD 鍛造 → decryptWithKey null（GCM 層恆拒＝空轉病理）', await (async () => {
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
// 錯誤碼語意分離：空 PIN ≠ 未配置；jr3d 兩 case 同碼分流
await A('wrapNoteKeyDual 空 PIN → ERR_PIN_EMPTY（非 NOT_CONFIGURED）', await (async () => {
  try { await wrapNoteKeyDual(TACET2, noteKey, passD, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual 空 PIN 全形空白正規化後 → ERR_PIN_EMPTY', await (async () => {
  try { await wrapNoteKeyDual(TACET2, noteKey, passD, '　'); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual 未配置 wrapDual → ERR_DUAL_NOT_CONFIGURED（契約不變）', await (async () => {
  try { await wrapNoteKeyDual(TACET, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_DUAL_NOT_CONFIGURED'; }
})());
await A('wrapNoteKeyDual3 空 PIN → ERR_PIN_EMPTY（兩 case 同碼分流）', await (async () => {
  try { await wrapNoteKeyDual3(TACET3, noteKey, passD, ''); return false; } catch (e) { return (e as Error).message === 'ERR_PIN_EMPTY'; }
})());
await A('wrapNoteKeyDual3 未配置 wrapDual3 → ERR_JR3W_NOT_CONFIGURED（契約不變）', await (async () => {
  try { await wrapNoteKeyDual3({}, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_JR3W_NOT_CONFIGURED'; }
})());
// PH1 鹽注入：預設舊值零行為變更
await A('derivePh1Argon 預設鹽零行為變更（同 pass 同值）',
  (await derivePh1Argon('probe-determinism-pass-42')) === ph1v2a);
await A('derivePh1Argon 預設分支源碼面 = encode(PH1_V2_SALT)（鹽預設單一真相錨；同-pass 同值斷言對預設值漂移無承載力）',
  /saltArg \?\? new TextEncoder\(\)\.encode\(PH1_V2_SALT\)/.test(await srcOf('../src/client/argon2.ts')));
await A('derivePh1Argon 自選鹽 → 不同派生值', (await derivePh1Argon('probe-determinism-pass-42', new Uint8Array(12))) !== ph1v2a);
await A('derivePh1Argon 自選鹽 hex64 形', /^[0-9a-f]{64}$/.test(await derivePh1Argon('x', new Uint8Array(12))));
await A('PH1_V2_SALT re-export 在場（index barrel；其他產品可見可注入同源鹽）', PH1_V2_SALT === 'tacet-ph1-v1');
// index barrel 新匯出：clearLocalWrap/buildBindPayload（「缺匯出」條誤差已校正——以閘承載）
await A('index barrel 匯出 clearLocalWrap/buildBindPayload', await (async () => {
  const src = await import('../src/index.ts');
  return typeof src.clearLocalWrap === 'function' && typeof src.buildBindPayload === 'function';
})());
// PinLockConfig 死欄退場：型別面真齒＝excess-property 探針（
// 舊形 typeof cfg==='object' 恆真空轉——實測校正；行號帳由毒化 tsc 輸出承載
// 而非註解寫死——新增段推移行號＝註解行號帳漂移）：required 復活形＝TS2741（PINLOCK
// 常數面）＋TS2345（未配置兩案），optional 復活形＝舊形探針未帶該欄＝excess-property 檢照不到＝tsc 0 綠——robust 形＝pristine 就在探針字面量帶 `noteKeyExtractable:
// undefined as never`＋前置 @ts-expect-error：欄位復活任何形（required/optional/false 字面量）都多出待位錯誤＝TS2578 紅；
// pristine 態錯誤恰由 expect-error 吸收＝全 repo tsc 0 綠（探針字面量缺 false 形欄不另生錯＝零加值面除名）。
// 本面綠態＝core+tacet 摘欄後編譯綠。@ts-expect-error 常駐在場（robust 形，見上註）；pristine 態恰由其吸收。
// @ts-expect-error — 死欄退場待位錯誤面（pristine 恰此一待位錯由本指令吸收；欄位復活任何形＝本指令反噬 TS2578＝P12 案紅）
const _cfgProbe: PinLockConfig = { pinLock: 'jr1p.', pinLockSaltPrefix: 'p:', pinLockAad: 'notekey-pinlock', noteKeyExtractable: undefined as never };
void _cfgProbe;
// 壞 b64 面向量（openNoteKey 誠實契約「任何不符恆回 null 不拋」的可觀察承載）：
await A('鍛造壞 base64 面字符 → unwrapNoteKey null（openNoteKey unb64 拋點吞收＝不拋契約；家族面毒化形＝頂層 crash，本面包 try/catch 收乾淨 ✗）', await (async () => {
  try {
    return (await unwrapNoteKey(TACET, 'jr1w.' + '!!not-base64!!', pass, salt)) === null;
  } catch { return false; } // 吞收契約破形（本體或呼叫端漏 catch）＝本面 false 紅，非 runner crash
})());
await A('openNoteKey 直接呼叫：壞 base64 → null 不拋（本體吞收點）', await (async () => {
  const kekC = await craftKek;
  return (await openNoteKey('jr1w.' + '!!not-base64!!', kekC, 'notekey', 'jr1w.')) === null;
})());

//── 13-3. 發行 tarball 治理面（外審 #7 的封閉集承載——open-card-pr.sh 摘除的 tarball 面對位；t_87ef62dd）──
//（pack 驗證讀 package.json files 白名單——npm 不可用環境 = 顯性 SKIP 形自守衛，非 silent true）
await A('[22] 發行 tarball 零 open-card-pr.sh（治理掃蕩面——pack 白名單逐檔對帳），pack 不可用 = SKIP 顯形', await (async () => {
  try {
    const cp132 = (globalThis as unknown as { process?: { getBuiltinModule?: (id: string) => { execFileSync?: (c: string, a: string[], o: Record<string, unknown>) => { toString(enc: string): string } } } }).process?.getBuiltinModule?.('node:child_process');
    if (!cp132?.execFileSync) return false; // 自守衛：缺席＝顯性 FAIL（非 silent true）
    const out132 = cp132.execFileSync('npm', ['pack', '--json', '--dry-run'], { cwd: new URL('..', import.meta.url).pathname, encoding: 'buffer', timeout: 120000 });
    const j132 = JSON.parse(out132.toString('utf8')) as { files?: { path: string }[] }[];
    const files132 = (j132[0]?.files ?? []).map((f) => f.path);
    const g132 = files132.filter((p) => p === 'scripts/open-card-pr.sh' || p.startsWith('scripts/'));
    return files132.length > 0 && !files132.includes('scripts/open-card-pr.sh') && g132.length === 2;
  } catch { return false; }
})());

// ── 14. 效能形契約（零行為變更——輸出 byte 等價是合約；錨面咬「形」） ──
//
// 效能批的閘承載物理：執行時間不能進閘（機器相依）——咬「並行形在場＋串行殘留歸零」
// 靜態錨＋「Argon 串行刻意保留」負向＋b64 輸出等價行為面＋Max-Age/sideEffects 字面＋
// ikm 組裝序行為向量（KAT14 凍結 blob）。執行帳（node 26.8.1 實測，2026-10-04）：
// buildBindPayload 串行 133-152ms→並行 68-84ms；dual 串行 234→並行 179ms median；
// b64 4MiB 132-181ms→18ms。瀏覽器實測 222ms→27ms。

};
secOpen(14, '[14] 效能形契約（buildBindPayload 並行／b64 分塊／argon 禁並行／CORS Max-Age／sideEffects）'); if (secEnter(14)) {

const noteCryptoSrc14 = await srcOf('../src/client/note-crypto.ts');
const argon2Src14 = await srcOf('../src/client/argon2.ts');
const corsSrc14 = await srcOf('../src/server/cors.ts');
await A('[14] buildBindPayload 兩段共用 Promise.all 並行錨（wrapNoteKey＋wrapNoteKeyWithRecToken）',
  /await Promise\.all\(\[\r?\n\s*wrapNoteKey\(cfg, noteKey, passphrase\),\r?\n\s*wrapNoteKeyWithRecToken\(cfg, noteKey, recToken, identity\)/.test(noteCryptoSrc14));
await A('[14] deriveKek2 輸入順序錨（pass 段 raw 收口形＋Promise.all 相鄰形——O2 毒形即本錨翻面）',
  /await Promise\.all\(\[\r?\n\s*derivePbkdf2Bits\(passphrase, salt1, PBKDF2_ITERATIONS\),\r?\n\s*derivePbkdf2Bits\(pin,/.test(noteCryptoSrc14));
await A('[14] deriveKek2Argon 正向串行錨（pass/pin 兩段 deriveArgon2id 串行在場）',
  /const passBits = await deriveArgon2id\(/.test(argon2Src14) && /const pinBits = await deriveArgon2id\(/.test(argon2Src14));
await A('[14] argon2 destructure 並行形歸零（舊串行面對稱收口——防逆向回歸）',
  argon2Src14.split('const [passBits, pinBits] = await Promise.all([').length === 1);
await A('[14] buildBindPayload 舊串行形歸零（await wrapNoteKeyWithRecToken 串行殘留）',
  !noteCryptoSrc14.includes('await wrapNoteKeyWithRecToken'));
await A('[14] deriveKek2 舊串行形歸零（串行 passBits 殘留）',
  !/const passBits = await derivePbkdf2Bits/.test(noteCryptoSrc14));
// 並行錨升左手側——destructure 與 Promise.all 相鄰形恰一，對調滑接（pin‖pass）
// 即 RED（RHS 指令序不變＝原本體並行錨不動，兩錨分工：RHS 面／組件序面）。
await A('[14] deriveKek2 destructure 左手側恰一（const [passBits, pinBits] ＋ Promise.all 相鄰形——swap 滑接即 RED）',
  noteCryptoSrc14.split('const [passBits, pinBits] = await Promise.all([').length === 2);
// 行為面：逐值凍結 jr2w. blob（手工 pristine 組裝＝passBits@0‖pinBits@32 序）——
// destructure 對調滑接產 pin‖pass ikm＝本 blob 不可解（pristine 自解
// true／互解 null 雙向一手實證）。凍結定值自足：
// salt1 'a1'×16／pinSalt 0xb2+i×16／iv 0x44+i×12／raw 'c3'×32／pass/pin 明寫——重放＝按定值
// 重建 KEK2（HKDF info 'journal-kek2-v1:jr2w.'、aad 'notekey2'）比對 unwrap=raw。
const KAT14 = {
  blob: 'jr2w.srO0tba3uLm6u7y9vr/AwURFRkdISUpLTE1OTy8+hmx+AhMYCgPVBH1Q1q1UnjPF9uvN/ie4DoYqh4LGkMTHvHDy/Sku/lMRvoRWfuqSuIlX0rEpVU8HfMajsaYtzaz1zHFQELEIuzTsM6+S',
  salt1: 'a1'.repeat(16),
  pass: 'correct-horse-battery-staple-42',
  pin: '482913',
  raw: 'c3'.repeat(32), // 計算式構造（手打對數面禁止——首跑 1 FAIL 即手打 raw 對數錯的實證）
};
await A('[14] jr2w. ikm 組裝序行為向量（凍結 blob unwrap=raw——destructure 對調滑接不可解）',
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
  // sideEffects 前提：src 標目 **遞迴** 枚舉（硬編碼清單退場——新模組
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
              // 宣告行初始化面：const x = <呼叫形>()＝模組載入即執行（缺口面）。
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

// ── 15. 密語正規化 v3 世代（normalizePassphrase＋jr4w./jr4d.＋PH1 v3） ──
//
// 帶內版本化母型實例：密語 KEK 輸入契約改變（raw → normalizePassphrase NFKC-only）＝新前綴。
// 命名兩軸分離：「v3 家族」＝PH1 規格代（derivePh1ArgonV3）；前綴數字軸 jr4w./jr4d.
// ＝KDF 世代代（jr1w→jr2w→jr3w→jr4w，README 家族表對照）。舊家族（jr1w./jr2w./jr3w./jr3d.）
// 函式體零改＝raw 契約永久不變——本節同字面雙家族對照向量（ＰＡＳＳ１２x／PASS12x）就是
// 「免換前綴合約證明」的承載面：同組字串在舊家族恆異 KEK（raw 直派生）、在 v3 家族恆同 KEK（NFKC 收容）。

};
secOpen(15, '[15] 密語正規化 v3 世代（normalizePassphrase／jr4w.／jr4d.／PH1 v3）'); if (secEnter(15)) {

const noteCryptoSrc15 = await srcOf('../src/client/note-crypto.ts');
const argon2Src15 = await srcOf('../src/client/argon2.ts');
const passD4_NFKC = normalizePassphrase(passD4); // 與 passD 恆等（NFKC 收容）——P2 毒化翻面本體（毒形即收口形計數錨翻＋毒翻 = NFKC-effective 帳面翻，雙承載）

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
await A('dual4 前綴 jr4d.', dual4.wrapped.startsWith('jr4d.'));
await A('dual4 salt1 = 16B hex', /^[0-9a-f]{32}$/.test(dual4.salt));
const unwrappedD4 = await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, pinD, dual4.salt);
const dual4NfkEq = unwrappedD4 !== null
  && hex(new Uint8Array(await crypto.subtle.exportKey('raw', unwrappedD4))) === origRaw; // 全形 wrap → NFKC 形：unwrap 真救回（null 恆 false＝normalize 摘除不可藏）
await A('dual4 unwrap 等值 noteKey（extractable 再 export；全形 wrap 面 NFKC 等價自證——not-null 恆 false 恆真盲區免疫）', dual4NfkEq);
const dual4a = await wrapNoteKeyDual4(TACET4, noteKey, passD, pinD); // ASCII NFKC 慣用形 wrap（passD＝passD4 的 NFKC 位——上式自證）
const dual4NfkRev = dual4a !== null && (await unwrapNoteKeyDual4(TACET4, dual4a.wrapped, passD4, pinD, dual4a.salt)) !== null; // ASCII 包 → 全形解（修真向：feed passD4；無 NFKC 即 null）
await A('dual4 pass 段 NFKC 反向等價（ASCII wrap → 全形 unwrap；PIN 段契約不動）', dual4NfkRev === true);
await A('dual4 PIN 大小寫不敏感（normalizePin 契約 v3 世代照舊）', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '2580AB', dual4.salt)) !== null);
await A('dual4 PIN 全形 NFKC 等價', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '２５８０ＡＢ', dual4.salt)) !== null);
await A('dual4 錯 PIN → null', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '999999', dual4.salt)) === null);
await A('dual4 空 PIN → null（unwrap 面）', (await unwrapNoteKeyDual4(TACET4, dual4.wrapped, passD, '', dual4.salt)) === null);
await A('wrapNoteKeyDual4 空 PIN → ERR_PIN_EMPTY（非 NOT_CONFIGURED——分流語意 v3 世代照舊）', await (async () => {
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
await A('未配置 wrapDual4 → wrapNoteKeyDual4 拒絕（ERR_JR4D_NOT_CONFIGURED——錯誤碼語意分離）', await (async () => { try { await wrapNoteKeyDual4({}, noteKey, passD, pinD); return false; } catch (e) { return (e as Error).message === 'ERR_JR4D_NOT_CONFIGURED'; } })());
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
await A('derivePh1ArgonV3 自選鹽 → 不同派生值（saltArg 慣例）',
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

// ── 16. 常駐毒化矩陣（自帶——對真模組行為斷言的毒化證據隨每執行重建） ──
//
// 母型（閘常駐毒化面）：對 /tmp 拷貝樹做突變後重跑同一組行為斷言——
// 「毒化態恰翻面」meta 斷言承載外部 poison runner 的證據；毒化跑在拷貝樹＝本 repo 樹零接觸。
// 期望值每毒型真跑實測（/tmp 拷貝樹一手實測，見各案歸屬帳）；還原面由
// /tmp 樹的出生即棄承載（本 repo 樹 byte 不動）。每案還原後重跑回綠（還原正確性的行為帳）。
//
// 案期望值（修正後程式碼上 /tmp 毒化重測，本 run 一手帳——還原後重跑回綠帶）：
//   P1 摘 jr4w unwrap 入口 normalize → nfail=4 帳（正規化等價面＋KAT 慣用形帳面＋兩 [15] 錨跟隨）
//   P2 本體夾帶 lowercase → nfail=11 帳（NFKC-effective 帳面翻面集；P3/P4/P5 針毒形零匹配＝全格向量化）
//   P3 摘 derivePh1ArgonV3 入口 normalize → nfail=2 帳（ph1v3 NFKC 等價面＋[15] 收口形錨）
//   P4 摘 jr4w wrap 入口 normalize → nfail=4 帳（NFD 收容面＋全形/ASCII 同密語面＋兩 [15] 錨）
//   P5 摘 jr4d wrap 入口 normalize → nfail=5 帳（dual4 等值面＋PIN 兩面＋兩 [15] 錨）
//   O1 jr3w.wrap 入口接 normalize（禁手）→ nfail=4 帳（jr3w 凍結兩面＋兩 [15] 錨）
//   O2 deriveKek2 pass 段接 normalize（禁手）→ nfail=2 帳（[14] 輸入順序錨＋jr2w 凍結 normalized 面）
//   O3 normalizePin 摘 trim/lowercase → nfail=9 帳（>=帽——韌性；PIN 契約毒化真 RED）
//   O4 摘 jr4d unwrap 入口 normalize（反拉禁手）→ nfail=4 帳（NFKC 反向等價面＋KAT 慣用形帳面＋兩 [15] 錨）
//   O1-src/O2-src/O4-src 源碼計數錨（[15] 同形複寫——防單點誤删）：
//   v3 家族入口 normalize 收口形恰 3×3＋PBKDF2 raw 恰 1——毒化形即計數變異，本 repo 樹直接斷言。
// 每案結束後還原／清樹（出生即棄）；designated 面帳寫在案例名內。

};
secOpen(16, '[16] 常駐毒化矩陣（v3 家族語意毒＋舊家族不變毒）'); if (secEnter(16)) {
{
  const getBuiltin = (id: string): unknown =>
    (globalThis as unknown as { process?: { getBuiltinModule?: (i: string) => unknown } }).process?.getBuiltinModule?.(id);
  const cpMod = getBuiltin('node:child_process') as { execFileSync?: (cmd: string, args: string[], opts: { cwd: string; encoding: string; stdio: unknown[]; env?: Record<string, string>; timeout?: number }) => string } | undefined;
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
      const treePaths16: string[] = []; // 殘留判準只看本 run 喚出的 tree16 路徑（跨執行/跨 host 零耦合）
      const tmpdir16 = osMod!.tmpdir!();
      const coreNM = path16.resolve(new URL('.', import.meta.url).pathname, '../node_modules');
      const repoRoot16 = path16.resolve(new URL('.', import.meta.url).pathname, '..'); // repo root 錨定（禁 cwd 依賴——自 repo 外呼叫 cp 樹也恆真）
      const gitIgnoreSkip = (src: string): boolean => src === '.git' || src.endsWith('/.git') || src.includes('/.git/') || src === 'node_modules' || src.endsWith('/node_modules') || src.includes('/node_modules/');
      let tree16 = '';
      const mkTree = (): void => {
        fs16!.rmSync!(tree16, { recursive: true, force: true });
        tree16 = fs16!.mkdtempSync!(path16.join(tmpdir16, 'core-poison-'));
        treePaths16.push(tree16); // 本 run 喚出記帳（收尾殘留判準的封閉集）
        fs16!.cpSync!(repoRoot16, tree16, { recursive: true, filter: (src: string) => !gitIgnoreSkip(src) }); // 零 .git/零 node_modules 實拷（repo root 錨定——非 cwd；CI 冷複製成本歸零——毒化樹 node_modules 走下方 symlink）
        fs16!.rmSync!(path16.join(tree16, 'node_modules'), { recursive: true, force: true });
        // node_modules 走 symlink（worktree 慣例 cp 語意不跟隨）：本閘執行樹一定有 node_modules
        //（@scure 對照組＋typescript）——毒化樹補 symlink 即可；缺席環境（bare npm ci 後無 install）
        // 本閘自己在主樹就跑不起來，不是毒化矩陣的責任面。
        // （[18] 毒化窗無此補線——t_ce675413 r1 已知差異：拷貝樹環境缺 @scure 參照組時
        //   內層輸出恰帶 [2] 參照組 FAIL 1 面＝可預期環境面，非缺陷；本機常態在場照綠。）
        exec16('ln', ['-s', nodeEnvOk ? coreNM : '', path16.join(tree16, 'node_modules')], { cwd: tree16, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      };
      const runGate16 = (): { rc: number; out: string } => {
        // 內層 gate 執行帶 POISON_GATE_INNER=1 sentinel——[16] 矩陣在內層自我跳過＝遞迴防線
        //（拷貝樹的閘檔含本節全文；無 sentinel 會自拷貝再自跑＝18+ 連鎖行程實證）。
        try { return { rc: 0, out: exec16('node', ['--experimental-strip-types', 'scripts/verify-core-crypto.ts'], { cwd: tree16, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...(processMod?.env ?? {}), POISON_GATE_INNER: '1' }, timeout: 240000 }) }; }
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
        // P1 名單面 designated（本 run 重測帳）：jr4w 正規化等價面＋[17] jr4w NFKC 慣用形
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
      // P2 本體夾帶 lowercase → NFKC-effective 行為翻面集（重測：nfail=11 帳——非 crash 形）
      {
        mkTree();
        const mut = poison16('src/client/note-crypto.ts',
          "export function normalizePassphrase(passphrase: string): string {\n  return passphrase.normalize('NFKC');\n}",
          "export function normalizePassphrase(passphrase: string): string {\n  return passphrase.normalize('NFKC').toLowerCase();\n}");
        const g = runGate16();
        // P2 名單面 designated（重測帳）：NFKC-effective 帳面翻面集（分離向量二＋並存不混＋jr4w
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
        // P3 名單面 designated：ph1v3 NFKC 等價面（全形 vs ASCII 同 ph2）真翻。
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
        // P4 名單面 designated：jr4w 全形/ASCII 同密語面（全形 wrap 的 NFKC 收容）真翻。
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
      // O2 deriveKek2 pass 段接 normalize（禁手形）→ 真翻面案（名單級承載；本 run 重測帳＝
      // [14] 輸入順序錨翻＋jr2w 凍結 normalized 面翻，恰 2 面——兩面各自 designated，帳寫在案斷言內）。
      {
        mkTree();
        const mut = poison16('src/client/note-crypto.ts',
          "  const [passBits, pinBits] = await Promise.all([\n    derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS),",
          "  const [passBits, pinBits] = await Promise.all([\n    derivePbkdf2Bits(normalizePassphrase(passphrase), salt1, PBKDF2_ITERATIONS),");
        const g = runGate16();
        // O2 行為翻 2 面帳（本 run 毒化重測）：[14] 輸入順序錨（毒形不匹配 raw 收口形恰-1 形）＋jr2w 凍結
        // normalized 解翻面（毒化 wrap 也 normalize → ascii 形同 KEK）——名單級承載＝[14] 輸入順序錨面（案內檢）；
        // nfail 精確 2 帳＝P5/P1 形的錨翻面恰補位（新案新增 PIN/dual 覆蓋時 >= 帽韌性）。
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
        // O1 名單面 designated（本 run 重測帳）：jr3w 凍結兩面（全形照解面翻＋normalized 恆拒
        // 面翻）＝raw 入口契約復活的行為齒；4 面帳＝兩行為面＋兩 [15] 錨跟隨。
        const o1fwRed = g.out.split('\n').some((l: string) => l.includes('jr3w 全形 wrap 照解') && l.trimStart().startsWith('✗'));
        const o1normRed = g.out.split('\n').some((l: string) => l.includes('jr3w 拒收 normalized 慣用形') && l.trimStart().startsWith('✗'));
        await A('[16] O1 jr3w.wrap 入口接 normalize（禁手形）→ 凍結兩面真翻（nfail=4 帳；名單級承載）',
          mut.applied && g.rc === 1 && nfail(g.out) >= 2 && o1fwRed && o1normRed, 'rc=' + g.rc + ' nfail=' + nfail(g.out) + ' fails=' + realFails(g.out).map(s => s.slice(0, 44)).join(';;'));
        fs16!.rmSync!(tree16, { recursive: true, force: true });
      }
      // O4 unwrapNoteKeyDual4 入口接 raw（v3 反拉形）→ 「毒態」行為面翻轉樣本（修正後真有齒）
      {
        mkTree();
        const mut = poison16('src/client/argon2.ts',
          "    const kek2 = await deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');",
          "    const kek2 = await deriveKek2Argon(cfg, passphrase, pinNorm, salt1, pinSalt, 'journal-kek2-v1:' + cfg.wrapDual4);\n    const rawHex = await decryptWithKey(kek2, ivPrefixedCt, 'notekey2');");
        const g = runGate16();
        // O4 名單面 designated（本 run 重測帳）：dual4 pass 段 NFKC 反向等價面（修正後
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
        // 與 [15] 同形計數錨＝「複寫防單點誤删」（[16] 內層保留 O-案源碼錨——[15] 錨被未來誤删時本段仍咬）。
        await A('[16] O1-src 計數錨（[15] 同形複寫——防單點誤删）：argon2 normalize 收口入口形恰 3（禁手形任何復活＝計數變異即 RED）',
          argonSrcNow.split('deriveKekArgon(deriveInput(passphrase)').length === 3
            && argonSrcNow.split('deriveArgon2id(\n    deriveInput(passphrase)').length === 2
            && argonSrcNow.split('deriveKek2Argon(cfg, deriveInput(passphrase)').length === 3);
        await A('[16] O2-src 計數錨：note-crypto PBKDF2 家族 pass 段 raw 形恰 1 處（deriveKek2；接 normalize 即 RED——raw 錨 length 2）',
          ncSrcNow.split('derivePbkdf2Bits(passphrase, salt1, PBKDF2_ITERATIONS)').length === 2);
        await A('[16] O4-src 計數錨（[15] 同形複寫）：jr4d unwrap 入口 normalize 形恰 2（wrap/unwrap 對稱；摘除或反拉即變異）',
          argonSrcNow.split('deriveKek2Argon(cfg, deriveInput(passphrase), pinNorm').length === 3);
      }
      // 收尾：毒化樹清理自證（封閉集——只核對本 run 喚出的 tree16 路徑；跨執行/
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
};

// ── 17. KAT 凍結向量：HKDF info 域世代分離（修正承載面） ──────────────
//
// 凍結常數計算式構造（KAT 母型——raw 'c3'.repeat(32) 寫 c3x32 帳面）：
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
    secOpen(17, '[17] KAT 凍結向量：HKDF info 域世代分離＋v3/raw 入口契約（jr3w./jr3d./jr4w./jr4d. 四 blob）'); if (secEnter(17)) {
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
    };
  }

// ── 18. 本機包裹專用前綴（wrapLocal opt-in＋讀舊寫新自癒；jr1l.） ──
//
// 舊實作借用 cfg.wrap（jr1w. passphrase 包裹前綴）寫本機包裹＝「一個前綴一份契約」的第二
// 違例（wrappedRec 專用前綴歸 v0.2.0 世代收口）。收口三面：
//   ①寫面專用前綴：storeLocalWrap 寫入恆 cfg.wrapLocal（jr1l.）；未配置＝退場無寫入
//     （cipherLocal opt-in 母型——未配置面零寫入零拋）。
//   ②讀舊寫新自癒：loadLocalWrap 先試新前綴（本體嚴格面）；命中舊形（借用期 jr1w. blob）
//     回落解密後重包 cfg.wrapLocal 回寫（自癒恰一次）；解不回（損壞/他機搬來）誠實 null
//     不硬遷移。
//   ③未配置態讀取面：照走舊形 cfg.wrap（行為不變），且不自癒重寫（heal 綁在新前綴面）。
// KEK 不動＝deriveGuestKey（identity 派生、passphrase-free——session 期免重打密語的機制
// 原樣）；本段只界「前綴」面（payload 布局的 KDF/prefix 契約由前綴界定——帶內版本化母型）。
secOpen(18, '[18] 本機包裹專用前綴（wrapLocal=jr1l. opt-in＋讀舊寫新自癒）'); if (secEnter(18)) {
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
  await A('[18] 源碼窗：窗尾 floor 插值帳（真窗 ' + localWin18.length + ' 字元當地量——floor 是帳漂移承重件，隨窗漂移即帳錯）', localWin18.length > 1910, 'win=' + localWin18.length);
  await A('[18] 源碼窗：本機段零 ERR_WRAP_NOT_CONFIGURED 禁令面（throw 復活即反——毒化咬復活）',
    !localWin18.includes('ERR_WRAP_NOT_CONFIGURED'));
  await A('[18] 源碼窗：寫面唯 cfg.wrapLocal seal＋舊借形零殘留（v1 借用面復活即反）',
    localWin18.split('sealNoteKey(cfg.wrapLocal').length === 2 && !localWin18.includes('sealNoteKey(cfg.wrap,'));
  await A('[18] 源碼窗：回落三元恰 1（收口形——自癒腿與未配置態同走單一 cfg.wrap 面；借用形復活即 2+）＋自癒接線（if legacy → storeLocalWrap identity legacy 恰 1）',
    localWin18.split('openNoteKey(stored, guest, \'notekey-local\', cfg.wrap)').length === 2
    && localWin18.split('await storeLocalWrap(cfg, identity, legacy)').length === 2
    && /if \(legacy\) \{\s*await storeLocalWrap\(cfg, identity, legacy\);/.test(localWin18));
  await A('[18] 界面欄：wrapLocal? 宣告恰 1（note-crypto 全檔——NoteCryptoConfig 選配欄）',
    ncSrc18.split('wrapLocal?: string;').length === 2);
  // ── [18] 常駐毒化矩陣（本機段結構毒三案——母型 [16] gate-rerun 形：/tmp 拷貝突變＋內層整組閘重跑＋出生即棄） ──
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
      const cp18 = getBuiltin18('node:child_process') as { execFileSync?: (cmd: string, args: string[], opts: { cwd: string; encoding: string; stdio: unknown[]; env?: Record<string, string>; timeout: number }) => string } | undefined;
      const runGate18 = (workDir: string): { rc: number; out: string } => {
        // 內層 gate 執行帶 POISON_GATE_INNER=1 sentinel——三毒化節在內層自我跳過＝遞迴防線
        //（[16] runGate16 同形；拷貝樹的閘檔含三節全文，無 sentinel 會自拷貝再自跑）。
        try {
          const out = cp18!.execFileSync!('node', ['--experimental-strip-types', 'scripts/verify-core-crypto.ts'], { cwd: workDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...((globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {}), POISON_GATE_INNER: '1' }, timeout: 240000 });
          return { rc: 0, out };
        } catch (e: unknown) {
          const err = e as { stdout?: string; stderr?: string; status?: number };
          return { rc: err.status ?? 1, out: (err.stdout ?? '') + (err.stderr ?? '') };
        }
      };
      // 毒化窗（同字面點數律——needlePA18/PB18/PC18/P18d 毒化前點數自檢在 withPoisonRun18 內）。
      // byte-exact 帳：srcBefore sha256 毒前釘死；srcAfter 同值＝毒化零突變本樹。
      const sha18 = (s: string): string =>
        (getBuiltin18('node:crypto') as { createHash?: (a: string) => { update: (s: string) => { digest: (e: string) => string } } } | undefined)?.createHash?.('sha256')!.update(s)!.digest('hex')!;
      const srcBefore18 = await srcOf('../src/client/note-crypto.ts');
      const shaBefore18 = sha18(srcBefore18);
      const trees18: string[] = [];

      // 三案改 gate-rerun 形（改形照 [16] runGate16 母型）：
      // 拷貝樹突變 src/client/note-crypto.ts 後重跑內層整組閘（POISON_GATE_INNER=1 遞迴
      // 防線——內層三毒化節自我跳過），數 [18] 名單 ✗ 真紅：designated-FAIL 帳＝毒化不只
      // 翻面，更要咬「未來有人把 [18] 主斷言改弱」——弱化後毒化名單帳不齊即 RED。
      const withPoisonRun18 = async (label: string, needle: string, replacement: string, cases: string[], want: number): Promise<void> => {
        const dir = fs18!.mkdtempSync!(os18!.tmpdir!() + '/t18-lw-')!;
        trees18.push(dir);
        try {
          fs18!.cpSync!(repoRoot18, dir, { recursive: true, filter: (s: string) => !skip18(s) });
          const p = dir + '/src/client/note-crypto.ts';
          const s0 = fs18!.readFileSync!(p, 'utf8');
          const cnt = s0.split(needle).length - 1;
          if (cnt !== 1) { await A(label + '（毒化 needle 對位自檢——錨缺席＝runner 設計錯非閘病）', false, 'needle cnt=' + cnt); return; }
          // 本拷貝樹無 node_modules symlink（對照 [16] mkTree 補線形＝[18] 已知差異——
          // 缺 @scure 參照組環境的內層輸出帶 [2] 參照組 FAIL 1 面＝可預期環境面，非缺陷）。
          fs18!.writeFileSync!(p, s0.split(needle).join(replacement), 'utf8');
          const g = runGate18(dir);
          const failLines18 = g.out.split('\n').filter((l: string) => l.trimStart().startsWith('✗') && l.includes('[18]'));
          const others18 = g.out.split('\n').filter((l: string) => l.trimStart().startsWith('✗') && !l.includes('[18]'));
          const designated18 = cases.filter((kw) => failLines18.some((l: string) => l.includes(kw)));
          const account18 = failLines18.map((l: string) => l.replace(/^\s*✗\s*/, '').slice(0, 40)).join(';;');
          await A(label + '→ [18] 名單真紅 ' + want + '（designated-FAIL 帳：實測 ' + designated18.length + '/' + want +
            '；' + account18.slice(0, 110) + '；others=' + others18.length + '）',
            g.rc === 1 && designated18.length === want && failLines18.length === want
            && others18.length === 1 && others18[0]!.includes('與 @scure/bip39 參照 200 組雙向一致')
            && cases.every((kw) => failLines18.filter((l: string) => l.includes(kw)).length === 1),
            'rc=' + g.rc + ' n18=' + failLines18.length + ' d=' + designated18.length + ' others=' + others18.length);
        } finally {
          fs18!.rmSync!(dir, { recursive: true, force: true });
        }
      };
      // P18 摘 fresh-face（三元→null）→ stored jr1l. blob 通路讀死＋源碼窗 floor 面翻（窗 shrink 1829<1910；throw 禁令面由 P18d 獨立承載）。floor 標籤插值當地量（窗長一變硬寫數字即靜默失真帳面——標籤插值即封口）
      await withPoisonRun18('[18] 毒化 P18 gate-rerun（P18：摘 fresh-face 三元→null）',
        needlePA18, '\n    const fresh = null;',
        ['空-held decrypt 經本機包裹通路', '自癒後二次讀回', '窗尾 floor 插值帳'], 3);
      // P18b 摘自癒回寫 → 讀面照解（通路讀面不依賴回寫線）＋回寫線計數窗錨翻面
      await withPoisonRun18('[18] 毒化 P18b gate-rerun（P18b：摘自癒回寫）',
        needlePB18, '      return legacy;',
        ['自癒回寫恆新前綴', '自癒 blob unwrap 等值', '自癒 blob 舊形恆拒', '回落三元恰 1'], 4);
      // P18c 寫面接回借用形（禁手）→ 寫面 fallback jr1w.（v1 借用面復活的行為翻轉）＋寫面唯一 seal 計數窗錨翻面
      await withPoisonRun18('[18] 毒化 P18c gate-rerun（P18c：寫面接回借用形）',
        needlePC18, 'sealNoteKey(cfg.wrap,',
        ['寫前綴 jr1l.', '寫入 payload unwrap', '自癒回寫恆新前綴', '自癒 blob unwrap 等值', '自癒 blob 舊形恆拒', '二次讀不自癒二次', '寫面唯 cfg.wrapLocal seal'], 7);
      // P18d 本機段禁令復活（ERR 半邊——長度中性＋36B）：storeLocalWrap 守衛 return→throw
      //（storeLocalWrap 自身 try/catch 吸收＝行為面零變；可觀察面＝本窗禁令錨，毒後窗 +36B）。
      await withPoisonRun18('[18] 毒化 P18d gate-rerun（P18d：storeLocalWrap 守衛復活 throw）',
        '    if (!cfg.wrapLocal) return;',
        "    if (!cfg.wrapLocal) throw new Error('ERR_WRAP_NOT_CONFIGURED');",
        ['本機段零 ERR_WRAP_NOT_CONFIGURED 禁令面'], 1);
      // 真樹 needle 對位錨＋byte-exact：毒化全程跑拷貝樹；真樹 sha256 毒前毒後恆等＝
      // 零突變帳——對照兩端帶 hex64 形狀條；hex64 形狀條帶 designated 毒化案（卡面指定）＝
      // 真守衛拒異形輸入（鍛造非 hex digest＋undefined——regex.test 恆 false；缺席＝斷言 RED 面，
      // shaOk18(undefined)=false）；恆真形毒化對異形輸入放行→designated 案 RED；守衛毒化不過 withPoisonRun18
      //（拷貝樹型）——in-process 毒殺＋還原一對帳，不動 tree18 封閉集。
      // needle 恰 1×4 計數防線＝誤改斷言窗本體（含守衛行）即 RED——名實一致帳。
      const shaOk18 = (x: string): boolean => /^[0-9a-f]{64}$/.test(x);
      const srcAfter18 = await srcOf('../src/client/note-crypto.ts');
      await A('[18] 還原 byte-exact 對照（真樹 sha256 毒前毒後恆且為 hex64——' + shaBefore18.slice(0, 12) + '…）',
        shaOk18(shaBefore18) && sha18(srcAfter18) === shaBefore18);
      await A('[18] 真樹 needle 對位錨（恰 1×4——真樹零突變的行程帶）',
        srcAfter18.split(needlePA18).length === 2 && srcAfter18.split(needlePB18).length === 2
        && srcAfter18.split(needlePC18).length === 2
        && srcAfter18.split('    if (!cfg.wrapLocal) return;').length === 2);
      await A('[18] 毒化樹零殘留（本 run 喚出 ' + trees18.length + ' 棵全清——封閉集判準）',
        trees18.length === 4 && trees18.every((t) => !fs18!.rmSync || !existsSync18(t)));
      // designated 毒化案（卡面指定——hex64 形狀條；in-process 毒殺即還原一對帳，不動 tree18 封閉集）：
      // 守衛恆真形 → byte-exact 主帳對毒化守衛判 RED 預期；還原後真守衛復活＝帳面復綠——
      // 「形條缺席咬不到」自我證明（卡面新增咬痕面＝真形 false／惡形 true 兩面都咬）。
      {
        const shaOk18Evil = (x: string): boolean => true;
        const fakeDigest = 'z'.repeat(64); // 非 hex64 鍛造 digest（守衛缺席時必放行的形）
        const greenWithReal = shaOk18(shaBefore18) && !shaOk18(fakeDigest)
          && !shaOk18(undefined as unknown as string);
        const redWithEvil = !shaOk18Evil(shaBefore18) || shaOk18Evil(fakeDigest)
          || shaOk18Evil(undefined as unknown as string);
        await A('[18] hex64 守衛 designated 毒化（恆真形 → 鍛造非 hex digest＋undefined 輸入放行；真守衛拒——形條缺席咬不到的形證）',
          greenWithReal && redWithEvil,
          'green=' + String(greenWithReal) + ' red=' + String(redWithEvil));
      }
    }
  }
}
};

// ── 19. ladder 表與重取鹽面（(a+) 案） ──────────────
//
// 驗證策略（真 SQLite，node:sqlite）：①ph2_ladder DDL（FK CASCADE／UNIQUE account_id）；
// ②重取鹽面 unwrapNoteKeyDual4WithSalt＝雙腿重試形為（ladder 遷移旋轉 salt1 後，呼叫端
// 以 login 回帶的新 salt 重試 jr4d 重包──新面 unwrap 必中、陳舊 salt 必 null 兩面承載）；
// ③ladder 表語意面（kinds 常數／表名單一真相）＋值主權威 upsert 行為面（真 node:sqlite
// 直驅 makePh2LadderStore：upsert 恰一列、同一舊值最新持有者勝、無 DELETE 語句面）。
// 表名/kind 常數的契約面（PH2_LADDER_TABLE='ph2_ladder'、KIND legacy/v2）由本段斷言直接咬住
//（fork migration 0011 與 core 原語同字面——漂移＝fork schema 與 core 原語脫鉤＝表缺席 fail-open 面）。
secOpen(19, '[19] ladder 表與重取鹽面（unwrapNoteKeyDual4WithSalt＋ph2_ladder）'); if (secEnter(19)) {
{
  const { DatabaseSync } = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { DatabaseSync?: unknown } };
  }).process?.getBuiltinModule?.('node:sqlite') ?? {};
  if (!DatabaseSync) throw new Error('ERR_SQLITE_UNAVAILABLE');
  await A('[19] ladder 表名契約：PH2_LADDER_TABLE = ph2_ladder（fork migration 同字面）', PH2_LADDER_TABLE === 'ph2_ladder');
  await A('[19] ladder kinds 契約：legacy/v2 兩形（常數面）', PH2_LADDER_KIND_LEGACY === 'legacy' && PH2_LADDER_KIND_V2 === 'v2');
  // 值主權威行為面（真 node:sqlite 直驅本體）：建表走 fork migration 同形（PK=ph2）。
  {
    const DatabaseSync19 = DatabaseSync as new (p: string) => { exec: (s: string) => void; prepare: (s: string) => { run: (...p: unknown[]) => { changes: number | bigint }; get: (...p: unknown[]) => unknown; all: (...p: unknown[]) => unknown[] } };
    const db19 = new DatabaseSync19(':memory:');
    db19.exec('CREATE TABLE users (account_id TEXT PRIMARY KEY, ph2 TEXT)');
    db19.exec("INSERT INTO users (account_id, ph2) VALUES ('acc19', 'ph2-new')");
    db19.exec("INSERT INTO users (account_id, ph2) VALUES ('ghost19', 'ph2-ghost')");
    const migSrc19 = await srcOf('../migrations/0011-ph2-ladder.sql');
    const ddlPos19 = migSrc19.indexOf('CREATE TABLE IF NOT EXISTS ph2_ladder');
    const ddl19 = migSrc19.slice(ddlPos19, migSrc19.indexOf(';', ddlPos19) + 1);
    db19.exec(ddl19.replace(/IF NOT EXISTS /g, ''));
    // 0012 對位面（t_87ef62dd）：0011 上線後的索引修正 migration——0011 帶冗餘
    // idx_ph2_ladder_ph2（PK=ph2 同鍵 duplicate）且 account_id 零索引；0012 DROP＋CREATE
    // 修正面在 fork 動線於 0011 之後執行（本段照序：建 0011 表＋0011 原索引 → 0012）。
    {
      const idxPos19 = migSrc19.indexOf('CREATE INDEX IF NOT EXISTS idx_ph2_ladder_ph2');
      if (idxPos19 >= 0) db19.exec(migSrc19.slice(idxPos19, migSrc19.indexOf(';', idxPos19) + 1)); // 0011 冗餘索引原樣（0012 要 DROP 的缺陷面）
      const src12 = await srcOf('../migrations/0012-fix-ph2-ladder-index.sql');
      await A('[19] 0011 對位錨：冗餘 idx_ph2_ladder_ph2 在場（0012 DROP 面＝0011 冗餘索引原樣）',
        idxPos19 >= 0 && src12.includes('DROP INDEX IF EXISTS idx_ph2_ladder_ph2'));
      const stmts12 = ['DROP INDEX IF EXISTS idx_ph2_ladder_ph2;', 'CREATE INDEX IF NOT EXISTS idx_ph2_ladder_account ON ph2_ladder(account_id);'];
      await A('[19] 0012 語句面：DROP 冗餘＋CREATE account_id 兩句（報告原樣；DROP 在前——殘留冗餘即 RED）',
        src12.split('DROP INDEX IF EXISTS idx_ph2_ladder_ph2;').length === 2
        && src12.split('CREATE INDEX IF NOT EXISTS idx_ph2_ladder_account ON ph2_ladder(account_id);').length === 2
        && src12.indexOf('DROP INDEX') < src12.indexOf('CREATE INDEX'));
      await A('[19] 0012 非 UNIQUE 契約（一帳多舊值設計——ladder 多歷列並存；UNIQUE 面殘留即 RED）',
        /CREATE (UNIQUE )?INDEX/.test(src12) && !src12.includes('UNIQUE INDEX'));
      for (const st12 of stmts12) db19.exec(st12);
      const idxAfter = db19.prepare('SELECT name FROM sqlite_master WHERE type = \'index\' AND tbl_name = \'ph2_ladder\'').all() as { name: string }[];
      const idxNames = idxAfter.map((r) => r.name).filter((n) => n !== 'sqlite_autoindex_ph2_ladder_1');
      await A('[19] 0012 pragma 動線：冗餘 ph2 index 摘除＋account_id index 在場（n 前後查——索引集恰 {idx_ph2_ladder_account}）',
        idxNames.length === 1 && idxNames[0] === 'idx_ph2_ladder_account', JSON.stringify(idxNames));
      await A('[19] 0012 冪等：0012 語句重跑零炸（IF EXISTS/IF NOT EXISTS 面——fork 重入動線）',
        await (async () => { try { db19.exec(stmts12.join('\n')); return true; } catch { return false; } })());
      // EXPLAIN QUERY PLAN：account_id 查詢走 SEARCH（非 SCAN——修復收益的直接承載面）；
      // ph2 查面走 autoindex（PK）＝冗餘索引摘除後照 SEARCH。
      const planAcc = String((db19.prepare('EXPLAIN QUERY PLAN SELECT * FROM ph2_ladder WHERE account_id = ?').get('acc19') as { detail?: string } | null)?.detail ?? '');
      const planPh2 = String((db19.prepare('EXPLAIN QUERY PLAN SELECT account_id FROM ph2_ladder WHERE ph2 = ?').get('old-19') as { detail?: string } | null)?.detail ?? '');
      await A('[19] 0012 EXPLAIN 動線：account_id 查詢 SEARCH ph2_ladder (idx_ph2_ladder_account)（非 SCAN）',
        planAcc.includes('SEARCH ph2_ladder USING INDEX idx_ph2_ladder_account') && !/(^|\s)SCAN\s/.test(planAcc), planAcc);
      await A('[19] 0012 EXPLAIN PK 面：ph2 查詢仍 SEARCH autoindex（冗餘索引摘除零傷——非 SCAN）',
        planPh2.includes('SEARCH') && !/(^|\s)SCAN\s/.test(planPh2), planPh2);
    }
    const env19 = {
      DB: {
        prepare(sql: string) {
          return {
            bind(...params: unknown[]) {
              return {
                async first() { return db19.prepare(sql).get(...params) as Row19 | null; },
                async run() { db19.prepare(sql).run(...params); return { changes: 1 }; },
              };
            },
          };
        },
      },
    } as unknown as Env19;
    const ladder19 = makePh2LadderStore(env19 as unknown as Parameters<typeof makePh2LadderStore>[0]);
    await ladder19.insert('acc19', 'old-19', PH2_LADDER_KIND_V2);
    await ladder19.insert('acc19', 'old-19b', PH2_LADDER_KIND_V2); // 同帳戶第二個舊值歷列
    await ladder19.insert('acc19', 'old-19', PH2_LADDER_KIND_LEGACY); // 同舊值 upsert（值主權威覆蓋）
    await ladder19.insert('ghost19', 'old-19', PH2_LADDER_KIND_V2); // 幽靈帳同舊值＝最新持有者勝
    const r19a = await ladder19.findByOldPh2('old-19');
    await A('[19] ladder upsert 值主權威：同一舊值恰一列（PK=ph2）且最新持有者勝',
      r19a !== null && r19a.accountId === 'ghost19' && r19a.ph2Kind === 'v2',
      JSON.stringify(r19a));
    const cnt19 = db19.prepare('SELECT COUNT(*) AS n FROM ph2_ladder').get() as { n: number };
    await A('[19] ladder upsert 恆一列（三案同表恰 2 列——值唯一＋多舊值歷列並存）', cnt19.n === 2, String(cnt19.n));
    const r19b = await ladder19.findByOldPh2('old-19b');
    await A('[19] ladder 多舊值歷列：第二舊值仍在場（同帳戶兩段遷移各存）', r19b !== null && r19b.accountId === 'acc19');
    await A('[19] ladder miss 面：查無列回 null', (await ladder19.findByOldPh2('nope-19')) === null);
  }

  // 重取鹽面：wrap 吃 passD4 全形（NFKC 載體）→ unwrap 以新 salt（ladder 遷移後重取）必中
  const rewrapD4 = await wrapNoteKeyDual4(TACET4, noteKey, passD4, pinD);
  const withSalt = await unwrapNoteKeyDual4WithSalt(TACET4, rewrapD4.wrapped, passD, pinD, rewrapD4.salt);
  await A('[19] WithSalt 重試面：重取 salt1（ladder 遷移後新值）→ unwrap = 原 noteKey',
    withSalt !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', withSalt))) === origRaw);
  await A('[19] WithSalt 陳舊鹽面：wrap 期的 salt1（已旋轉面）→ null（鹽旋轉後舊鹽解不開）',
    (await unwrapNoteKeyDual4WithSalt(TACET4, rewrapD4.wrapped, passD, pinD, dual4.salt)) === null);
  await A('[19] WithSalt 錯 passphrase → null（同 unwrapNoteKeyDual4 本體契約）',
    (await unwrapNoteKeyDual4WithSalt(TACET4, rewrapD4.wrapped, 'wrong-passphrase', pinD, rewrapD4.salt)) === null);
  await A('[19] WithSalt 未配置 cfg（wrapDual4 缺）→ null（opt-in 鐵律同向）',
    (await unwrapNoteKeyDual4WithSalt({ pinSalt3Prefix: 'tacet-note-pin3:' }, rewrapD4.wrapped, passD, pinD, rewrapD4.salt)) === null);
}
};
// ── 20. 復原套件專用前綴＋HKDF 派生世代 ──
//
// 裁定：採搭車——wrappedRec 專用前綴＋KEK_rec 改
// HKDF-SHA256（jr3d KEK2 HKDF 為先例）；「一個前綴一份契約」第二違例（wrappedRec 共用
// cfg.wrap＋同 AAD）同步收口。收口五面（檢查對齊定案）：
//   ①專用前綴 cfg.wrapRec（jr1r.；命名＝語意後綴軸，沿 jr1l. 定案）＋專屬 AAD
//     'notekey-rec'（帶內版本化：payload 契約面綁派生世代）。
//   ②世代配對門（檢查對齊 C1/C2）：wrapRec＋recKekHkdf 兩欄一體（同缺同在）——
//     部分配置（XOR）＝ERR_REC_CFG_PARTIAL 拒寫（fail-closed 禁寫出「jr1r.×PBKDF2」
//     寫得出讀不回 blob 與「jr1w.×HKDF」借用 blob）；讀面部分配置照走舊面回落
//     （承諾面：配置形正確時舊 blob 永遠可解）。
//   ③KEK_rec 派生世代 cfg.recKekHkdf（HKDF 專責）：HKDF-SHA256( ikm = recToken（256-bit
//     實體因子——KDF 強度無意義，世代收的是派生域分離）, salt = recKekSalt？
//     16B hex（未配置＝零鹽）, info = 'journal-kek-rec-v1:' + recKekHkdf, L = 32 )。
//     info 合成名沿 argon2 家族慣例（HKDF info 呼叫端帶入定形）。
//     PBKDF2 舊派生＝deriveRecLegacyKek 單一本體（寫面未配置世代＋讀面回落同源）。
//   ④讀舊寫新雙試：兩欄齊備 unwrap＝jr1r. 面（HKDF）先行、未中→舊面（cfg.wrap＋
//     notekey＋PBKDF2）回落（救回動線順向雙試＝裁定過渡保護
//     涵蓋；摘雙試＝遷移率裁定非日曆）。兩欄皆缺席（舊 cfg）＝單試舊面（行為不變）。
//   ⑤四象限 write→read 矩陣（檢查對齊 M1）：每象限「自 wrap 可自 unwrap 或 wrap 拒絕」
//     ＋超集 cfg 可讀子集 blob（升級路徑保護）＋B01 歷史缺陷形恆拒（升 KDF＝換前綴）。
secOpen(20, '[20] 復原套件專用前綴（wrapRec=jr1r. opt-in）＋KEK_rec HKDF 世代（recKekHkdf opt-in，兩欄一體配對門）'); if (secEnter(20)) {
{
  const recSalt20 = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const TACET5: NoteCryptoConfig = { ...TACET, wrapRec: 'jr1r.', recKekHkdf: 'jr1r.', recKekSalt: recSalt20 };
  const raw20 = hex(new Uint8Array(await crypto.subtle.exportKey('raw', noteKey)));
  const eqNoteKey20 = async (k: CryptoKey | null): Promise<boolean> =>
    k !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === raw20;
  const rawKat20 = '57c72afacd486194c41227f42311600e287a7d48baa7a3e9de32fa460c089699'; // KAT 凍結 noteKey（外探針實測入冊）
  const eqRawKat20 = async (k: CryptoKey | null): Promise<boolean> =>
    k !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === rawKat20;
  const recToken20 = generateRecToken();
  const KAT_BLOB_R20 = 'jr1r.bkvBFdKjNVfidHcfn0WoyyRJLkajWhXF7WmPdc3Q9FCNNxDz+7PgN0x25BjuAZPFi1oP3t+8dblrnSQEltkieBh33xoyChcGKe1wEfaStQF6ITBNb6vBZKVXDEQ=';

  // P1 寫面：兩欄齊備＝jr1r.＋專屬 AAD；cfg.wrap 腿（passphrase 包裹）不受牽連
  const freshRec20 = await wrapNoteKeyWithRecToken(TACET5, noteKey, recToken20, identityA);
  await A('[20] 新世代 wrappedRec 前綴 jr1r.（寫面契約——借用期 cfg.wrap 形＝反）', freshRec20.startsWith('jr1r.'));
  await A('[20] KAT 自洽前置（live wrap 樣本可重放）：jr1r. blob＋同 identity → 原 noteKey',
    eqNoteKey20(await unwrapNoteKeyWithRecToken(TACET5, freshRec20, recToken20, identityA)));
  await A('[20] 寫面 jr1w. 腿不受牽連（passphrase 包裹照走本前綴）',
    (await wrapNoteKey(TACET5, noteKey, pass)).wrapped.startsWith('jr1w.'));

  // P2 舊契約面凍結：未配置世代 wrap/unwrap（byte 不變承載——函式體零改面）
  const legacyRec20 = await wrapNoteKeyWithRecToken(TACET, noteKey, recToken20, identityA);
  await A('[20] 未配置世代 wrappedRec 前綴 jr1w.（契約面永不變——借用面凍結）', legacyRec20.startsWith('jr1w.'));
  await A('[20] 未配置世代 unwrap = 原 noteKey（PBKDF2 舊派生契約原樣）',
    eqNoteKey20(await unwrapNoteKeyWithRecToken(TACET, legacyRec20, recToken20, identityA)));
  await A('[20] KAT 凍結 blob（舊 PBKDF2 契約面）：凍結 recToken＋凍結 identity 鹽域＋凍結 blob 逐位可解（凍結常數計算式構造——KAT 母型；對錨＝凍結 noteKey raw 非本段活金鑰）',
    eqRawKat20(await unwrapNoteKeyWithRecToken(TACET, 'jr1w.a4xchJ+EPui8iQy5dKpQyGjalu0nlJMsDd0LaLyRrY3mt+6112Se4NvaibymRFHsMg1LgOYsBVy15t0CiU1ipf9g8rniqBmdf1R5LzVXQdNJDCzbAfubPUKc/FE=', '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000')));
  await A('[20] seal 未配置守衛：cfg.wrap 缺席 legacy 路徑直呼 → ERR_WRAP_NOT_CONFIGURED（呼叫端亦可先行拒絕——雙防線外層）',
    (async () => {
      const noWrap20 = { ...TACET, wrap: undefined } as unknown as NoteCryptoConfig;
      try { await wrapNoteKeyWithRecToken(noWrap20, noteKey, recToken20, identityA); return false; }
      catch { return true; }
    })());
  await A('[20] 帳面 92B 錨（鹽內嵌面契約）：jr1r. payload 嚴格 92B（hex64 64B＋iv 12＋tag 16——HKDF 鹽屬「派生面內嵌 cfg、payload 零內嵌」，pinSalt 前綴不在 rec 鹽形契約內）',
    freshRec20.length > 'jr1r.'.length && unb64Mod(freshRec20.slice('jr1r.'.length)).length === 92);

  // P3 新世代讀舊寫新（雙試）＋家族互斥＋KAT 世代帶
  await A('[20] 新世代讀舊 blob（過渡保護）：舊 PBKDF2/AAD/前綴面回落雙試 → 原 noteKey',
    eqNoteKey20(await unwrapNoteKeyWithRecToken(TACET5, legacyRec20, recToken20, identityA)));
  await A('[20] 家族互斥：jr1r. blob 餵未配置世代 cfg → null（新面恆拒——家族隔離對稱面）',
    (await unwrapNoteKeyWithRecToken(TACET, freshRec20, recToken20, identityA)) === null);
  await A('[20] KAT 凍結 blob：jr1r. 逐位重放（凍結 recToken/salt/identity/blob 恆定——HKDF 世代派生確定性重驗；對錨＝凍結 noteKey raw 非本段活金鑰）',
    eqRawKat20(await unwrapNoteKeyWithRecToken(TACET5, KAT_BLOB_R20, '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000')));
  await A('[20] KAT 世代齒（鹽入派生正向翻面）：凍結 recToken/identity/blob 不變、鹽域換值 → null（鹽 A wrap→鹽 B unwrap 恆不重合——HKDF salt 有入派生）',
    (await unwrapNoteKeyWithRecToken({ ...TACET5, recKekSalt: 'ffeeddccbbaa99887766554433221100' }, KAT_BLOB_R20, '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000')) === null);
  await A('[20] KAT 世代齒（info 域帶毒化案同錨）：HKDF info 尾綴換值（鹽/identity/blob 恆定）→ null（info 有入派生——R2 毒化翻轉的 clean 鏡）',
    (await unwrapNoteKeyWithRecToken({ ...TACET5, recKekHkdf: 'jr1r-x' }, KAT_BLOB_R20, '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000')) === null);
  await A('[20] HKDF 世代正交面（配對門收口後契約）：僅 recKekHkdf（wrapRec 缺席）＝配對門拒寫，讀面 jr1r. blob 照舊面回落零接納（cfg.wrap 在場＝PBKDF2 腿零承載——HKDF 派生禁借 jr1w. 前綴）',
    (await unwrapNoteKeyWithRecToken({ ...TACET, recKekHkdf: 'jr1r.' }, freshRec20, recToken20, identityA)) === null);

  // identity 參數語意（HKDF 族零接觸面——docstring identity-free by design 承載）
  const freshB20 = await wrapNoteKeyWithRecToken(TACET5, noteKey, recToken20, 'acct-bbbbbbbbbbbbbbbb');
  await A('[20] identity HKDF 族零接觸（docstring identity-free 契約自證化——誤接線即 RED）',
    freshB20.startsWith('jr1r.') && eqNoteKey20(await unwrapNoteKeyWithRecToken(TACET5, freshB20, recToken20, 'acct-cccccccccccccccc')));
  await A('[20] identity 互斥面（舊契約面）：錯 identity unwrap → null（rec 鹽＝recSaltPrefix‖identity 定值——同 recToken 異 KEK）',
    (await unwrapNoteKeyWithRecToken(TACET, legacyRec20, recToken20, 'acct-bbbbbbbbbbbbbbbb')) === null);

  // P4 契約面守衛（形檢 fail-closed）
  await A('[20] 壞 recKekSalt fail-closed：unwrap → null（HKDF 腿 throw→catch，零 legacy 回落——cfg 誤配整面 fail-closed）',
    (await unwrapNoteKeyWithRecToken({ ...TACET5, recKekSalt: 'xyz123' }, freshRec20, recToken20, identityA)) === null);
  await A('[20] 壞 recKekSalt wrap 面拋 ERR_REC_KEK_SALT（fail-closed 拒寫——派生世代誤配即禁寫）',
    (async () => { try { await wrapNoteKeyWithRecToken({ ...TACET5, recKekSalt: 'xyz123' }, noteKey, recToken20, identityA); return false; } catch (e) { return (e as Error).message === 'ERR_REC_KEK_SALT'; } })());

  // P5 世代配對門（檢查對齊 C1/C2 收口——兩欄一體，fail-closed 拒寫）
  await A('[20] 配對門 wrapRec-only（C1 象限）：拋 ERR_REC_CFG_PARTIAL（禁寫「jr1r.×PBKDF2」寫得出讀不回 blob）',
    (async () => { try { await wrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, noteKey, recToken20, identityA); return false; } catch (e) { return (e as Error).message === 'ERR_REC_CFG_PARTIAL'; } })());
  await A('[20] 配對門 recKekHkdf-only（C2 象限）：拋 ERR_REC_CFG_PARTIAL（禁借 jr1w. 前綴 carrying HKDF 派生）',
    (async () => { try { await wrapNoteKeyWithRecToken({ ...TACET, recKekHkdf: 'jr1r.' }, noteKey, recToken20, identityA); return false; } catch (e) { return (e as Error).message === 'ERR_REC_CFG_PARTIAL'; } })());
  // B01 歷史缺陷形向量（收口後零接納面）：HKDF-on-jr1w. 借形 blob——守衛形拒寫＝
  // 無構造源（升級探針缺陷形），凍結重放式對借形 blob 的恆拒承載（對錨＝null 非 noteKey）。
  const legacyB01_20 = 'jr1w.' + modB64(new Uint8Array(92).fill(7));
  await A('[20] 配對門錯誤序前於鹽形檢（部分配置形不驗鹽——門先收）',
    (async () => { try { await wrapNoteKeyWithRecToken({ ...TACET, recKekHkdf: 'jr1r.', recKekSalt: 'xyz123' }, noteKey, recToken20, identityA); return false; } catch (e) { return (e as Error).message === 'ERR_REC_CFG_PARTIAL'; } })());
  await A('[20] 配對門讀面寬容：wrapRec-only cfg 讀舊 jr1w. blob → 原 noteKey（部分配置禁寫不禁讀——舊 blob 永遠可解）',
    eqNoteKey20(await unwrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, legacyRec20, recToken20, identityA)));
  await A('[20] 配對門讀面寬容（C1 歷史缺陷形救回面）：wrapRec-only cfg 逐位重放凍結舊 blob（PBKDF2 鹽域）→ 凍結 noteKey',
    eqRawKat20(await unwrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, 'jr1w.a4xchJ+EPui8iQy5dKpQyGjalu0nlJMsDd0LaLyRrY3mt+6112Se4NvaibymRFHsMg1LgOYsBVy15t0CiU1ipf9g8rniqBmdf1R5LzVXQdNJDCzbAfubPUKc/FE=', '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000')));
  await A('[20] 配對門讀面恆拒（B01 歷史缺陷形）：recKekHkdf-only cfg 讀 HKDF-on-jr1w. 形 blob → null（借形缺陷 blob 零接納面；升 KDF＝換前綴）',
    (await unwrapNoteKeyWithRecToken({ ...TACET, recKekHkdf: 'jr1r.', recKekSalt: recSalt20 }, legacyB01_20, recToken20, identityA)) === null);

  // M1 四象限 write→read 矩陣（檢查對齊——四象限配置（wrapRec，recKekHkdf）逐格對帳面；
  // 每格「write：blob 前綴（或配對門拒）→ read：同 cfg 自解行為」＋超集 cfg 讀子集 blob）。
  {
    const qCfg10 = (): NoteCryptoConfig => ({ ...TACET, wrapRec: 'jr1r.' });
    const qCfg01 = (): NoteCryptoConfig => ({ ...TACET, recKekHkdf: 'jr1r.', recKekSalt: recSalt20 });
    const wrapQ = async (c: NoteCryptoConfig): Promise<string> => {
      try { return await wrapNoteKeyWithRecToken(c, noteKey, recToken20, identityA); }
      catch (e) { return (e as Error).message; }
    };
    const b00q = await wrapQ({ ...TACET });
    const b10q = await wrapQ(qCfg10());
    const b01q = await wrapQ(qCfg01());
    const b11q = await wrapQ({ ...TACET5 });
    await A('[20] M1 write 面四格：B00→jr1w.／B10→ERR_REC_CFG_PARTIAL／B01→ERR_REC_CFG_PARTIAL／B11→jr1r.（部分配置零寫出面——C1/C2 借形禁產）',
      b00q.startsWith('jr1w.') && b10q === 'ERR_REC_CFG_PARTIAL' && b01q === 'ERR_REC_CFG_PARTIAL' && b11q.startsWith('jr1r.'),
      b00q.slice(0, 5) + '/' + b10q + '/' + b01q + '/' + b11q.slice(0, 5));
    const r00q = await unwrapNoteKeyWithRecToken({ ...TACET }, b00q, recToken20, identityA);
    const r11q = await unwrapNoteKeyWithRecToken({ ...TACET5 }, b11q, recToken20, identityA);
    await A('[20] M1 read 面自解格：B00/B11 同 cfg 自 wrap 自 unwrap＝原 noteKey（B10/B01 無 blob＝write 面承載）',
      (await eqNoteKey20(r00q)) && (await eqNoteKey20(r11q)));
    await A('[20] M1 超集讀子集（升級路徑保護）：B10/B01 cfg 皆可讀 B00 舊 blob（舊面回落）',
      (await eqNoteKey20(await unwrapNoteKeyWithRecToken(qCfg10(), b00q, recToken20, identityA)))
      && (await eqNoteKey20(await unwrapNoteKeyWithRecToken(qCfg01(), b00q, recToken20, identityA))));
    await A('[20] M1 超集讀子集：B11 cfg 讀 B00 blob（雙試回落＝原 noteKey）、B00 cfg 讀 B11 blob（子集讀超集＝null——家族隔離對稱面）',
      (await eqNoteKey20(await unwrapNoteKeyWithRecToken({ ...TACET5 }, b00q, recToken20, identityA)))
      && ((await unwrapNoteKeyWithRecToken({ ...TACET }, b11q, recToken20, identityA)) === null));
  }

  // 源碼窗（計數錨——接線漂移即 RED；needle+1 式對照 [14][15][16] 母型；錨為敘述形且 docstring 零咬；
  // 檢查對齊 M1 後配對門落地——窗口全體重錨隨修正形；「HKDF 腿零借 cfg.wrap」的接線由 R2 贊毒化承載）
  const noteCryptoSrc20 = await srcOf('../src/client/note-crypto.ts');
  await A('[20] 源碼窗：專屬 AAD 接線恰 2（wrap seal 面與 unwrap open 面各恰 1——回收共用面復活/錯位接線即變異）',
    noteCryptoSrc20.split("kek, 'notekey-rec')").length === 2 && noteCryptoSrc20.split("'notekey-rec', cfg.wrapRec)").length === 2);
  await A('[20] 源碼窗：世代配對門恰 1（ERR_REC_CFG_PARTIAL 拋點，split 帳＝出現＋1——門摘除＝拒寫面失效即 RED）',
    noteCryptoSrc20.split("throw new Error('ERR_REC_CFG_PARTIAL')").length === 2);
  await A('[20] 源碼窗：配對門接線形恰 1（wrapRec 或 recKekHkdf 在場即入門——單欄短路復活即形變異）',
    noteCryptoSrc20.split('if (cfg.wrapRec || cfg.recKekHkdf) {').length === 2
    && noteCryptoSrc20.split("if (!cfg.wrapRec || !cfg.recKekHkdf) throw new Error('ERR_REC_CFG_PARTIAL');").length === 2);
  await A('[20] 源碼窗：HKDF 專責接線恰 1（兩欄齊備守衛＋t_87ef62dd 快檢條件面——派生雙模/C2 借形復活/短路回歸即變異）',
    noteCryptoSrc20.split('if (cfg.wrapRec && cfg.recKekHkdf && wrapped.startsWith(cfg.wrapRec)) {').length === 2);
  await A('[20] 源碼窗：PBKDF2 fallback 殘留歸零＋deriveRecKek 呼叫面恰 3（非空洞計數：fallback 形歸零＋def＋兩呼叫端在場——C2 收口面）',
    noteCryptoSrc20.split('if (!cfg.recKekHkdf) return deriveKek').length === 1
    && noteCryptoSrc20.split('deriveRecKek(').length === 4);
  await A('[20] 源碼窗：deriveRecLegacyKek def＋呼叫恰 3（split 帳＝出現＋1；legacy 本體單一真相——寫面＋讀面同源）',
    noteCryptoSrc20.split('deriveRecLegacyKek(').length === 4);
  await A('[20] 源碼窗：cfg.wrapRec 敘述形恰 2（配對門 XOR 一對——借用面復活即計數變異；t_87ef62dd 快檢面零咬：腿接線是 startsWith 閉括號形非 XOR 敘述形）',
    noteCryptoSrc20.split('cfg.wrapRec ||').length === 3
    && noteCryptoSrc20.split('!cfg.wrapRec ||').length === 2);

  // R 系毒化（自毒化驗齒——/tmp 拷貝樹 fresh import，出生即棄；期望值真跑後定值，帳面直覺禁沿；
  // 檢查對齊：R2 重錨＝info 字面→KAT 世代齒、R4 label 對齊、R5 新案＝配對門（C1/C2 唯一閘承載））
  const getBuiltin20 = (id: string): unknown =>
    (globalThis as unknown as { process?: { getBuiltinModule?: (i: string) => unknown } }).process?.getBuiltinModule?.(id);
  const fs20 = getBuiltin20('node:fs') as {
    rmSync?: (p: string, o?: { recursive: boolean; force?: boolean }) => void;
    cpSync?: (a: string, b: string, o?: { recursive: boolean; filter?: (s: string) => boolean }) => void;
    readFileSync?: (p: string, e?: string) => string;
    writeFileSync?: (p: string, c: string, e?: string) => void;
    mkdtempSync?: (p: string) => string;
    existsSync?: (p: string) => boolean;
  } | undefined;
  const os20 = getBuiltin20('node:os') as { tmpdir?: () => string } | undefined;
  const inner20 = (getBuiltin20('node:process') as { env?: Record<string, string | undefined> } | undefined)?.env?.POISON_GATE_INNER === '1';
  const ready20 = !!os20?.tmpdir && !!fs20?.mkdtempSync && !!fs20?.cpSync && !!fs20?.readFileSync && !!fs20?.writeFileSync && !!fs20?.rmSync;
  const needleR1 = "    return sealNoteKey(cfg.wrapRec, noteKey, kek, 'notekey-rec');";
  const needleR3 = "    const legacyKek = await deriveRecLegacyKek(cfg, recToken, identity);";
  const needleR5 = "if (!cfg.wrapRec || !cfg.recKekHkdf) throw new Error('ERR_REC_CFG_PARTIAL');";
  const srcNow20 = await srcOf('../src/client/note-crypto.ts');
  await A('[20] 毒化錨前綴自檢（毒化窗同字面點數先行；split 計數帳＝出現數＋1）',
    srcNow20.split(needleR1).length === 2 && srcNow20.split(needleR3).length === 2
    && srcNow20.split("const info = 'journal-kek-rec-v1:'").length === 2 && srcNow20.split(needleR5).length === 2);
  if (inner20 || !ready20) {
    await A('[20] 毒化矩陣載體就緒（node 內建模組在場；內層遞迴由 sentinel 跳過＝正常；缺席＝顯性 FAIL）',
      inner20 && !ready20 ? false : inner20, 'env unavailable AND not inner');
  } else {
    const repoRoot20 = new URL('..', import.meta.url).pathname;
    const skip20 = (s: string): boolean => s.endsWith('/.git') || s.includes('/.git/') || s.includes('/node_modules') || s.split('/').pop() === 'node_modules';
    const trees20: string[] = [];
    const withPoison20 = async (applyS: (s: string) => string, probe: (dir: string) => Promise<void>): Promise<void> => {
      const dir = fs20!.mkdtempSync!(os20!.tmpdir!() + '/t20-')!;
      trees20.push(dir);
      try {
        fs20!.cpSync!(repoRoot20, dir, { recursive: true, filter: (s: string) => !skip20(s) });
        const p = dir + '/src/client/note-crypto.ts';
        const s0 = fs20!.readFileSync!(p, 'utf8');
        fs20!.writeFileSync!(p, applyS(s0), 'utf8');
        await probe(dir);
      } finally {
        fs20!.rmSync!(dir, { recursive: true, force: true });
      }
    };
    const freshImport20 = async (dir: string): Promise<Record<string, unknown>> => await import('file://' + dir + '/src/client/note-crypto.ts') as Record<string, unknown>;
    const baseCfg20 = (): NoteCryptoConfig => ({ ...TACET, wrapRec: 'jr1r.', recKekHkdf: 'jr1r.', recKekSalt: recSalt20 });

    // R1 摘專屬 AAD（寫面接回共用 'notekey'）→ jr1r. 新面 unwrap 死＝單純換前綴假收口（designated）
    await withPoison20(
      (s: string) => s.replace(needleR1, "    return sealNoteKey(cfg.wrapRec, noteKey, kek, 'notekey');"),
      async (dir: string) => {
        const mod = (await freshImport20(dir)) as typeof import('../src/client/note-crypto.ts');
        const cfg = baseCfg20();
        const nk = await mod.generateNoteKey();
        const rt = mod.generateRecToken();
        const blob = await mod.wrapNoteKeyWithRecToken(cfg, nk, rt, identityA);
        const back = await mod.unwrapNoteKeyWithRecToken(cfg, blob, rt, identityA);
        await A('[20] 毒化 R1 摘專屬 AAD → 新面 unwrap 死（blob 內 AAD 舊契約形——designated）', back === null, String(back !== null));
      });
    // R2 HKDF info 域摘除（重錨：毒化打 info 字面——info 變數吃 recKekHkdf 值本身、
    // 家族成名域零在場→KAT 凍結 blob unwrap 死＝KAT 世代齒一次到位（designated））
    await withPoison20(
      (s: string) => s.replace("const info = 'journal-kek-rec-v1:' + hkdfTail;", 'const info = hkdfTail;'),
      async (dir: string) => {
        const mod = (await freshImport20(dir)) as typeof import('../src/client/note-crypto.ts');
        const back = await mod.unwrapNoteKeyWithRecToken(baseCfg20(), KAT_BLOB_R20, '62ff0221e30b56740ec210cd36df2e9667841585c6d0fcd5200826b965aa36a5', 'kat-id-0000000000000000');
        await A('[20] 毒化 R2 info 字面移除 → KAT blob unwrap 死（KAT 世代齒——info 有入派生的正向翻面——designated）', back === null, String(back !== null));
      });
    // R3 摘舊面雙試（legacy 派生錯鹽）→ 新世代讀舊 blob 死（過渡保護有齒）＋舊 cfg 面同死（同一本體）
    await withPoison20(
      (s: string) => s.replace(needleR3, "    const legacyKek = await deriveRecLegacyKek(cfg, recToken, identity + 'x');"),
      async (dir: string) => {
        const mod = (await freshImport20(dir)) as typeof import('../src/client/note-crypto.ts');
        const cfg = baseCfg20();
        const nk = await mod.generateNoteKey();
        const rt = mod.generateRecToken();
        const legacy = await mod.wrapNoteKeyWithRecToken(TACET, nk, rt, identityA);
        const back = await mod.unwrapNoteKeyWithRecToken(cfg, legacy, rt, identityA);
        await A('[20] 毒化 R3 摘舊面雙試 → 新世代讀舊 blob 死（designated——過渡保護有齒）', back === null, String(back !== null));
        const backOld = await mod.unwrapNoteKeyWithRecToken(TACET, legacy, rt, identityA);
        await A('[20] 毒化 R3 舊 cfg 面同死（legacy 派生本體單一真相——兩處呼叫同源）', backOld === null, String(backOld !== null));
      });
    // R4 前綴借用面復活（wrapRec 面接回 cfg.wrap）→ 寫面 fallback jr1w.（designated；契約翻轉齒由 P1 前綴斷言承載）
    await withPoison20(
      (s: string) => s.replace(needleR1, "    return sealNoteKey(cfg.wrap, noteKey, kek, 'notekey-rec');"),
      async (dir: string) => {
        const mod = (await freshImport20(dir)) as typeof import('../src/client/note-crypto.ts');
        const cfg = baseCfg20();
        const nk = await mod.generateNoteKey();
        const rt = mod.generateRecToken();
        const blob = await mod.wrapNoteKeyWithRecToken(cfg, nk, rt, identityA);
        await A('[20] 毒化 R4 前綴借用面復活 → 寫面 fallback jr1w.（毒化執行證——契約翻轉齒由 P1 前綴斷言承載）',
          typeof blob === 'string' && blob.startsWith('jr1w.'), String(blob ?? '').slice(0, 8));
      });
    // R5 忠實回退（檢查對齊新增案——C1/C2 拒寫面的唯一閘承載；designated）：
    // 門分支回寫生產形（wrapRec 面吃 legacy 派生＋notekey-rec 契約），尾端
    // cfg.wrap 腿原樣留任（wrapRec 缺席續走 cfg.wrap＋poisoned deriveRecKef HKDF）＝
    // 兩歷史缺陷象限（C1＝jr1r.×PBKDF2／C2＝jr1w.×HKDF）寫出面精確重現——毒化代碼照寫、
    // 兩缺陷形復活並自解 null 的行為翻面承載。
    const poisonR5 = (s: string): string => s.replace(
      "  if (cfg.wrapRec || cfg.recKekHkdf) {\n    if (!cfg.wrapRec || !cfg.recKekHkdf) throw new Error('ERR_REC_CFG_PARTIAL');\n    const kek = await deriveRecKek(cfg, recToken);\n    return sealNoteKey(cfg.wrapRec, noteKey, kek, 'notekey-rec');\n  }",
      '  if (cfg.wrapRec) {\n    const kek = await deriveRecLegacyKek(cfg, recToken, identity);\n    return sealNoteKey(cfg.wrapRec, noteKey, kek, "notekey-rec");\n  }',
    );
    await withPoison20(poisonR5, async (dir: string) => {
      const mod = (await freshImport20(dir)) as typeof import('../src/client/note-crypto.ts');
      const nk = await mod.generateNoteKey();
      const rt = mod.generateRecToken();
      const blobC1 = await mod.wrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, nk, rt, identityA);
      const blobC2 = await mod.wrapNoteKeyWithRecToken({ ...TACET, recKekHkdf: 'jr1r.', recKekSalt: recSalt20 }, nk, rt, identityA);
      const backC1 = await mod.unwrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, blobC1, rt, identityA);
      await A('[20] 毒化 R5 忠實回退 → C1 歷史缺陷形復活（jr1r.×PBKDF2 blob 寫出＋毒形讀面自解 null＝B10 象限寫得出讀不回——designated）',
        typeof blobC1 === 'string' && blobC1.startsWith('jr1r.') && backC1 === null,
        String(blobC1 ?? '').slice(0, 5) + '/' + String(backC1 !== null));
      await A('[20] 毒化 R5 忠實回退 → C2 歷史缺陷形復活（jr1w. 前綴 carrying 派生 HKDF blob 寫出——designated；借形契約面重現）',
        typeof blobC2 === 'string' && blobC2.startsWith('jr1w.'), String(blobC2 ?? '').slice(0, 5));
    });
    // 檢核：R5 毒化代碼（忠實回退形）寫出的 C1 形 blob，在守衛形（未毒化）讀面下不可救——配對門價值的直接行為證（缺口行為化）
    {
      const dirP = fs20!.mkdtempSync!(os20!.tmpdir!() + '/t20r5-')!;
      trees20.push(dirP);
      try {
        fs20!.cpSync!(repoRoot20, dirP, { recursive: true, filter: (s: string) => !skip20(s) });
        const pP = dirP + '/src/client/note-crypto.ts';
        const sP = fs20!.readFileSync!(pP, 'utf8');
        if (poisonR5(sP) === sP) throw new Error('R5 anchor missing');
        fs20!.writeFileSync!(pP, poisonR5(sP), 'utf8');
        const modP = (await import('file://' + dirP + '/src/client/note-crypto.ts')) as typeof import('../src/client/note-crypto.ts');
        const nkP = await modP.generateNoteKey();
        const rtP = (await modP.generateRecToken());
        const rawP = hex(new Uint8Array(await crypto.subtle.exportKey('raw', nkP)));
        const blobC1 = await modP.wrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, nkP, rtP, identityA);
        const rawEqP = async (k: CryptoKey | null): Promise<boolean> => k !== null && hex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) === rawP;
        const back = await unwrapNoteKeyWithRecToken({ ...TACET, wrapRec: 'jr1r.' }, blobC1, rtP, identityA);
        const backUp = await unwrapNoteKeyWithRecToken(TACET5, blobC1, rtP, identityA);
        await A('[20] 配對門價值行為證：R5 毒化代碼寫出 C1 形 blob → 守衛形讀面自解 null（B10 象限缺口的行為化翻面）',
          back === null, String(back === null));
        await A('[20] 配對門價值行為證：C1 形 blob 在完整新世代 cfg 下讀面亦 null（HKDF KEK≠PBKDF2 KEK——升級不救 B10）',
          backUp === null && !(await rawEqP(back)),
          String(backUp === null) + '/' + String(await rawEqP(back)));
      } finally {
        fs20!.rmSync!(dirP, { recursive: true, force: true });
      }
    }
    // 常駐自證：毒化樹零殘留（本 run 喚出 6 棵全清——封閉集判準；出生即棄拷貝樹＋真樹 needle 計數自證）
    // 錨名：真樹 needle 對位錨（t_ce675413 命名同款）——樹出生即棄，非毒化還原動作。
    const srcAfter20 = (getBuiltin20('node:fs') as { readFileSync?: (p: string, e?: string) => string })!.readFileSync!(
      new URL('../src/client/note-crypto.ts', import.meta.url).pathname, 'utf8');
    await A('[20] 真樹 needle 對位錨（真樹零突變的行程帶）',
      srcAfter20.split(needleR1).length === 2 && srcAfter20.split(needleR3).length === 2
      && srcAfter20.split("const info = 'journal-kek-rec-v1:'").length === 2 && srcAfter20.split(needleR5).length === 2);
    const existsSync20 = (p: string): boolean =>
      typeof fs20!.existsSync === 'function' ? fs20!.existsSync!(p) : false;
    await A('[20] 毒化樹零殘留（本 run 喚出 ' + trees20.length + ' 棵全清——封閉集判準）',
      trees20.length === 6 && trees20.every((t) => !existsSync20(t)));
  }
}
};

// ── 21. CI 供應鏈面（npm ci --ignore-scripts＋Dependabot runner 分流）──
//
// 外審 #1 的落地裁定（t_87ef62dd）：public 密碼學套件 repo 的 CI 安裝不吃依賴腳本——
// --ignore-scripts 是安裝面防線（postinstall/preinstall/prepare 全免執行）；
// Dependabot PR 走 GitHub-hosted runner 隔離（self-hosted runner 不接機器人分支）。
// 靜態錨面：workflow YAML 本體的接線（job-if C1 母型＋actor 分流＋runs-on fromJSON 陣列形）。
secOpen(21, '[21] CI 供應鏈面（npm ci --ignore-scripts＋dependabot runner 分流）'); if (secEnter(21)) {
{
  // 環境鍵＝.github 目錄存在（存在性鍵非檔名硬讀——r1 MINOR-3）：閘 src 檔在 files 白名單
  // 而 .github 不出包——tarball 消費樹硬讀 workflows＝未守衛 ENOENT，rc=1 尾段全吞。
  // 目錄缺席＝顯性 SKIP 行（消費端常態；[16]/[18] 毒化樹 pristine 基準由此同保線）；
  // 目錄在場而檔案缺席＝srcOf 硬 FAIL（repo 面牙齒不退位——軟讀文件名會把 repo 內
  // 摘 workflow 校準成靜默綠＝掉牙）。
  const fs21 = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { existsSync?: (p: string | URL) => boolean } | undefined };
  }).process?.getBuiltinModule?.('node:fs');
  const ghDir21 = !!fs21?.existsSync && fs21.existsSync(new URL('../.github/', import.meta.url));
  if (ghDir21) {
    const srcVy21 = await srcOf('../.github/workflows/verify.yml');
    const srcPy21 = await srcOf('../.github/workflows/publish.yml');
    await A('[21] verify.yml：npm ci --ignore-scripts（安裝面防線——依賴腳本零在場）',
      srcVy21.includes('npm ci --ignore-scripts'));
    await A('[21] verify.yml：job-if 同 repo 保衛（C1 母型——fork／他 repo branch 不上 runner；dependabot 分支照跑不擋＝分流入 RUN 面——r1 MAJOR-1）',
      /if: github\.event_name != 'pull_request' \|\| github\.event\.pull_request\.head\.repo\.full_name == github\.repository/.test(srcVy21));
    await A('[21] verify.yml：runs-on dependabot 分流＝fromJSON 陣列形（actor→["ubuntu-latest"]；fallback fromJSON 兩標籤組 ["self-hosted","journal-core"]——裸逗號字串 fallback＝StringToken 單一 literal 標籤缺陷形零承載，r2 MAJOR-1）',
      /runs-on: \$\{\{ fromJSON\(github\.event_name == 'pull_request' && github\.actor == 'dependabot\[bot\]' && '\["ubuntu-latest"\]' \|\| '\["self-hosted","journal-core"\]'\) \}\}/.test(srcVy21));
    await A('[21] publish.yml：npm ci --ignore-scripts（tag 驅動無 actor 面；typecheck+verify 先行＝腳本面零在場）',
      srcPy21.includes('npm ci --ignore-scripts'));
  } else {
    await A('[21] CI 源碼面：.github 缺席環境（tarball 發行樹常態）＝顯性 SKIP（workflow 斷言 4 收斂為 1 SKIP 行——消費端計數帳 503）',
      true, 'no .github dir — consumption tree face');
  }
  // 摘除自證（t_760f44e8 治理掃蕩補漏；fs 原語缺席環境＝顯性 FAIL 形自守衛——非 silent true）
  await A('[21] open-card-pr.sh 摘除（主機路徑＋GITHUB_TOKEN 線索面；fs 原語缺席＝顯性 FAIL 自守衛）',
    !!fs21?.existsSync && !fs21.existsSync(new URL('../scripts/open-card-pr.sh', import.meta.url)));
  // NIT-1 自證（isBrokenLink repo-root 錨定）：根錨路徑在場形（本 repo 常態 @scure 在場）
  // ＋CWD 無關面（probe 眼：lstat 走 import.meta.url 起手——cwd=任意時仍指 repo）。
  // 缺陷形（裸 '@scure/bip39' 殘留）＝源碼負向咬（regex 敘述形）。
  {
    const gateSrc21 = await srcOf('../scripts/verify-core-crypto.ts');
    await A('[21] NIT-1：isBrokenLink 路徑錨 = import.meta.url 起手（repo root 錨定——CWD 相對 lstat 誤報面收口）',
      /const repoRootRef = new URL\('\.\.\/node_modules\/@scure\/bip39', import\.meta\.url\)/.test(gateSrc21));
    await A('[21] NIT-1：裸 CWD 相對 lstat 殘留歸零（缺陷形負向——lstatSync\(\'@scure 直接形零殘留）',
      !/lstatSync\('@scure\/bip39'\)/.test(gateSrc21) && !/existsSync\('@scure\/bip39'\)/.test(gateSrc21));
    await A('[21] NIT-1：isBrokenLink 判準本體在場（lstat isSymbolicLink && !existsSync——斷鏈 vs 真缺席分流保線）',
      /isSymbolicLink\(\) && !fsMod\.existsSync\(repoRootRef\)/.test(gateSrc21));
    await A('[21] r2 MINOR-1：fs 直讀守衛＝URL 物件直傳（existsSync .github 在場面＋srcOf readFileSync rel 面——file: URL 原生接線，零 .pathname 中介）',
      /fs21\.existsSync\(new URL\('\.\.\/\.github\/', import\.meta\.url\)\)/.test(gateSrc21)
      && /fs\.readFileSync\(new URL\(rel, import\.meta\.url\), 'utf8'\)/.test(gateSrc21));
    await A('[21] r2 MINOR-1：fs 原語直讀 .pathname 形零殘留（缺陷形負向——URL %編碼失真→existsSync 恆 false→SKIP 分枝靜默退位面收口）',
      !/existsSync\(new URL\([^)]*\)\.pathname\)/.test(gateSrc21)
      && !/readFileSync\(new URL\([^)]*\)\.pathname/.test(gateSrc21));
  }
}
};

secOpen(23, '[23] loginRouteCore ladder 查表守衛（外審 #8 幽靈帳——現值 miss → ladder → 兩面 miss 才 createUser）'); if (secEnter(23)) {
{
  // getBuiltin23：node 內建模組動態存取（本段自備 helper——[19]/[21] 同構；structured type 零 node types 依賴）
  const getBuiltin23 = (id: string): unknown =>
    (globalThis as unknown as { process?: { getBuiltinModule?: (i: string) => unknown } }).process?.getBuiltinModule?.(id);
  const { DatabaseSync } = (getBuiltin23('node:sqlite') as { DatabaseSync?: unknown } | undefined) ?? {};
  if (!DatabaseSync) throw new Error('ERR_SQLITE_UNAVAILABLE');
  const { loginRouteCore } = await import('../src/server/auth.ts');
  const enc23 = new TextEncoder();
  const hex23 = (u8: Uint8Array): string => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
  const ncCrypto23 = (getBuiltin23('node:crypto') as { createHash?: (a: string) => { update: (s: string) => { digest: (e: string) => string } } } | undefined) ?? { createHash: () => { throw new Error('ERR_CRYPTO_UNAVAILABLE'); } };
  const sha256Sync23 = (s: string): string => ncCrypto23.createHash!('sha256').update(s).digest('hex');
  const sha23 = async (s: string): Promise<string> => hex23(new Uint8Array(await crypto.subtle.digest('SHA-256', enc23.encode(s))));
  // PH1 hex64 樣本（直入 login body）：loginRouteCore 對 body 做 sha256Hex＝ph2——fixture 種子
  // 必須種 sha256(ph1)（雜湊後落表）；種 ph1 本身進 ph2 欄＝miss by construction（種錯層）。
  const ph1a23 = sha256Sync23('jr23-current-ph1');
  const ph1b23 = sha256Sync23('jr23-old-ph1');
  const ph1c23 = sha256Sync23('jr23-ghost-ph1');
  const ph1d23 = sha256Sync23('jr23-nolad-ph1');
  const ph1e23 = sha256Sync23('jr23-failo-ph1');
  const ph1x23 = sha256Sync23('jr23-sessi-ph1');
  const rowA23 = sha256Sync23(ph1a23);
  const row23old = sha256Sync23('jr23-v3cur-ph1');
  const row23x = sha256Sync23(ph1x23);

  const mkDb23 = (): { db: { exec: (s: string) => void; prepare: (s: string) => { run: (...p: unknown[]) => { changes: number }; get: (...p: unknown[]) => unknown; all: (...p: unknown[]) => unknown[] } }; env23: unknown } => {
    const db = new (DatabaseSync as new (p: string) => { exec: (s: string) => void; prepare: (s: string) => { run: (...p: unknown[]) => { changes: number }; get: (...p: unknown[]) => unknown; all: (...p: unknown[]) => unknown[] } })(':memory:');
    db.exec('CREATE TABLE login_rate (ip TEXT PRIMARY KEY, window_start INTEGER, count INTEGER)');
    db.exec('CREATE TABLE users (account_id TEXT PRIMARY KEY, ph2 TEXT UNIQUE, salt TEXT, wrapped_key TEXT, wrapped_rec TEXT, rec_hash TEXT)');
    return {
      db,
      env23: {
        DB: {
          prepare: (sql: string) => ({
            bind: (...params: unknown[]) => ({
              run: async () => {
                let results: unknown[] = [];
                try { results = db.prepare(sql).all(...params) as unknown[]; }
                catch { try { db.prepare(sql).run(...params); } catch {} }
                return { results, meta: {} };
              },
            }),
          }),
        },
      } as unknown as never,
    };
  };
  const USER_COLS23 = 'account_id AS userKey, ph2, salt, wrapped_key AS wrapped, wrapped_rec AS wrappedRec, rec_hash AS recHash';

  // ① 現值 hit：單查命中，ladder 零呼叫零建號（現值 hit 短路在 findByIdentityQuery）
  {
    const t = mkDb23();
    const calls23 = { ladder: 0, create: 0 };
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async () => { calls23.create++; return 'acct-ghost-23'; },
      getByUserKey: async () => null,
      revokeAllSessions: async () => {},
      insertSession: async () => {},
      ladderLookup: async () => { calls23.ladder++; return null; },
    };
    t.db.prepare("INSERT INTO users (account_id, ph2, salt, wrapped_key) VALUES ('acct-23a', ?, 's23', 'wr23')").run(rowA23);
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-1', ph1a23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string; status: string };
    await A('[23] 現值 hit 回 200 ready（userKey 恰 acct-23a——登入 body 相容現值契約）', res23.status === 200 && j23.status === 'ready' && j23.userKey === 'acct-23a');
    await A('[23] 現值 hit：ladderLookup 零呼叫（短路在 findByIdentityQuery）', calls23.ladder === 0);
    await A('[23] 現值 hit：createUser 零呼叫（零幽靈面）', calls23.create === 0);
  }

  // ② ladder hit（現值 miss）＝回舊帳不建幽靈；getByUserKey 讀現值（ph2Kind 語意照 ladder.ts）；
  //    session 歸宿舊帳 userKey
  {
    const t = mkDb23();
    const calls23 = { ladder: 0, create: 0, byKey: [] as string[] };
    let sess23: { tokenHash: string; userKey: string; expiresAt: number } | null = null;
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async () => { calls23.create++; return 'acct-ghost-23'; },
      getByUserKey: async (key: string) => { calls23.byKey.push(key); return (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE account_id = ?`).get(key) as unknown) || null; },
      revokeAllSessions: async () => {},
      insertSession: async (tokenHash: string, userKey: string, expiresAt: number) => { sess23 = { tokenHash, userKey, expiresAt }; },
      ladderLookup: async () => { calls23.ladder++; return 'acct-23old'; },
    };
    t.db.prepare("INSERT INTO users (account_id, ph2, salt, wrapped_key) VALUES ('acct-23old', ?, 's23', 'wr23')").run(row23old);
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-2', ph1b23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string; status: string };
    await A('[23] ladder hit → userKey=舊帳 acct-23old（不建幽靈）', j23.userKey === 'acct-23old' && calls23.create === 0);
    await A('[23] ladder hit：ladderLookup 恰 1 呼叫（守衛接線在場）', calls23.ladder === 1);
    await A('[23] ladder hit 語意照 ladder.ts：回帳走 getByUserKey（現值面承載——非表列直接回）', calls23.byKey.length === 1 && calls23.byKey[0] === 'acct-23old');
    await A('[23] ladder hit → ready 分流（帳戶 ph2 在場）', j23.status === 'ready');
    await A('[23] ladder hit → session 落在舊帳 userKey（tokenSha256＋30 天）', sess23 !== null && (sess23 as { userKey: string }).userKey === 'acct-23old'
      && /^[0-9a-f]{64}$/.test((sess23 as { tokenHash: string }).tokenHash)
      && (sess23 as { expiresAt: number }).expiresAt > Date.now() + 29 * 86400e3);
  }

  // ③ 兩面 miss → 建 1 幽靈（ph2 恆等＝sha256(登入 PH1)）
  {
    const t = mkDb23();
    let inserted23: string | null = null;
    const calls23 = { ladder: 0 };
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async (ph2: string) => { inserted23 = ph2; return 'acct-ghost-23'; },
      getByUserKey: async () => null,
      revokeAllSessions: async () => {},
      insertSession: async () => {},
      ladderLookup: async () => { calls23.ladder++; return null; },
    };
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-3', ph1c23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string; status: string };
    await A('[23] 兩面 miss → 建 1 幽靈（createUser 恰 1——幽靈語意照舊）', j23.userKey === 'acct-ghost-23');
    await A('[23] 幽靈 ph2 = sha256Hex(登入 PH1)（subtle 交叉驗——種子層對帳）', inserted23 !== null && inserted23 === await sha23(ph1c23));
    await A('[23] 兩面 miss：ladderLookup 有呼叫（配置在場＝守衛有接線）＋require_binding 分流', calls23.ladder === 1 && j23.status === 'require_binding');
  }

  // ④ lookup 未配置（optional undefined）＝0.2.3 單查行為零變（ladder 零呼叫——向後相容鐵律）
  {
    const t = mkDb23();
    const calls23 = { create: 0 };
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async () => { calls23.create++; return 'acct-ghost-23'; },
      getByUserKey: async () => null,
      revokeAllSessions: async () => {},
      insertSession: async () => {},
    };
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-4', ph1d23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string };
    await A('[23] ladderLookup 未配置 → 直接建幽靈（0.2.3 單查行為恆等——optional 退場鐵律）', j23.userKey === 'acct-ghost-23' && calls23.create === 1);
  }

  // ⑤ ladder store 拋錯（表缺席）＝fail-open 視同 miss，不炸登入
  {
    const t = mkDb23();
    let createCalls23 = 0;
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async () => { createCalls23++; return 'acct-ghost-23'; },
      getByUserKey: async () => null,
      revokeAllSessions: async () => {},
      insertSession: async () => {},
      ladderLookup: async () => { throw new Error('no such table: ph2_ladder'); },
    };
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-5', ph1e23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string };
    await A('[23] ladder 拋錯 fail-open＝登入不炸、續建幽靈（tacet store.ts 母型上位）', res23.status === 200 && j23.userKey === 'acct-ghost-23' && createCalls23 === 1);
  }

  // ⑥ ladder hit：帳戶現值已旋轉（ph2 異值欄面）——status 分流照 user?.ph2 實值
  {
    const t = mkDb23();
    const store23 = {
      findByIdentityQuery: async (ph2: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE ph2 = ?`).get(ph2) as unknown) || null,
      createUser: async () => 'acct-ghost-23',
      getByUserKey: async (key: string) => (t.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE account_id = ?`).get(key) as unknown) || null,
      revokeAllSessions: async () => {},
      insertSession: async () => {},
      ladderLookup: async () => 'acct-23old',
    };
    t.db.prepare("INSERT INTO users (account_id, ph2, salt, wrapped_key) VALUES ('acct-23old', 'ph2-rotated-current-23', 's23', 'wr23')").run();
    const res23 = await loginRouteCore(t.env23 as never, store23 as never, 'ip-23-6', ph1b23);
    const j23 = JSON.parse(await res23.text()) as { userKey: string; status: string };
    await A('[23] ladder hit（現值已旋轉異值欄）→ userKey=舊帳、status=ready（user?.ph2 在場分流本體契約）', j23.userKey === 'acct-23old' && j23.status === 'ready');
  }

  // ⑦ 毒化（拷貝樹 in-gate，t_0ab6e760 母型）：ladderGuard 接線摘除 → ladder hit 案翻建幽靈。
  // 毒化跑在 /tmp 拷貝樹＝本 repo 樹 byte 不動；還原 byte-exact＋樹出生即棄。
  // POISON_GATE_INNER sentinel（[16]/[18]/[20] 遞迴防線母型）：內層跑份自我跳過毒化節。
  {
    const inner23 = (getBuiltin23('node:process') as { env?: Record<string, string | undefined> } | undefined)?.env?.POISON_GATE_INNER === '1';
    if (inner23) {
      await A('[23] 毒化證據：內層跑份自我跳過（POISON_GATE_INNER sentinel——遞迴防線母型）', true, 'POISON_GATE_INNER=1');
    } else {
      const fs23 = (getBuiltin23('node:fs') as {
        mkdtempSync?: (p: string) => string;
        mkdirSync?: (p: string, o?: unknown) => void;
        copyFileSync?: (a: string | URL, b: string) => void;
        readdirSync?: (p: string | URL) => string[];
        readFileSync?: (p: string | URL, e: string) => string;
        writeFileSync?: (p: string, s: string, e: string) => void;
        rmSync?: (p: string, o?: unknown) => void;
      } | undefined) ?? undefined;
      const path23x = (getBuiltin23('node:path') as { join?: (...p: string[]) => string } | undefined) ?? undefined;
      const os23 = (getBuiltin23('node:os') as { tmpdir?: () => string } | undefined) ?? undefined;
      const url23 = (getBuiltin23('node:url') as { pathToFileURL?: (p: string) => { href: string } } | undefined) ?? undefined;
      if (!fs23?.mkdtempSync || !path23x?.join || !os23?.tmpdir || !url23?.pathToFileURL) {
        // 原語缺席環境＝顯性 SKIP 行（非 silent true——t_87ef62dd 環境鍵母型）
        await A('[23] 毒化面（原語缺席環境）＝顯性 SKIP 行，毒化證據缺席顯形非 silent true',
          false, 'node fs/path/os/url 原語缺席——毒化面 skip（消費端精簡 Node 形；repo 樹常態不見此行）');
      } else {
        // 拷貝樹源＝本閘的套件根（import.meta.url 起手——repo 樹與消費樹同構，零硬編碼路徑）
        const pkgRootUrl23 = new URL('../', import.meta.url);
        const srcDirUrl23 = new URL('src/server/', pkgRootUrl23);
        const tree23 = fs23.mkdtempSync!(path23x.join(os23.tmpdir(), 't23-ladder-'));
        fs23.mkdirSync!(path23x.join(tree23, 'src/server'), { recursive: true });
        const filesSer23 = fs23.readdirSync!(srcDirUrl23).filter((f) => f.endsWith('.ts'));
        for (const f of filesSer23) fs23.copyFileSync!(new URL('src/server/' + f, pkgRootUrl23), path23x.join(tree23, 'src/server', f));
        await A('[23] 毒化樹拷貝：src/server 全檔在場（auth.ts＋依賴鏈四檔≥5）', filesSer23.length >= 5 && filesSer23.includes('auth.ts'), 'n=' + filesSer23.length);
        // 毒化錨（唯一）：接線面 `?? (await ladderGuard(store, ph2))` 摘除 → 單查直路
        //（removal-form——毒面＝ladder hit 案翻建幽靈；未配置案照綠＝行為面恰此面翻）。
        const needle23 = '(await store.findByIdentityQuery(ph2)) ?? (await ladderGuard(store, ph2))';
        const srcAuth23 = fs23.readFileSync!(new URL('src/server/auth.ts', pkgRootUrl23), 'utf8');
        const cnt23 = srcAuth23.split(needle23).length - 1;
        await A('[23] 毒化錨恰 1（split 計數——接線形單點承載）', cnt23 === 1, 'cnt=' + cnt23);
        if (cnt23 === 1) {
          fs23.writeFileSync!(path23x.join(tree23, 'src/server/auth.ts'), srcAuth23.split(needle23).join('await store.findByIdentityQuery(ph2)'), 'utf8');
          try {
            const modP = (await import(url23.pathToFileURL(path23x.join(tree23, 'src/server/auth.ts')).href + '?poison23=1')) as unknown as { loginRouteCore: typeof loginRouteCore };
            const tP = mkDb23();
            const storeP = {
              findByIdentityQuery: async () => null,
              createUser: async () => 'acct-ghost-23',
              getByUserKey: async (key: string) => (tP.db.prepare(`SELECT ${USER_COLS23} FROM users WHERE account_id = ?`).get(key) as unknown) || null,
              revokeAllSessions: async () => {},
              insertSession: async () => {},
              ladderLookup: async () => 'acct-23old',
            };
            tP.db.prepare("INSERT INTO users (account_id, ph2, salt, wrapped_key) VALUES ('acct-23old', ?, 's23', 'wr23')").run(row23old);
            const resP = await modP.loginRouteCore(tP.env23 as never, storeP as never, 'ip-23-P', ph1b23);
            const jP = JSON.parse(await resP.text()) as { userKey: string; status: string };
            await A('[23] 毒化（ladderGuard 接線摘除）→ ladder hit 案翻建幽靈（行為面真翻——designated）',
              jP.userKey === 'acct-ghost-23', 'userKey=' + jP.userKey);
          } catch (e) {
            await A('[23] 毒化重演（行為面真翻）', false, 'crash: ' + String((e as Error).message).slice(0, 160));
          }
          fs23.writeFileSync!(path23x.join(tree23, 'src/server/auth.ts'), srcAuth23, 'utf8');
          const restored23 = fs23.readFileSync!(path23x.join(tree23, 'src/server/auth.ts'), 'utf8') === srcAuth23;
          fs23.rmSync!(tree23, { recursive: true, force: true });
          await A('[23] 毒化還原 byte-exact＋樹出生即棄（本 repo 樹零接觸——零殘毒面）', restored23);
        } else {
          fs23.rmSync!(tree23, { recursive: true, force: true });
        }
      }
    }
  }
}

};
// ── 26. 格式規格＋測試向量（docs/format-spec.md＋docs/vectors/*.json） ──
//
// 單向契約：源碼 → scripts/generate-vectors.ts → JSON（凍結證據，commit 入 repo）→ 本段只檢存在＋shape。
// 本段不依賴產生器、不重算 KDF（向量含隨機 iv/鹽＝重算即漂移）；BIP39 是確定性轉寫，逐組對照現行原語。
// teeth：payload 位元組長度＝b64 解碼真值、fields 拼接＝payload 逐位元組、布局長度＝規格表列、
// 欄位名限定形逐一在規格對應節、凍結 blob 逐字＝本閘 KAT 字面（[14]/[17]/[20]）、RFC 9106 期望值＋參數＝argon2.ts 常數。
secOpen(26, '[26] 格式規格＋測試向量（docs/format-spec.md＋docs/vectors 存在性＋shape）'); if (secEnter(26)) {
{
  const readJson26 = async (rel: string): Promise<Record<string, unknown> | null> => {
    try { return JSON.parse(await srcOf(rel)) as Record<string, unknown>; } catch { return null; }
  };
  const spec26 = await srcOf('../docs/format-spec.md').catch(() => '');
  const fam26 = await readJson26('../docs/vectors/families.json');
  const kat26 = await readJson26('../docs/vectors/kat.json');
  const bip26 = await readJson26('../docs/vectors/bip39.json');
  type Vec26 = { prefix: string; family: string; layout: string; kdf: string; aad: string; inputs: Record<string, unknown>; wire: string; payload_len: number; fields: { name: string; offset: number; len: number; hex: string }[] };
  const vecs26 = (Array.isArray(fam26?.vectors) ? fam26!.vectors : []) as Vec26[];
  const HEAD26 = ['format', 'package_version', 'spec', 'generator', 'note'];
  await A('[26] 規格檔＋三向量檔在場且 JSON parse；頂層共通欄齊（format=journal-core-vectors/1、spec/generator 路徑字面——產生器不被閘依賴，發行包不帶產生器）',
    spec26.length > 0 && !!fam26 && !!kat26 && !!bip26
    && [fam26, kat26, bip26].every((j) => HEAD26.every((k) => typeof j![k] === 'string') && j!.format === 'journal-core-vectors/1'
      && j!.spec === 'docs/format-spec.md' && j!.generator === 'scripts/generate-vectors.ts'));
  // 規格表前綴集（§1 家族逐條表：| `prefix` | 家族 | 布局 | payload | KDF | AAD |）
  const specRows26 = spec26.split('\n').filter((l) => /^\| `jr[0-9a-z]{2}\.`(（[^|]*）)? \|/.test(l) && /\| (content|salt-external|salt-embedded) \|/.test(l));
  const specPrefixes26 = new Set(specRows26.map((l) => l.match(/^\| `(jr[0-9a-z]{2}\.)`/)![1]));
  const vecPrefixes26 = new Set(vecs26.map((v) => v.prefix));
  await A('[26] 家族覆蓋雙向：規格家族表 16 列前綴集＝families.json 前綴集（15 前綴；jr1w. 兩世代各一組）',
    specRows26.length === 16 && vecs26.length === 16 && specPrefixes26.size === 15
    && [...specPrefixes26].every((p) => vecPrefixes26.has(p)) && [...vecPrefixes26].every((p) => specPrefixes26.has(p)));
  const VKEYS26 = ['prefix', 'family', 'layout', 'kdf', 'aad', 'inputs', 'wire', 'payload_len', 'fields'];
  await A('[26] families 位元組 shape：payload_len＝wire b64 解碼真長；fields offset 連續、len 總和＝payload_len、hex 拼接＝payload 逐位元組',
    vecs26.length > 0 && vecs26.every((v) => {
      if (!VKEYS26.every((k) => k in v) || !v.wire.startsWith(v.prefix)) return false;
      let payload: Uint8Array;
      try { payload = unb64Mod(v.wire.slice(v.prefix.length)); } catch { return false; }
      let off = 0;
      for (const f of v.fields) { if (f.offset !== off || f.hex.length !== f.len * 2) return false; off += f.len; }
      return payload.length === v.payload_len && off === v.payload_len && v.fields.map((f) => f.hex).join('') === hex(payload);
    }));
  await A('[26] 布局長度＝規格：salt-external 92／salt-embedded 108（pinSalt 頭 16）／content 28+UTF8(plaintext)；且規格家族表該前綴列含同布局＋同長度',
    vecs26.length > 0 && vecs26.every((v) => {
      const want = v.layout === 'salt-external' ? 92 : v.layout === 'salt-embedded' ? 108 : v.layout === 'content' ? 28 + enc.encode(String(v.inputs.plaintext)).length : -1;
      const lenCol = v.layout === 'content' ? '28+n' : String(want);
      const head = v.layout === 'salt-embedded' ? v.fields[0]?.name === 'pinSalt' && v.fields[0]?.len === 16 : v.fields[0]?.name === 'iv';
      return want === v.payload_len && head && specRows26.some((l) => l.startsWith('| `' + v.prefix + '`') && l.includes('| ' + v.layout + ' | ' + lenCol + ' |'));
    }));
  // 欄位名限定形（通用字 name/len/hex/source… 在規格檔隨處可見＝裸字檢查無咬力）：頂層欄＝§7 頭表／§7.1／§7.2 對應節
  // 的表列 `| \`欄\` |`；巢狀欄＝限定形 `父[].欄`／`rfc9106.欄` 逐字在規格檔。欄名集取自向量檔實際鍵（新增欄未入規格＝紅）。
  const sec26 = (from: string, to: string): string => { const i = spec26.indexOf(from); const j = to ? spec26.indexOf(to, i + 1) : spec26.length; return i < 0 || j < 0 ? '' : spec26.slice(i, j); };
  const s7h26 = sec26('## 7. ', '### 7.1 '), s71_26 = sec26('### 7.1 ', '### 7.2 '), s72_26 = sec26('### 7.2 ', '### 7.3 '), s73_26 = sec26('### 7.3 ', '');
  const row26 = (sec: string, k: string): boolean => sec.includes('\n| `' + k + '` |');
  const keysOf26 = (xs: unknown): string[] => [...new Set((Array.isArray(xs) ? xs : []).flatMap((x) => (x && typeof x === 'object' ? Object.keys(x) : [])))];
  const fieldKeys26 = keysOf26(vecs26.flatMap((v) => (Array.isArray(v.fields) ? v.fields : [])));
  const rfcKeys26 = Object.keys((kat26?.rfc9106 ?? {}) as object);
  const frozenKeys26 = keysOf26(kat26?.frozen_blobs), credKeys26 = keysOf26(kat26?.credentials), sampleKeys26 = keysOf26(bip26?.samples);
  // 反空轉下限：實際鍵集須涵蓋閘面讀取的欄（鍵集取自資料＝資料缺欄時下限擋住空集合真值）
  const floor26 = (ks: string[], need: string[]): boolean => need.every((k) => ks.includes(k));
  await A('[26] 欄位名對規格（限定形）：頂層欄＝§7 頭表／§7.1 vectors 表／§7.2 kat 表逐列；巢狀欄逐一以 `fields[].欄`／`rfc9106.欄`／`frozen_blobs[].欄`／`credentials[].欄`／`samples[].欄` 出現在對應節（欄名集取自向量檔實鍵＋閘讀欄下限）',
    spec26.length > 0 && !!kat26 && !!bip26
    && HEAD26.every((k) => row26(s7h26, k)) && keysOf26(vecs26).every((k) => row26(s71_26, k)) && VKEYS26.every((k) => row26(s71_26, k))
    && ['rfc9106', 'frozen_blobs', 'credentials'].every((k) => k in kat26! && row26(s72_26, k)) && 'samples' in bip26! && s73_26.includes('`samples`')
    && floor26(fieldKeys26, ['name', 'offset', 'len', 'hex']) && fieldKeys26.every((k) => s71_26.includes('`fields[].' + k + '`'))
    && floor26(rfcKeys26, ['memory_kib', 'iterations', 'parallelism', 'tag_len', 'password_hex', 'salt_hex', 'expected_tag_hex']) && rfcKeys26.every((k) => s72_26.includes('`rfc9106.' + k + '`'))
    && floor26(frozenKeys26, ['prefix', 'wire', 'payload_len', 'expected_note_key_hex', 'source']) && frozenKeys26.every((k) => s72_26.includes('`frozen_blobs[].' + k + '`'))
    && floor26(credKeys26, ['kind', 'expected_hex']) && credKeys26.every((k) => s72_26.includes('`credentials[].' + k + '`'))
    && floor26(sampleKeys26, ['entropy_hex', 'checksum_hex', 'words', 'source']) && sampleKeys26.every((k) => s73_26.includes('`samples[].' + k + '`')));
  const gate26 = await srcOf('./verify-core-crypto.ts');
  const frozen26 = (Array.isArray(kat26?.frozen_blobs) ? kat26!.frozen_blobs : []) as { prefix: string; wire: string; payload_len: number; expected_note_key_hex: string; source: string }[];
  const rfc26 = (kat26?.rfc9106 ?? {}) as Record<string, unknown>;
  const creds26 = (Array.isArray(kat26?.credentials) ? kat26!.credentials : []) as { kind: string; expected_hex: string }[];
  const argon26 = await import('../src/client/argon2.ts');
  const kp26 = argon26.ARGON_RFC9106_PARAMS;
  await A('[26] kat 對帳：RFC 9106 expected_tag_hex＝ARGON_RFC9106_EXPECTED、參數 m/t/p/tag/pwd/salt＝ARGON_RFC9106_PARAMS（argon2.ts 常數——verifyArgonKat／產生器同源）；凍結 blob 7 筆逐字＝本閘 KAT 字面（[14]/[17]/[20]）且 payload_len＝解碼真長；憑證樣本 5 筆 hex64',
    argon26.ARGON_RFC9106_EXPECTED === rfc26.expected_tag_hex
    && rfc26.memory_kib === kp26.memoryKib && rfc26.iterations === kp26.iterations && rfc26.parallelism === kp26.parallelism
    && rfc26.tag_len === kp26.tagLen && kp26.tagLen === argon26.ARGON_TAG_LEN
    && rfc26.password_hex === kp26.passwordByte.toString(16).padStart(2, '0').repeat(kp26.passwordLen) && rfc26.salt_hex === '00'.repeat(kp26.saltLen)
    && frozen26.length === 7 && frozen26.every((b) => gate26.includes("'" + b.wire + "'") && b.wire.startsWith(b.prefix)
      && unb64Mod(b.wire.slice(b.prefix.length)).length === b.payload_len && /^[0-9a-f]{64}$/.test(b.expected_note_key_hex))
    && creds26.length === 5 && creds26.every((c) => /^[0-9a-f]{64}$/.test(c.expected_hex)));
  const samples26 = (Array.isArray(bip26?.samples) ? bip26!.samples : []) as { entropy_hex: string; checksum_hex: string; words: string[]; source: string }[];
  await A('[26] bip39 抽樣 ≥32 組：entropy hex64＋24 詞＋checksum＝SHA-256(entropy)[0]；逐組對照現行轉寫原語（recTokenToWords 逐詞相等——確定性轉寫非 KDF 重算）',
    samples26.length >= 32 && (await (async () => {
      for (const s of samples26) {
        if (!/^[0-9a-f]{64}$/.test(s.entropy_hex) || s.words?.length !== 24) return false;
        const cs = new Uint8Array(await crypto.subtle.digest('SHA-256', hexToBytes(s.entropy_hex) as BufferSource))[0];
        if (cs.toString(16).padStart(2, '0') !== s.checksum_hex) return false;
        if ((await bip.recTokenToWords(s.entropy_hex))?.join(' ') !== s.words.join(' ')) return false;
      }
      return true;
    })()));
  const pkg26 = JSON.parse(await srcOf('../package.json')) as { files?: string[] };
  await A('[26] 發行面：package.json files 含 docs（tarball 帶規格＋向量——消費端可對帳）＋產生器排除（!scripts/generate-vectors.ts——[22] scripts 封閉集 2 檔不動）',
    Array.isArray(pkg26.files) && pkg26.files.includes('docs') && pkg26.files.includes('!scripts/generate-vectors.ts'));
}
}

// ── 27. 高階 Vault API（src/client/vault.ts＋argon-auto.ts＋argon-worker.ts＋vendor hash-wasm） ──
//
// 行為面（對真模組）：create→encrypt→decrypt 三資料形 roundtrip、AAD＝`<app>:<recordId>` 以低階原語
// 手解對帳、unlockVault 新前綴（jr4w.）／舊前綴（jr3w. Argon、jr1w. PBKDF2）、upgrade 同鑰驗證重包、
// changePassphrase 週期（含 PIN jr4d. 進出）、復原套件（jr1r.）、VaultError 毒化（搬列 AAD／竄改／
// 形不符／配置缺欄）、載體覆寫顯形（setArgonLoader 注入優先＋錯值載體 KAT 拒用）、真 Worker 載體
//（node worker_threads 轉接層跑 argonWorkerSource 原文——瀏覽器 blob 形同源碼）、回退鏈（Worker 失效→
// inline＋onFallback；無回退鏈＝KDF_UNSUPPORTED；派生期載體失效歸因不誤報 WRAP_MISMATCH）、vendor 孿生
//（去縮排原文 sha256＝檔內常數＝閘釘選值）、零 runtime deps＋exports 子路徑＋分層單向。
// 收尾恆 resetArgonCarrier()＋setArgonLoader(null)——後續段零載體殘留。
secOpen(27, '[27] 高階 Vault API（roundtrip 三資料形／新舊前綴解鎖／upgrade／換密語／復原／VaultError 毒化／載體覆寫＋Worker 回退鏈／vendor 孿生）'); if (secEnter(27)) {
{
  const codeOf27 = async (p: Promise<unknown>): Promise<string> => {
    try { await p; return 'OK'; } catch (e) { return e instanceof VaultError ? e.code : 'NON-VAULT:' + String((e as Error)?.message ?? e); }
  };
  const fam27 = (h: { family: unknown }): string | null => h.family as string | null; // getter 讀值（禁 TS 跨 await 窄化）
  const bytesEq27 = (a: unknown, b: Uint8Array): boolean =>
    a instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);
  const CFG27: VaultOptions = {
    app: 'tacet-vault27',
    cipher: 'jr1v.',
    argon: { wrap4: 'jr4w.', wrap3: 'jr3w.', wrapDual4: 'jr4d.', wrapDual3: 'jr3d.', pinSalt3Prefix: 'tacet-note-pin3:' },
    legacy: { wrap: 'jr1w.', wrapDual: 'jr2w.', pinSaltPrefix: 'tacet-note-pin1:' },
    recovery: { wrapRec: 'jr1r.', recKekHkdf: 'tacet-vault27' },
  };
  const PASS27 = 'correct horse ｂａｔｔｅｒｙ 27';
  try {
    // ① roundtrip 三資料形
    const c27 = await createVault(PASS27, CFG27);
    const v27 = c27.vault;
    const str27 = '默·日記 — 🌙 line\nbreak';
    const obj27 = { title: '標題', tags: ['a', 'b'], n: 3, ok: true, nil: null, nested: { x: [1, { y: 'z' }] } };
    const bytes27 = new Uint8Array([0, 1, 2, 254, 255, 0, 128]);
    const bS27 = await v27.encrypt('rec-s', str27);
    const bJ27 = await v27.encrypt('rec-j', obj27);
    const bB27 = await v27.encrypt('rec-b', bytes27);
    const bE27 = await v27.encrypt('rec-e', new Uint8Array(0));
    const bES27 = await v27.encrypt('rec-es', '');
    await A('[27] create→encrypt→decrypt roundtrip 三資料形（字串含 Unicode／JSON 巢狀物件／Uint8Array 含 0x00＋空陣列＋空字串）還原同型；blob 前綴＝cfg.cipher；同明文兩次密文異（隨機 iv）',
      [bS27, bJ27, bB27, bE27, bES27].every((b) => b.startsWith('jr1v.'))
      && (await v27.decrypt('rec-s', bS27)) === str27
      && JSON.stringify(await v27.decrypt('rec-j', bJ27)) === JSON.stringify(obj27)
      && bytesEq27(await v27.decrypt('rec-b', bB27), bytes27)
      && bytesEq27(await v27.decrypt('rec-e', bE27), new Uint8Array(0))
      && (await v27.decrypt('rec-es', bES27)) === ''
      && (await v27.encrypt('rec-s', str27)) !== bS27);

    // ② 寫面形＋AAD 域（低階原語手解對帳）
    const rec27 = c27.serverRecord;
    const nk27 = await unwrapNoteKey4(CFG27.argon, rec27.wrapped, PASS27, rec27.salt);
    const openRaw27 = async (key: CryptoKey | null, blob: string, aad: string): Promise<Uint8Array | null> => {
      if (!key) return null;
      try {
        const p = unb64Mod(blob.slice(5));
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.slice(0, 12) as BufferSource, additionalData: enc.encode(aad) as BufferSource }, key, p.slice(12) as BufferSource));
      } catch { return null; }
    };
    const rawS27 = await openRaw27(nk27, bS27, 'tacet-vault27:rec-s');
    const kit27 = c27.recovery;
    await A('[27] 寫面形：serverRecord jr4w.＋salt hex32、family wrap4、needsUpgrade false、carrier node；低階 unwrapNoteKey4 解得同鑰——AAD＝`<app>:<recordId>`（tag 0x73＋UTF-8 本體）、裸 recordId／他 app 域恆解不開；復原套件 recToken hex64＋wrappedRec jr1r.＋recTokenHash＝SHA-256(recToken)',
      rec27.wrapped.startsWith('jr4w.') && /^[0-9a-f]{32}$/.test(rec27.salt) && v27.family === 'wrap4' && v27.needsUpgrade() === false && v27.carrier === 'node'
      && !!rawS27 && rawS27[0] === 0x73 && new TextDecoder().decode(rawS27.subarray(1)) === str27
      && (await openRaw27(nk27, bS27, 'rec-s')) === null && (await openRaw27(nk27, bS27, 'other-app:rec-s')) === null
      && !!kit27 && /^[0-9a-f]{64}$/.test(kit27.recToken) && kit27.wrappedRec.startsWith('jr1r.') && kit27.recTokenHash === await sha(kit27.recToken));

    // ③ unlockVault 新前綴
    const u27 = await unlockVault(PASS27, rec27, CFG27);
    await A('[27] unlockVault 新前綴（jr4w.）：另一 handle 解前 handle 三資料形密文；family wrap4、needsUpgrade false',
      u27.family === 'wrap4' && !u27.needsUpgrade()
      && (await u27.decrypt('rec-s', bS27)) === str27 && JSON.stringify(await u27.decrypt('rec-j', bJ27)) === JSON.stringify(obj27)
      && bytesEq27(await u27.decrypt('rec-b', bB27), bytes27));

    // ④ unlockVault 舊前綴（jr3w. Argon／jr1w. PBKDF2）——同一 noteKey 兩包
    const OLD27 = 'old pass 27';
    const nkOld27 = await generateNoteKey();
    const r3_27 = await wrapNoteKey3(CFG27.argon, nkOld27, OLD27);
    const r1_27 = await wrapNoteKey(TACET, nkOld27, OLD27);
    const u3_27 = await unlockVault(OLD27, r3_27, CFG27);
    const u1_27 = await unlockVault(OLD27, r1_27, CFG27);
    const bOld27 = await u3_27.encrypt('rec-old', 'old-era');
    await A('[27] unlockVault 舊前綴各一：jr3w.（family wrap3）／jr1w.（family wrap，PBKDF2 舊世代讀面＝carrier null 不需 Argon）皆 needsUpgrade true；兩 handle 同鑰互解＋低階 noteKey 手解同 AAD 域',
      u3_27.family === 'wrap3' && u1_27.family === 'wrap' && u3_27.needsUpgrade() && u1_27.needsUpgrade() && u1_27.carrier === null && u3_27.carrier === 'node'
      && (await u1_27.decrypt('rec-old', bOld27)) === 'old-era'
      && new TextDecoder().decode((await openRaw27(nkOld27, bOld27, 'tacet-vault27:rec-old'))?.subarray(1)) === 'old-era');

    // ⑤ upgrade：錯密語拒（狀態不動）→ 正確密語重包 jr4w.；舊包裹仍可解（舊前綴語意不動）；雙因子 jr3d. → jr4d.
    const upWrong27 = await codeOf27(u3_27.upgrade('not the pass'));
    const stillOld27 = u3_27.family === 'wrap3' && u3_27.serverRecord?.wrapped === r3_27.wrapped;
    const up27 = await u3_27.upgrade(OLD27);
    const uUp27 = await unlockVault(OLD27, up27, CFG27);
    const uOld27b = await unlockVault(OLD27, r3_27, CFG27);
    const upIdem27 = await u3_27.upgrade('ignored when current');
    const r3d27 = await wrapNoteKeyDual3(CFG27.argon, nkOld27, OLD27, '2468');
    const uD27 = await unlockVault(OLD27, r3d27, { ...CFG27, pin: '2468' });
    const dualBefore27 = fam27(uD27) === 'wrapDual3' && uD27.needsUpgrade(); // 升級前快照（斷言式在全部動作後求值）
    const upDualNoPin27 = await codeOf27(uD27.upgrade(OLD27));
    const upD27 = await uD27.upgrade(OLD27, { pin: '2468' });
    await A('[27] needsUpgrade/upgrade 真值行：錯密語＝ERR_VAULT_WRAP_MISMATCH 且狀態不動；正確＝新前綴 jr4w. 包同一 noteKey（新包裹解舊密文）、needsUpgrade 翻 false、已最新再呼＝原包裹欄原樣；舊 jr3w. 包裹照解；jr3d. 缺 PIN＝ERR_VAULT_PIN_REQUIRED、帶 PIN → jr4d.（family wrapDual4）',
      upWrong27 === 'ERR_VAULT_WRAP_MISMATCH' && stillOld27
      && up27.wrapped.startsWith('jr4w.') && fam27(u3_27) === 'wrap4' && !u3_27.needsUpgrade()
      && (await uUp27.decrypt('rec-old', bOld27)) === 'old-era' && (await uOld27b.decrypt('rec-old', bOld27)) === 'old-era'
      && upIdem27.wrapped === up27.wrapped
      && dualBefore27 && upDualNoPin27 === 'ERR_VAULT_PIN_REQUIRED'
      && upD27.wrapped.startsWith('jr4d.') && fam27(uD27) === 'wrapDual4' && !uD27.needsUpgrade());

    // ⑥ changePassphrase 週期（含 PIN 進出）
    const NEW27 = 'new pass 27';
    const cp27 = await v27.changePassphrase(NEW27);
    const uNew27 = await unlockVault(NEW27, cp27, CFG27);
    const oldOnNew27 = await codeOf27(unlockVault(PASS27, cp27, CFG27));
    const oldRecStill27 = await unlockVault(PASS27, rec27, CFG27);
    const cpD27 = await v27.changePassphrase(NEW27, { pin: '1357' });
    const famD27 = v27.family;
    const noPin27 = await codeOf27(unlockVault(NEW27, cpD27, CFG27));
    const uPin27 = await unlockVault(NEW27, cpD27, { ...CFG27, pin: '1357' });
    const cpNoPin27 = await codeOf27(v27.changePassphrase(NEW27));
    const cpBack27 = await v27.changePassphrase(NEW27, { pin: null });
    await A('[27] changePassphrase 週期：同一 noteKey 重包 jr4w.（新密語解舊密文、舊密語對新包裹＝WRAP_MISMATCH、舊包裹欄不被本 API 觸及）；pin 字串→jr4d.（無 PIN 解鎖＝PIN_REQUIRED、帶 PIN 解）；雙因子省略 pin＝PIN_REQUIRED；pin:null 回 jr4w.；空密語＝BAD_PASSPHRASE、空白 PIN＝BAD_PIN',
      cp27.wrapped.startsWith('jr4w.') && cp27.wrapped !== rec27.wrapped && (await uNew27.decrypt('rec-s', bS27)) === str27
      && oldOnNew27 === 'ERR_VAULT_WRAP_MISMATCH' && (await oldRecStill27.decrypt('rec-s', bS27)) === str27
      && cpD27.wrapped.startsWith('jr4d.') && famD27 === 'wrapDual4' && noPin27 === 'ERR_VAULT_PIN_REQUIRED'
      && (await uPin27.decrypt('rec-j', bJ27) as { title?: string }).title === '標題'
      && cpNoPin27 === 'ERR_VAULT_PIN_REQUIRED' && cpBack27.wrapped.startsWith('jr4w.') && fam27(v27) === 'wrap4'
      && (await codeOf27(v27.changePassphrase(''))) === 'ERR_VAULT_BAD_PASSPHRASE'
      && (await codeOf27(v27.changePassphrase(NEW27, { pin: '   ' }))) === 'ERR_VAULT_BAD_PIN');

    // ⑦ VaultError 毒化（記錄密文面）
    const tamper27 = (() => { const p = unb64Mod(bS27.slice(5)); p[p.length - 1] ^= 0x01; return 'jr1v.' + modB64(p); })();
    const errObj27 = await (async () => { try { await v27.decrypt('rec-OTHER', bS27); return null; } catch (e) { return e; } })();
    const cyc27: Record<string, unknown> = {}; cyc27.self = cyc27;
    await A('[27] VaultError 毒化（記錄面）：錯 recordId（AAD 搬列）／末位元翻轉竄改／他 vault 金鑰＝ERR_VAULT_DECRYPT；他前綴／壞 base64／過短＝ERR_VAULT_BAD_BLOB；空 recordId＝BAD_RECORD_ID；undefined／ArrayBuffer／Uint16Array／BigInt／循環物件＝BAD_DATA；錯誤物件 instanceof VaultError＋name＋isVaultError 分流',
      errObj27 instanceof VaultError && (errObj27 as VaultError).name === 'VaultError' && isVaultError(errObj27, 'ERR_VAULT_DECRYPT') && !isVaultError(errObj27, 'ERR_VAULT_BAD_BLOB')
      && (await codeOf27(v27.decrypt('rec-s', tamper27))) === 'ERR_VAULT_DECRYPT'
      && (await codeOf27(u3_27.decrypt('rec-s', bS27))) === 'ERR_VAULT_DECRYPT'
      && (await codeOf27(v27.decrypt('rec-s', 'jr1b.' + bS27.slice(5)))) === 'ERR_VAULT_BAD_BLOB'
      && (await codeOf27(v27.decrypt('rec-s', 'jr1v.!!not-base64!!'))) === 'ERR_VAULT_BAD_BLOB'
      && (await codeOf27(v27.decrypt('rec-s', 'jr1v.' + modB64(new Uint8Array(20))))) === 'ERR_VAULT_BAD_BLOB'
      && (await codeOf27(v27.encrypt('', 'x'))) === 'ERR_VAULT_BAD_RECORD_ID'
      && (await codeOf27(v27.decrypt('', bS27))) === 'ERR_VAULT_BAD_RECORD_ID'
      && (await codeOf27(v27.encrypt('r', undefined as never))) === 'ERR_VAULT_BAD_DATA'
      && (await codeOf27(v27.encrypt('r', new ArrayBuffer(4) as never))) === 'ERR_VAULT_BAD_DATA'
      && (await codeOf27(v27.encrypt('r', new Uint16Array(2) as never))) === 'ERR_VAULT_BAD_DATA'
      && (await codeOf27(v27.encrypt('r', 10n as never))) === 'ERR_VAULT_BAD_DATA'
      && (await codeOf27(v27.encrypt('r', cyc27 as never))) === 'ERR_VAULT_BAD_DATA');

    // ⑧ 配置／serverRecord 拒（opt-in 未配置即拒、不猜）
    const noW4_27 = { ...CFG27, argon: { ...CFG27.argon, wrap4: undefined } };
    await A('[27] VaultError 拒（配置／包裹欄面）：serverRecord 缺 salt／缺 wrapped／salt 大寫／null＝BAD_RECORD；未知前綴＝WRAP_UNKNOWN；缺 argon.wrap4／缺 app／缺 cipher／前綴互為前綴／recovery 半配置／PIN 寫面未配置＝ERR_VAULT_CONFIG；空密語＝BAD_PASSPHRASE',
      (await codeOf27(unlockVault(PASS27, { wrapped: rec27.wrapped } as never, CFG27))) === 'ERR_VAULT_BAD_RECORD'
      && (await codeOf27(unlockVault(PASS27, { salt: rec27.salt } as never, CFG27))) === 'ERR_VAULT_BAD_RECORD'
      && (await codeOf27(unlockVault(PASS27, { wrapped: rec27.wrapped, salt: rec27.salt.toUpperCase() }, CFG27))) === 'ERR_VAULT_BAD_RECORD'
      && (await codeOf27(unlockVault(PASS27, null as never, CFG27))) === 'ERR_VAULT_BAD_RECORD'
      && (await codeOf27(unlockVault(PASS27, { wrapped: 'jr9w.' + rec27.wrapped.slice(5), salt: rec27.salt }, CFG27))) === 'ERR_VAULT_WRAP_UNKNOWN'
      && (await codeOf27(createVault(PASS27, noW4_27))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault(PASS27, { ...CFG27, app: '' }))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault(PASS27, { ...CFG27, cipher: '' }))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault(PASS27, { ...CFG27, cipher: 'jr4' }))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault(PASS27, { ...CFG27, recovery: { wrapRec: 'jr1r.', recKekHkdf: '' } }))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault(PASS27, { ...CFG27, argon: { wrap4: 'jr4w.' }, pin: '1234' }))) === 'ERR_VAULT_CONFIG'
      && (await codeOf27(createVault('', CFG27))) === 'ERR_VAULT_BAD_PASSPHRASE');

    // ⑨ 復原套件
    const rv27 = await recoverVault(kit27!.recToken, kit27!.wrappedRec, CFG27);
    const rvFamNull27 = rv27.family === null && rv27.serverRecord === null && rv27.carrier === null && !rv27.needsUpgrade();
    const rvUp27 = await codeOf27(rv27.upgrade(PASS27));
    const rvCp27 = await rv27.changePassphrase('recovered 27');
    const rvU27 = await unlockVault('recovered 27', rvCp27, CFG27);
    const wrongTok27 = (kit27!.recToken[0] === 'a' ? 'b' : 'a') + kit27!.recToken.slice(1);
    await A('[27] 復原套件：recoverVault(recToken, wrappedRec) 解舊密文；family／serverRecord／carrier 皆 null（HKDF 不需 Argon）、upgrade＝BAD_RECORD、changePassphrase 設新密語後 unlock 可解；錯 recToken／非 hex64／他前綴＝ERR_VAULT_RECOVERY；未配置 recovery＝ERR_VAULT_CONFIG',
      (await rv27.decrypt('rec-s', bS27)) === str27 && rvFamNull27 && rvUp27 === 'ERR_VAULT_BAD_RECORD'
      && rvCp27.wrapped.startsWith('jr4w.') && (await rvU27.decrypt('rec-b', bB27) as Uint8Array).length === bytes27.length
      && (await codeOf27(recoverVault(wrongTok27, kit27!.wrappedRec, CFG27))) === 'ERR_VAULT_RECOVERY'
      && (await codeOf27(recoverVault('xyz', kit27!.wrappedRec, CFG27))) === 'ERR_VAULT_RECOVERY'
      && (await codeOf27(recoverVault(kit27!.recToken, 'jr1w.' + kit27!.wrappedRec.slice(5), CFG27))) === 'ERR_VAULT_RECOVERY'
      && (await codeOf27(recoverVault(kit27!.recToken, kit27!.wrappedRec, { ...CFG27, recovery: undefined }))) === 'ERR_VAULT_CONFIG');

    // ⑩ 載體覆寫顯形（setArgonLoader 注入恆優先；錯值載體 KAT 拒用）
    let cnt27 = 0;
    const fac27 = hashWasmArgon2Factory();
    const countLoader27 = () => { cnt27++; return Promise.resolve(fac27); };
    setArgonLoader(countLoader27);
    const cInj27 = await createVault(PASS27, { ...CFG27, recovery: undefined });
    const injKind27 = cInj27.vault.carrier;
    const injCur27 = currentArgonCarrier();
    const uFromNode27 = await unlockVault(PASS27, rec27, CFG27); // 注入載體解 node 載體所寫
    setArgonLoader(null);
    const uFromInj27 = await unlockVault(PASS27, cInj27.serverRecord, CFG27); // node 載體解注入載體所寫
    const zeroLoader27 = () => Promise.resolve({ argon2id: (async () => new Uint8Array(32)) as never });
    setArgonLoader(zeroLoader27);
    const badKat27 = await codeOf27(createVault(PASS27, CFG27));
    setArgonLoader(null);
    await A('[27] 載體覆寫顯形：setArgonLoader 注入＝carrier／currentArgonCarrier 皆 injected 且注入載體實被呼叫；注入↔node 互解（逐位元一致）；撤注入回 node；錯值載體（恆零輸出）＝RFC 9106 KAT 拒用 ERR_VAULT_KDF_UNSUPPORTED（zero-fallback：不降級）',
      injKind27 === 'injected' && injCur27 === 'injected' && cnt27 > 0
      && (await uFromNode27.decrypt('rec-s', bS27)) === str27 && uFromInj27.family === 'wrap4' && uFromInj27.carrier === 'node'
      && currentArgonCarrier() === 'node' && badKat27 === 'ERR_VAULT_KDF_UNSUPPORTED');

    // ⑪ 真 Worker 載體（node worker_threads 轉接層跑 argonWorkerSource 原文）
    const wt27 = (globalThis as unknown as { process?: { getBuiltinModule?: (id: string) => unknown } }).process?.getBuiltinModule?.('node:worker_threads') as
      { Worker?: new (src: string, o: { eval: boolean }) => { postMessage(m: unknown, t?: unknown): void; terminate(): Promise<number>; on(ev: string, f: (x: unknown) => void): void } } | undefined;
    if (!wt27?.Worker) {
      await A('[27] 真 Worker 載體（worker_threads 缺席環境）＝顯性 FAIL 行（非 silent true）', false, 'node:worker_threads 缺席');
    } else {
      const SHIM27 = "const { parentPort } = require('node:worker_threads'); globalThis.self = { postMessage: (m, t) => parentPort.postMessage(m, t), set onmessage(f) { parentPort.on('message', (d) => f({ data: d })); } };\n";
      let made27 = 0;
      const nodeWorker27 = (): ArgonWorkerLike => {
        made27++;
        const w = new wt27.Worker!(SHIM27 + argonWorkerSource(), { eval: true });
        const like: ArgonWorkerLike = { postMessage: (m, t) => w.postMessage(m, t), terminate: () => { void w.terminate(); }, onmessage: null, onerror: null };
        w.on('message', (d) => like.onmessage?.({ data: d }));
        w.on('error', (e) => like.onerror?.(e));
        return like;
      };
      const wOpts27 = { chain: ['worker', 'inline'] as const, createWorker: nodeWorker27 };
      const cW27 = await createVault(PASS27, { ...CFG27, recovery: undefined, carrier: wOpts27 });
      const wKind27 = cW27.vault.carrier;
      const wCur27 = currentArgonCarrier();
      const uW27 = await unlockVault(PASS27, rec27, { ...CFG27, carrier: wOpts27 }); // Worker 解 node 所寫
      resetArgonCarrier();
      const afterReset27 = currentArgonCarrier();
      const uWn27 = await unlockVault(PASS27, cW27.serverRecord, CFG27); // node 解 Worker 所寫
      await A('[27] 真 Worker 載體：chain [worker,inline]＋worker_threads 轉接 argonWorkerSource 原文＝carrier worker（單一 Worker 重用）；Worker↔node 互解逐位元一致；resetArgonCarrier 撤自裝載體回 node',
        wKind27 === 'worker' && wCur27 === 'worker' && made27 === 1 && uW27.carrier === 'worker'
        && (await uW27.decrypt('rec-s', bS27)) === str27 && uWn27.family === 'wrap4' && uWn27.carrier === 'node' && afterReset27 === 'node');
    }

    // ⑫ 回退鏈＋失效歸因
    const events27: { from: string; to: string }[] = [];
    const broken27 = (): ArgonWorkerLike => { throw new Error('CSP worker-src blocked (simulated)'); };
    const fb27 = await unlockVault(PASS27, rec27, { ...CFG27, carrier: { chain: ['worker', 'inline'], createWorker: broken27, onFallback: (e) => events27.push(e) } });
    const fbKind27 = fb27.carrier;
    const fbCur27 = currentArgonCarrier();
    resetArgonCarrier();
    const noFb27 = await codeOf27(unlockVault(PASS27, rec27, { ...CFG27, carrier: { chain: ['worker'], createWorker: broken27 } }));
    resetArgonCarrier();
    // 健康 KAT（32 KiB）、64 MiB 派生即 ok:false 的 flaky Worker：無回退＝KDF_UNSUPPORTED（非 WRAP_MISMATCH）；有回退＝成功＋事件
    const flaky27 = (): ArgonWorkerLike => {
      const fac = hashWasmArgon2Factory();
      const like: ArgonWorkerLike = {
        postMessage: (m) => {
          const q = m as { id: number; memorySize: number; password: string | Uint8Array; salt: Uint8Array; iterations: number; parallelism: number; hashLength: number };
          void (async () => {
            if (q.memorySize > 1024) { like.onmessage?.({ data: { id: q.id, ok: false, error: 'OOM (simulated)' } }); return; }
            const out = await fac.argon2id({ ...q, outputType: 'binary' }) as Uint8Array;
            like.onmessage?.({ data: { id: q.id, ok: true, out } });
          })();
        },
        terminate: () => {},
        onmessage: null,
        onerror: null,
      };
      return like;
    };
    const attrib27 = await codeOf27(unlockVault(PASS27, rec27, { ...CFG27, carrier: { chain: ['worker'], createWorker: flaky27 } }));
    resetArgonCarrier();
    const events27b: unknown[] = [];
    const fl27 = await unlockVault(PASS27, rec27, { ...CFG27, carrier: { chain: ['worker', 'inline'], createWorker: flaky27, onFallback: (e) => events27b.push(e) } });
    const flKind27 = fl27.carrier === 'worker' ? currentArgonCarrier() : fl27.carrier;
    resetArgonCarrier();
    const absent27 = await codeOf27(unlockVault(PASS27, rec27, { ...CFG27, carrier: { chain: ['worker'] } })); // node 無全域 Worker＝載體缺席
    const emptyChain27 = await codeOf27(createVault(PASS27, { ...CFG27, carrier: { chain: [] } }));
    resetArgonCarrier();
    await A('[27] 回退鏈顯形：Worker 建構失敗→inline（onFallback 1 次 worker→inline、carrier 翻 inline）；chain 無 inline＝ERR_VAULT_KDF_UNSUPPORTED；派生期 Worker 失效（KAT 過、64 MiB 失敗）無回退＝KDF_UNSUPPORTED 不誤報 WRAP_MISMATCH、有回退＝成功＋事件；載體缺席（node 無全域 Worker、chain [worker]）＝KDF_UNSUPPORTED；空 chain＝CONFIG',
      fbKind27 === 'inline' && fbCur27 === 'inline' && events27.length === 1 && events27[0].from === 'worker' && events27[0].to === 'inline'
      && noFb27 === 'ERR_VAULT_KDF_UNSUPPORTED'
      && attrib27 === 'ERR_VAULT_KDF_UNSUPPORTED'
      && (await fl27.decrypt('rec-s', bS27)) === str27 && flKind27 === 'inline' && events27b.length === 1
      && absent27 === 'ERR_VAULT_KDF_UNSUPPORTED' && emptyChain27 === 'ERR_VAULT_CONFIG');
  } catch (e) {
    await A('[27] 行為面未預期拋出（應全數經 VaultError 分流或斷言承載）', false, String((e as Error)?.stack ?? e).slice(0, 400));
  } finally {
    resetArgonCarrier();
    setArgonLoader(null);
  }

  // ⑬ vendor 孿生＋零 runtime deps
  const vendSrc27 = await srcOf('../src/client/vendor/hash-wasm-argon2.ts');
  const vb27 = vendSrc27.indexOf('  // VENDOR-BEGIN\n');
  const ve27 = vendSrc27.indexOf('  // VENDOR-END\n');
  const restored27 = vb27 > 0 && ve27 > vb27
    ? vendSrc27.slice(vb27 + '  // VENDOR-BEGIN\n'.length, ve27).split('\n').map((l) => (l.startsWith('  ') ? l.slice(2) : l)).join('\n')
    : '';
  const HASH_WASM_PIN27 = 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094'; // hash-wasm@4.12.0 dist/argon2.umd.min.js
  const kat27 = await hashWasmArgon2Factory().argon2id({ password: new Uint8Array(32).fill(1), salt: new Uint8Array(16), iterations: 3, parallelism: 4, memorySize: 32, hashLength: 32, outputType: 'hex' });
  const pkg27 = JSON.parse(await srcOf('../package.json')) as { dependencies?: unknown; devDependencies?: Record<string, string>; files?: string[]; exports?: Record<string, { types?: string; default?: string }> };
  await A('[27] vendor 孿生：去兩格縮排原文 sha256＝HASH_WASM_ARGON2_SHA256＝閘釘選值（hash-wasm@4.12.0）；vendor inline 載體 RFC 9106 KAT 一致且零全域寫入；零 runtime deps（無 dependencies 欄）＋hash-wasm 僅 devDependencies＋產生器 tarball 排除',
    restored27.length > 20000 && await sha(restored27) === HASH_WASM_ARGON2_SHA256 && HASH_WASM_ARGON2_SHA256 === HASH_WASM_PIN27 && HASH_WASM_VERSION === '4.12.0'
    && kat27 === ARGON_RFC9106_EXPECTED && (globalThis as unknown as { hashwasm?: unknown }).hashwasm === undefined
    && pkg27.dependencies === undefined && typeof pkg27.devDependencies?.['hash-wasm'] === 'string'
    && !!pkg27.files?.includes('!scripts/vendor-hash-wasm.cjs'));

  // ⑭ exports 子路徑＋分層單向＋靜態錨
  const vaultSrc27 = await srcOf('../src/client/vault.ts');
  const autoSrc27 = await srcOf('../src/client/argon-auto.ts');
  const lowSrcs27 = [await srcOf('../src/client/note-crypto.ts'), await srcOf('../src/client/argon2.ts')];
  await A('[27] exports `./client/vault` 指 dist（types .d.ts＋default .js 雙形）；分層單向（note-crypto.ts／argon2.ts 零 import vault／argon-auto／argon-worker）；AAD 構形錨 `app + \':\' + recordId` 恰 1；argon-auto 零 PBKDF2 碼面（無 \'PBKDF2\' 字面、無 note-crypto import——zero-fallback 錨）',
    pkg27.exports?.['./client/vault']?.types === './dist/client/vault.d.ts' && pkg27.exports?.['./client/vault']?.default === './dist/client/vault.js'
    && lowSrcs27.every((s) => !/from '\.\/(vault|argon-auto|argon-worker)/.test(s))
    && vaultSrc27.includes('new TextEncoder().encode(app + \':\' + recordId)')
    && vaultSrc27.split('TextEncoder().encode(app + \':\' + recordId)').length - 1 === 1
    && !/['"]PBKDF2['"]|from '\.\/note-crypto/.test(autoSrc27));
}
}

secOpen(24, '[24] runner 契約自證（--only 解析契約 fail-closed＋段級帳面顯形）'); if (secEnter(24)) {
  await A('[24] --only 解析契約（全跑態）：spec 缺席＝onlySet 空集＝secEnter 恆真（CI 形契約不變——npm run verify 全帳；--only 態本面恆真跳過＝帳面由次面承載）',
    !onlyMode() ? (onlySpecRaw === null && parseOnly('').err === 'ERR_ONLY_SPEC_EMPTY' && secEnter(1) && secEnter(23)) : true);
  await A('[24] --only 解析契約（CSV／範圍／混形三形同集合）：16,17,18 ≡ 16-18（同集合）；16,17-19 展開 16..19；單調遞增去重 18,16-17,16 → [16,17,18]',
    JSON.stringify(parseOnly('16,17,18').set) === JSON.stringify([16, 17, 18])
    && JSON.stringify(parseOnly('16-18').set) === JSON.stringify([16, 17, 18])
    && JSON.stringify(parseOnly('16,17-19').set) === JSON.stringify([16, 17, 18, 19])
    && JSON.stringify(parseOnly('18,16-17,16').set) === JSON.stringify([16, 17, 18]));
  await A('[24] --only 解析契約（fail-closed 分流）：空值／非數字 token／慣例 skip 段 22／未定段（0／99）／倒序範圍＝ERR_ONLY_*（exit 1 由頂層守衛承載——parse 面證 err 分流真值）',
    parseOnly('').err === 'ERR_ONLY_SPEC_EMPTY' && parseOnly('abc').err === 'ERR_ONLY_SPEC_TOKEN'
    && parseOnly('0').err === 'ERR_ONLY_SPEC_UNKNOWN_SEC' && parseOnly('22').err === 'ERR_ONLY_SPEC_UNKNOWN_SEC'
    && parseOnly('99').err === 'ERR_ONLY_SPEC_UNKNOWN_SEC' && parseOnly('2-1').err === 'ERR_ONLY_SPEC_RANGE'
    && parseOnly('16,,17').err === 'ERR_ONLY_SPEC_EMPTY_TOKEN');
  await A('[24] 段級帳面顯形契約：全跑態 onlySpecDisp 空＋onlyTag 光禿；--only 態 spec CSV 遞增＋(--ONLY …) 尾碼形＋secRan 本段已入帳',
    onlyMode() ? ((secRan.get(24) ?? 0) >= 3 && onlySpecDisp() === (onlyParsed?.set ?? []).join(',') && onlyTag().startsWith('(--ONLY ')) : (onlySpecDisp() === '' && onlyTag() === ''));
  await A('[24] skip 慣例面：secEnter(22)＝false（22 慣例 skip 段——secOpen 行缺席＋bannerless 斷言群帳入 [13] 的慣例面；secEnter 全跑態 n≥1 且 n≠22 即真＝段落帳冊退役）',
    secEnter(22) === false);
}

secOpen(25, '[25] 段級運行樣本：secEnter 真值表＋tag 形帳＋secCases 段帳'); if (secEnter(25)) {
  await A('[25] secEnter 真值表：bannerless 段全跑態行為（99 非段位＝不在 secOrder 段帳＝secRan 零位面——帳面逐段只列 secOrder；n=0 恆 false；原哨兵 27 隨 A3 [27] 實段落地改 99）；全跑態實段 1/15/23 全真',
    !onlyMode() ? (secEnter(0) === false && (secRan.get(99) ?? 0) === 0 && secEnter(1) && secEnter(15) && secEnter(23)) : true);
  await A('[25] tag/spec 形帳：--only 態 (--ONLY …) 括形＋spec 遞增 CSV 非空；全跑態 spec 空＋tag 裸',
    onlyMode() ? (onlyTag().startsWith('(--ONLY ') && onlyTag().endsWith(')') && onlySpecDisp().length > 0)
      : (onlySpecDisp() === '' && onlyTag() === ''));
  await A('[25] secCases 段帳登記義務（負向斷言——teeth）：secRan 實跑段（本機樹 [23]⑤ fail-open 表缺席異常面照行）必已登記；secCases 缺鍵且非 22 段＝RED（secCases 全摘禁令的行為面承載）',
    (() => { for (const [k25] of secRan) if (!secCases[k25] && k25 !== 22) return false; return true; })());
  await A('[25] self-account：secCases[25] = 4 恰此四案（段帳面 self-proving——帳漂移即本面 RED；secCases 載體面：[24]/[25] 自證段＋--only 段存在面＋teeth 三載體）',
    secCases[25] === 4 && (secRan.get(25) ?? 0) === 3);
}

// ── 段級帳面（誠實帳——skip 段恆列帳「未跑非通過」；全跑態逐段案數對 secCases 帳面）──
const secOrder = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27];
const secTotal = secOrder.reduce((a, n) => a + (secCases[n] ?? 0), 0);
const ranSecs = secOrder.filter((n) => (secRan.get(n) ?? 0) > 0);
const selTotal = secOrder.filter((n) => !onlyMode() || onlySet.has(n) || n === 24 || n === 25).reduce((a, n) => a + (secCases[n] ?? 0), 0);
const skipSecs = secOrder.filter((n) => !ranSecs.includes(n));
console.log('\n──── 段級帳面 ────');
for (const nSec of secOrder) {
  const ranN = secRan.get(nSec) ?? 0;
  const rowLabel = ranSecs.includes(nSec)
    ? (failures.length === 0 ? 'ok' : '見 ✗（失敗 ' + failures.length + '——詳上）')
    : 'skip（--only 態未選段——本輪未跑非通過）';
  console.log('[' + nSec + '] 案 ' + ranN + '/' + (secCases[nSec] ?? 0) + ' · ' + rowLabel);
}

console.log(`\n${passed} 斷言全綠` + (failures.length ? `；${failures.length} 失敗` : ''));
if (onlyMode()) {
  console.log('--only 態：段 ' + onlySpecDisp() + ' 運行，本輪 ' + passed + '/' + selTotal + '（含 runner 自證段 ' + ((secCases[24] ?? 0) + (secCases[25] ?? 0)) + '；總帳 ' + secTotal + ' 案非本輪載；skip ' + skipSecs.length + ' 段——本輪未跑非通過）');
}
if (failures.length) {
  console.error('失敗項：', failures);
  process.exit(1);
}

console.log('CORE-CRYPTO-VERIFY-OK(' + passed + ' assertions)' + onlyTag());