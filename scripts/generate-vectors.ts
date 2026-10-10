/**
 * generate-vectors.ts — 線上格式測試向量產生器（docs/vectors/*.json；規格＝docs/format-spec.md）。
 * 執行：node --experimental-strip-types scripts/generate-vectors.ts
 *
 * 單向契約：源碼原語 → 本產生器 → JSON（commit 入 repo，凍結證據）→ 驗證閘 [26] 只檢存在／shape。
 * 驗證閘不依賴本檔；CI 不重算（隨機 iv／鹽每次不同＝重算即漂移，向量是凍結證據非可重放輸出）。
 *
 * 禁自帶第二真相：
 * - 全部向量由真原語產生（對真模組，禁鏡像——驗證閘同律）；
 * - 凍結 KAT blob 與其輸入一律從 scripts/verify-core-crypto.ts 源碼字面抽取（KAT14/KAT17/[20]），
 *   全形密語沿閘母型計算式（codePoint + 0xfee0）構造；
 * - 每筆向量寫出前以真 unwrap/decrypt 自檢回原值，任一不符即 exit 1、不寫檔。
 */

import {
  unb64, toHex, hexToBytes, importAesGcm, sha256HexExport,
  encryptNote, decryptNote, makeHeldKey, encryptAttach, decryptAttach, encryptLocal, decryptLocal,
  wrapNoteKey, unwrapNoteKey, wrapNoteKeyShare, unwrapNoteKeyShare,
  wrapNoteKeyWithRecToken, unwrapNoteKeyWithRecToken, storeLocalWrap,
  wrapNoteKeyDual, unwrapNoteKeyDual, deriveGuestKey, ph1Of, recTokenHash,
  type NoteCryptoConfig,
} from '../src/client/note-crypto.ts';
import {
  wrapNoteKey3, unwrapNoteKey3, wrapNoteKey4, unwrapNoteKey4, wrapNoteKeyShare3, unwrapNoteKeyShare3,
  wrapNoteKeyDual3, unwrapNoteKeyDual3, wrapNoteKeyDual4, unwrapNoteKeyDual4,
  verifyArgonKat, derivePh1Argon, derivePh1ArgonV3, ARGON_RFC9106_EXPECTED, ARGON_RFC9106_PARAMS,
  ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM, ARGON_TAG_LEN, PH1_V2_SALT, PH1_V3_SALT,
  type Argon3Config,
} from '../src/client/argon2.ts';
import { wrapNoteKeyPinLock, unwrapNoteKeyPinLock, PINLOCK_ITERATIONS, type PinLockConfig } from '../src/client/pinlock.ts';
import { PBKDF2_ITERATIONS, PIN_PBKDF2_ITERATIONS } from '../src/client/note-crypto.ts';
import type { KeyStore } from '../src/client/keys.ts';
import * as bip from '../src/client/bip39.ts';

type FsLike = {
  readFileSync: (p: string | URL, enc: string) => string;
  writeFileSync: (p: string | URL, data: string, enc: string) => void;
  mkdirSync: (p: string | URL, o: { recursive: boolean }) => void;
};
const proc = (globalThis as unknown as {
  process?: { getBuiltinModule?: (id: string) => unknown; exit: (code: number) => never };
}).process;
const fs = proc?.getBuiltinModule?.('node:fs') as FsLike | undefined;
if (!fs) throw new Error('ERR_FS_UNAVAILABLE');

function fail(msg: string): never {
  console.error('GENERATE-VECTORS FAIL: ' + msg);
  return proc!.exit(1);
}

// ── 凍結常數抽取（單一真相＝驗證閘源碼字面） ────────────────────────────────
const gateSrc = fs.readFileSync(new URL('./verify-core-crypto.ts', import.meta.url), 'utf8');
function pick(re: RegExp, label: string, src = gateSrc): string {
  const m = src.match(re);
  if (!m) fail('閘源碼抽取失敗：' + label);
  return m[1];
}
function block(start: string): string {
  const i = gateSrc.indexOf(start);
  if (i < 0) fail('閘源碼區塊缺席：' + start);
  return gateSrc.slice(i, gateSrc.indexOf('};', i));
}
const fullwidth = (s: string): string => Array.from(s).map((c) => String.fromCodePoint(c.codePointAt(0)! + 0xfee0)).join(''); // 閘 KAT17 母型計算式

const pass = pick(/const pass = '([^']+)'/, 'pass');
const passD = pick(/const passD = '([^']+)'/, 'passD');
const pinD = pick(/const pinD = '([^']+)'/, 'pinD');
const pass4 = pick(/const pass4 = '([^']+)'/, 'pass4');
const identityA = pick(/const identityA = '([^']+)'/, 'identityA');
const note = pick(/const note = '([^']+)'/, 'note');

const k14 = block('const KAT14 = {');
const KAT14 = {
  blob: pick(/blob: '([^']+)'/, 'KAT14.blob', k14),
  salt1: pick(/salt1: '([0-9a-f]{2})'\.repeat\(16\)/, 'KAT14.salt1', k14).repeat(16),
  pass: pick(/pass: '([^']+)'/, 'KAT14.pass', k14),
  pin: pick(/pin: '([^']+)'/, 'KAT14.pin', k14),
  raw: pick(/raw: '([0-9a-f]{2})'\.repeat\(32\)/, 'KAT14.raw', k14).repeat(32),
};
const k17 = block('const KAT17 = {');
const KAT17 = {
  raw: pick(/raw: '([0-9a-f]{2})'\.repeat\(32\)/, 'KAT17.raw', k17).repeat(32),
  pass3Raw: fullwidth(pick(/pass3Raw: Array\.from\('([^']+)'\)/, 'KAT17.pass3Raw', k17)),
  passDbRaw: fullwidth(passD),
  jr3w: pick(/jr3w: '([^']+)'/, 'KAT17.jr3w', k17),
  s3: pick(/s3: '([0-9a-f]{32})'/, 'KAT17.s3', k17),
  jr3d: pick(/jr3d: '([^']+)'/, 'KAT17.jr3d', k17),
  sd3: pick(/sd3: '([0-9a-f]{32})'/, 'KAT17.sd3', k17),
  jr4w: pick(/jr4w: '([^']+)'/, 'KAT17.jr4w', k17),
  s4: pick(/s4: '([0-9a-f]{32})'/, 'KAT17.s4', k17),
  jr4d: pick(/jr4d: '([^']+)'/, 'KAT17.jr4d', k17),
  sd4: pick(/sd4: '([0-9a-f]{32})'/, 'KAT17.sd4', k17),
};
const s20 = gateSrc.slice(gateSrc.indexOf("secOpen(20,"));
const KAT20 = {
  recSalt: pick(/const recSalt20 = '([0-9a-f]{32})'/, 'recSalt20', s20),
  raw: pick(/const rawKat20 = '([0-9a-f]{64})'/, 'rawKat20', s20),
  blobR: pick(/const KAT_BLOB_R20 = '([^']+)'/, 'KAT_BLOB_R20', s20),
  blobLegacy: pick(/unwrapNoteKeyWithRecToken\(TACET, '(jr1w\.[^']+)'/, 'KAT20 legacy blob', s20),
  recToken: pick(/KAT_BLOB_R20, '([0-9a-f]{64})'/, 'KAT20 recToken', s20),
  identity: pick(/KAT_BLOB_R20, '[0-9a-f]{64}', '([^']+)'/, 'KAT20 identity', s20),
};

// ── 部署形 config（Tacet 實例前綴；與閘 TACET/TACET2/3/4/5 同值——自檢 unwrap 承載對帳） ──
const mapStore = new Map<string, string>();
const store: KeyStore = {
  get: (k) => mapStore.get(k) ?? null,
  set: (k, v) => { mapStore.set(k, v); },
  remove: (k) => { mapStore.delete(k); },
  noteKeyWrap: (id) => `tacet_notekey:${id}`,
};
const CFG: NoteCryptoConfig = {
  guestKdfPrefix: 'tacet-note-u1',
  recSaltPrefix: 'tacet-note-rec1:',
  cipherGuest: 'jr1u.',
  cipherBound: 'jr1b.',
  wrap: 'jr1w.',
  wrapLocal: 'jr1l.',
  wrapShare: 'jrsw.',
  wrapDual: 'jr2w.',
  pinSaltPrefix: 'tacet-note-pin1:',
  cipherAttach: 'jr1c.',
  cipherLocal: 'jr1d.',
  store,
};
const CFG_REC: NoteCryptoConfig = { ...CFG, wrapRec: 'jr1r.', recKekHkdf: 'jr1r.', recKekSalt: KAT20.recSalt };
const ARGON: Argon3Config = { wrap3: 'jr3w.', wrapDual3: 'jr3d.', pinSalt3Prefix: 'tacet-note-pin3:', wrapShare3: 'jr3s.', wrap4: 'jr4w.', wrapDual4: 'jr4d.' };
const PINLOCK: PinLockConfig = { pinLock: 'jr1p.', pinLockSaltPrefix: 'tacet-pinlock-v1:', pinLockAad: 'notekey-pinlock' };

const NOTE_KEY_HEX = KAT17.raw; // c3×32（閘 KAT 母型）
const noteKey = await importAesGcm(hexToBytes(NOTE_KEY_HEX), true);
const rawOf = async (k: CryptoKey | null): Promise<string | null> =>
  k ? toHex(new Uint8Array(await crypto.subtle.exportKey('raw', k))) : null;
const sharePass = 'share-link-passphrase-42';
const lockPin = '135790';
const aad = 'noteId:n1';

// ── payload 欄位切分（規格 §1 三布局） ─────────────────────────────────────
type Field = { name: string; offset: number; len: number; hex: string };
function fieldsOf(layout: string, payload: Uint8Array): Field[] {
  const spans: [string, number][] = layout === 'salt-embedded'
    ? [['pinSalt', 16], ['iv', 12], ['ct', 64], ['tag', 16]]
    : layout === 'salt-external'
      ? [['iv', 12], ['ct', 64], ['tag', 16]]
      : [['iv', 12], ['ct', payload.length - 28], ['tag', 16]];
  const out: Field[] = [];
  let off = 0;
  for (const [name, len] of spans) {
    out.push({ name, offset: off, len, hex: toHex(payload.slice(off, off + len)) });
    off += len;
  }
  if (off !== payload.length) fail(`欄位切分總和 ${off} ≠ payload ${payload.length}（${layout}）`);
  return out;
}

const families: Record<string, unknown>[] = [];
async function family(
  prefix: string, name: string, layout: string, kdf: string, aadStr: string,
  inputs: Record<string, unknown>, wire: string, selfCheck: () => Promise<boolean>,
): Promise<void> {
  if (!wire.startsWith(prefix)) fail(`${prefix} 前綴不符：${wire.slice(0, 8)}`);
  if (!(await selfCheck())) fail(`${prefix}（${name}）自檢 unwrap/decrypt 失敗`);
  const payload = unb64(wire.slice(prefix.length));
  const expectLen = layout === 'salt-embedded' ? 108 : layout === 'salt-external' ? 92 : 28 + new TextEncoder().encode(String(inputs.plaintext)).length;
  if (payload.length !== expectLen) fail(`${prefix} payload ${payload.length}B ≠ 規格 ${expectLen}B`);
  families.push({ prefix, family: name, layout, kdf, aad: aadStr, inputs, wire, payload_len: payload.length, fields: fieldsOf(layout, payload) });
}
const keyIs = async (k: CryptoKey | null): Promise<boolean> => (await rawOf(k)) === NOTE_KEY_HEX;

// content 家族
{
  const idp = { current: () => identityA };
  const guestHeld = makeHeldKey();
  const guestCt = await encryptNote(CFG, guestHeld, note, aad, idp);
  await family('jr1u.', 'guest 時代密文', 'content', "K_u = SHA-256(UTF8(guestKdfPrefix ‖ identity))", aad,
    { plaintext: note, aad, guestKdfPrefix: CFG.guestKdfPrefix, identity: identityA, key_hex: await rawOfGuest() }, guestCt,
    async () => (await decryptNote(CFG, makeHeldKey(), guestCt, aad, idp)) === note);
  const held = makeHeldKey(); held.set(noteKey);
  const boundCt = await encryptNote(CFG, held, note, aad, idp);
  await family('jr1b.', '綁定時代密文', 'content', 'none (noteKey)', aad,
    { plaintext: note, aad, note_key_hex: NOTE_KEY_HEX }, boundCt,
    async () => (await decryptNote(CFG, held, boundCt, aad, idp)) === note);
  const attachAad = 'jr1a:note-abc:att-001';
  const attachPlain = JSON.stringify({ v: 1, kind: 'img', mime: 'image/png', w: 1, h: 1, b64: 'AA==' });
  const attachCt = await encryptAttach(CFG, noteKey, attachPlain, attachAad);
  await family('jr1c.', '附件密文', 'content', 'none (noteKey or K_u, caller-chosen)', attachAad,
    { plaintext: attachPlain, aad: attachAad, note_key_hex: NOTE_KEY_HEX }, attachCt,
    async () => (await decryptAttach(CFG, noteKey, attachCt, attachAad)) === attachPlain);
  const localAad = 'note-abc';
  const localPlain = JSON.stringify({ v: 1, body: note });
  const localCt = await encryptLocal(CFG, noteKey, localPlain, localAad);
  await family('jr1d.', '本機 IDB 密文', 'content', 'none (caller-injected key)', localAad,
    { plaintext: localPlain, aad: localAad, note_key_hex: NOTE_KEY_HEX }, localCt,
    async () => (await decryptLocal(CFG, noteKey, localCt, localAad)) === localPlain);
}
async function rawOfGuest(): Promise<string> {
  // K_u 本體＝SHA-256(prefix ‖ identity)；deriveGuestKey 輸出 nonextractable，故以同式 digest 記錄（交叉核對：下方自檢）
  const d = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(CFG.guestKdfPrefix + identityA))));
  const probe = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, await deriveGuestKey(CFG, identityA), new Uint8Array(1));
  const probe2 = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, await importAesGcm(hexToBytes(d)), new Uint8Array(1));
  if (toHex(new Uint8Array(probe)) !== toHex(new Uint8Array(probe2))) fail('K_u 記錄值與 deriveGuestKey 不一致');
  return d;
}

// 鹽外置家族（92B）
{
  const w1 = await wrapNoteKey(CFG, noteKey, pass);
  await family('jr1w.', 'passphrase 包裹', 'salt-external', `PBKDF2-HMAC-SHA256 iterations=${PBKDF2_ITERATIONS}, salt=16B external`, 'notekey',
    { passphrase: pass, salt_hex: w1.salt, note_key_hex: NOTE_KEY_HEX }, w1.wrapped,
    async () => keyIs(await unwrapNoteKey(CFG, w1.wrapped, pass, w1.salt)));
  const recLegacy = await wrapNoteKeyWithRecToken(CFG, noteKey, KAT20.recToken, identityA);
  await family('jr1w.', '復原套件包裹（未配置世代／舊契約）', 'salt-external', `PBKDF2-HMAC-SHA256 iterations=${PBKDF2_ITERATIONS}, salt=UTF8(recSaltPrefix ‖ identity)`, 'notekey',
    { rec_token: KAT20.recToken, recSaltPrefix: CFG.recSaltPrefix, identity: identityA, note_key_hex: NOTE_KEY_HEX }, recLegacy,
    async () => keyIs(await unwrapNoteKeyWithRecToken(CFG, recLegacy, KAT20.recToken, identityA)));
  const recNew = await wrapNoteKeyWithRecToken(CFG_REC, noteKey, KAT20.recToken, identityA);
  await family('jr1r.', '復原套件包裹（HKDF 世代）', 'salt-external', "HKDF-SHA256 ikm=UTF8(recToken), salt=recKekSalt, info=UTF8('journal-kek-rec-v1:' + recKekHkdf), L=32", 'notekey-rec',
    { rec_token: KAT20.recToken, recKekHkdf: CFG_REC.recKekHkdf, recKekSalt: CFG_REC.recKekSalt, hkdf_info: 'journal-kek-rec-v1:' + CFG_REC.recKekHkdf, note_key_hex: NOTE_KEY_HEX }, recNew,
    async () => keyIs(await unwrapNoteKeyWithRecToken(CFG_REC, recNew, KAT20.recToken, identityA)));
  const localIdentity = 'acct-localwrap-vector';
  await storeLocalWrap(CFG, localIdentity, noteKey);
  const localWire = mapStore.get(store.noteKeyWrap(localIdentity)) ?? fail('jr1l. storeLocalWrap 未寫入');
  await family('jr1l.', '本機包裹', 'salt-external', "K_u = SHA-256(UTF8(guestKdfPrefix ‖ identity))", 'notekey-local',
    { guestKdfPrefix: CFG.guestKdfPrefix, identity: localIdentity, storage_key: store.noteKeyWrap(localIdentity), note_key_hex: NOTE_KEY_HEX }, localWire,
    async () => {
      // 空 held＋bound 密文 → decryptNote 經 loadLocalWrap 讀 jr1l. 取回 noteKey（本機包裹真讀面）
      const writer = makeHeldKey(); writer.set(noteKey);
      const ct = await encryptNote(CFG, writer, note, aad, { current: () => localIdentity });
      const reader = makeHeldKey();
      return (await decryptNote(CFG, reader, ct, aad, { current: () => localIdentity })) === note && keyIs(reader.get());
    });
  const ws = await wrapNoteKeyShare(CFG, noteKey, sharePass);
  await family('jrsw.', '分享包裹 V1（建立面退役）', 'salt-external', `PBKDF2-HMAC-SHA256 iterations=${PBKDF2_ITERATIONS}, salt=16B external`, 'notekey-share',
    { share_passphrase: sharePass, salt_hex: ws.salt, note_key_hex: NOTE_KEY_HEX }, ws.wrapped,
    async () => keyIs(await unwrapNoteKeyShare(CFG, ws.wrapped, sharePass, ws.salt)));
  const argonDesc = (input: string): string => `Argon2id(${input}) m=${ARGON_MEMORY_KIB}KiB t=${ARGON_ITERATIONS} p=${ARGON_PARALLELISM} tag=${ARGON_TAG_LEN}B version=0x13, salt=16B external`;
  const w3 = await wrapNoteKey3(ARGON, noteKey, pass);
  await family('jr3w.', 'passphrase 包裹（Argon2id）', 'salt-external', argonDesc('raw passphrase'), 'notekey',
    { passphrase: pass, salt_hex: w3.salt, note_key_hex: NOTE_KEY_HEX }, w3.wrapped,
    async () => keyIs(await unwrapNoteKey3(ARGON, w3.wrapped, pass, w3.salt)));
  const pass4fw = fullwidth(pass4);
  const w4 = await wrapNoteKey4(ARGON, noteKey, pass4fw);
  await family('jr4w.', 'passphrase 包裹（密語正規化 v3）', 'salt-external', argonDesc('NFKC(passphrase)'), 'notekey',
    { passphrase: pass4fw, passphrase_nfkc: pass4fw.normalize('NFKC'), salt_hex: w4.salt, note_key_hex: NOTE_KEY_HEX }, w4.wrapped,
    async () => keyIs(await unwrapNoteKey4(ARGON, w4.wrapped, pass4, w4.salt)));
  const s3 = await wrapNoteKeyShare3(ARGON, noteKey, sharePass);
  await family('jr3s.', '分享包裹 V2（Argon2id）', 'salt-external', argonDesc('raw share passphrase'), 'notekey-share',
    { share_passphrase: sharePass, salt_hex: s3.salt, note_key_hex: NOTE_KEY_HEX }, s3.wrapped,
    async () => keyIs(await unwrapNoteKeyShare3(ARGON, s3.wrapped, sharePass, s3.salt)));
}

// 鹽內嵌家族（108B）
{
  const d2 = await wrapNoteKeyDual(CFG, noteKey, passD, pinD);
  await family('jr2w.', 'PIN 第二因子合鑰（PBKDF2）', 'salt-embedded',
    `HKDF-SHA256(ikm = PBKDF2(pass, salt1, ${PBKDF2_ITERATIONS}) ‖ PBKDF2(normalizePin(pin), UTF8(pinSaltPrefix ‖ hex(pinSalt)), ${PIN_PBKDF2_ITERATIONS}), salt=pinSalt, info=UTF8('journal-kek2-v1:' + wrapDual))`, 'notekey2',
    { passphrase: passD, pin: pinD, pinSaltPrefix: CFG.pinSaltPrefix, hkdf_info: 'journal-kek2-v1:' + CFG.wrapDual, salt1_hex: d2.salt, note_key_hex: NOTE_KEY_HEX }, d2.wrapped,
    async () => keyIs(await unwrapNoteKeyDual(CFG, d2.wrapped, passD, pinD, d2.salt)));
  const argon2x = (passIn: string): string => `HKDF-SHA256(ikm = Argon2id(${passIn}, salt1) ‖ Argon2id(normalizePin(pin), UTF8(pinSalt3Prefix ‖ hex(pinSalt))), m=${ARGON_MEMORY_KIB}KiB t=${ARGON_ITERATIONS} p=${ARGON_PARALLELISM}, salt=pinSalt, info=UTF8('journal-kek2-v1:' + prefix))`;
  const d3 = await wrapNoteKeyDual3(ARGON, noteKey, passD, pinD);
  await family('jr3d.', 'PIN 第二因子合鑰（Argon2id）', 'salt-embedded', argon2x('raw pass'), 'notekey2',
    { passphrase: passD, pin: pinD, pinSalt3Prefix: ARGON.pinSalt3Prefix, hkdf_info: 'journal-kek2-v1:' + ARGON.wrapDual3, salt1_hex: d3.salt, note_key_hex: NOTE_KEY_HEX }, d3.wrapped,
    async () => keyIs(await unwrapNoteKeyDual3(ARGON, d3.wrapped, passD, pinD, d3.salt)));
  const d4 = await wrapNoteKeyDual4(ARGON, noteKey, KAT17.passDbRaw, pinD);
  await family('jr4d.', 'PIN 第二因子合鑰（密語正規化 v3）', 'salt-embedded', argon2x('NFKC(pass)'), 'notekey2',
    { passphrase: KAT17.passDbRaw, passphrase_nfkc: KAT17.passDbRaw.normalize('NFKC'), pin: pinD, pinSalt3Prefix: ARGON.pinSalt3Prefix, hkdf_info: 'journal-kek2-v1:' + ARGON.wrapDual4, salt1_hex: d4.salt, note_key_hex: NOTE_KEY_HEX }, d4.wrapped,
    async () => keyIs(await unwrapNoteKeyDual4(ARGON, d4.wrapped, passD, pinD, d4.salt)));
  const lock = await wrapNoteKeyPinLock(PINLOCK, noteKey, lockPin);
  await family('jr1p.', '本機 PIN 鎖定', 'salt-embedded', `PBKDF2-HMAC-SHA256(normalizePin(pin), UTF8(pinLockSaltPrefix ‖ hex(pinSalt)), ${PINLOCK_ITERATIONS})`, PINLOCK.pinLockAad!,
    { pin: lockPin, pinLockSaltPrefix: PINLOCK.pinLockSaltPrefix, note_key_hex: NOTE_KEY_HEX }, lock,
    async () => keyIs(await unwrapNoteKeyPinLock(PINLOCK, lock, lockPin)));
}

// ── KAT ──────────────────────────────────────────────────────────────────────
if (!(await verifyArgonKat())) fail('RFC 9106 KAT 不符（載體不正確）');
const frozen: Record<string, unknown>[] = [];
async function frozenBlob(source: string, prefix: string, wire: string, inputs: Record<string, unknown>, expected: string, open: () => Promise<CryptoKey | null>): Promise<void> {
  if ((await rawOf(await open())) !== expected) fail(`凍結 blob ${prefix}（${source}）解包不符`);
  frozen.push({ source, prefix, wire, payload_len: unb64(wire.slice(prefix.length)).length, inputs, expected_note_key_hex: expected });
}
await frozenBlob('verify [14] KAT14', 'jr2w.', KAT14.blob,
  { passphrase: KAT14.pass, pin: KAT14.pin, salt1_hex: KAT14.salt1, pinSaltPrefix: CFG.pinSaltPrefix, hkdf_info: 'journal-kek2-v1:jr2w.' }, KAT14.raw,
  () => unwrapNoteKeyDual(CFG, KAT14.blob, KAT14.pass, KAT14.pin, KAT14.salt1));
await frozenBlob('verify [17] KAT17', 'jr3w.', KAT17.jr3w, { passphrase: KAT17.pass3Raw, salt_hex: KAT17.s3 }, KAT17.raw,
  () => unwrapNoteKey3(ARGON, KAT17.jr3w, KAT17.pass3Raw, KAT17.s3));
await frozenBlob('verify [17] KAT17', 'jr3d.', KAT17.jr3d,
  { passphrase: KAT17.passDbRaw, pin: pinD, salt1_hex: KAT17.sd3, pinSalt3Prefix: ARGON.pinSalt3Prefix, hkdf_info: 'journal-kek2-v1:jr3d.' }, KAT17.raw,
  () => unwrapNoteKeyDual3(ARGON, KAT17.jr3d, KAT17.passDbRaw, pinD, KAT17.sd3));
await frozenBlob('verify [17] KAT17', 'jr4w.', KAT17.jr4w, { passphrase: pass4, salt_hex: KAT17.s4 }, KAT17.raw,
  () => unwrapNoteKey4(ARGON, KAT17.jr4w, pass4, KAT17.s4));
await frozenBlob('verify [17] KAT17', 'jr4d.', KAT17.jr4d,
  { passphrase: passD, pin: pinD, salt1_hex: KAT17.sd4, pinSalt3Prefix: ARGON.pinSalt3Prefix, hkdf_info: 'journal-kek2-v1:jr4d.' }, KAT17.raw,
  () => unwrapNoteKeyDual4(ARGON, KAT17.jr4d, passD, pinD, KAT17.sd4));
await frozenBlob('verify [20]', 'jr1r.', KAT20.blobR,
  { rec_token: KAT20.recToken, identity: KAT20.identity, recKekHkdf: 'jr1r.', recKekSalt: KAT20.recSalt, hkdf_info: 'journal-kek-rec-v1:jr1r.' }, KAT20.raw,
  () => unwrapNoteKeyWithRecToken(CFG_REC, KAT20.blobR, KAT20.recToken, KAT20.identity));
await frozenBlob('verify [20]', 'jr1w.', KAT20.blobLegacy,
  { rec_token: KAT20.recToken, identity: KAT20.identity, recSaltPrefix: CFG.recSaltPrefix }, KAT20.raw,
  () => unwrapNoteKeyWithRecToken(CFG, KAT20.blobLegacy, KAT20.recToken, KAT20.identity));

const ph1Legacy = await ph1Of(pass);
const ph1v2 = await derivePh1Argon(pass);
const ph1v3 = await derivePh1ArgonV3(fullwidth(pass4));
if (ph1v3 !== await derivePh1ArgonV3(pass4)) fail('PH1 v3 NFKC 等價不成立');
const credentials = [
  { kind: 'ph1_legacy', input: pass, salt: null, expected_hex: ph1Legacy },
  { kind: 'ph1_v2', input: pass, salt: PH1_V2_SALT, expected_hex: ph1v2 },
  { kind: 'ph1_v3', input: fullwidth(pass4), input_nfkc: pass4, salt: PH1_V3_SALT, expected_hex: ph1v3 },
  { kind: 'ph2_of_ph1_v2', input: ph1v2, salt: null, expected_hex: await sha256HexExport(ph1v2) },
  { kind: 'rec_token_hash', input: KAT20.recToken, salt: null, expected_hex: await recTokenHash(KAT20.recToken) },
];

// ── BIP39 抽樣（seeded 1..32＋兩端點；@scure 參照逐詞對照） ─────────────────
const scure = await import('@scure/bip39').catch(() => fail('@scure/bip39 參照缺席（先跑 npm ci＋scripts/prepare-core-pkg.cjs）'));
const scureWl = (await import('@scure/bip39/wordlists/english.js')).wordlist;
const bipSamples: Record<string, unknown>[] = [];
const entropies: [Uint8Array, string][] = [];
for (let s = 1; s <= 32; s++) entropies.push([bip.seededSampleBytes(s), 'seeded:' + s]);
entropies.push([new Uint8Array(32), 'edge'], [new Uint8Array(32).fill(0xff), 'edge']);
for (const [ent, source] of entropies) {
  const entHex = toHex(ent);
  const words = await bip.generateBip39Words(ent);
  const ref = scure.entropyToMnemonic(ent, scureWl).split(' ');
  if (words.join(' ') !== ref.join(' ')) fail('BIP39 與 @scure 不一致：' + source);
  if ((await bip.wordsToRecToken(words)) !== entHex) fail('BIP39 words→hex 回轉不符：' + source);
  const checksum = new Uint8Array(await crypto.subtle.digest('SHA-256', ent as BufferSource))[0];
  bipSamples.push({ source, entropy_hex: entHex, checksum_hex: checksum.toString(16).padStart(2, '0'), words });
}

// ── 寫檔 ─────────────────────────────────────────────────────────────────────
const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
const head = {
  format: 'journal-core-vectors/1',
  package_version: pkg.version,
  spec: 'docs/format-spec.md',
  generator: 'scripts/generate-vectors.ts',
  note: 'Frozen evidence generated once by calling the real primitives; not recomputed in CI (random iv/salt). Verify gate [26] checks presence and shape only.',
};
const outDir = new URL('../docs/vectors/', import.meta.url);
fs.mkdirSync(outDir, { recursive: true });
const write = (name: string, body: Record<string, unknown>): void =>
  fs.writeFileSync(new URL(name, outDir), JSON.stringify({ ...head, ...body }, null, 2) + '\n', 'utf8');
write('families.json', { vectors: families });
write('kat.json', {
  rfc9106: {
    algorithm: 'Argon2id', version: '0x13', memory_kib: ARGON_RFC9106_PARAMS.memoryKib, iterations: ARGON_RFC9106_PARAMS.iterations,
    parallelism: ARGON_RFC9106_PARAMS.parallelism, tag_len: ARGON_RFC9106_PARAMS.tagLen,
    password_hex: ARGON_RFC9106_PARAMS.passwordByte.toString(16).padStart(2, '0').repeat(ARGON_RFC9106_PARAMS.passwordLen),
    salt_hex: '00'.repeat(ARGON_RFC9106_PARAMS.saltLen), secret: null, associated_data: null,
    expected_tag_hex: ARGON_RFC9106_EXPECTED,
  },
  frozen_blobs: frozen,
  credentials,
});
write('bip39.json', { samples: bipSamples });
console.log(`GENERATE-VECTORS-OK(families=${families.length} frozen=${frozen.length} credentials=${credentials.length} bip39=${bipSamples.length})`);
