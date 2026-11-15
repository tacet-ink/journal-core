/**
 * jr5e.ts — ECDH 單向封裝原語（jr5e.，request-secret；R1 design-final 問 2 core 收編；
 * R3a t_c4ecb987，core 0.11.0）。
 *
 * 契約真源：vault tacet/design-docs/request-secret-r1-design-final.md 問 2（2026-10-24 定稿：
 * P-256＋HKDF 全參數實測＋凍結 KAT＋N1-N4 負例；node v26.8.1 final-probe.mjs 全綠）。
 * 本模組＝core 側純函式實作；向量對拍守門（docs/vectors/kat.json jr5e_kat＋閘 [33]/[26]）。
 *
 * 單向語意：B（填表端）每次填表新創 ephemeral 金鑰對、用完即棄；eph 私鑰永不上線、
 * 永不落地。A（索取端）私鑰只在領取連結 fragment（JWK d）。封裝對 A.pub、以 A.priv 解——
 * B 端無解還路（eph 私鑰丟棄＝數學上不可解還），I 線回收窗（R2）到期即死。
 *
 * 全參數（R1 問 2 裁決）：
 *   ikm = ECDH P-256 共享點 32B（x 座標；B 端 ephPriv×A.pub，A 端 aPriv×ephPub——同一 ikm）
 *   HKDF-SHA256: salt = eph_pub raw 65B（0x04 非壓縮點，blob 內明文上線）
 *                info = AAD（呼叫端傳入；slot 部署形＝'jr5e:'+slot_id）
 *   AES-256-GCM: iv 12B、16B tag 置 ct 尾；無 tag-stamp（明文形固定＝裸 UTF-8，無標記字元）
 *   blob = jr5e. + b64url( eph_pub[65] ‖ iv[12] ‖ ct ‖ tag[16] )
 *
 * WebCrypto 派生形（M-3 實測收口）：正形＝兩步（deriveKey ECDH→HKDF non-extractable
 * usages ['deriveKey'] → deriveKey HKDF→AES-GCM）；step2 AES-GCM 參數必帶 length:256
 * （Node v26.8.1 缺席拒）。單步形拒（Node v26.8.1 實測——兩步形為跨端正形，瀏覽器同款）。
 * JWK import 規矩：公鑰 usages 必 []；私鑰 usages 必含 'deriveKey'。
 *
 * AAD 參數化（brief L126）：seal/open 以 aad 字串參數傳入；本檔只導出域常量
 * JR5E_AAD_DOMAIN（slot 部署形＝'jr5e:'+slot_id）——I 線 inbox 換域直接複用，零 core 改動。
 *
 * 失敗契約：openEnvelope 對 prefix/形/b64/長度/off-curve/GCM 認證 任何一環回 null 不拋
 * （off-curve eph_pub＝importKey DataError 面）；sealEnvelope 壞輸入 fail-loud（TypeError）。
 * 值不回呼叫端明文以外任何面（R3 §2-2）。
 *
 * 編碼例外面：b64url 無 padding（與 jr5s. 同族新編碼，舊家族 b64 帶 padding 不動；
 * format-spec §4.16）。
 */

import { b64urlDecode, b64urlEncode, concatBytes3 } from './util.ts';

/** wire 前綴（ASCII 契約字面） */
export const JR5E_PREFIX = 'jr5e.';
/** AAD 域前綴（部署＝slot 綁結；函式面以 aad 參數化，域常量僅部署形） */
export const JR5E_AAD_DOMAIN = 'jr5e:';
/** 曲線（凍結——自訂曲線＝否決案，改＝換前綴） */
export const JR5E_CURVE = 'P-256';
export const JR5E_EPH_PUB_BYTES = 65;
export const JR5E_IV_BYTES = 12;
export const JR5E_GCM_TAG_BYTES = 16;
/** blob 下限＝至少 1 byte 真明文（93B 空明文＝拒） */
export const JR5E_BLOB_MIN_BYTES = JR5E_EPH_PUB_BYTES + JR5E_IV_BYTES + 1 + JR5E_GCM_TAG_BYTES;

/** EC JWK（P-256）：公鑰＝kty/crv/x/y；私鑰多 d */
export interface JwkEC {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  d?: string;
}

// encoder／decoder 逐呼叫建置（閘 [14] sideEffects 前提：模組頂層零執行點——宣告行
// 初始化式 new 即模組載入執行點；TextEncoder／TextDecoder 無狀態且輕量，逐呼叫成本可忽略）。
function enc(): TextEncoder { return new TextEncoder(); }
function dec(): TextDecoder { return new TextDecoder('utf-8', { fatal: true }); }

/**
 * JWK → raw 65B 未壓縮公鑰點（0x04‖X[32]‖Y[32]）。
 * 驗形：kty==='EC'、crv==='P-256'、x/y b64url（無 padding）解碼恰 32B——不符回 null。
 */
export function jwkPubRaw(jwk: unknown): Uint8Array | null {
  if (jwk == null || typeof jwk !== 'object') return null;
  const o = jwk as Record<string, unknown>;
  if (o.kty !== 'EC' || o.crv !== 'P-256') return null;
  if (typeof o.x !== 'string' || typeof o.y !== 'string') return null;
  let x: Uint8Array, y: Uint8Array;
  try {
    x = b64urlDecode(o.x);
    y = b64urlDecode(o.y);
  } catch { return null; }
  if (x.length !== 32 || y.length !== 32) return null;
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  return raw;
}

async function importEcdhPub(raw: Uint8Array): Promise<CryptoKey> {
  // off-curve 點＝DataError（Node v26.8.1 實測；调用端 try/catch 收 null / throw）
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'ECDH', namedCurve: JR5E_CURVE }, false, []);
}

async function importEcdhPrivJwk(jwk: unknown): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk as JwkEC, { name: 'ECDH', namedCurve: JR5E_CURVE }, false, ['deriveKey']);
}

/**
 * 兩步 HKDF 派生（M-3 正形）：ECDH(pub, priv) → HKDF(salt=ephPubRaw, info=AAD) → AES-GCM-256。
 * step1 non-extractable usages ['deriveKey']；step2 必帶 length:256。
 */
async function deriveAesKey(pubKey: CryptoKey, privKey: CryptoKey, ephPubRaw: Uint8Array, aad: string, usage: KeyUsage): Promise<CryptoKey> {
  const hkdfParams = { name: 'HKDF' as const, hash: 'SHA-256', salt: ephPubRaw as BufferSource, info: enc().encode(aad) as BufferSource };
  const hk = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: pubKey }, privKey, hkdfParams, false, ['deriveKey']);
  return crypto.subtle.deriveKey(hkdfParams, hk, { name: 'AES-GCM', length: 256 }, false, [usage]);
}

/**
 * 生 ephemeral／receiver 金鑰對（P-256）→ JWK 對（priv 含 d、pub 不含）。
 * B 端填表建 ephemeral 對；A 端領取前建 receiver 對（d 進領取連結 fragment）。
 */
export async function generateEnvelopeKeyPair(): Promise<{ privJwk: JwkEC; pubJwk: JwkEC }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: JR5E_CURVE }, true, ['deriveKey', 'deriveBits']);
  const privJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JwkEC;
  const pubJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JwkEC;
  return { privJwk, pubJwk };
}

/**
 * 封裝（B 端寫面）：明文 → 對 aPubJwk 的單向封裝 blob。
 * ephPrivJwk＝B 本次填表新創 ephemeral 私鑰 JWK（用完即棄）。
 * 壞輸入 throw TypeError（fail-loud）；iv 必顯式傳 12B（KAT 可重放）。
 */
export async function sealEnvelope(plaintext: string, aPubJwk: unknown, ephPrivJwk: unknown, iv: Uint8Array, aad: string): Promise<string> {
  if (typeof plaintext !== 'string' || plaintext.length === 0) throw new TypeError('jr5e: plaintext must be non-empty');
  if (iv == null || iv.length !== JR5E_IV_BYTES) throw new TypeError('jr5e: iv must be 12 bytes');
  if (typeof aad !== 'string' || aad.length === 0) throw new TypeError('jr5e: aad must be a non-empty string');
  const aPubRaw = jwkPubRaw(aPubJwk);
  if (!aPubRaw) throw new TypeError('jr5e: aPubJwk invalid (want EC P-256 JWK, x/y b64url 32B)');
  const ephPubRaw = jwkPubRaw(ephPrivJwk);
  if (!ephPubRaw) throw new TypeError('jr5e: ephPrivJwk invalid (want EC P-256 JWK, x/y b64url 32B)');
  const aPubKey = await importEcdhPub(aPubRaw);
  const ephPrivKey = await importEcdhPrivJwk(ephPrivJwk);
  const aesKey = await deriveAesKey(aPubKey, ephPrivKey, ephPubRaw, aad, 'encrypt');
  const ctTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: enc().encode(aad) as BufferSource },
    aesKey, enc().encode(plaintext) as BufferSource));
  return JR5E_PREFIX + b64urlEncode(concatBytes3(ephPubRaw, iv, ctTag));
}

/**
 * 解封（A 端讀面，null 母型）：blob＋receiver 私鑰 JWK＋AAD → 明文。
 * 驗序：前綴 → b64url 正形（無 padding）→ blob 長界（≥94B）→ eph_pub 0x04 首
 * → importKey（off-curve＝DataError → null）→ AAD 綁結 GCM 認證 → UTF-8 fatal 解碼。
 */
export async function openEnvelope(blob: unknown, aPrivJwk: unknown, aad: unknown): Promise<string | null> {
  if (typeof blob !== 'string' || !blob.startsWith(JR5E_PREFIX)) return null;
  if (typeof aad !== 'string' || aad.length === 0) return null;
  let raw: Uint8Array;
  try { raw = b64urlDecode(blob.slice(JR5E_PREFIX.length)); } catch { return null; }
  if (raw.length < JR5E_BLOB_MIN_BYTES) return null;
  const ephPubRaw = raw.subarray(0, JR5E_EPH_PUB_BYTES);
  if (ephPubRaw[0] !== 0x04) return null;
  const iv = raw.subarray(JR5E_EPH_PUB_BYTES, JR5E_EPH_PUB_BYTES + JR5E_IV_BYTES);
  const ctTag = raw.subarray(JR5E_EPH_PUB_BYTES + JR5E_IV_BYTES);
  let ephPubKey: CryptoKey;
  try { ephPubKey = await importEcdhPub(ephPubRaw); } catch { return null; }
  let aPrivKey: CryptoKey;
  try { aPrivKey = await importEcdhPrivJwk(aPrivJwk); } catch { return null; }
  try {
    const aesKey = await deriveAesKey(ephPubKey, aPrivKey, ephPubRaw, aad, 'decrypt');
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: enc().encode(aad) as BufferSource },
      aesKey, ctTag as BufferSource));
    if (plain.length === 0) return null;
    return dec().decode(plain);
  } catch { return null; }
}
