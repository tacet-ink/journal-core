/**
 * util.ts — secret 家族內部編碼工具（非 exports 子路徑，server/env.ts 內部模組同款形）。
 *
 * b64url 正形＝無 padding（'-'/'_' 字母表；secret 家族線上正形，/secret 與 request-secret
 * 兩家族共用）。解碼面接受標準 '+'/'/' 字母表（輸入相容），正形輸出恆為 '-'/'_'。
 * b64urlDecode 嚴格：拒 '=' padding（任意位置）、len%4==1、非字母表字元（TypeError 拋出——
 * 呼叫端 open/decrypt 面自行收 null；正形契約＝無 padding，兩家族上限導出鏈以無 padding 計）。
 */

const B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
// B64V 以 Object.freeze 形（閘 [14] sideEffects 前提：頂層零語句＋宣告行初始化式零裸呼叫；
// wordlist.ts:7 同款白名單形）——建置本體在函式宣告內，模組載入零執行點。
function buildB64V(): Record<string, number> {
  const t: Record<string, number> = {};
  for (let i = 0; i < B64A.length; i++) t[B64A[i]] = i;
  t['+'] = 62; // 標準字母表輸入相容（正形輸出仍 '-'/'_'）
  t['/'] = 63;
  return t;
}
const B64V = Object.freeze(buildB64V());

/** 無 padding b64url 編碼（正形）。 */
export function b64urlEncode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    s += B64A[(n >> 18) & 63] + B64A[(n >> 12) & 63];
    if (i + 1 < bytes.length) s += B64A[(n >> 6) & 63];
    if (i + 2 < bytes.length) s += B64A[n & 63];
  }
  return s;
}

/**
 * 嚴格 b64url 解碼（無 padding 正形；'+'/'/' 字母表相容輸入）。
 * 任何非正形（padding、len%4==1、雜字元）→ TypeError（不靜默吞）。
 */
export function b64urlDecode(text: string): Uint8Array {
  if (typeof text !== 'string' || text.length === 0) throw new TypeError('b64url: empty input');
  if (text.length % 4 === 1) throw new TypeError('b64url: impossible length (len%4==1)');
  if (text.includes('=')) throw new TypeError('b64url: padding rejected (canonical form is unpadded)');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const c0 = B64V[text[i]];
    if (c0 === undefined) throw new TypeError('b64url: bad char at ' + i);
    const t1 = text[i + 1];
    if (t1 === undefined) throw new TypeError('b64url: truncated quad');
    const c1 = B64V[t1];
    if (c1 === undefined) throw new TypeError('b64url: bad char at ' + (i + 1));
    out[o++] = (c0 << 2) | (c1 >> 4);
    const t2 = text[i + 2];
    if (t2 !== undefined) {
      const c2 = B64V[t2];
      if (c2 === undefined) throw new TypeError('b64url: bad char at ' + (i + 2));
      out[o++] = ((c1 & 15) << 4) | (c2 >> 2);
      const t3 = text[i + 3];
      if (t3 !== undefined) {
        const c3 = B64V[t3];
        if (c3 === undefined) throw new TypeError('b64url: bad char at ' + (i + 3));
        out[o++] = ((c2 & 3) << 6) | c3;
      }
    }
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hexstr: string): Uint8Array {
  if (typeof hexstr !== 'string' || hexstr.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hexstr)) {
    throw new TypeError('hex: invalid input');
  }
  const out = new Uint8Array(hexstr.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hexstr.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** 三段拼接（eph_pub ‖ iv ‖ ct‖tag 組裝；避免多次展開）。 */
export function concatBytes3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}
