/**
 * bip39.ts — 復原套件轉寫層（BIP39 英文 24 詞 ⇄ entropy 32B ⇄ recToken hex64）。
 *
 * 契約裁定（2026-09-10 復原套件三件）：
 * - **轉寫層，非 KDF 升級**：24 詞 ⇄ hex64 可逆互轉；線上契約（rec_hash = SHA-256(hex64)、
 *   wrappedRec = jr1w. + GCM(PBKDF2(recToken, ...))）完全不變，伺服器零改動。
 *   熵等價：24 詞 = 256-bit entropy + 8-bit checksum（BIP39 標準）；與舊 hex64 同熵。
 * - **checksum 是轉寫品質閘**：單詞打錯 255/256 機率當場被抓（64 hex 轉寫無此偵測）；
 *   解析失敗一律回 null（不洩漏哪類錯：字數/詞表外/checksum 統一，UI 統一訊息）。
 * - **只收 24 詞**：12 詞是降級禁用（security-roadmap 裁定）；15/18/21 不收（契約面單一）。
 * - **相容層永久**：舊帳戶 hex64 紙本照走現行鏈；recTokenToWords 供既有套件顯示用。
 * - **零依賴**：SHA-256 用 WebCrypto（全 async API）；bits 打包自製（閘 [9] 以
 *   @scure/bip39 參照實作 200 組雙向對照守證）。禁用 @scure 的 mnemonicToSeed
 *   （PBKDF2-SHA512 seed 派生與 Tacet 契約無關，不可混入）。
 */
import { wordlist } from './wordlist.ts';

const HEX64_RE = /^[0-9a-f]{64}$/;

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

function hexToBytes(hexStr: string): Uint8Array {
  const out = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 輸入正規化：NFKC → 換行/全形空白/多空白收斂單半形空格 → 小寫（wordlist 全小寫，輸入容錯）。 */
function normalizeWords(input: string): string[] {
  return input.normalize('NFKC').trim().toLowerCase().split(/\s+/).filter(w => w.length > 0);
}

/** 11-bit 打包（BIP39 標準位元累積器；carry 恆 < 19 bits，索引 = 低位遮罩 0x7ff）。 */
function entropyToIndexes(entropy: Uint8Array, checksum: number): number[] {
  const bytes = new Uint8Array(entropy.length + 1);
  bytes.set(entropy);
  bytes[entropy.length] = checksum; // 32B entropy → checksum 8 bits = SHA-256 首位元組全值
  const indexes: number[] = [];
  let carry = 0;
  let bits = 0;
  for (const byte of bytes) {
    carry = (carry << 8) | byte;
    bits += 8;
    if (bits >= 11) {
      bits -= 11;
      indexes.push((carry >>> bits) & 0x7ff);
      carry &= (1 << bits) - 1;
    }
  }
  return indexes;
}

/** 11-bit 逆打包：24 個索引 → 33 bytes（entropy 32B + checksum 1B）。 */
function indexesToBytes(indexes: number[]): Uint8Array {
  const out = new Uint8Array(33);
  let carry = 0;
  let bits = 0;
  let pos = 0;
  for (const idx of indexes) {
    carry = (carry << 11) | idx;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      out[pos++] = (carry >>> bits) & 0xff;
      carry &= (1 << bits) - 1;
    }
  }
  return out; // 餘 3 bits = checksum 低位的補零，丟棄
}

/** 產生 24 詞套件（entropy 32B 隨機 → +8-bit checksum → 24 詞）。 */
export async function generateBip39Words(): Promise<string[]> {
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  const checksum = (await sha256(entropy))[0];
  return entropyToIndexes(entropy, checksum).map(idx => wordlist[idx]);
}

/** 24 詞 → recToken hex64。任何不符（字數/詞表外/checksum）回 null，不洩漏哪類錯。 */
export async function wordsToRecToken(input: string | string[]): Promise<string | null> {
  const words = typeof input === 'string' ? normalizeWords(input) : input.map(w => w.normalize('NFKC').trim().toLowerCase());
  if (words.length !== 24) return null;
  const indexes: number[] = [];
  for (const w of words) {
    const idx = wordlist.indexOf(w);
    if (idx < 0) return null;
    indexes.push(idx);
  }
  const bytes = indexesToBytes(indexes);
  const entropy = bytes.slice(0, 32);
  const checksum = bytes[32];
  const expected = (await sha256(entropy))[0];
  if (checksum !== expected) return null;
  return bytesToHex(entropy);
}

/** recToken hex64 → 24 詞（既有套件顯示需求；非 hex64 或格式不符回 null）。 */
export async function recTokenToWords(recToken: string): Promise<string[] | null> {
  if (!HEX64_RE.test(recToken)) return null;
  const entropy = hexToBytes(recToken);
  const checksum = (await sha256(entropy))[0];
  return entropyToIndexes(entropy, checksum).map(idx => wordlist[idx]);
}

/** 抄寫抽驗位置：24 詞中抽 4 個不重複位置（0-23），排序回傳（顯示順序穩定）。 */
export function spotCheckIndexes(): number[] {
  const pool = Array.from({ length: 24 }, (_, i) => i);
  for (let i = pool.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, 4).sort((a, b) => a - b);
}