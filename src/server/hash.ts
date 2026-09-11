/**
 * hash.ts — 品牌無關的雜湊／token 工具。
 * 產品專屬 obfuscate/deobfuscate 不入 core（透明品牌裁定：明文 JSON + TLS）。
 */

export async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 相容別名：姊妹產品呼叫點用此名。 */
export const hashString = sha256Hex;

/** 256-bit 隨機 session token（hex）。伺服器只存 SHA-256。 */
export function generateSessionToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** 常數時間字串比較（防時序側信道；多產品共用抽出）。 */
export function timingSafeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}