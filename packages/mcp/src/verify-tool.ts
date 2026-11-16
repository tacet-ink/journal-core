/**
 * verify-tool.ts — verify 工具（＝R3b CLI verify 子命令語義；import 同一 runVerify 原語）。
 *
 * MISMATCH 是 verdict 而非 tool failure：isError 恆 false（fail-closed 語義由文本承載——
 * 客戶端/agent 讀文本判定，錯誤通道留給「工具本身跑不動」）。
 */
import { DEFAULT_BASE_URL, DEFAULT_SUMS_URL } from '@tacet-ink/journal-cli/dist/n3.js';
import { runVerify } from '@tacet-ink/journal-cli/dist/verify.js';

export interface VerifyOutcome {
  isError: boolean;
  text: string;
}

export async function handleVerifyTool(rawArgs: Record<string, unknown> | undefined): Promise<VerifyOutcome> {
  const args = rawArgs ?? {};
  const base = typeof args.base === 'string' && args.base.length > 0 ? args.base : DEFAULT_BASE_URL;
  try {
    const u = new URL(base);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('proto');
  } catch {
    return { isError: true, text: `base 形態錯：${base}（需 http/https URL）` };
  }
  const sums = typeof args.sums === 'string' && args.sums.length > 0 ? args.sums : DEFAULT_SUMS_URL;
  const r = await runVerify({ base, sums, json: false });
  return { isError: false, text: r.lines.join('\n') };
}
