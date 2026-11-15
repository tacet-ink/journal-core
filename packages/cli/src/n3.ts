/**
 * n3.ts — N3「先驗證，再交給人」（request-secret brief §四 L139-150；2026-10-26 用戶裁定）。
 *
 * 三步（交付前必跑）：
 *   1. 抓線上的 /sreq 頁（verify 子命令同驗 /secret）；
 *   2. 算 sha256（core server/hash sha256Hex——零自帶加密）；
 *   3. 比對公開 repo 的 SHA256SUMS（github.com/tacet-ink/one-time-secret）。
 * 不符（含任一抓取失敗／entries 缺席）＝停、告知、不給連結（fail-closed；N3 失敗
 * 路徑一律不出連結、不建 slot）。
 *
 * 誠實界線（README 必載）：工具只驗自己抓到的那份——伺服器對特定瀏覽器送不同內容
 * 時察覺不到；擋的是大規模替換，不是針對性攻擊。頂層頁無 SRI；信任錨＝公開 repo
 * 所在的 GitHub。
 */

import { sha256Hex } from '@tacet-ink/journal-core/server/hash';
import { fetchBytes, fetchSumsOrLocal, FetchError, HttpError } from './net.ts';

/** 公開 repo SHA256SUMS 預設真值源（main 分支 raw） */
export const DEFAULT_SUMS_URL =
  'https://raw.githubusercontent.com/tacet-ink/one-time-secret/main/SHA256SUMS';
/** live 站預設 base */
export const DEFAULT_BASE_URL = 'https://tacet.ink';

/** SHA256SUMS 行形：<64 hex>（兩個空格或 ' *'）<name>；解析＝name→lowercase hex map。 */
export function parseSums(text: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (t.length === 0 || t.startsWith('#')) continue;
    const mm = /^([0-9a-fA-F]{64})\s+\*?([^\s]+)$/.exec(t);
    if (!mm) continue; // 非正形行＝略過（下方 entries 缺席守衛會咬「該驗的沒在場」）
    m.set(mm[2], mm[1].toLowerCase());
  }
  return m;
}

export type N3Reason =
  | 'ok'
  | 'mismatch'
  | 'missing-entry'
  | 'live-fetch-fail'
  | 'sums-fetch-fail'
  | 'invalid-utf8';

export interface N3Result {
  /** 頁名（SHA256SUMS entry 名）：secret.html / sreq.html */
  page: string;
  /** live URL */
  url: string;
  liveSha: string | null;
  sumsSha: string | null;
  match: boolean;
  reason: N3Reason;
  detail: string;
}

function fetchFail(res: N3Result, reason: N3Reason, detail: string): N3Result {
  res.match = false;
  res.reason = reason;
  res.detail = detail;
  return res;
}

/**
 * 驗單頁：抓 live 頁→sha256→比對 sums entry。任何失敗面＝match:false（fail-closed）。
 * base 無尾斜杠；pagePath 形 '/sreq'（URL path）、pageName 形 'sreq.html'（sums entry）。
 */
export async function checkPage(base: string, pagePath: string, pageName: string, sumsRef: string): Promise<N3Result> {
  const base0 = base.replace(/\/+$/, '');
  const url = base0 + pagePath;
  const res: N3Result = {
    page: pageName,
    url,
    liveSha: null,
    sumsSha: null,
    match: false,
    reason: 'ok',
    detail: '',
  };
  // 1＋2. 抓 live＋sha256（UTF-8 fatal 解碼——非法編碼＝fail-closed，不比對半解值）
  let text: string;
  try {
    const bytes = await fetchBytes(url);
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) {
    const reason: N3Reason =
      e instanceof FetchError ? 'live-fetch-fail' : e instanceof HttpError ? 'live-fetch-fail' : 'invalid-utf8';
    return fetchFail(res, reason, e instanceof Error ? e.message : String(e));
  }
  res.liveSha = await sha256Hex(text);
  // 3. sums（URL 或本地路徑）
  try {
    const sumsBytes = await fetchSumsOrLocal(sumsRef);
    const sumsText = new TextDecoder('utf-8', { fatal: true }).decode(sumsBytes);
    const sums = parseSums(sumsText);
    const entry = sums.get(pageName);
    if (!entry) {
      return fetchFail(res, 'missing-entry', `SHA256SUMS 無 ${pageName} entry`);
    }
    res.sumsSha = entry;
  } catch (e) {
    return fetchFail(res, 'sums-fetch-fail', e instanceof Error ? e.message : String(e));
  }
  if (res.liveSha !== res.sumsSha) {
    return fetchFail(res, 'mismatch', `sha256 不符（live ${res.liveSha.slice(0, 12)}… vs sums ${res.sumsSha.slice(0, 12)}…）`);
  }
  res.match = true;
  res.reason = 'ok';
  res.detail = 'sha256 相符';
  return res;
}

/** request 主路徑的 N3 門：只驗 /sreq（人將去填寫的那一頁）。 */
export async function n3Gate(base: string, sumsRef: string): Promise<N3Result> {
  return checkPage(base, '/sreq', 'sreq.html', sumsRef);
}

/** verify 子命令：/secret＋/sreq 同驗。 */
export async function checkAll(base: string, sumsRef: string): Promise<N3Result[]> {
  return [
    await checkPage(base, '/secret', 'secret.html', sumsRef),
    await checkPage(base, '/sreq', 'sreq.html', sumsRef),
  ];
}
