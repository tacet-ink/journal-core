/**
 * verify.ts — `tacet-secret verify`（人可自跑：同時驗 /secret 與 /sreq）。
 *
 * N3 的「自驗」面：request 主路徑只驗 /sreq（人將填寫的那一頁）；verify 子命令把
 * 兩頁都驗、印出四方帳（live sha / sums sha / 判定）——exit 0＝全 MATCH，1＝任一
 * 不符或抓取失敗（fail-closed：抓不到也視為不過）。
 */

import { checkAll, DEFAULT_BASE_URL, DEFAULT_SUMS_URL, type N3Result } from './n3.ts';

export interface VerifyOpts {
  base: string;
  sums: string;
  json: boolean;
}

export interface VerifyOutcome {
  exit: number;
  lines: string[];
  jsonOut?: Record<string, unknown>;
}

const REASON_ZH: Record<string, string> = {
  ok: 'OK',
  mismatch: '不符',
  'missing-entry': 'sums 缺該頁 entry',
  'live-fetch-fail': '抓 live 頁失敗',
  'sums-fetch-fail': '抓 SHA256SUMS 失敗',
  'invalid-utf8': 'live 頁非 UTF-8',
};

export function formatVerify(r: N3Result): string[] {
  const rows: string[] = [];
  rows.push(`頁 ${r.page}（${r.url}）`);
  rows.push(`  live sha256: ${r.liveSha ?? '（未取得）'}`);
  rows.push(`  sums sha256: ${r.sumsSha ?? '（未取得）'}`);
  rows.push(`  判定: ${r.match ? 'MATCH' : 'MISMATCH'}（${REASON_ZH[r.reason] ?? r.reason}${r.detail ? `——${r.detail}` : ''}）`);
  return rows;
}

export async function runVerify(o: VerifyOpts): Promise<VerifyOutcome> {
  const results = await checkAll(o.base, o.sums);
  const lines: string[] = [];
  for (const r of results) {
    lines.push(...formatVerify(r));
  }
  const allOk = results.every((r) => r.match);
  lines.push(
    allOk
      ? '結論：兩頁皆 MATCH 公開 repo SHA256SUMS（工具驗的是它自己抓到的那份——擋大規模替換，不擋針對性攻擊；信任錨＝GitHub）。'
      : '結論：存在 MISMATCH／失敗面——按 N3 紀律停手：不給連結、不建 slot。',
  );
  return {
    exit: allOk ? 0 : 1,
    lines,
    jsonOut: {
      ok: allOk,
      base: o.base,
      sums: o.sums,
      results: results.map((r) => ({
        page: r.page,
        url: r.url,
        live_sha256: r.liveSha,
        sums_sha256: r.sumsSha,
        match: r.match,
        reason: r.reason,
      })),
    },
  };
}

export { DEFAULT_BASE_URL, DEFAULT_SUMS_URL };
