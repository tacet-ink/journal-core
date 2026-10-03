/**
 * ratelimit.ts — per-IP fixed-window 限流（D1 計數，跨 isolate 有效；單句 UPSERT…RETURNING）。
 *
 * 設計（2026-10-04 t_b91ed07f，外部審查 MAJOR：原 4 往返條件寫入鏈 1 往返收口）：
 * - 限流語意是 fixed window：以 window_start 為窗錨，窗過期整窗重置。
 *   （原檔頭「滑動視窗」措辭錯誤——c7c8701 只修 README 未修本檔；本卡一併收口。）
 * - 單條 UPSERT…RETURNING 原子完成「計數＋窗重置＋讀回放行判準」：
 *   同 IP 併發首發不再有 INSERT/輸家競態（同語句同鍵衝突時第二發原子吃到
 *   count+1；D1 實測 RETURNING 逐發回真值——同 IP 併發首發不 undercount）。
 * - fail-open 裁定不變（2026-09-06）：限流儲存故障時放行（保護面不可反噬主功能），
 *   只擋明確超額。RETURNING 異形回應（results 空／alias 斷裂）同向 fail-open
 *   並 console.error 照實回報（r2 MINOR-3：異形不反向成 deny）。
 *
 * 放行判準：RETURNING 的 count <= max（窗口內超額後的每一發都回實際 count，
 * 由呼叫端以 count <= max 拒絕——計數不封頂，超額仍逐發累計）。
 *
 * 呼叫端須自建表（無 GC 機制：舊 IP 列不清，表隨活躍 IP 數緩慢增長——
 * 每列 ~40 bytes，量級可忽略；如需回收見下方 GC 註記）：
 *   CREATE TABLE IF NOT EXISTS {table} (ip TEXT PRIMARY KEY, window_start INTEGER, count INTEGER);
 * 可選 GC（未內建）：定期 DELETE WHERE window_start < {now} - windowMs。
 */

import type { Env } from './env.ts';

export interface RateWindow {
  table: string;
  windowMs: number;
  max: number;
}

/**
 * 表名只允許 \w 字元（字母／數字／底線）：表名直接拼進 SQL 字串，禁注入符號。
 * 違例 throw——配置錯誤在開發期炸開，不靜默。
 */
function assertSafeTable(table: string): void {
  if (!/^[\w]+$/.test(table)) throw new Error(`ERR_RATE_TABLE_NAME: ${table}`);
}

/** @internal（0.1.6 公開面走 index.ts checkRate）。UPSERT…RETURNING 單句（{table} 佔位由呼叫端替換；D1 實測 RETURNING 列經 results 回帶）。 */
export const SQL_RATE_BUMP = `INSERT INTO {table} (ip, window_start, count) VALUES (?1, ?2, 1)
  ON CONFLICT(ip) DO UPDATE SET
    count        = CASE WHEN window_start <= ?3 THEN 1 ELSE count + 1 END,
    window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start END
  RETURNING count AS n`;

/** @internal（0.1.6 公開面走 index.ts checkRate）。放行判準單一真相：窗口內超額後照實回實際 count，呼叫端以 count <= max 拒絕。 */
export function isRateAllowed(count: number, max: number): boolean {
  return count <= max;
}

async function bumpRate(env: Env, w: RateWindow, ip: string): Promise<boolean> {
  assertSafeTable(w.table);
  const now = Date.now();
  try {
    const { results } = await env.DB.prepare(
      SQL_RATE_BUMP.replaceAll('{table}', w.table)
    ).bind(ip, now, now - w.windowMs).run();
    const first = results[0] as { n?: unknown } | undefined;
    const n = first?.n;
    if (typeof n !== 'number' || !Number.isFinite(n)) {
      // 異形回應（results 空／alias 斷裂）與儲存故障同向 fail-open（2026-09-06 裁定：
      // 缺陷偏向放行，不反向成 deny）；真 D1 不產生（探針實證）——守衛照實回報。
      console.error(`[ratelimit] ${w.table} unexpected RETURNING shape:`, first);
      return true;
    }
    return isRateAllowed(n, w.max);
  } catch (e) {
    // fail-open 裁定（2026-09-06）：儲存故障時放行，只擋明確超額
    console.error(`[ratelimit] ${w.table} update failed:`, e);
    return true;
  }
}

export function checkRate(env: Env, w: RateWindow, ip: string): Promise<boolean> {
  return bumpRate(env, w, ip);
}