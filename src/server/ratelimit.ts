/**
 * ratelimit.ts — per-IP fixed-window 限流（D1 計數，跨 isolate 有效；單句 UPSERT…RETURNING）。
 *
 * 設計（2026-10-04 定案：原 4 往返條件寫入鏈 1 往返收口）：
 * - 限流語意是 fixed window：以 window_start 為窗錨，窗過期整窗重置。
 *   （原檔頭「滑動視窗」措辭錯誤——c7c8701 只修 README 未修本檔；本檔一併收口。）
 * - 單條 UPSERT…RETURNING 原子完成「計數＋窗重置＋讀回放行判準」：
 *   同 IP 併發首發不再有 INSERT/輸家競態（同語句同鍵衝突時第二發原子吃到
 *   count+1；D1 實測 RETURNING 逐發回真值——同 IP 併發首發不 undercount）。
 * - fail-open 裁定不變（2026-09-06）：限流儲存故障時放行（保護面不可反噬主功能），
 *   只擋明確超額。RETURNING 異形回應（results 空／alias 斷裂）同向 fail-open
 *   並 console.error 照實回報（異形不反向成 deny）。
 *
 * 放行判準：RETURNING 的 count <= max（窗口內超額後的每一發都回實際 count，
 * 由呼叫端以 count <= max 拒絕——計數不封頂，超額仍逐發累計）。
 *
 * 限流鍵（2026-10-11 定案）：checkRate 入口經 normalizeRateIp 正規化——IPv6 聚合至 /64
 * （單一終端可自由輪換 /64 內尾段＝完整地址當鍵即每發新鍵、限流失效）；IPv4-mapped
 * 位址回點分 IPv4（＝原生 IPv4 同 /32 鍵，review r1 MAJOR-1 收口）；IPv4 與非 IPv6 形原樣。
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

const HEXTET = /^[0-9a-f]{1,4}$/i;
const IPV4_OCTET = /^(0|[1-9]\d{0,2})$/;

/** IPv6 文字形 → 8 組 hextet 數值（RFC 4291 §2.2：`::` 至多一處、嵌入 IPv4 僅居末）；非法形回 null。 */
function parseIpv6(s: string): number[] | null {
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parts = halves.map((h) => (h === '' ? [] : h.split(':')));
  const last = parts[parts.length - 1];
  const v4: number[] = [];
  if (last.length > 0 && last[last.length - 1].includes('.')) {
    const q = last.pop()!.split('.');
    if (q.length !== 4 || !q.every((o) => IPV4_OCTET.test(o) && Number(o) <= 255)) return null;
    v4.push(Number(q[0]) * 256 + Number(q[1]), Number(q[2]) * 256 + Number(q[3]));
  }
  if (!parts.every((p) => p.every((g) => HEXTET.test(g)))) return null;
  const n = parts.reduce((a, p) => a + p.length, 0) + v4.length;
  const hex = (p: string[]): number[] => p.map((g) => parseInt(g, 16));
  if (halves.length === 1) return n === 8 ? [...hex(parts[0]), ...v4] : null;
  if (n > 7) return null;
  return [...hex(parts[0]), ...new Array<number>(8 - n).fill(0), ...hex(parts[1]), ...v4];
}

/**
 * 限流鍵正規化（單一真相；純函式、零 throw）：
 * - IPv6 → /64 前綴＋`/64` 標記（RFC 5952 規範形：hextet 前導零摘除、小寫、零串壓縮），
 *   例 `2001:0DB8:0000:000A::1` → `2001:db8:0:a::/64`、`::1` → `::/64`；zone id（`%…`）先剝除。
 *   介面 ID 歸零後末 4 組恆零＝最長零串恆為尾串（前綴內零串至多 3 組），故壓縮形＝前綴摘尾零組＋`::`。
 * - IPv4-mapped（::/96 前綴＋映射尾組，RFC 4291 §2.5.5.2）→ 點分 IPv4 原鍵——mapped 位址就是 IPv4
 *   節點的表示法，回 /32 與原生同鍵（hex 尾組 twin `::ffff:c000:201` 同鍵 192.0.2.1；禁併入 ::/64 全域桶）。
 * - IPv4／`'unknown'`／空串／無法解析形：原樣返回（鍵照樣進表＝可見面，不靜默丟鍵）。
 */
export function normalizeRateIp(ip: string): string {
  if (typeof ip !== 'string' || !ip.includes(':')) return ip;
  const pct = ip.indexOf('%');
  const g = parseIpv6(pct >= 0 ? ip.slice(0, pct) : ip);
  if (!g) return ip;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) return [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.');
  const net = g.slice(0, 4);
  while (net.length > 0 && net[net.length - 1] === 0) net.pop();
  return net.map((h) => h.toString(16)).join(':') + '::/64';
}

export function checkRate(env: Env, w: RateWindow, ip: string): Promise<boolean> {
  return bumpRate(env, w, normalizeRateIp(ip));
}