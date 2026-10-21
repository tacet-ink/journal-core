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
 * 第二層粗桶（2026-10-20 J7，外審報告 J7 條收口）：/64 帽 10/min 擋不住「同 /48 輪換 50 個
 * /64」的分散攻擊（PoC F 實證 500/500 放行）——checkRateLadder 第二窗以 normalizeRateIpCoarse
 * 粗鍵（IPv6→/48、IPv4→/24；**第二層非取代**——/64 細窗是 2026-10-11 定案載體，本層加帽
 * 非改鍵）＋粗桶表（同構 UPSERT；呼叫端須建表＋GC 承載，同 login_rate 母型）各計。
 *
 * fail-open 收口（J7，2026-10-20）：auth 類端點「D1 故障＝全放行」＝攻擊者在 D1 故障期
 * 全站登入無帽——**非 fail-closed 429**（單點故障反噬主功能，2026-09-06 裁定初諱）亦非
 * 完全放行：bumpRate/checkRateLadder 支援 opts.fallbackInMemory——D1 出錯或 RETURNING
 * 異形時退 per-isolate 記憶體計數（module-scope Map；isolate 生命週期恆有效，跨 isolate
 * 失效＝攻擊者換 isolate 也重置的誠實面，比完全放行嚴）。auth 面 opt-in（呼叫端顯式
 * 傳 opts），其他端點（shares/notes…）零觸＝完全零行為變。
 *
 * 全站登入計數（J7 觀測面）：globalLoginBump＝固定鍵 'global' 單列 UPSERT（同構；
 * 呼叫端須建表＋GC 承載）——每呼叫 +1 全站計數、回窗內真值；本層只做計數面，
 * 告警通道（閾值觸發 webhook/log 行）由呼叫端承載（無現成通道則 log JSON 一行）。
 *
 * 呼叫端須自建表（無 GC 機制：舊 IP 列不清，表隨活躍 IP 數緩慢增長——
 * 每列 ~40 bytes，量級可忽略；GC 由呼叫端承載（tacet maintenance 母型——schema.sql 表
 * 清單真相源＋固定形 SQL_RATE_GC_<表> 常數＋runRateTablesGc batch 接線））：
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

/** @internal（0.4.1 J7）。per-isolate 記憶體退避計數器（module-scope；isolate 生命週期恆有效、
 * 跨 isolate 失效＝攻擊者換 isolate 也重置的誠實面）。key＝`${table}:${rateKey}`。
 * 只在 fallbackInMemory 且 D1 故障/異形時觸碰——健康路徑零成本、零寫入面。
 * 無上限/無掃尾收口（r1 MINOR-2）：D1 長故障期大 IPv6 段攻擊者可造大量 distinct 粗/細鍵推
 * isolate 記憶體——size 過 MEM_FALLBACK_MAX（65536）整 Map 清（＝攻擊者換 isolate 同向重置，
 * 語意一致；誠實面：清後計數從 0 重起＝D1 故障期短暫退避失效窗，故障期本就非封鎖面）。 */
const MEM_FALLBACK_MAX = 65536;
const memFallback = new Map<string, { start: number; count: number }>();

function memBump(key: string, windowMs: number, max: number, now: number): boolean {
  const e = memFallback.get(key);
  const start = e && now - e.start < windowMs ? e.start : now;
  const count = e && now - e.start < windowMs ? e.count + 1 : 1;
  memFallback.set(key, { start, count });
  if (memFallback.size > MEM_FALLBACK_MAX) memFallback.clear();
  return isRateAllowed(count, max);
}

/**
 * 單窗計數（0.1.6 公開面走 index.ts checkRate；ip 已正規化）。
 * opts.fallbackInMemory（0.4.1 J7，opt-in）：D1 出錯或 RETURNING 異形時退 per-isolate
 * 記憶體計數（比完全放行嚴；auth 面才傳——limit 表故障≠全站登入狂、亦非全站 429）。
 * 未傳 opts＝原 fail-open 完全放行（其他端點零行為變鐵律）。
 */
export async function bumpRate(env: Env, w: RateWindow, ip: string, opts?: { fallbackInMemory?: boolean }): Promise<boolean> {
  assertSafeTable(w.table);
  const now = Date.now();
  const mem = (): boolean => memBump(`${w.table}:${ip}`, w.windowMs, w.max, now);
  try {
    const { results } = await env.DB.prepare(
      SQL_RATE_BUMP.replaceAll('{table}', w.table)
    ).bind(ip, now, now - w.windowMs).run();
    const first = results[0] as { n?: unknown } | undefined;
    const n = first?.n;
    if (typeof n !== 'number' || !Number.isFinite(n)) {
      // 異形回應（results 空／alias 斷裂）：原 fail-open 放行（2026-09-06 裁定）；
      // fallbackInMemory 面同退記憶體計數（異形＝本窗判準不可信，仍擋明確超額）。
      console.error(`[ratelimit] ${w.table} unexpected RETURNING shape:`, first);
      return opts?.fallbackInMemory ? mem() : true;
    }
    return isRateAllowed(n, w.max);
  } catch (e) {
    // fail-open 裁定（2026-09-06）：儲存故障時放行，只擋明確超額；
    // fallbackInMemory 面退 per-isolate 記憶體計數（J7 auth 收口——非全站 429 亦非全放行）。
    console.error(`[ratelimit] ${w.table} update failed:`, e);
    return opts?.fallbackInMemory ? mem() : true;
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
 * - embedded-IPv4 三家族刻意聚合進其所屬前綴的 /64（deliberate nondecision）：IPv4-compatible（RFC 4291 §2.5.5.1 已棄）::192.0.2.1 → ::/64、SIIT ::ffff:0:192.0.2.1 → ::/64、NAT64 64:ff9b::192.0.2.1 → 64:ff9b::/64——僅 IPv4-mapped（§2.5.5.2）還原點分 IPv4。
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

export function checkRate(env: Env, w: RateWindow, ip: string, opts?: { fallbackInMemory?: boolean }): Promise<boolean> {
  return bumpRate(env, w, normalizeRateIp(ip), opts);
}

/**
 * 限流粗鍵正規化（J7 第二層；純函式、零 throw）：
 * - IPv6 → /48 前綴＋`/48` 標記（同 normalizeRateIp 的 RFC 5952 規範形：前導零摘除、小寫、
 *   零串壓縮；前綴取前 3 組 hextet），例 `2001:db8:1234:5678::1` → `2001:db8:1234::/48`、
 *   `::1` → `::/48`；zone id（`%…`）先剝除。
 * - IPv4-mapped → 先還原點分 IPv4（同 §2.5.5.2 裁定）再 /24：`::ffff:192.0.2.1` →
 *   `192.0.2.0/24`——mapped 位址回 IPv4 粗桶，禁併入 `::/48` 全域桶（同 /64 層裁定）。
 * - IPv4 → 前三組 octet＋`0/24`：`192.0.2.33` → `192.0.2.0/24`。
 * - `'unknown'`／空串／無法解析形／octet 越界：原樣返回（與細層同律：鍵照樣進表＝可見面）。
 * - 粗層是**第二層非取代**：細層 /64 鍵（t_b30cbc5f 定案）與本層 /48|/24 鍵各入各表、
 *   各自計數——同 /48 輪換 50 個 /64 的分散攻擊（PoC F）被本層 60/min 帽收斂。
 */
export function normalizeRateIpCoarse(ip: string): string {
  if (typeof ip !== 'string') return ip;
  if (ip.includes(':')) {
    const pct = ip.indexOf('%');
    const g = parseIpv6(pct >= 0 ? ip.slice(0, pct) : ip);
    // 非法 IPv6 形原樣返回（同細層律；本行不與細層 needle 同字面——[12] 毒化錨恰 1 契約）。
    if (g === null) return ip;
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
      const a = g[6] >> 8, b = g[6] & 255, c = g[7] >> 8;
      return `${a}.${b}.${c}.0/24`;
    }
    const net = g.slice(0, 3);
    while (net.length > 0 && net[net.length - 1] === 0) net.pop();
    return net.map((h) => h.toString(16)).join(':') + '::/48';
  }
  const q = ip.split('.');
  if (q.length === 4 && q.every((o) => IPV4_OCTET.test(o) && Number(o) <= 255)) {
    return `${q[0]}.${q[1]}.${q[2]}.0/24`;
  }
  return ip;
}

/**
 * 雙窗 ladder（J7 第二層；0.4.1）：同 IP 兩窗**各計**——細窗 w（/64 帽照舊）＋粗窗 w2
 * （粗鍵 normalizeRateIpCoarse＋粗桶表）。任一窗超額即 false（計數不封頂語意兩窗照舊，
 * 超額發兩窗皆照實累計＝審計可見）。兩窗須為**不同表**（同表＝雙 UPSERT 同鍵＝計數翻倍，
 * 呼叫端配置錯誤由 assertSafeTable 外的表面自證——本層不代判表異，契約由呼叫端常數承載）。
 * opts.fallbackInMemory：任一窗 D1 故障/異形時該窗退 per-isolate 記憶體計數（同
 * bumpRate 裁定——非全站 429 亦非全放行；auth 面 opt-in，其他端點零行為變）。
 */
export async function checkRateLadder(env: Env, w: RateWindow, w2: RateWindow, ip: string, opts?: { fallbackInMemory?: boolean }): Promise<boolean> {
  const okFine = await bumpRate(env, w, normalizeRateIp(ip), opts);
  const okCoarse = await bumpRate(env, w2, normalizeRateIpCoarse(ip), opts);
  return okFine && okCoarse;
}

/**
 * 全站登入計數（J7 觀測面；0.4.1）：固定鍵 `'global'` 單列 UPSERT（同構 fixed window）——
 * 每呼叫 +1、回**窗內實際 count**（計數不封頂、超額照實累計＝審計面）。本層只做計數面
 * 與故障 fail-open 放行（回 null＝本發計數不可信，呼叫端跳過告警判斷）；告警通道
 * （閾值觸發 webhook／log JSON 行 `{'evt':'login_rate_global','n':N}`）由呼叫端承載——
 * 本層零 I/O 副作用（console.error 除外的既有裁定）。
 */
export async function globalLoginBump(env: Env, w: RateWindow): Promise<number | null> {
  assertSafeTable(w.table);
  const now = Date.now();
  try {
    const { results } = await env.DB.prepare(
      SQL_RATE_BUMP.replaceAll('{table}', w.table)
    ).bind('global', now, now - w.windowMs).run();
    const n = (results[0] as { n?: unknown } | undefined)?.n;
    if (typeof n !== 'number' || !Number.isFinite(n)) {
      console.error(`[ratelimit] ${w.table} unexpected RETURNING shape (global):`, results[0]);
      return null;
    }
    return n;
  } catch (e) {
    // fail-open：計數面故障不得反噬登入主功能（2026-09-06 裁定同向）。
    console.error(`[ratelimit] ${w.table} global bump failed:`, e);
    return null;
  }
}