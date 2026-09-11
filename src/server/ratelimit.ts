/**
 * ratelimit.ts — per-IP 滑動視窗限流（D1 計數，跨 isolate 有效；併發安全版）。
 *
 * 教訓來源（生產實證）：
 * - in-memory Map 在多 isolate/多 colo 下無效（實測 24 發分散多機房全 200）
 * - 原單句 UPDATE 計數在併發下輕微超額 → 改單條件寫入鏈：INSERT 競態輸家先試
 *   「作用中未超額」計數 UPDATE（輸家直接掉到 reset 會把贏家的作用中視窗誤判成拒絕）
 * - fail-open 裁定：限流儲存故障時放行（保護面不可反噬主功能），只擋明確超額
 *
 * 呼叫端須自建表：
 *   CREATE TABLE IF NOT EXISTS {table} (ip TEXT PRIMARY KEY, window_start INTEGER, count INTEGER);
 */

import type { Env } from './env';

export interface RateWindow {
  table: string;
  windowMs: number;
  max: number;
}

async function bumpRate(env: Env, w: RateWindow, ip: string): Promise<boolean> {
  const now = Date.now();
  try {
    // 快路徑：未超額的既有列直接 +1（單句原子，競態安全）
    const upd = await env.DB.prepare(
      `UPDATE ${w.table} SET count = count + 1
       WHERE ip = ? AND window_start > ? AND count < ?`
    ).bind(ip, now - w.windowMs, w.max).run();
    if ((upd.meta?.changes ?? 0) > 0) return true;
    // 無列或窗口過期：INSERT；主鍵競態（同 IP 併發首發）→ 輸家先試「作用中未超額」
    // 計數 UPDATE（kimi MAJOR 修復：輸家直接掉到 reset 會把贏家的作用中視窗誤判成
    // 拒絕 → 空視窗併發首發 undercount 到只剩 1 次）。再 fallback 到重置式 UPDATE。
    const ins = await env.DB.prepare(
      `INSERT INTO ${w.table} (ip, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT(ip) DO NOTHING`
    ).bind(ip, now).run();
    if ((ins.meta?.changes ?? 0) > 0) return true;
    const loser = await env.DB.prepare(
      `UPDATE ${w.table} SET count = count + 1
       WHERE ip = ? AND window_start > ? AND count < ?`
    ).bind(ip, now - w.windowMs, w.max).run();
    if ((loser.meta?.changes ?? 0) > 0) return true;
    // 列已存在且未超額：窗口過期 → 重置；窗口內但剛才 count>=max 沒吃到 → 拒絕
    const reset = await env.DB.prepare(
      `UPDATE ${w.table} SET window_start = ?, count = 1
       WHERE ip = ? AND window_start <= ?`
    ).bind(now, ip, now - w.windowMs).run();
    if ((reset.meta?.changes ?? 0) > 0) return true;
    return false;
  } catch (e) {
    // fail-open 裁定（2026-09-06）：儲存故障時放行，只擋明確超額
    console.error(`[ratelimit] ${w.table} update failed:`, e);
    return true;
  }
}

export function checkRate(env: Env, w: RateWindow, ip: string): Promise<boolean> {
  return bumpRate(env, w, ip);
}