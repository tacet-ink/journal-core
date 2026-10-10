/**
 * env.ts — core 對 Worker Env 的最小介面。各 fork 的 Env 以此為基底擴充。
 *
 * D1Database 型別以模組 import 承載（非全域 triple-slash reference）：
 * 消費者未帶 @cloudflare/workers-types 時，吃 client 面 .d.ts 不會被 env.d.ts 的
 * 全域型別缺席炸掉（types= reference 在 types 套件缺席＝TS2688 全檔紅；import type
 * 缺席＝該欄型別 any 化＋TS2304 只在吃 env.d.ts 的檔案現形＝影響面收斂）。
 */
import type { D1Database } from '@cloudflare/workers-types';

export interface Env {
  DB: D1Database;
}