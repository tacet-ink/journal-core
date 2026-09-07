/**
 * env.ts — core 對 Worker Env 的最小介面。各 fork 的 Env 以此為基底擴充。
 */
export interface Env {
  DB: D1Database;
}