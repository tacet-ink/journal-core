/**
 * ladder.ts — 密語正規化 v3 世代 ladder 表（server 內部表）。
 *
 * （a+）方案（設計裁定）：遷移時舊 ph2 值入 server 內部表（ph2_ladder），
 * users 表零 schema 變更、ph2 欄 UNIQUE 恆動──client 舊 bundle 的單欄 v2-first 查表
 * 在遷移後仍對既有帳戶命中（查 users.ph2 現值＝v2 形），行為不變。
 *
 * 語意面：
 * - ladder hit（現值未命中 → ladder 命中）＝不建幽靈、回舊帳（fork 語意面 ph2Kind='legacy'）。
 *   v3 帳戶：鹽與包裹已旋轉成 v3 形；fork 語意「本 login 的舊形憑證 unwrap 必失敗；
 *   client 以 ladder 缺鹽面誠實告知升級」對應 v0.2.0 前的單欄舊 bundle（帶 ph1_v3 的
 *   新 client 恰命中 v3 現值、前綴自描述走 v3 腿）。
 * - ladder miss（兩面皆查無）＝才建幽靈（fork createUser，v2 先行）。
 * - 幽靈帳戶走完遷移後以同舊值 upsert（ON CONFLICT(ph2)＝值主權威覆蓋，最新持有者勝）。
 * - 表列隨帳戶刪除清理（FK ON DELETE CASCADE，fork delete-account 面零新語句）；
 *   users 列是真值面，ladder 表列可重建（v2 形重新遷移即重落）——表列毀損不傷帳戶面。
 * - 幽靈 GC（wrapped_key IS NULL 判準）不收 ladder 命中面（帳戶列仍在＝判準不變）。
 *
 * 零知識照舊：ladder 只存 ph2 hash 與 account_id，零 PII、零密語材料。
 *
 * 職責分工（fork 對位面）：表名／migration 由 fork migrations 承載（0011-ph2-ladder.sql，
 * PK=ph2 值主權威形）；本層提供「以舊 ph2 查列」與「遷移時入表」原語，查表接線
 * （現值 miss → ladder → 建幽靈）在 fork route（tacet loginRoute，v2-first 裁定）。
 */

import type { Env } from './env.ts';

/** ladder 表名（migration 同名；單一真相，fork migration 與本原語同字面）。 */
export const PH2_LADDER_TABLE = 'ph2_ladder';

/** ladder 行 kinds：'legacy'（SHA-256 快雜湊世代）與 'v2'（v2 形前身，遷移的正常前身）。
 *  「帳戶現在用什麼形」的真相在 users.ph2 班表行（ph2_ladder 只承載舊值）；kind 欄
 *  純粹是「這個舊值當年是什麼形」的語意記錄。 */
export type Ph2LadderKind = 'legacy' | 'v2';
export const PH2_LADDER_KIND_LEGACY = 'legacy';
export const PH2_LADDER_KIND_V2 = 'v2';

/** ladder 行形（fork schema 對位面）。 */
export interface Ph2LadderRow {
  accountId: string;
  ph2Kind: string;
  createdAt: number;
}

/** 以「舊 ph2」查 ladder（fork store 對位面）。null = ladder miss。 */
export function makePh2LadderStore(env: Env): {
  findByOldPh2(oldPh2: string): Promise<Ph2LadderRow | null>;
  insert(accountId: string, oldPh2: string, oldKind: Ph2LadderKind): Promise<void>;
} {
  return {
    async findByOldPh2(oldPh2: string): Promise<Ph2LadderRow | null> {
      const row = await env.DB.prepare(
        `SELECT account_id, ph2_kind, upgraded_at FROM ${PH2_LADDER_TABLE} WHERE ph2 = ?`,
      ).bind(oldPh2).first<{ account_id: string; ph2_kind: string; upgraded_at: number }>();
      if (!row) return null;
      return { accountId: row.account_id, ph2Kind: row.ph2_kind, createdAt: row.upgraded_at };
    },
    async insert(accountId: string, oldPh2: string, oldKind: Ph2LadderKind): Promise<void> {
      // upsert ON CONFLICT(ph2)（值主權威，PK 定形）：同一舊值恰一列，最新持有者勝——
      // A 遷移落 (V→A) 後 V 值幽靈帳戶後建並遷移＝覆蓋為 (V→B)。無 DELETE 語句：行留存
      // 續供幽靈守衛（行隨帳戶刪除由 FK CASCADE 清）；fork 寫入面另備 ladderDelete 給
      // delete-account 清場面。
      // fail-open（遷移率聚合面）：插表失敗只讓下一輪 login 重試同一 upsert
      //（v3 查表 miss 再走 ladder miss → 建 v2 幽靈的行為面）──遷移本體不因本表故障回退。
      await env.DB.prepare(
        `INSERT INTO ${PH2_LADDER_TABLE} (ph2, account_id, ph2_kind, upgraded_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(ph2) DO UPDATE SET account_id = excluded.account_id, ph2_kind = excluded.ph2_kind, upgraded_at = excluded.upgraded_at`,
      ).bind(oldPh2, accountId, oldKind, Date.now()).run();
    },
  };
}