/**
 * ladder.ts — 密語正規化 v3 世代 ladder 表（v0.2.0 批卡② t_ce216a63；server 內部表）。
 *
 * （a+）方案（主 session 收案裁定）：遷移時舊 ph2 值入 server 內部表（ph2_ladder），
 * users 表零 schema 變更、ph2 欄 UNIQUE 恆動──client 舊 bundle 的單欄 v2-first 查表
 * 在遷移後仍對既有帳戶命中（查 users.ph2 現值＝v2 形），行為不變。
 *
 * 語意面：
 * - ladder hit（現值未命中 → ladder 命中）＝不建幽靈、回舊帳＋ph2Kind='legacy' 語意
 *   （v3 帳戶：鹽與包裹已旋轉，本 login 的舊形憑證 unwrap 必失敗；client 以
 *   ladder 缺鹽面誠實告知升級）。
 * - ladder miss（兩面皆查無）＝才建幽靈（createUser，v2 先行）。
 * - 遷移線（migratePh2ToV3）成功落 v3 後 ladder 被覆蓋（直銷，一帳一列）。
 * - 表列隨帳戶刪除清理（fork delete-account 面加一句）；users 列是真值面，ladder
 *   表列可重建（v2 形重新遷移即重落）——表列毀損不傷帳戶面。
 * - 幽靈 GC（wrapped_key IS NULL 判準）不收 ladder 命中面（帳戶列仍在＝判準不變）。
 *
 * 零知識照舊：ladder 只存 ph2 hash 與 account_id，零 PII、零密語材料。
 *
 * 職責分工（fork 對位面）：表名／migration 由 fork schema 承載（0011-ph2-ladder.sql）；
 * 本層提供「以舊 ph2 查列」原語＋「遷移時入表」原語，查表接線（現值 miss → ladder →
 * 建幽靈）在 fork route（tacet loginRoute，v2-first 裁定）。
 */

import type { Env } from './env.ts';

/** ladder 表名（migration 同名；單一真相，fork migration 與本原語同字面）。 */
export const PH2_LADDER_TABLE = 'ph2_ladder';

/** ladder 行 kinds：'legacy'（SHA-256 快雜湊世代）與 'v3'（normalizePassphrase 世代，
 *  v0.2.0 卡②遷移收口）。'v2'／'v3' 的「帳戶現在用什麼形」真相在 users.ph2 班表行
 *  （ph2_ladder 只承載舊值）；此欄純粹是「這個舊值當年是什麼形」的語意記錄。 */
export type Ph2LadderKind = 'legacy' | 'v3';
export const PH2_LADDER_KIND_LEGACY = 'legacy';
export const PH2_LADDER_KIND_V3 = 'v3';

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
        `SELECT account_id, ph2_kind, created_at FROM ${PH2_LADDER_TABLE} WHERE ph2 = ?`,
      ).bind(oldPh2).first<{ account_id: string; ph2_kind: string; created_at: number }>();
      if (!row) return null;
      return { accountId: row.account_id, ph2Kind: row.ph2_kind, createdAt: row.created_at };
    },
    async insert(accountId: string, oldPh2: string, oldKind: Ph2LadderKind): Promise<void> {
      // fail-open（遷移率聚合面）：插表失敗只讓同密語下一輪 login 重遷一次
      //（v3 查表 miss 再走 ladder miss → 建 v2 幽靈的行為面）──遷移本體不因本表故障回退。
      await env.DB.prepare(
        `INSERT INTO ${PH2_LADDER_TABLE} (account_id, ph2, ph2_kind, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET ph2 = excluded.ph2, ph2_kind = excluded.ph2_kind, created_at = excluded.created_at`,
      ).bind(accountId, oldPh2, oldKind, Date.now()).run();
    },
  };
}