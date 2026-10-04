-- 0011-ph2-ladder.sql：密語正規化 v3 世代 ladder 表（kanban t_ce216a63 card②，2026-10-04）。
-- 前置：v0.2.0 批卡①（core t_2e4b713f）——normalizePassphrase（NFKC-only）＋jr4w./jr4d.
-- 前綴家族＋PH1 v3 鹽域（PH1_V3_SALT='tacet-ph1-v2'）＋derivePh1ArgonV3。
--
-- （a+）方案（主 session 收案批裁定）：遷移時舊 ph2 值入 server 內部 ladder 表，
-- users 表零 schema 變更、ph2 欄 UNIQUE 恆動——client 舊 bundle 的單欄 v2-first 查表
-- 在遷移後仍對既有帳戶命中（查 users.ph2 現值＝v2 形），行為不變。
-- ph2Kind='v3' 語意（帳戶已升 normalizePassphrase 世代）由 ladder 表承載：
--   login 現值未命中 → ladder 命中（同密語 v3 形）＝帳戶是 v3 世代。
--
-- 統計面聚合量測（卡面 0910 稽核母型——只 COUNT，零 PII）：
--   SELECT COALESCE(l.ph2_kind, 'v2') AS ph2_kind, COUNT(*) AS n FROM users u
--     LEFT JOIN ph2_ladder l ON l.ph2 = u.ph2 GROUP BY COALESCE(l.ph2_kind, 'v2');
-- （ph2Kind v3 收斂觀測點；部署輪主 session 執行並謄帳）
--
-- 部署門執行（主 session，一次性；schema.sql 彙總版同批同步載入新建構）：
--   npx wrangler d1 execute tacet-db --remote --file migrations/0011-ph2-ladder.sql

PRAGMA defer_foreign_keys = TRUE;

-- PK 面裁定（run 590 定形）：ph2 本身為 PRIMARY KEY（值主權威——同一舊值恰一列，
-- 最新持有者勝：A 遷移落 ladder(V→A) 後，若 V 值幽靈帳戶後建並同樣遷移，upsert
-- 以 ON CONFLICT(ph2) 覆蓋為 (V→B)，查表恆回唯一列）。account_id NOT NULL＋UNIQUE
-- index（一帳戶可有多舊值歷列：legacy→v2→v3 每段遷移各存一段舊值）；FK CASCADE
-- 隨帳戶刪除清列（fork delete-account 面零新語句）。表列可重建（v2 形重新遷移即重落）。
CREATE TABLE IF NOT EXISTS ph2_ladder (
  ph2 TEXT PRIMARY KEY NOT NULL,          -- 舊值本身（值主權威；查表鍵＝主鍵）
  account_id TEXT NOT NULL,               -- 持有者（UNIQUE index；帳戶刪除即清）
  ph2_kind TEXT NOT NULL,                 -- 舊值當年形：'legacy'｜'v2'
  upgraded_at INTEGER NOT NULL,           -- 舊形被覆蓋的時刻（時鐘面；遷移率觀測）
  FOREIGN KEY (account_id) REFERENCES users(account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ph2_ladder_ph2 ON ph2_ladder(ph2);