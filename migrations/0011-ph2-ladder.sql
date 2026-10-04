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

CREATE TABLE IF NOT EXISTS ph2_ladder (
  account_id TEXT NOT NULL,              -- ladder 對位（一帳戶單列；移段直銷）
  ph2 TEXT NOT NULL,                     -- 舊段 ph2 形（'v2'｜'legacy'，搬入即存）
  upgraded_at INTEGER NOT NULL,          -- 舊形被覆蓋的時刻（時鐘面；遷移率觀測）
  PRIMARY KEY (account_id),
  FOREIGN KEY (account_id) REFERENCES users(account_id)
);