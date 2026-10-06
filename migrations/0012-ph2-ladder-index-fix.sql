-- 0012-ph2-ladder-index-fix.sql：ph2_ladder 索引修正（外審報告 #3，t_87ef62dd）。
--
-- 前置：0011-ph2-ladder.sql（2026-10-05 已部署 prod＝禁回改本卡對位說明）。
-- 0011 缺陷（外審複證屬實）：
--   ①重複冗餘 index——idx_ph2_ladder_ph2 對 PRIMARY KEY(ph2) 逐位同構，
--     PK 本身即查表索引（findByOldPh2 WHERE ph2 = ? 走 PK），duplicate 浪費寫入面。
--   ②account_id 索引缺席——「一帳戶多舊值歷列」查詢（delete-account 清場對位、
--     帳戶面維運）全表 SCAN；FK 欄零索引是 SQLite/D1 對位常見債。
-- 修正（報告原樣）：DROP 冗餘 ph2 index＋CREATE account_id index。
--   非 UNIQUE——「一帳戶多舊值」是一帳多列設計（legacy→v2→v3 每段遷移各存一段舊值），
--   UNIQUE 索引會讓第二段遷移 INSERT 直接炸（與 ladder upsert 語意正交）。
-- 聚合量測語句（0011 母型）不動：LEFT JOIN 走 ph2 = PK 面照舊。
--
-- 契約：0011 已上線不分叉環境照舊；本 migration 純索引面、零行為變更、可重入。

DROP INDEX IF EXISTS idx_ph2_ladder_ph2;

CREATE INDEX IF NOT EXISTS idx_ph2_ladder_account ON ph2_ladder(account_id);