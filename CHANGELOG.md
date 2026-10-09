# 更新日誌（Changelog）

本專案版本的歷史摘要。格式仿 [Keep a Changelog](https://keepachangelog.com/)、
語言從專案慣例（zh）。
日期取各版 release commit 的實際日期：0.1.3 起有 tag（v0.1.3…），取 tag 指向 commit 的日期；
0.1.0–0.1.2 無 tag（publish-on-tag 慣例 v0.1.3 才確立），取該版版號 bump commit 的日期。

## [未發布]

**Security** — CI 供應鏈加固：npm ci 一律 `--ignore-scripts`（verify／publish 兩 workflow——依賴安裝不執行任何安裝腳本）；
Dependabot PR 分流 GitHub-hosted runner 執行驗證（self-hosted runner 不接機器人分支——分流不是擋，驗證照跑）；
移除 repo 內 PR 產生器腳本（含主機路徑與權杖線索——治理掃蕩補漏）。

**Changed** — 密語包裹前綴快檢上移：五個解包入口（passphrase／分享兩代＋復原套件兩腿）在金鑰派生前
先比對前綴——錯誤前綴的試探不再付出 Argon2id／PBKDF2 派生成本（輸出行為不變）。
`loginRouteCore` 內建 ladder 查表守衛（2026-10-06 外審 #8 幽靈帳）：現值（PH2）miss 時改走
`AuthStore.ladderLookup`（optional）查 `ph2_ladder`——命中回舊帳不建幽靈；ladder 也 miss（或
lookup 未配置、或 store 拋錯 fail-open）才 `createUser`。lookup 未配置＝與 0.2.3 單查行為恆等
（零新增必配面）；守衛只動查表零寫入面（insert 續在 `rekeyWithLadder` 遷移線、delete 在 fork 的
delete-account 流程）。README server login wiring 節同步。

**Added** — 資料庫索引修正 migration：ph2_ladder 摘除重複索引、補 account_id 索引（帳戶查詢走索引不走全表）。

**Migration** — 套用 `migrations/0012-fix-ph2-ladder-index.sql`：純索引面、零行為變更、可重入
（DROP INDEX IF EXISTS／CREATE INDEX IF NOT EXISTS——重複套用零傷）。

## [0.2.3] — 2026-10-06

README／SECURITY 安全聯絡信箱換 security@tacet.ink（品牌信域統一——gmail 退役；
0.2.2 tarball README 帶舊信箱兩行＝修正時序在 tag 後的注記，本節載具折疊出門）。

## [0.2.2] — 2026-10-06

README 治理字面清掃隨 0.2.2 載具出門（[0.2.0] 批卡引用、內部治理敘事——字面面，零原語）
＋[0.1.6] 節文收斂至三行（批項歸併——內容零失）＋floor 插值帳（[18] 源碼窗 floor
標籤改插值當地量——窗長一變即靜默失真面封口）＋shaOk18 對照毒化案（hex64 守衛
缺席咬痕收口）＋[未發布] 標題位 ref 定義形慣例確立（下一節位翻正照 [0.2.2] 節形）。

## [0.2.1] — 2026-10-06

wrappedRec 專用前綴 jr1r.＋recToken HKDF 世代（與 recKekHkdf 兩欄一體——部分配置拒寫，
[ERR_REC_CFG_PARTIAL]；新面先行舊面回落雙試）；包內補 migrations/ 目錄（0011 ladder 樣本——
閘在包內環境可直驅建表）。

## [0.2.0] — 2026-10-05

本機包裹專用前綴 jr1l.（wrapLocal opt-in，讀舊寫新自癒）；
密語正規化 v3 世代（normalizePassphrase NFKC-only＋jr4w./jr4d. 前綴家族＋PH1 v3 鹽域）；
ladder 表原語（ph2_ladder＋AuthStore v3 re-key 介面＋0011 遷移樣本）。

## [0.1.6] — 2026-10-04

**Breaking changes**：

- `hexToBytes` 改 fail-closed：非法 hex（奇數長度／非 hex 字元／空字串）從「靜默歸零」
  改為拋 `ERR_BAD_HEX`——原本依賴「非法輸入得零值字串」行為的呼叫端需顯式接錯
  （unwrap 家族 try/catch 承接＝回 null 契約不變）。
- guest 時代空 identity 改 fail-closed：加密面拋 `ERR_NO_IDENTITY`、解密面回 `null`——
  空字串 identity（如未登入就加密）不再靜默產出「空帳號金鑰」。
- `wrapNoteKey*` 家族空 PIN 錯誤碼改拋 `ERR_PIN_EMPTY`（原為 `ERR_DUAL_NOT_CONFIGURED`）——
  「密碼欄空」與「功能未配置」語意分流；以錯誤字串比對 `ERR_DUAL_NOT_CONFIGURED`
  判空 PIN 的呼叫端需改比對新碼。
- `PinLockConfig` 移除必填欄 `noteKeyExtractable`（介面欄位移除）——解包輸出的 noteKey
  恆為 extractable（鐵律，不再是可調選項）；帶此欄的 config 物件在 TS 下會編譯錯誤
  （多餘屬性／缺必填），移除該欄即可。

非 breaking 面：限流改 UPSERT…RETURNING 單句（四次往返寫入鏈收口）＋CORS Max-Age 面＋
PH1 固定域鹽注入（鹽一經選定 per-product 恆固定）＋engines 下限 >=24.7.0＋CI 加固
（typecheck＋actions SHA 釘選）＋PBKDF2 並行＋b64 分塊效能批＋isCipherFor 空字首組裝守衛
（空前綴配置態不再永真放行）；解包呼叫端對 fail-closed 拋面照舊以 try/catch 承接＝回 null 契約不變。

## [0.1.5] — 2026-09-20

guest 前綴空字串畸形正規化（加密面同拒、解密面整面收斂）＋README 措辭收斂。

## [0.1.4] — 2026-09-19

本機 IDB stored 密文前綴 jr1d.（cipherLocal opt-in）＋附件密文前綴 jr1c.
（cipherAttach opt-in）＋cipherGuest 轉選配＋bip39 閘固定種子（樣本可重放）。

## [0.1.3] — 2026-09-12

README 徽章（npm／MIT／node／verify）＋CI verify／publish workflows。

## [0.1.2] — 2026-09-11

npm metadata 補齊（homepage／repository／bugs——npm 頁側欄 repo 連結）。

## [0.1.1] — 2026-09-11

消費者摩擦修正——README 誠實標註 strip-types 禁用面（node_modules 內禁 strip-types）、
摘零價值 postinstall。

## [0.1.0] — 2026-09-11

初版：brand-parameterized e2e crypto＋zero-knowledge auth core——
兩時代金鑰模型、帶內版本化前綴契約、pinlock／雙因子合鑰／分享包裹原語、
Argon2id 與 RFC 9106 KAT、復原套件 24 詞轉寫層。

[0.2.3]: https://github.com/tacet-ink/journal-core/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tacet-ink/journal-core/compare/v0.2.1...v0.2.2
[未發布]: https://github.com/tacet-ink/journal-core/compare/v0.2.3...HEAD
[0.2.1]: https://github.com/tacet-ink/journal-core/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tacet-ink/journal-core/compare/v0.1.6...v0.2.0
[ERR_REC_CFG_PARTIAL]: https://github.com/tacet-ink/journal-core/blob/v0.2.1/src/client/note-crypto.ts
[0.1.6]: https://github.com/tacet-ink/journal-core/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/tacet-ink/journal-core/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/tacet-ink/journal-core/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/tacet-ink/journal-core/compare/d4b65af...v0.1.3
[0.1.2]: https://github.com/tacet-ink/journal-core/compare/803ba11...d4b65af
[0.1.1]: https://github.com/tacet-ink/journal-core/compare/235308d...803ba11
[0.1.0]: https://github.com/tacet-ink/journal-core/commit/235308d