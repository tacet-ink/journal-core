# 更新日誌（Changelog）

本專案版本的歷史摘要。格式仿 [Keep a Changelog](https://keepachangelog.com/)、
語言從專案慣例（zh）。
日期取各版 release commit 的實際日期：0.1.3 起有 tag（v0.1.3…），取 tag 指向 commit 的日期；
0.1.0–0.1.2 無 tag（publish-on-tag 慣例 v0.1.3 才確立），取該版版號 bump commit 的日期。

## [0.4.1] — 2026-10-21

**Added** — 限流第二層粗桶（coarse bucket）＋全站登入計數＋fail-open 記憶體退避（`src/server/ratelimit.ts`，
0.4.1，J7 外審收口）：細層 `/64` 帽 10/min 擋不住同 `/48` 輪換 50 個 `/64` 的分散攻擊（PoC F 實證
500/500 放行）；第二層非取代細層，同鍵不同表各入各窗。

- `normalizeRateIpCoarse(ip)`：IPv6 → RFC 5952 正規形取前 3 組 hextet 成 `/48` 前綴（zone id 剝除、
  前導零摘除、零串壓縮）；IPv4-mapped（`::ffff:a.b.c.d`）回 IPv4 `/24` 前三組 octet（禁併 `::/48`
  全域桶——`/64` 層 §2.5.5.2 裁定同律）；IPv4 → `a.b.c.0/24`；無法解析/nonstring 原樣返回零 throw。
- `bumpRate(env, w, ip, opts?: { fallbackInMemory?: boolean })`：additive opts——D1 故障或
  `RETURNING` 異形（`n` 非有限數字）時，`fallbackInMemory` 在場退 per-isolate 記憶體計數
  （`Map<"${table}:${key}", {start, count}>`，健康路徑零成本）；**未傳 opts＝原 fail-open 完全
  放行**（其他端點零行為變鐵律）。誠實面：isolate 本地態，換 isolate 即重置（攻擊者換 isolate
  亦重置）＝退避非封鎖。review r1 MINOR-2 收口：記憶體計數器 size 過 `65536` 鍵整 Map 清
  （D1 長故障期大 IPv6 段攻擊者造大量 distinct 粗/細鍵推 isolate 記憶體的無界面——整清＝
  攻擊者換 isolate 同向重置、語意一致；清後計數從 0 重起＝D1 故障期短暫退避失效窗，故障期
  本就非封鎖面）。
- **單窗路徑退避披露（review r1 MINOR-1，安全向收口）**：`loginRouteCore` **單窗**路徑
  （未接 `coarseRate`）的 D1 故障面＝`≤0.4.0` 完全放行 → `0.4.1` per-isolate 記憶體帽
  （`{ fallbackInMemory: true }` 兩路徑皆傳）——雙窗（`fine+coarse` 皆傳）的計數行為不受本披露影響
  （該形＝0.4.1 新載入面）。
  ≤0.4.0 pin 呼叫端不受影響（pin 不隨 0.4.1 升級＝原行為）；跟隨升級的 `loginRouteCore`
  呼叫端＝限流表故障時從全放行收口為記憶體帽（非全站 429，與 2026-09-06 fail-open 裁定的
  auth 收口面向一致）。
- `checkRateLadder(env, fine, coarse, ip, opts?)`：雙窗原子計數（細窗 `normalizeRateIp`＋粗窗
  `normalizeRateIpCoarse` 各入各表），任一窗超額即 false（計數不封頂語意兩窗照舊，超額發兩窗
  皆照實累計＝審計可見）；單窗 D1 故障僅該窗退記憶體，健康窗真 DB 照計（非整 ladder 429 亦非
  整 ladder 放行）。兩窗須為不同表（同表＝雙 UPSERT 同鍵翻倍——契約由呼叫端常數承載）。
- `globalLoginBump(env, w) → Promise<number | null>`：固定鍵 `'global'` 單列 UPSERT，每呼叫 +1 回
  窗內實際 count（計數不封頂、超額照實累計＝審計面；呼叫端 IP 不進計數鍵）；故障 fail-open 回
  null（呼叫端跳過告警判斷，計數面故障不反噬登入主功能）。

**Added** — `AUTH_RATE_COARSE`（`src/server/auth.ts`）＋`loginRouteCore` 選配 `coarseRate` 參數
（第 5 參、additive）：`{ table: 'coarse_login_rate', windowMs: 60_000, max: 60 }`（60/min＝報告
建議值、卡面裁定）。傳入＝`checkRateLadder(env, AUTH_RATE, coarseRate, ip, { fallbackInMemory:
true })` 雙窗；**未傳＝單窗零行為變**（0.3.x pin／兄弟 fork 零影響）。auth 面 opt-in
`fallbackInMemory`——限流層唯一接線的 fail-open 退避點。

**Added** — `verify-core-crypto` 新段 [30]（coarse 純函式四案／ladder 雙窗各計／未接粗窗零變／細窗
帽 11 發 429／粗窗帽 61 發 429（同 /48 輪換 60 個不同 /64＝PoC F 收斂面）／兩窗互不干擾／
AUTH_RATE_COARSE 契約／index barrel 匯出同一函式／wiring 靜態錨恰 1×2／無 opts 原 fail-open／
D1 故障退記憶體計數／RETURNING 異形同退／單窗故障健康窗照計／globalLoginBump 固定鍵＋fail-open／
拷貝樹毒化：粗窗正規化摘除→/48 分散 50×10 發全放行（PoC F 缺陷形復現＝designated 真翻）＋
POISON_GATE_INNER 遞迴防線＋還原 byte-exact 樹出生即棄）。`[12]` wiring 錨隨 opts 透傳翻新。
帳 554→575。

## [0.4.0] — 2026-10-20

**Added** — `AuthStore.ph2Of?(ph1Hex) → Promise<string>` optional 注入點（`src/server/auth.ts`，
0.4.0 minor，J2b PH2 pepper 收口）：`loginRouteCore` 的 PH2 落庫形派生注入面——注入＝雙讀
過渡動線（先查 `ph2Of(PH1)` 新形（pepper 收口 HMAC 落庫形）→ miss 再查 `sha256(PH1)` 舊形
＋ladder 守衛；幽靈建帳恆吃新形 `createUser(ph2Of(PH1))`＝新帳戶落庫即過 pepper）；
**未注入（undefined）＝`sha256Hex(PH1)` 單查零變**（byte-identical 0.3.x——兄弟 fork 零影響
鐵律）。契約三行：純函數（同 ph1 恆同值＝PH2 UNIQUE 查詢鍵確定性來源）、舊形命中「順手
改寫新形」＝fork 責任（本層零寫入面）、**`ph2Of` 拋錯外拋＝fail-closed 不 fail-open**（pepper
讀取缺失/故障＝顯性 5xx——靜默退回無 pepper 形＝攻擊者部署面小錯差即整線降級）。additive
optional 欄＝tacet pin 0.3.5 不受影響、兄弟 fork 零改動。

**Added** — `verify-core-crypto` 新段 [29]（loginRouteCore ph2Of 注入：未注入零變（舊形 hit
單查序恰 [raw]）／注入新形 hit（一查 [new] 舊形面短路）／注入舊形 hit 雙讀過渡（[new,raw]）／
注入兩面 miss 幽靈建帳吃新形／ph2Of 拋錯 fail-closed 外拋（不回落舊形）／未注入＋現值 miss
ladder 守衛動線零變／拷貝樹毒化：ph2Of 雙讀接線摘除→新形 hit 案翻建幽靈（designated 真翻）
＋POISON_GATE_INNER 遞迴防線＋還原 byte-exact 樹出生即棄）。帳 542→550。

## [0.3.6] — 2026-10-19

**Added** — 高階 API `createShareEnvelope(cfg, argon, plaintext, aad, sharePass, idp)`（`src/client/argon2.ts`，
根 barrel＋`./client/argon2` 子路徑公開匯出）：單篇分享建立的 core 單一真相——一次性 `shareKey`
（`generateNoteKey()`，與帳戶主鑰隔離）→ 該次快照密文（`encryptNote`，held 恆 set 走 `cipherBound`）
→ `jr3s.` 分享包裹（`wrapNoteKeyShare3`）三件一組產出。無狀態純函數：`shareKey` 每次新生成、
module 層無快取殘留（「envelope 殘部快取 shareKey」否決案）。落點 argon2.ts（note-crypto→argon2
已是單向 import；放 note-crypto 會造循環）。

**Changed** — `wrapNoteKeyShare`（note-crypto）與 `wrapNoteKeyShare3`（argon2）公開 API 參數
`noteKey`→`shareKey`（型別不變＝0.3.6 minor 面，零 breaking）＋JSDoc 契約警語「⚠️ 不可傳入帳戶
主鑰（noteKey）——分享包裹的金鑰範圍＝該次分享；傳主鑰＝收分享者可解全帳戶（J1；tacet 親例）」。
**Rejected**（外審 J1 收口裁決）：簽名改成拒收主鑰＝否決（core 無法區分主鑰與 shareKey，都是
AES-256 key）；契約面警告＋更名＝正解。

**Deprecated** — `ph1Of`（note-crypto，legacy 無塩 `SHA-256(pass)`）標 `@deprecated`：登入 wire
暴露 GPU 可全速爆破的密碼指標，不可與 Argon2id PH1 同時作為上線探證（外審 J2）；新整合恆改用
`derivePh1ArgonV3`／`deriveVaultPh1`。函式本體零動（legacy 平台登入與 deleteAccount 證明面仍在用；
退場窗口＝J2a 批，帶內版本化）。

**Added** — `verify-core-crypto` 新段 [28]（分享 envelope 高階 API：三件形／roundtrip＋AAD 跨 noteId／
錯 sharePass・錯 salt→null／每次呼叫新 shareKey／主鑰 vs shareKey 隔離／無狀態純函數毒化錨（拷貝樹
wrap 端固定零鑰突變→roundtrip＋同鑰兩面真翻＋POISON_GATE_INNER 遞迴防線）／JSDoc 契約錨／
ph1Of deprecated 錨／index 匯出面）。README 家族表 `jrsw.`/`jr3s.` 兩行同步契約警語＋`ph1Of`
退場標＋`createShareEnvelope` 使用節＋帳 531→542。全閘 542 斷言（booking 帳；執行態含本機
條件面浮動）。

## [0.3.5] — 2026-10-18

**Fixed** — `decryptNote` 空字串密文正規化：trim 後空（`''`／純空白）從「無前綴＝舊明文
原樣返回」相容層原樣回傳，改為 fail-closed 回 null（與本函式任何不符面同一 null 契約，
不拋）。空/空白非合法舊明文——畸形空密文進解密面會被當舊明文落 UI（truthiness 正規化
缺失）；非空字串零影響（舊明文相容層、bound/guest 兩路徑、未配置 guest 整面拒絕契約全不動）。
`decryptAttach`／`decryptLocal` 對空恆已回 null（非缺口，本輪零改動）。

**Added** — `verify-core-crypto` 斷言：[2] 空字串／純空白密文 → null 兩案＋[16] P6 毒化案
（摘 decryptNote 空字串守衛 → 兩新斷言真翻＋還原回綠）。全閘 535 斷言。

## [0.3.4] — 2026-10-13

**Added** — vault 子路徑新獨立 export `deriveVaultPh1(passphrase, ph1Salt)`（高階 Vault API 的
PH1 登入憑證派生，hex64）：本體委派 `derivePh1ArgonV3`（PH1 v3＝
Argon2id(normalizePassphrase(pass), 鹽, m=64MiB, t=3, p=1)→hex64），派生語意單一真相
仍在 argon2.ts，本函式只是 vault 側入口收口位。鹽契約三行照 README PH1 節：
鹽一經選定恆固定（per-product，PH2 UNIQUE 約束）、`PH1_V3_SALT` 禁當 v2 派生面
`saltArg` 餵入（反之亦然——鹽撞位警告）、其他產品用自有鹽域（禁硬編 tacet 鹽當預設）。
`createVault`／`unlockVault` 簽名與返回形零變更（additive 鐵律）。

**Added** — `VaultErrorCode` union 新增 `ERR_VAULT_WRONG_PASSPHRASE` 查詢別名字面：
`isVaultError(e, 'ERR_VAULT_WRONG_PASSPHRASE')` 對 code === 'ERR_VAULT_WRAP_MISMATCH'
回 true、反之亦然（雙向別名；對其餘錯誤碼恆 false）。拋出面零變更——錯密語仍拋
`ERR_VAULT_WRAP_MISMATCH`（失敗面刻意不細分密語錯／包裹竄改：同一 GCM 失敗，細分＝
oracle——vault-error.ts 檔頭設計契約原文不動），別名只在查詢面。下游披露：union 增寬——
窮舉 `switch`／`Record<VaultErrorCode,…>` 表若加 `ERR_VAULT_WRONG_PASSPHRASE` case，
因拋出面恆 `ERR_VAULT_WRAP_MISMATCH`，該 case 必永不命中（別名只在查詢面）。

**Added** — 高階 Vault API 零設定前綴推導 `resolveVaultConfig(input)`：`{ app }` 最小設定，
全部 5 個前綴值由 app 決定性推導（記錄密文 `<app>1v.`／寫面 `<app>4w.`／PIN `<app>4d.`／
鹽域 `<app>3s:`／舊世代讀面 `<app>3w.`·`<app>3d.`·`<app>1w.`·`<app>2w.`·`<app>1s.`；
`recovery: true` opt-in 推導 `<app>1r.`＋HKDF info 域 `<app>kek1`、零鹽契約）。
`createVault`／`unlockVault`／`recoverVault` 三入口接線：整組前綴缺省＝resolver 推導預設、
顯式 `argon`／`cipher` 在場＝顯式全配置路徑（零推導、回歸 diff 恆 0）；app 契約
`^[A-Za-z0-9_-]+$`＝**零設定路徑專載**（非契約 app 誤入零設定＝`ERR_VAULT_CONFIG`
fail-closed 不猜；顯式全配置路徑 app 字面照 0.3.3 既有契約零驗——契約閘不跨路徑加寬）。
PIN 恆 opt-in
（帶值＝同族尾碼推導不拒）；recovery 缺省恆不推導（零鹽選擇不可靜默——opt-in 鐵律）；
`legacy.wrap: false`＝零設定 vault 預設語意（舊契約回落腿關閉——identity 綁域的 jr1w.
復原套件不屬本 API）。`VaultErrorCode` union 零新碼（推導拒恆走 `ERR_VAULT_CONFIG`）。

**Added** — `VaultRecoverySpec` 型別匯入（＝既顯式物件形別名）＋`VaultConfigInput` 輸入形
（三入口共用——零設定 `{app}` 與顯式全配置同形進位）。

**驗證閘（W1 補記）** — 0.3.4 W1 輪：[27] 加三腿（`deriveVaultPh1` 行為面 hex64＋委派
逐位一致＋正規化收容、錯密語拋出面＋`isVaultError` 查詢別名雙向命中＋跨碼恆不命中、
`deriveVaultPh1` 獨立 export 靜態面＋拋出面零轉拋）＋⑧c over-broad 別名回歸齒。帳 522→525。

**驗證閘** — [27] 加四腿：零設定推導表（全前綴決定性＋defaulted 旗標＋app 契約 fail-closed
——契約閘＝零設定路徑專載）、
零設定端到端（三入口全動線——`createVault(pass, { app })` 最小設定三行跑通＋changePassphrase
帶 PIN 同族推導 jr4d.＋recoverVault 復原動線＋跨設定形隔離）、零設定讀舊＋upgrade 沿帳戶家族形
（半顯式 legacy 槽推導殘部讀 <app>3w./<app>1w./<app>3d.、upgrade 同鑰重包沿帳戶形）、
靜態接線錨（resolver 字面恰 10＋接線形恰 3＋app 契約 regex 錨＋推導表尾碼錨——毒化齒）。
⑧ 顯式路徑回歸帳添三案（推導域共存前綴互斥 bait、PIN 進位直通 OK面、resolver 顯式 CFG27
全量回歸直通）＋⑧f 顯式路徑 app 契約放寬回歸案（顯式全配置 app 契約外字面——空白／帶點——
直通＝家族面照常＋跨碼恆非 CONFIG）。帳 525→530。

**Added** — 復原套件 24 詞形（bip39 轉寫層既有原語上車）：`VaultRecoveryKit` 加 `words` 欄
（＝`recTokenToWords(recToken)` 的 BIP39 英文 24 詞；`recToken` hex64 欄保留——雙形相容既有 kit
消費端）。`recoverVault` 入參 `recToken` 收三形：hex64（既有契約原樣）／24 詞空格分隔單字串／
24 詞字串陣列——詞形內部 `wordsToRecToken` 轉回 hex64 後走原驗證路（正規化 NFKC＋小寫照
bip39.ts 轉寫層契約；任何不符——錯詞 checksum／錯數／詞表外——照舊 `ERR_VAULT_RECOVERY`）。
線上契約零變更：rec_hash＝SHA-256(hex64)、wrappedRec 逐位不動；24 詞 ⇄ hex64 可逆互轉＝熵等價。

**驗證閘（W5 補記）** — [27] 加一腿：復原套件 24 詞形（kit.words 恆等 recTokenToWords(recToken)
＋words⇄hex64 roundtrip 恆同、recoverVault 三形入參同解同密文＋復原動線同構、詞形非法三毒
（錯詞／23 詞／詞表外）同碼 ERR_VAULT_RECOVERY）。帳 530→531。

**Changed** — 發行面 dist-only 瘦身（用戶裁定 A 案）：package.json `files` 白名單由
`dist`／`docs`／`src`／`scripts`（＋三行 `!scripts/*` 排除）收斂為恰 `dist`／`docs`／`migrations`／
`README.md`／`LICENSE`——tarball 65 檔→45 檔（unpacked 902,051→383,521 bytes，同樹 dist 對照實測；
0.3.3 registry 帳 65 檔／843,325 bytes）；src／scripts 隨包退役（0.3.0–0.3.3 隨包→0.3.4 dist-only：
閘與向量產生器為 repo 樹面；稽核閱讀路徑＝GitHub 瀏覽 src＋docs/format-spec 規格＋docs/vectors
向量——`docs/` 仍隨包）；[21] 包內 SKIP 對照帳段隨瘦身退役（發行包不再帶閘——README quickstart
對照行同步收口）；[22]／[26]／[27] 三錨隨窗 reshape（scripts 封閉集恰 2 檔→零 scripts 在場；
產生器／vendor 樹面在場錨），verify 帳 531 不變（reshape 零增刪斷言）。
行為面零變更：`exports` 全子路徑恆指 dist，消費端 import 面不受影響（dts-fixture 兩組
moduleResolution 照綠）。

## [0.3.3] — 2026-10-12

**驗證閘** — [12] 限流鍵段就地加力：無法解析形案改以 `Object.is` 驗原樣回傳，並補齊
非字串四型（undefined／null／NaN／物件）；新增 checkRate 入口靜態接線錨（限流模組內
`bumpRate(env, w, normalizeRateIp(ip))` 恰出現一次——入口摘除正規化即翻紅），帳 521→522。
[21] SKIP 標籤可維護性：tarball 環境的顯性 SKIP 行不再寫死消費端帳數（舊標籤 503 每版
必過期），改記帳差 −3 並指回 README「CI 供應鏈面」行——消費端帳數真相源單一化、隨版記帳。

**文件** — `normalizeRateIp` 文件註解補記嵌入 IPv4 三家族的刻意不還原：IPv4-compatible
`::192.0.2.1`、SIIT `::ffff:0:192.0.2.1` 聚合進 `::/64`，NAT64 `64:ff9b::192.0.2.1` 聚合進
`64:ff9b::/64`——僅 IPv4-mapped 還原點分 IPv4（0.3.2 既有行為，純註解）。

行為面零變更：本版無 Added／Changed／Fixed／Security 條目——0.3.2 出車後的變更全屬
驗證閘、原始碼註解與帳面文件。

## [0.3.2] — 2026-10-12

**Changed** — 限流鍵 IPv6 /64 聚合正規載具（0.3.1 未含此正規化，本版起承載）：
`normalizeRateIp` 單一真相上車——IPv6 鍵收 /64 前綴（RFC 5952 規範形＋`/64` 標記，
與裸位址可辨；zone id 先剝、大寫／零壓縮正規化），**IPv4-mapped 位址回點分 IPv4
原生 /32 鍵**（mapped 依 RFC 4291 §2.5.5.2 即 IPv4 節點——塌縮 ::/64 桶會形成全球
lockout DoS 向量）；IPv4／`unknown`／空串／無法解析形原樣（鍵照樣入表＝可見面）。
checkRate 入口接線，呼叫端介面零變；限流聚合語意變更標記（行為變更）——升級影響三點：既有 IPv6 逐址鍵升級當下計數視窗一次性重置、mapped 位址併入點分 IPv4 桶、同 /64 多主機共額度。
驗證閘 [12] 新段 +15 案（50→65）：同 /64 共鍵、跨 /64 分鍵、同 /48 異 /64 不共鍵、
RFC 5952 規範形＋零組不碰撞、::/64 邊界、zone id／大寫／嵌入 IPv4、mapped→點分
IPv4 twin 同鍵＋相異主機各鍵、非 v6 原樣三案、barrel 同物件、拷貝樹毒化聚合分支
摘除＝v6 八案真翻紅。verify 帳 506→521。

**Added** — 根入口新公開匯出 `normalizeRateIp`：限流鍵 IPv6 /64 正規化的單一真相入口
（詳 **Changed** 節）——0.3.1 的 72 個 exports 至本版 73 個，唯一新增即此。

**Added** — GC（garbage collection）排程面：伺服器維護 GC 條目（幽靈帳號／孤立
session／分享包裹／附件孤兒／授權超額）由前端 worker 每日低峰排程（Cloudflare
Workers Cron Triggers，每日 UTC 19:00＝台灣 03:00 離峰）觸發；既有 1/200 抽樣
fallback 保留（cron 為主、抽樣為 fallback；GC_EVERY_N 與 GC 門檻常數不動）。
（排程主體 commit 在 tacet.ink 伺服器側 repo；本節為核心面依發布確定後節位回填。）

## [0.3.1] — 2026-10-10

**Added** — 高階 Vault API（`./client/vault`）：`createVault`／`unlockVault`／`recoverVault`
不用懂前綴即可註冊/登入/復原（新面前綴家族自動生成：`<app>` 域鹽＋最新世代 jr4 家族；
AAD 自動綁 `<app>:<recordId>`）；`VaultHandle.encrypt/decrypt` 收字串/JSON/Uint8Array 三形
（tag 首字元分型）；`changePassphrase`／`needsUpgrade()`／`upgrade()`（同鑰驗證重包——
帶內版本化律；資料零換鑰）；`VaultError` 型別化錯誤家族（`ERR_VAULT_*` code 欄）——
低階原語零語意變更（本層為純新增呼叫端）。Argon2id 載體平台預設（`./client/vault` 內建
回退鏈 injected→node→worker→inline、可覆寫、`setArgonLoader` 注入恆優先；首用 RFC 9106
KAT 前檢＝錯誤載體拒用不降級——zero-fallback）；Web Worker 載入器內建（登入不卡畫面——
worker_threads 轉接同一原文雙端串行）；hash-wasm 4.12.0 進 devDependencies＋vendor 產生器
`scripts/vendor-hash-wasm.cjs`（tarball 以 `!` 排除；產物 `src/client/vendor/hash-wasm-argon2.ts`
sha256 釘選、去縮排可逆、零全域寫入——產品碼零 runtime deps 鐵律不破）。
驗證閘新段 [27] 十四案（roundtrip 三形／新舊前綴解鎖／upgrade／換密語／復原／VaultError
毒化／載體覆寫＋Worker 回退鏈／vendor 孿生＋exports 分層單向）。

## [0.3.0] — 2026-10-10

**Added** — dist 發行：`npm run build`（tsc 原生 emit——ESM＋`.d.ts`，`tsconfig.build.json`；
`prepublishOnly` 內建＝手動出車防線）；publish workflow 顯式 build＋dist import 冒煙步
（建置失敗在 publish 前顯形）。`exports`/`main`/`types` 收口指 dist（13 子路徑逐條
types＋default 雙形——types 恆 `.d.ts`、default 恆 `.js`）；tarball `files` 加 `dist`，
`src` 保留（低階消費者源碼可讀＋稽核面，imports 恆走 dist）。瀏覽器、Node、Deno、
Bun、Workers 從此免打包器直接 import；Node `--experimental-strip-types` 的
「node_modules 內 .ts 禁區」類問題（消費端 `.core-pkg` realpath 手術）隨 dist 出車退役。

**Added** — 線上格式規格 `docs/format-spec.md`（逐前綴家族的 payload 位元組布局與欄位長度、
KDF 參數、AAD、加密原語、帶內版本化世代契約；從源碼錄，不新增契約）＋JSON 測試向量
`docs/vectors/`（`families.json` 各家族 wrap/encrypt 一組、`kat.json` RFC 9106＋驗證閘凍結 blob 七組
＋PH1/PH2 憑證樣本、`bip39.json` 34 組抽樣）——由 `scripts/generate-vectors.ts` 呼叫真原語一次性
產生、凍結入 repo（不隨 CI 重算）。驗證閘新段 [26]：向量存在性＋位元組 shape＋欄位名對規格＋
凍結 blob 逐字對閘 KAT（verify 帳 484→492；發行包 481→489）。tarball `files` 加 `docs`（產生器 `scripts/generate-vectors.ts` 留 repo、以 `!` 排除不入 tarball——發行包 scripts 封閉集仍 2 檔）。
README（zh＋English Summary）：Usage 改 dist 直接 import（「必走打包器」舊文退役）、
English Summary 增「Format spec & test vectors」段、模組段補 dist 發行形。

## [0.2.5] — 2026-10-10

**Security** — `loginRouteCore` ladder 查表守衛上載具（0.2.4 tarball 不含 #8 修復——載具時序，本版翻正；`AuthStore.ladderLookup` 未配置行為恆等 0.2.3 零降級）。

**Added** — 驗證閘段級 `--only` 運行能力（工具面，零原語觸碰）：`node --experimental-strip-types
scripts/verify-core-crypto.ts --only 16,17,18`（CSV／範圍 `16-18`／混形 `16,17-19` 三形同集合）
只跑指定段——setup（跨段消費向量群）恆跑、毒化矩陣內層 rerun 不繼承 `--only`（內層恆全帳，
`POISON_GATE_INNER` 語意不變）、`--only` 缺席預設恆全跑（CI/deploy 面零降級）。帳面誠實契約：
總帳顯形「本輪 X/選段帳 N（段帳總和 483 案——非本輪載面）」＋逐段 `案 X/帳 · skip（未跑非通過）` 行＋
OK 標記改 `CORE-CRYPTO-VERIFY-OK(--ONLY 16-18)` 顯形；段號語法違約（空值／非數字／未定段／
倒序範圍）＝`ERR_ONLY_*` fail-closed exit 1。段帳為執行帳（healthy-repo 全跑真值；
語法帳與之差 7＝既有環境條件態——帳面逐段顯形）。審查輪重跑指定段不再付全帳 6-8 分鐘
（同機實測：全跑 ~370s；`--only 16,17,18` ~350s——兩大毒化重段的內層 gate-rerun 恆全跑＝
重段省少；便宜段才有大差：`--only 1` ~1.2s、`--only 20` ~3s）。

**Fixed** — [18] 毒化 runner 斷言摘死析取（[25] 段帳重寫前寫下的未來失敗面保險腿——段語意
重寫後已亡，保留只會吞真失敗面）；[25] 段帳登記義務負向斷言上線（secRan 實跑段必已登記——
secCases 全摘即 RED）；secCases 敘事收窄成契約窗〔[24]/[25] 自證段＋--only 段存在＋teeth〕；
[0.2.4] 已版發行補收——[23]⑥ 毒化案 getByUserKey 改 db-backed 正讀復齒＋ladderLookup
 docstring 對 fail-open 碼面＋ladder.ts 職責分工節對 0.2.4 內建接線（9af261e；補錄隨本版出門）；
README 三行 verify 帳照實 484 收帳。

## [0.2.4] — 2026-10-09

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

[0.3.3]: https://github.com/tacet-ink/journal-core/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/tacet-ink/journal-core/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/tacet-ink/journal-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tacet-ink/journal-core/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/tacet-ink/journal-core/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/tacet-ink/journal-core/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/tacet-ink/journal-core/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tacet-ink/journal-core/compare/v0.2.1...v0.2.2
[0.3.4]: https://github.com/tacet-ink/journal-core/compare/v0.3.3...v0.3.4
[0.3.5]: https://github.com/tacet-ink/journal-core/compare/v0.3.4...v0.3.5
[未發布]: https://github.com/tacet-ink/journal-core/compare/v0.3.5...HEAD
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