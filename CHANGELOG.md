# 更新日誌（Changelog）

本專案版本的歷史摘要。格式仿 [Keep a Changelog](https://keepachangelog.com/)、
語言從專案慣例（zh）。
日期取各版 release commit 的實際日期：0.1.3 起有 tag（v0.1.3…），取 tag 指向 commit 的日期；
0.1.0–0.1.2 無 tag（publish-on-tag 慣例 v0.1.3 才確立），取該版版號 bump commit 的日期。

## [0.8.0] — 2026-11-10

**Security** — ring MAC 多裝置承載（外審 2026-11-10 N1：0.7.0 macKey 只在首寫裝置本地，第二裝置無 key
＝v2 blob 讀不到）：macKey 恆 32B `crypto.getRandomValues`（新原語 `generateRingMacKey`；禁從 noteKey/密語
派生——輪替前提＝舊鑰可能外流），本體仍不以明文入 blob，改以**密語 KEK 包裹＋復原 KEK 包裹雙包**
（`RingMacConfig.macKeyWrapped`，`WrappedForms` 同構）內嵌 v2 blob 頂層 `mk` 尾欄、**受 MAC 覆蓋**（canonical
附 mk 嚴格三欄子集——包裹面竄改恆攔）、隨 blob 走 server（零新欄）＝server 零知識不變（見密文）；第二裝置僅憑
密語（`keyRingWrappedMacKey` 讀 mk → 既有 `unwrapNoteKey`／`unwrapNoteKeyWithRecToken` 解包 →
`ringMacKeyHexOf` → `parseKeyRing`）完成 MAC 驗證＝寫出即全裝置可驗；換密語＝重包不重簽（macKey 本體與既有 ring
MAC 不變），凡不走 `keyRingAddEntry`／`keyRingRetire` 的 re-emission（換密語重包、復原套件重出）**必先
`keyRingBumpEpoch` 再 serialize**——重包改受 MAC 覆蓋字面＝同 epoch 新 MAC，次裝置高水紀錄恆拒（R1 MAJOR-1）。
MAC 輸入擴欄帶帳號域
`ep<epoch>:<accountId>:<canonical>`（`RingMacConfig.accountId` 必需；形：非空、禁 `:`、≤256——違例 serialize
`ERR_RING_MAC_ACC_BAD`／parse null）：可共享 macKey 後 server 對調兩帳 ring 面收口（同 key 異帳恆異 MAC）。
`requireMac?: boolean` 選配：true ⇒ 無 mac 欄 blob（legacy face）parse 恆 null（K1e 剝欄回滾殲；開啟時機＝
消費端遷移完成裁定；未設/false＝0.7.0 行為零變）。**未配置／v1 形 byte-identical 不變**（opt-in 母型——KRM-a
凍結錨 SHA-256 同值）。**殘餘界線**：新裝置無本地高水紀錄＝首見即信；無 mk 欄的 v2 blob（host 未提供
`macKeyWrapped`）第二裝置讀不到＝fail-closed（部署面非攻擊面）；已配置但從未寫出 v2≥1 blob 的帳期窗
strip-both/replay 照收（write-side 接線落地即解）。

**Security** — 保留命名空間安全網（外審 2026-11-10 N3 修法 2；core 預設開啟）：`decryptNote` 相容層＋
`makeInboundCipher` 明文軌兩面——命名空間形（`^jr\d[a-z]\.`）一律 null（D1b/c/d 收口；修前原樣回傳／截斷收
入庫）；既有家族零變（jr1b./jr1u. 完整形照解照收、kid 配置態零動、`allowPlaintext:false` 零動）；JSDoc 界線＝
D1e 前導空白面不在本網（根治＝`allowPlaintext:false`，消費端接線另卡）。S1 v1 族收齊：已知前綴字面在場、非完整
b64 形→null（帽內 `jr1b.!!!` 照收、超帽 junk 截斷收→null 收口；kid 族同律）；`isCipherFor` 分類面零動；無前綴
真明文對照組照 `allowPlaintext` 語意。

**Changed** — 變換即推進（外審 N2 同 epoch 改寫收口）：帶 epoch ring 的 `keyRingAddEntry`／`keyRingRetire`
自動 +1（serialize 恆可出恆帶推進後 epoch——「同 epoch 改寫」面殲；retire 已缺席冪等原样零推進）；epoch 缺席的
v1 形零漂移；`keyRingBumpEpoch` 保留相容（顯式 +1——v1 緣起 ring 首配置態首寫仍以本函式遞增）。新 export
`keyRingMeetsHighWater(seen, incoming)`（`RingHighWater {epoch, mac?}`）：incoming null／epoch 形廢→false；
seen null→首見即信 true；epoch 較低→拒；同 epoch 異 mac→拒；`parseKeyRing` v2 成功面帶回 `KeyRing.mac`＝
呼叫端高水紀錄 epoch+mac 同存承載。**Breaking**：`RingMacConfig` 配置態現在必需 `accountId`；0.7.0 產出
（無帳號域）的 v2 blob MAC 在 0.8.0 配置態恆 null（發布前零消費者接線——無遷移面）。gate 帳 678→691：
[32] 67→80（KRM-p 變換即推進／KRM-q 高水 helper／KRM-r requireMac／KRM-s 帳號域／KRM-t mk 欄／KRM-u 裝置 B
解包／KRM-v macKey 原語形／KRM-w 換密語 re-emission 必先 bump（R1 MAJOR-1）8 案＋毒化 P5 變換即推進摘除→KRM-p/m
翻紅、P6 帳號域摘除→KRM-s 翻紅、P7 requireMac 臂摘除→KRM-r 翻紅、P8 高水 mac 比對臂摘除→KRM-q 翻紅 4 案＋毒化樹
try/finally 還原案（R1 MINOR-5）1 案；既有 KRM-m 改變換即推進語意、KRM-o 重簽載體帶帳號域；R1 修正輪 +2
（KRM-w＋毒化樹還原））。

**Changed** — K5 根入口匯出收齊：`src/index.ts` keyring 區塊補 `keyRingBumpEpoch`＋`RingMacConfig`（外審
2026-11-10 K5——根入口無法產生 v2 blob）＋0.7.0/0.8.0 新 API root 滯後同類（`keyRingMeetsHighWater`／
`RingHighWater`／`generateRingMacKey`／`ringMacKeyHexOf`／`keyRingWrappedMacKey`）；ci-subpath-probe root
具名 import 斷言（值腿靜態具名 import link 期即紅＋型腿安裝樹 .d.ts 字面）。文檔版次修正：0.6.0 起→0.7.0 起
（README×3＋rotation-design.md §12＋auth.ts 註解——npm 序列 0.5.2→0.7.0 無 0.6.0）＋退場條件句幻影起點收正
（四處）＋SECURITY.md 支援表。CI：verify.yml「Install typescript」步補 `--ignore-scripts`（in-file D4 保險面
保留——旗標即防禦面同向）＋gate [21] 靜態齒。gate 帳 691→702：[32] 80→87（PLT-h..m 六案＋兩面 CORE_NS_RE
同源靜態帳）＋[21] 19→21（Install typescript --ignore-scripts 齒＋探針 root 具名 import 齒）＋[31] 12→14
（P6 安全網摘除／P7 S1 分派摘除毒化兩向＋P1/P3 針源同步）；R1 CORS Access-Control-Expose-Headers 不改（tacet
同源不受影響——記錄即可）。

## [0.7.0] — 2026-11-08

**Security** — ring 回滾面收口（外審 2026-11-07 #3：被入侵 server 對 legacy 態 `users.keyring`
blob 可回推舊 blob（被輪替掉的舊 kid 集復活）或置 null（client 鏡像摘除））：新增
`RingMacConfig`（`macAad`）＋`serializeKeyRing(ring, macCfg, macKeyHex)` v2 形——頂層
`epoch`/`mac` 兩欄、`mac＝HMAC-SHA256(HKDF-SHA256(macKey, info=macAad), `ep<epoch>:<v1 形
canonical JSON>`)`；macKey 由 host app per-account 本地持有、不進 blob 不過 server（server
面零知識保持）。parse 配置態 fail-closed：mac 在場必驗（key 缺/錯/竄改→null）、epoch 形檢
（`"3"`/[3] 字串化同 `ep3:` 的型別混淆唯一防線）、**epoch floor**（配置態 epoch 缺席/<1 恆拋/
null——r2 MAJOR-1「epoch ≥ 1 ⇔ MAC 已驗」不變式：v2 面 epoch-0 恆 null＝與 legacy face（恆
epoch 0）自然可分辨，遞增只經 `keyRingBumpEpoch`、epoch 缺席（v1 緣起首配置態）的 serialize 恆拋＝epoch-0
v2 blob 無出廠面——**0.8.0 校正**：帶 epoch ring 的變換後無 bump serialize 實際可出——同 epoch 改寫面，N2，0.8.0
變換即推進收口；原句過寬）、legacy blob（無 mac 欄）讀契約保留（epoch=0，帶內兼容）。**未配置＝v1 形
byte-identical**（opt-in 母型——姊妹 fork 零影響鐵律）。**殘餘界線**：新裝置無本地 epoch 記錄＝
首見即信；已配置但從未寫出 v2≥1 blob 的帳（高水 book 仍 0）期窗內 strip-both/replay 仍 0≥0
照收（write-side 接線落地即解）；sync guard、LS 高水標記與 v2 寫入端接線＝tacet 產品層
follow-up。

**Changed** — `serializeKeyRing`／`parseKeyRing` async 化（0.6.x 同步簽名→Promise；MAC 用
WebCrypto HMAC）；`keyRingBumpEpoch` 新原語（epoch+1 純函式，缺席/非法視 0 不拋）、`KeyRing`
選配 `epoch` 欄、ring 變換（addEntry/retire）攜帶 epoch 不自增。gate 帳 639→678（批尾合流推進：[21] 10→19／[23] 18→23／[32] 61→67＝J4 毒齒 14 案＋J3 async 帳面接軌；0.5.3 未發布節內容併入）：
[32] 42→61（KRM-a..o 15 案＋毒化 P1..P4——MAC 驗證呼叫摘除→KRM-c/d/e/f/l 翻紅、epoch 形檢
摘除→KRM-g 翻紅、serialize/parse floor 摘除→KRM-o 翻紅（真簽 epoch-0 重簽載體——floor 唯一
防線），[31] 段拷貝樹毒化母型同形）；[25] book teeth 帳面同步。

## [0.6.0] — 2026-11-07

**Security** — 明文相容層 opt-out（外審 2026-11-07 #4：`decryptNote` 無前綴字串在
`cipherGuest` 配置態原樣回傳（dist 實跑 "Forged by the server" 照收）＋`makeInboundCipher`
收明文無關閉選項——與「server never sees plaintext」宣稱落差）：兩面新增 optional
`allowPlaintext`（`NoteCryptoConfig`／`CipherFormats`）。**未配置／true＝現行契約零變**
（opt-out 母型——關閉是 fork 顯式選擇；未配置態 byte-identical，姊妹 fork 零影響鐵律）；
**false＝關閉相容層**：client——無前綴字串一律 null 不落明文（guest/bound 軌不受牽連）；
server——落帽真明文→null、超帽真明文→null（無截斷面，明文截斷帽不折半收假密文）、
帽內純 b64 慣例軌→null（無前綴＝不可驗證內容，與明文相容層同面）。關閉態回傳值不再含
未驗證內容：開放態相容層回傳值＝**未驗證內容**（伺服器／傳輸層不需金鑰即可寫入此層）——
介面標示入 README 設計節與 JSDoc。gate 帳 630→639：[32] +7（PLT-a..g）、[31] +2（毒化
P4/P5）；相容層退場條件：0.7.0 後兩個 minor 週期內遷移完即摘（原式以未發行的 0.6.0 為起點——npm 版本序列 0.5.2→0.7.0，外審 2026-11-10 校正；fork 需顯式配置
`allowPlaintext:true` 或接受摘除面）——README「設計」節＋「界限」節＋
rotation-design §12 誠實面三處落條。
## [0.5.3] — 2026-11-08（**未發布**——版本號讓位堆疊，內容合流入 0.7.0 發布面）

**Added** — `rateLimitedResponse()` export：429 面帶 `Retry-After: 60`（RFC 9110 delta-seconds；字面
60＝`AUTH_RATE.windowMs` 60_000 單窗設計窗長，多窗語意下為下限估計）。`loginRouteCore` 限流命中面改走
此函式（body `ERR_RATE_LIMITED`／status 429／CORS 頭與舊形恆等，唯一增量＝Retry-After 頭）；`errResponse`
本體與其餘呼叫面零動——兄弟 fork／pin 版 byte-identical 零影響。

**Fixed** — `keyRingGet` runtime proto 面：entries 取值改 `Object.hasOwn` 檢查——kid=`__proto__`／
`constructor` 等原型鏈鍵回 null（舊形 `?? null` 回 Object.prototype／函式物件）。序列化入口 `parseKeyRing`
走 JSON.parse 產純 object 且 kid 形檢已拒非 legacy/8-hex 鍵，本面只封 runtime 以非自有鍵查表的攻擊面；
自有鍵回值零變。

**Changed** — verify workflow：runs-on 分流鍵 actor→PR 作者（`github.event.pull_request.user.login`——
actor＝事件觸發者，人為 synchronize/reopen 可把 Dependabot 分支推上 self-hosted＝分流鍵偽裝面；PR 作者欄
恆為開 PR 身分）；補 `node scripts/dts-fixture.cjs` 步（dts-fixture.cjs:2 註解宣稱的 CI 等價步落真；前置
typescript 顯式安裝（lockfile 版釘、--no-save）＋`npm run build`——npm pack 不觸發 prepublishOnly、dist
須先建）＋新 `scripts/ci-subpath-probe.cjs` 探針步（repo package.json exports 15 鍵逐一 `node -e import()`
子行程 runtime import——0.5.0 漏 `./client/keyring` exports subpath 型問題的回歸網；scripts/ 不入 tarball）。

**Changed** — 文檔誠實面：SECURITY.md 支援版 0.5.x（0.4.x EOL 自 0.5.0，2026-10-25）；README 輪替行誠實化
（階段 1 設計 §9 已裁定；0.5.1 起輪替原語族已上線 npm、`rotateNoteKey` 端到端動線尚未落）、`jr2p.`
「設計面」字面→已上線（:127 表／界限段）、PIN 強度帳 68s／1.9h／41h 加「速率外推非實測」標記（數字照留；
PoC C 28.7s 實測底照留）、CORS `*` 預設面理由句（沙箱 demo 預設／部署面由呼叫端覆寫收口；`cors.ts` 零動）。

**Changed** — gate 帳 630→650（+20）：[21] +9（J4 三齒各「契約在場／毒化錨恰 1／毒化翻 false」——runs-on
分流鍵 actor 復原形／dts-fixture 步摘除／探針步摘除；既有 runs-on 案 regex 隨碼同步 user.login 形）、
[23] +5（⑧ 限流第 11 發 429 帶 Retry-After 60＋CORS／前 10 發 200 零 Retry-After／直呼形＝errResponse 同面
唯一差 Retry-After＋barrel 同一函式；⑦ 同樹二次毒化：錨恰 1＋接線復原舊形→Retry-After 翻 null）、
[32] +6（⑦ 原型鏈鍵五形 null／自有鍵面零變＋serialize/parse 往返／parseKeyRing 入口拒 `__proto__`／
`constructor`；src/client 拷貝樹毒化：樹在場&錨恰 1／復原 `?? null`→`__proto__` 翻 Object.prototype／
byte-exact 還原＋樹出生即棄）；`secCases` [21] 10→19、[23] 18→23、[32] 35→41。

## [0.5.2] — 2026-11-07

**Fixed** — `decryptNote` 對輪替後 kid 前綴族 miss→null（外審 2026-11-07 高優先 #1：
相容層串漏封）：`cfg.cipherBound2/cipherAttach2/cipherLocal2` 配置時，`jr2b./jr2c./jr2d.<kid>.`
族字串在 `decryptNote` 本面一律 null（rotation-design §3.2 路由序「jr2b.<kid>. 族 → jr1b. →
guest → 舊明文相容層」的 miss 面＝null 不降級；該族解密由 `decryptNote2/decryptAttach2/
decryptLocal2` 承載）。修前無此分支＝`cipherGuest` 在場時走舊明文相容層原樣回傳。判定＝基前綴
字面在場（startsWith）：kid 欄畸形同樣整面 null（不回落盲試）。未配置基前綴＝零變（opt-in 律；
gate [32] J1-d byte-identical 面證）。

**Fixed** — `makeInboundCipher` kid 前綴族驗形（外審高優先 #2：雙點形辨不出＝超帽誤落明文
截斷 40054→20480 且 `isCipherFor:true`）：`CipherFormats` 新增 optional `cipherPrefixes2`
（基前綴族如 `['jr2b.']`；完整前綴＝base + kid + '.'，kid 欄 `^[0-9a-f]{8}$`——core 原語組裝）。
配置後：帽內完整形原樣入庫；帽內形廢（junk 身體／kid 欄形廢）→ null 不落明文層；超帽帶任何
kid 族字面一律 null 絕不截斷。`isCipherFor` 對 kid 族完整形 true／形廢 false／未配置 false，
既存 tuple 面零動。未配置＝整面退場（現行消費端 byte-identical；gate [32] J2-d）。

**Changed** — gate 帳 618→630：[32] +9（J1-a..d decryptNote 四情境正常鑰/舊鑰/竄改/搬列全 null
＋同構/畸形/opt-in 零變；J2-a..e inboundCipher 帽內/帽外/形廢/未配置/isCipherFor）、[31] +3
拷貝樹毒化（P1 摘三族判定→J1-a 翻紅；P2 摘帽內分派→J2-a 翻紅＋J2-b 由尾段防禦行承載照綠；
P3 摘超帽子句→J2-c 翻紅；錨行漂移＝`ERR_POISON_ANCHOR_DRIFT_31_P*` fail-closed）；`secCases`
[31] 7→10、[32] 26→35（帳齒兩向咬）。

**Security** — 修前 server 不需任何金鑰即可毀本地副本（回傳 `jr2b.<kid>.` 殘列＝相容層原樣
落 UI／覆寫本地）與截斷密文面（超帽 kid 族被當明文截斷入庫＝密文損毀）——外審 2026-11-07
報告 #1/#2 俱封。

## [0.4.3] — 2026-10-22

**Changed** — 安全文件「不可驗證字樣」改實測公開基準（J14 外審 D1：誠實面收口）：
`src/client/pinlock.ts`「離線爆破 6 位數字 ≈ 單 GPU 數天」→ RTX 4090 公開基準
（PBKDF2-SHA256 ≈8.8e9 iter/s）：6 位純數字 ≈68 秒、8 位數字 ≈1.9 小時、6 碼小寫英數
≈41 小時（PoC C 實證底：4 位 16 核 CPU 28.7s 命中）＝**門檻不是牆**（設計裁定不變：
鎖定閘取即時性、非登入 oracle 戰場）。`src/client/argon2.ts`「上升一至兩個數量級」→
對 PBKDF2-SHA256 600k 的 GPU 實測/估計倍數 ≈10-20 倍（記憶體頻寬受限；PoC B CPU 面
SHA-256d vs Argon2id ≈5×10⁴）＋覆蓋界線（僅 Argon 派生的密語指紋面；wire 層
`SHA-256(pass)`（J2 legacy）不受它保護）。README「界限（誠實面）」增四行：PIN 類保護
實測值、分享面金鑰範圍（v0.3.6 起一次性 `shareKey`）、Argon2id 成本倍數＋legacy PH1
wire 指紋面（tacet S3 已 v3-first；core `loginRouteCore` 相容面照留）。

**Added** — 正式參數 KAT（J14a：prod 參數 m=64MiB t=3 p=1）：`kat.json` 增
`argon_prod` 組（確定性輸入 pwd/salt、非生產密語/鹽）＋`src/client/argon2.ts` 新 export
`verifyArgonKatProd`＋`ARGON_PROD_PARAMS`／`ARGON_PROD_EXPECTED` 凍結向量（node:crypto
真原語產生，與 `scripts/generate-vectors.ts` 同源——gate 載體 node 端走 node:crypto
原生＝同一路徑）。瀏覽器載體 KAT 維持 RFC 小參數（載入延遲契約：wasm ~180ms 一次，
雙份 KAT＝載入面翻倍）——正式 64MiB 路「零向量」面收口（kat.json rfc9106 memory_kib=32
小參數限定 vs 新組 65536）。gate [7] 增正式參數 KAT 1 案、[26] kat 對帳段增
`argon_prod` 對帳行（欄位名＋參數逐位對 `ARGON_PROD_PARAMS`／`ARGON_PROD_EXPECTED`）。

**Changed** — `secCases` 帳面修正＋「超額也 RED」補齒（J14b：段帳=執行帳契約完整形）：
`[16]` 15→21（含 r1 U1 超額 teeth＋r2 U2 欠額 teeth 共 4 案）、`[2]` 7→9（0.3.5 起既有帳面漂移——本卡同步修正）、`[7]` 27→28（J14a 新增）、`[12]` 66→69（J15 新增）、`[25]` 4→5（r2 NIT-2：book 鍵雙向等值 teeth——缺鍵段兩 tooth 皆 `?? 0` 不咬面收口）；尾段段帳顯形雙向也 RED（超額 ranN＞帳＋欠額 ranN＜帳；r1 MAJOR-1：0.4.3 首版只補超額齒＝半交付，卡前提「原先只咬執行＜帳」經 reviewer 一手毒化證實為錯——雙向皆 display-only；欠額齒抓「斷言被刪／循環吃空／段未進入」＝靜默驗證流失面；條件態豁免 r2 MINOR-1 逐段收窄：`--only` 態僅 skip 段豁免（選中段欠向照咬——r1 整輪 `!onlyMode()` 過寬面已收）、`POISON_GATE_INNER` 內層跑份僅 sentinel 自我跳過段 [16]/[18]/[20]/[23]/[28]/[29]/[30]/[31] 豁免（內層 1 案 vs 外層 N 案＝設計中的條件態；內層非 sentinel 段欠向照咬＝U2 teeth 內層咬通面記錄承載））。帳基線勘誤（r2 MINOR-3；r3 MINOR-1 勘誤）：main book 578／真執行 582（book 578＋[16] 17/15、[2] 9/7 雙超額各 2；README@main 印 582 屬實＝book 側才是舊帳）→ 0.4.3 book 578→591（itemized [2]+2／[7]+1／[12]+3／[16]+6／[25]+1＝+13，含補帳 4 案＋新斷言 9 案）／真執行 582→591（run-delta +9——+13 為 book-delta，分寫防 595 誤讀；全段 ranN==帳無超額）＝**591**。

**Added** — `recHashStoredOf` 上 core 介面（J15：rec_hash 落庫形單一真相）：
`src/server/auth.ts` 匯出 `recHashStoredOf(sent)`（=`'v2:'`＋sha256(wire 值)；參照
tacet queries.ts 同形）＋`REC_HASH_MARK`；`AuthStore.getByRecHash` JSDoc 加「server 必須
以 `recHashStoredOf(client 值)` 落庫／bind——禁原樣存 wire 值（DB 外洩＝復原證明外洩）」。
tacet 改 import core 版（雙源收口）歸 S8。gate [12] 增落庫形 3 案（形＝標記＋sha256Hex
同源＋定值凍結＋不同 wire 值恆異）。

**Changed** — `SECURITY.md` 支援版本表：0.2.x→0.4.x 支援中＋0.3.x EOL（0.4.0 起，
2026-10-20）——誠實歷史面（表格式兩行）。版本 0.4.2→0.4.3（bump 歸本卡；發布窗歸主 session）。

## [0.4.2] — 2026-10-22

**Added** — `buildBindPayload4`（`src/client/note-crypto.ts`，0.4.2，J8 外審收口）：綁定/匯出
建檔面的金鑰包裹四件套升 Argon2id 世代——pass 段 KDF 由 `jr1w.`（PBKDF2-SHA256 600k）改走
`wrapNoteKey4`（`jr4w.` Argon2id m=64MiB t=3 p=1；NFKC 正規化入口在 argon2 派生層）。rec 腿
（recovery 套件）契約零動（`wrapNoteKeyWithRecToken` 照例：recToken 256-bit 實體因子，世代照
cfg 兩欄）——「一個前綴一份契約」，`jr4w.` 只承載 Argon 派生。

- `buildBindPayload4(cfg, cfg4, noteKey, passphrase, recToken, identity)`：雙配置面
  （`NoteCryptoConfig`＋`Argon3Config`）；pass 段吃 `wrap4` 在場守衛（未配置
  `ERR_JR4W_NOT_CONFIGURED` fail-closed）、rec 段吃 `NoteCryptoConfig`；兩段 `Promise.all`
  並行（串行形＝效能形契約違規，[14]/[31] 雙段錨面）；回傳形與舊形同構
  `{ wrapped, salt, wrappedRec, recTokenHash }`（salt＝pass 段隨機鹽 hex32；recTokenHash＝
  `sha256(recToken)` 恆等）。
- 動機（J8）：舊形 `buildBindPayload` 的 wrapped 走 `jr1w.` PBKDF2，對 GPU 離線 oracle 友善；
  綁定/匯出建檔面升 Argon2id 後每猜成本升一至兩個數量級。`jr4w.` 前綴本身 0.4.0 已上（
  `wrapNoteKey4` 既有），本卡收口的是**綁定組裝面**換 KDF 世代。
- 舊形 `buildBindPayload` 標 `@deprecated J8（2026-10-21）`：舊檔案兼容面留置（讀舊寫新契約
  面永不變），新建綁定/匯出檔面請改用 `buildBindPayload4`。
- `src/index.ts` barrel 增匯出 `buildBindPayload4`。
- 閘 [31] 新增（`scripts/verify-core-crypto.ts`）：`buildBindPayload4` 前綴/roundtrip/毒化/
  家族面 7 斷言——四件套形面（`jr4w.` 前綴＋salt hex32＋recTokenHash 恆等）、pass 段
  roundtrip（`unwrapNoteKey4` 回收原始 noteKey）、rec 段 roundtrip（`wrapNoteKeyWithRecToken`
  零動承載）、salt 面＝pass 段隨機鹽、毒化矩陣（pass 段 KDF swap→PBKDF2 於隔離樹
  →前綴形面＋roundtrip 真翻＋byte-exact 還原回綠）、index barrel 同一函式。毒化矩陣載體
  與 [16]/[18] 同形（`POISON_GATE_INNER` sentinel 遞迴防線＋`cpSync` 隔離樹＋symlink
  node_modules）。帳 575→582。

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