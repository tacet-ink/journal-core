# @tacet-ink/journal-cli — tacet.ink 索取祕密本機 CLI

R3b（t_8b19f126）：把 tacet.ink「索取祕密」流程搬進終端機——**agent 工具套件 2/3**
（1/3＝R3a core `jr5s`/`jr5e` 原語收編；3/3＝投遞工具，現已停車，I 線收件匣不併入）。

加密**全部**來自 `@tacet-ink/journal-core` 0.11.0（`./secret/jr5e` 子路徑＋`server/hash`）——
本套件零自帶加密（設計 L132）。

## 這是什麼

三個子命令，一條紀律（另附 `verify-site`：部署紀錄對 live 站的自驗面，見〈部署驗證（verify-site）〉）：

| 子命令 | 做什麼 | 誰跑 |
| --- | --- | --- |
| `request` | **主路徑**：N3 先驗證→建 slot→把**填寫連結**（公鑰面）交人；**取件連結**（私鑰＋token）只寫入本機檔案 | agent 跑 |
| `verify` | 同時驗 `/secret` 與 `/sreq` 對公開 repo `SHA256SUMS`，印四方帳 | 人可自跑 |
| `submit` | 把內容填進 slot——**預設關**：人在 TTY 輸入 slot 編號確認才動 | 人跑（或 CI 明式） |
| `verify-site` | 公開部署紀錄最新一筆的 manifest 對 live 站逐檔比對 sha256＋CSP | 任何人可自跑 |

**值永不回模型上下文**（設計 L128-129）：

- 輸入面＝參照，不是值：`env:NAME`／`file:PATH`——命令行與上下文只出現參照字面；
- 輸出面＝「已寫入 \<path\>」：stdout 永不含 token 原值、私鑰 JWK、明文內容；
- 參照路徑採**白名單**（外洩通道風險面，見下）。

## 安裝

本套件 `private: true`——**不上 npm**（發 npm 在上架階段統一處理）。
發佈 tag 規約（2026-10-24 裁定）：多包 tag 形 `<名>-v<version>`（如
`journal-cli-v0.1.0`）；包名禁 `v` 開頭（防 tag 撞名）；root 包（journal-core）
維持 `v*` 單包形。repo 內使用：

```sh
cd <journal-core repo root>
npm ci                      # workspaces 自動鏈接 packages/*
npm run build -w @tacet-ink/journal-core   # core dist（CLI import 面）
npm run build -w @tacet-ink/journal-cli
node packages/cli/dist/cli.js --help
# 或經 workspace bin 鏈接：node_modules/.bin/tacet-secret --help
```

Node ≥ 24.7（`node:crypto` WebCrypto＋`fetch`）。

### 首跑（全新環境）

不需預建 `~/.tacet-secret`：`request` 首跑自建該狀態目錄（700）與取件包檔（600）——
umask 077 下亦然（mkdir 後補 chmod 齊權限）。`~` 在 `file:` 參照裡**不會**被
CLI 展開——請寫全徑（`$HOME/…` 由 shell 先展開）；文件裡的 `~/.tacet-secret`
都是指狀態目錄的位置，不是參照字面。

## 使用

```sh
# 主路徑：N3 驗證後開 slot（預設 7d）——stdout 給填寫連結（可交人）
tacet-secret request

# annual 層（效期檔位 14d；權杖走參照，永不進命令行）
tacet-secret request --annual --annual-token env:TACET_SECRET_ANNUAL_TOKEN --ttl 14d

# 人自驗（對 live；也可 --base/--sums 指向本機／備份）
tacet-secret verify

# 投遞（預設關）：人在終端機跑，CLI 會要求輸入 slot 編號確認
tacet-secret submit '<填寫連結>' file:$HOME/.tacet-secret/payload.txt

# 部署驗證：live 站逐檔對公開部署紀錄最新一筆（任何人可自跑；exit 0/1/2 見下節）
tacet-secret verify-site

# 可選自檢（core 0.11.0 向量：jr5e/jr5s KAT＋負向量，走真模組）
tacet-secret --self-test
```

### 參數

| 旗標 | 適用 | 說明 |
| --- | --- | --- |
| `--ttl 10m\|1h\|3d\|7d\|14d` | request | 效期檔位（R1 問 8）；預設 7d；14d 僅 annual |
| `--annual` | request | annual 層（效期 14d 解鎖；需 `--annual-token` 參照） |
| `--annual-token env:NAME\|file:PATH` | request | annual 權杖參照（白名單守衛） |
| `--out file:PATH\|PATH` | request | 取件包輸出路徑（白名單守衛；預設 `~/.tacet-secret/<slot_id>.retrieve.json`；不覆蓋既有檔） |
| `--base URL` | request/verify/submit | 站 base（預設 `https://tacet.ink`；本機/dev 可指向 stub） |
| `--sums URL\|PATH` | request/verify | SHA256SUMS 真值源（預設＝公開 repo `main/SHA256SUMS` raw；亦收本地路徑） |
| `--json` | request/verify/verify-site | stdout 附加機器可讀 JSON（元資料面；仍零機密值） |
| `--url URL` | verify-site | live 站 base（預設 `https://tacet.ink`） |
| `--log URL` | verify-site | 部署紀錄帳本 raw URL（預設＝公開 deploy-log repo `main/deploy-log.jsonl`） |
| `--confirm-input <slot_id>` | submit | CI/測試面：以參數代確認（須配 `--allow-non-tty`） |
| `--allow-non-tty` | submit | 跳過 TTY 要求（仍須 `--confirm-input` 明式值） |

### exit code

| code | 意義 |
| --- | --- |
| 0 | ok |
| 1 | 執行失敗（N3 不符／API 錯／verify MISMATCH／404 不可填寫／逾時） |
| 2 | 用法錯（參數形／未知旗標／ttl 非法） |
| 3 | submit 非 TTY 拒（未送出任何東西） |
| 4 | 參照／白名單拒（含 `--out` 越界或已存在） |
| 5 | submit 確認中止（輸入非 slot id） |

`verify-site` 用自己的 0/1/2 面（見〈部署驗證（verify-site）〉）；用法錯同上表為 2。

## 安全設計

### N3 先驗證，再交給人（2026-10-26 用戶裁定）

`request` 在**任何 API 呼叫之前**跑三步：

1. 抓線上的 `/sreq` 頁（`verify` 同驗 `/secret`）；
2. 算 sha256（core `server/hash`）；
3. 比對公開 repo 的 `SHA256SUMS`。

不符（含任一抓取失敗、entry 缺席）＝**停、告知、不給連結**（exit 1；零 API 呼叫、
不建 slot）。`verify` 子命令是同一機的「人可自跑」面：印 live sha／sums sha／判定的
四方帳。

### 白名單（外洩通道風險面）

`env:`/`file:` 參照與 `--out` 都過白名單守衛（拒＝exit 4，值零外洩）：

- **file:**：`realpath` 後必落在白名單目錄內（分隔符界）或恰等白名單檔案；
  目錄／設備／缺席／非 UTF-8 一律拒。
- **env:**：變數名必在白名單——`TACET_SECRET_ENV_WHITELIST`（`,` 分隔，在場即為唯一
  真相）；未設時預設規則＝名字以 `TACET_SECRET_` 開頭。值缺席或空＝拒。
- 白名單來源（合併）：內建 `~/.tacet-secret/`（工具狀態目錄）；env
  `TACET_SECRET_WHITELIST`（`:` 分隔路徑）；`~/.tacet-secret/whitelist`
  （每行一路徑，`#` 註解）。
- 誠實界線：白名單由**操作者**在 agent 啟動環境／狀態檔預設；agent 能自設的 env
  就能自讀（同信任域）。白名單的紀律面＝把「參照路徑」收進可稽核的有限集，
  模型上下文永遠只出現參照字面、不出現值。

### 送出預設關

`submit` 在一切 API 呼叫**之前**設人確認閘：

- 非 TTY（agent 子程序、CI 未明式）＝**直接拒**（exit 3，零 API、零重試）；
- TTY＝印摘要（slot id／目的／來源參照／內容位元組數——**零內容**）＋要求輸入
  slot 編號；輸入不符＝中止（exit 5）。
- CI 明式面：`--allow-non-tty --confirm-input <slot_id>`（把確認決定留在 pipeline
  定義裡，而非工具預設）。
- 投遞 write-once（R1 問 9：已填寫／過期／不存在→404 三者不可區分）；**零重試**
  （write-once 語義下重試只製造混淆）。

### 取件連結包

`request` 成功後，取件連結（含 A 私鑰 fragment `#k=` 與取件 token `&t=`）只寫入
白名單路徑的 JSON 檔（`~/.tacet-secret/<slot_id>.retrieve.json`，chmod 600，
state 目錄 700，不覆蓋既有檔）。stdout 只有「已寫入 \<path\>」。

## 部署驗證（verify-site）

`verify-site` 讓任何人自己核對：**live 站此刻送出的每個檔案，是否就是營運者在公開部署紀錄裡記下的
最新一版**。零寫入、零遙測——只發 GET（UA 與部署端 canary 同字），不寫任何檔案。

```sh
tacet-secret verify-site                                         # 預設：https://tacet.ink＋公開帳本
tacet-secret verify-site --url https://tacet.ink --json          # 附機器可讀 JSON
tacet-secret verify-site --log https://<鏡像>/deploy-log.jsonl   # 帳本鏡像（manifest 相對它解析）
```

| 旗標 | 說明 |
| --- | --- |
| `--url URL` | live 站 base（預設 `https://tacet.ink`；http/https，不含 query／fragment） |
| `--log URL` | 帳本 raw URL（預設 `https://raw.githubusercontent.com/tacet-ink/deploy-log/main/deploy-log.jsonl`；http/https） |
| `--json` | stdout 附加機器可讀 JSON（verdict／mismatches／redirect_skip／network_errors／chain_errors） |

它做什麼：

1. 抓帳本 `deploy-log.jsonl`（schema `tacet-deploy-log/v1`，append-only；部署「先記後上」）→
   全帳形檢（seq 1..n 連續、schema、type、manifest 路徑形）→ **最後一行＝最新一筆**。
2. 最新一筆是 `type=correction`（營運者自己記錄了「現場不符」）→ 印更正摘要（observed_at／
   references_seq／mismatches）、**不探測 live**、exit 1——最新已知狀態就是不符。
3. `deploy`／`baseline`：抓該行 `manifest`（相對帳本 URL 解析）→ manifest 位元組 sha256 必等於
   帳行 `manifest_sha256`（帳鏈）；帳行快速核對值（`rb_hash`／`index_html`／`csp_header` 等）必與
   manifest 內值一致。
4. 逐檔：`manifest.files` 剔除 `_headers`／`_redirects`；候選網址序 `[路徑, 去 .html,
   去 index.html（留尾斜線）, 再去尾斜線]`；不跟隨轉址逐一 GET，首個「200 且 sha256 相符」即過。
5. CSP：GET `<url>/privacy`，取最後一筆 `content-security-policy` 值 trim 後 sha256，對 manifest 的
   `csp_header.value_sha256`（manifest 記「無」則 live 也必須無；一有一無＝不符）。

輸出最後一行恆為四標記之一：`VERIFY-SITE-OK (<n> compared / <k> redirect-skip / seq <s>)`
（compared 含 CSP 一項，與部署端 canary 同計）、`VERIFY-SITE-MISMATCH (…)`（前列逐檔 `✗` 行）、
`VERIFY-SITE-CORRECTION (…)`、`VERIFY-SITE-NETWORK (…)`。

exit code（本子命令自訂面）：

| code | 意義 |
| --- | --- |
| 0 | 全符：帳鏈完整，live 逐檔與 CSP 皆與最新一筆 manifest 相符 |
| 1 | 不符：檔案或 CSP 不符／帳鏈破／最新一筆是更正紀錄／帳面形不合法（帳本或 manifest 取得 200 但不可解析、schema 不符、空帳） |
| 2 | 網路／取得錯：帳本或 manifest 取不到、live 回 401/403/5xx／逾時／連線拒、CSP 探測面（/privacy）失敗；用法錯（未知旗標／位置參數／網址形錯）亦為 2 |

不符與取得錯並存時以 1 為準（不符是已確證的發現；取得錯照列）。

### 誠實界限（verify-site）

- **帳本由營運者寫入**：本命令證明的是「live 站＝營運者公開記下的那一版」，不證明那一版本身無害。
  帳本與站屬同一營運者——擋的是記錄之外的替換（託管／CDN 被竄、未入帳的部署），不擋營運者
  自己入帳並部署的版本（那屬原始碼審查與可重現建置的範圍）。
- **工具只驗自己抓到的那份**（同 N3 界線）：伺服器若只對特定使用者送不同內容，本命令察覺不到。
- **不重試**：每個候選網址一發；CDN 暫時性錯誤直接 exit 2。重跑一次命令即為重試。
- **redirect 以 3xx 探測揭露**：不跟隨轉址；全部候選都沒有 200、且有 3xx 轉往該檔候選集之外
  （如 `/landing.html` → `/`）的檔案記為 `redirect-skip`——逐筆列出、不判紅。部署端 canary（M-1）
  只對 `_redirects` 帶碼來源記 skip；本命令拿不到 `_redirects`（平台檔不在網路上），改以 3xx 探測，
  **寬於 M-1 帳面核對**——skip 數異常時請人工檢視。轉往同一檔其他候選的 3xx（平台把 `x.html`
  轉到 `x` 的網址規範化）不算轉址來源：那個檔仍須在候選裡找到 200，漂亮網址 404＝不符、5xx＝取得錯。
- **`_headers`／`_redirects` 平台設定檔不比對**：它們不以檔案形式出現在網路上；`_headers` 裡的
  CSP 改由下一條覆蓋。
- **CSP 經 /privacy**：只比 `/privacy` 回應的最後一筆 `content-security-policy` 標頭；其他路徑的
  標頭不在比對範圍內。

## 誠實界線（必讀）

1. **工具只驗自己抓到那份**：N3 驗證的是 CLI 本機 fetch 拿到的那份內容——
   若伺服器對特定瀏覽器送不同內容（針對性 MitM／DNS 投毒），本工具察覺不到。
   N3 擋的是**大規模替換**（整個站／整個 repo 被換），不是針對性攻擊（設計 L146-149＋§9）。
2. **頂層頁無 SRI**：`/sreq`／`/secret` 的頂層 HTML 沒有可用的 SRI 子資源完整性
   鏈——頁面內載入的 script 不在 N3 的 sha256 覆蓋內（整頁檔案 hash 只覆蓋
   頂層那一份字節）。
3. **信任錨＝GitHub**：N3 的比較基準是公開 repo
   （`github.com/tacet-ink/one-time-secret`）的 `SHA256SUMS`——信任鏈終點落在
   該 repo 所在平台的帳號安全；CLI 不驗證「repo 本身有沒有被入侵」。
4. **conf_code 是同一性指紋，非授權**：`submit` 成功面印的 `conf_code`
   （4 hex）＝`sha256(eph_pub ‖ slot_nonce)[:4]`——供取件端比對「內容是不是
   我要的那一份」，**不證明**內容合法性，也**不是**取件憑證（取件憑證是 token，
   單用）。
5. **內容進程序記憶體是事實**：`submit` 從白名單參照讀入值後，值就在 CLI 程序
   記憶體（投遞前）；本工具不改變「內容此前可能已進 agent／模型上下文」的事實
   （I 線界線——投遞工具已停車，本套件不承擔那一段）。
6. **eph 一用一換**：每次 `submit` 新創 ephemeral 金鑰對，用完即銷（記憶體面）；
   iv 每次 `crypto.getRandomValues` 新抽；AAD 含 slot id（`jr5e:<slot_id>`）防
   跨 slot 重放（R1 問 5/10）。

## 差異化（類別描述）

本工具在把填寫連結交給人**之前**，先驗證線上頁面與公開 repo 的 `SHA256SUMS`
一致（**verify-before-deliver**），不符即停、不給連結。同類的本機祕密遞送工具
（一次一用連結型）目前沒有這一步——多數只把「產生連結」交給使用者，頁面與
repo 是否被換，由使用者自行對帳。此處刻意以類別描述，不點名任何產品。

## 測試

```sh
npm run typecheck -w @tacet-ink/journal-cli   # tsc 零錯
npm run build -w @tacet-ink/journal-cli
npm run verify -w @tacet-ink/journal-cli      # 單元閘（段帳＋毒化）
npm run e2e -w @tacet-ink/journal-cli         # hermetic 過程層（stub＋真 PTY；零外網）
```

e2e 的 hermetic 性：本地 `/sreq` stub（`scripts/lib/devstack-stub.cjs`）＋tmp HOME
＋自 re-exec 於真 PTY（`scripts/lib/pty-run.py`）——submit 人確認走真 TTY stdin。
沙箱注意：部分沙箱對「子程序→環回臨時埠」的 egress 有攔截（本機 guard 實測），
故 e2e 網路面走 in-process（同程序 fetch 到 stub）、離線面走子程序；兩層合攏才
是完整帳。live 真值對帳（`tacet-secret verify` 對 `https://tacet.ink`）不在 hermetic
e2e 內——由 preflight probe 一發直取（對 live 的四方帳是時變量，不宜凍進 hermetic 閘）。

## 檔案

```
src/cli.ts      入口＋參數解析＋exit code 紀律
src/n3.ts       N3 三步（checkPage/n3Gate/checkAll）＋sums 解析
src/net.ts      fetch 助（timeout/size cap；零重試零快取）
src/refs.ts     env:/file: 參照＋白名單守衛
src/request.ts  request 子命令（主路徑）
src/verify.ts   verify 子命令（四方帳）
src/site.ts     verify-site 子命令（公開部署紀錄→live 逐檔比對＋CSP）
src/submit.ts   submit 子命令（人確認閘＋投遞）
src/state.ts    取件連結包（600/700；不覆蓋）
src/selftest.ts --self-test（core 0.11.0 向量，零鏡像）
scripts/verify-cli.ts   單元閘
scripts/e2e-cli.cjs     hermetic 過程層 e2e
scripts/lib/devstack-stub.cjs  /sreq 站 stub
scripts/lib/site-fixture.ts    verify-site hermetic 電池（帳本 root／live root 分路）
scripts/lib/pty-run.py  真 PTY 載具（mail-box 答列）
```
