# R5 上架——chris 親行清單（t_7bf0cf9a）

本卡（R5）已完成的機械面：npm 三包 tag 已推（對帳＝docs/RELEASE.md §3）、
`server.json` 實落＋dry-run 綠、plugin bundle 終檢、PR／topics 材料備齊（下方附錄）。
以下各項需帳號／憑證／互動親行；逐項列材料與動線。

## §0. 前置（§1 registry 之前）：npmjs.com 建兩新包＋Trusted Publisher

1. 登入 npmjs.com（`@tacet-ink` scope owner 帳號）。
2. 建 `@tacet-ink/journal-cli` 與 `@tacet-ink/journal-mcp`（Add a package；scope 已存在）。
3. 每包各設 **Trusted Publisher**：Package settings → Trusted Publisher → GitHub Actions →
   repository `tacet-ink/journal-core`、workflow `publish.yml`、environment `npm`
   （與 journal-core 既有設法同形）。
4. 完成後：Actions 頁重跑兩筆失敗 run（`gh run rerun <run id>`；或
   Settings → Actions → 該 run → Re-run jobs）。tag 與 commit 已就位＝零 git 動作。
   驗證：`npm view @tacet-ink/journal-cli version`／`... journal-mcp version` 回 0.11.0。

## §1. 官方 MCP Registry（mcp-publisher；login＝chris 親行）

**順序鐵律：等 `@tacet-ink/journal-mcp@0.11.0` 已上 npm（§0 完成）再發 registry。**

1. 安裝：`npm i -g mcp-publisher`（或 `brew install mcp-publisher`）。
2. `cd packages/mcp`（`server.json` 已落 repo，無需再 init；改 metadata 才需重跑）。
3. `mcp-publisher login`——GitHub OAuth 互動，**以 tacet-ink 身分登入**
   （io.github.tacet-ink 命名空間經 GitHub org 核對；login 身分須對該 org 有權）。
4. `mcp-publisher publish`（本地 dry-run 本卡已綠：`mcp-publisher publish --dry-run`）。
5. 驗證（免憑證）：
   `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.tacet-ink/tacet-secret"`
   回 JSON 含 `"name":"io.github.tacet-ink/tacet-secret"` 即成。
6. 版本狀態管理（日後）：`mcp-publisher status`（deprioritize／restore／deprecate）。

## §2. Claude plugin directory（提交＝chris 親行）

入口：**developer portal `claude.ai/directory/manage`**（舊 Console form 已遷；
官方文檔 https://claude.com/docs/plugins/submit）。

1. 前置：
   - 提交帳號所在 Claude 組織＝**可提交 plan**（付費；plan/role 見官方
     「who can submit to the directory」節）。
   - 該組織的 **GitHub 帳號連上 claude.ai**，且該帳號對
     `tacet-ink/journal-core` **有 push 權**（portal 硬查；repo 已公開✓）。
2. 提交流程（portal 逐 step）：
   - **Submit new → Plugin bundle**。
   - **Source**：Repository＝`tacet-ink/journal-core`；**Plugin path＝`packages/mcp`**
     （含 `.claude-plugin/plugin.json` 的資料夾）；Branch or tag＝留空
     （跟 default branch main）或釘 `v*` tag。
   - **Validate**（portal 校驗；本地等價＝`claude plugin validate --strict packages/mcp`，
     e2e [C1] 已綠）。
   - **Listing details**：讀自 `plugin.json`＋`packages/mcp/README.md`（要改先改 repo 再
     重 Validate）。
   - **Data handling**（逐題答案，文案照抄）：
     - 讀/存個人資料？—「是。祕密明文只在持祕密者本地：CLI 寫入使用者白名單路徑；
       取回 bundle（私鑰＋token）落本地 state 目錄（0600）。本 plugin 不存雲端。」
     - 送往 declared connectors 以外的服務？—「僅送往 **tacet.ink**（使用者的 Tacet
       服務）：明文在使用者瀏覽器本地 AES-256-GCM 加密後才過線，server 只存密文、
       永不見明文；plugin 的 MCP server 本機 stdio 運行，不向任何第三方傳內容。」
     - 資料保存多久？—「祕密一次讀取即燒毀（read-once）；server 端密文自動 purge；
       本地 bundle 由使用者刪除。」
     - 18 歲以下？—「否。」
   - **Compliance**：contact email＋四項 acknowledgements。
   - **Review and submit**：選 GitHub push webhook（repo admin 設定）或 scheduled check。
3. 提交後：自動安全掃描＋人工審查；上線後 **Usage 分頁安裝數＝第一個量測點**
   （研究 §C2；非本卡 KPI）。
4. 不另提 MCP connector：本 server＝本機 stdio（零遠端 MCP 裁定）——官方只要求
   「你運行的 remote MCP server」才需 connector 提交。

## §3. skills.sh／agentskills（投遞清單＋提交文檔）

同一份 SKILL.md（`packages/mcp/skills/tacet-secret/SKILL.md`；frontmatter 已帶
`name`＋`description`——skills.sh 分佈形要求，本卡補）。

- **skills.sh**（vercel-labs/skills CLI；無 submit 按鈕＝community 目錄）：
  - 直接安裝（repo 已公開即生效，零動作）：
    `npx skills add https://github.com/tacet-ink/journal-core/tree/main/packages/mcp/skills/tacet-secret`
  - 進 leaderboard 索引：照 `vercel-labs/skills` repo 的 contribution 指引登記
    （issue/PR 形式以該 repo 現況為準）；未登記也能被 `npx skills find` 收錄。
  - 注意：`npx skills add <owner>/<repo>`（repo 根）形要求 SKILL.md 在 repo 根＝
    本 repo 不適用（monorepo）——用上面的 direct-path 形。
- **agentskill.sh**（提交頁 https://agentskill.sh/submit）：
  - 「Import from a GitHub repository or paste a direct link to any SKILL.md file」：
    貼 `https://raw.githubusercontent.com/tacet-ink/journal-core/main/packages/mcp/skills/tacet-secret/SKILL.md`
    （或 repo 路徑）。
  - 所有權標記＝Settings 連 GitHub（tacet-ink org 或 chris 帳號）→ auto-claim；daily sync
    自動跟（可加 webhook `https://agentskill.sh/api/webhooks/github` push 事件＝即時）。
- 描述面紀律（研究 B3）：SKILL.md `description` 已寫觸發時機（「需要某人提供密碼、
  API 金鑰或 token 時使用——不要讓值貼進對話」）＝agent 選它的決定面，勿稀釋。

## §4. awesome-mcp-servers PR（不點名律照；PR 本文照 repo 慣例）

材料＝下方附錄 A（entry 行）＋附錄 B（PR 標題/本文）。動線（chris 或指定操作人）：

1. Fork `wong2/awesome-mcp-servers`。
2. 在 fork 的 README「Community Servers」段插入附錄 A 一行——**字母序位置：
   `**[TalentoHQ]` 之前**（該段最後一條 S 開頭 entry 之後；以 fork 當下 README 為準，
   行號會漂，認 anchor 行）。
3. 開 PR：標題/本文照附錄 B（repo 無 PR 模板＝慣例即簡短本文）。

## §5. tacet-ink/one-time-secret topics（dashboard 手動；API 無憑證車道）

- 本卡 GitHub 憑證車道＝SSH alias（git push 用），無 API token／gh／vault 登入＝
  API 面不可達（卡 §3.6 備案：轉 chris dashboard 手動）。
- 動線：`github.com/tacet-ink/one-time-secret` → Settings → About → **Topics**。
- 清單（10 個、類別描述形；現在 0 個→做完 10 個對帳）——逐個輸入：

  ```
  one-time-secret
  secret-sharing
  zero-knowledge
  end-to-end-encryption
  ephemeral
  webcrypto
  sha256
  static-site
  single-file
  privacy
  ```

  （GitHub topics 只收 lowercase／連字號；上表即正形。）

---

## 附錄 A. awesome-mcp-servers entry 行（單行，插 Community Servers 段）

```
- **[tacet-secret](https://github.com/tacet-ink/journal-core/tree/main/packages/mcp)** - Ask someone for a password, API key, or token without pasting the value into the chat: `request` opens a zero-knowledge fill-in link (public key only; the page is verified against a public SHA256SUMS before delivery), `verify` cross-checks the site's two pages. Stdio only — no remote MCP.
```

## 附錄 B. PR 標題／本文

**標題**：Add tactet-secret (zero-knowledge secret request, stdio MCP)

**本文**：

```
Adds `tacet-secret` (tacet.ink) to Community Servers.

A stdio MCP server for requesting passwords / API keys / tokens from another
person without pasting values into the chat: `request` produces a
zero-knowledge fill-in link (public key only) after verifying the /sreq page
against a public SHA256SUMS; `verify` cross-checks the site's pages against
the manifest. Stdio only — no remote MCP (secrets never transit a third
party).

- Repo: https://github.com/tacet-ink/journal-core (packages/mcp)
- npm: @tacet-ink/journal-mcp
```
