# @tacet-ink/journal-mcp（R3c）

tacet.ink 索取祕密的 **MCP stdio server**——`request`／`verify` 兩工具。
R3b CLI（`packages/cli`）是 core；本包是薄殼：import 同一批原語（N3／refs／state／
request 語義／verify 四方帳），MCP 只加協議面＋交付決策。

## 定位與裁定

- **stdio only（零遠端 MCP 裁定）**：遠端 server＝加密只能在 server 端做→破零知識，
  且身分綁定衝突（R1 設計：身分綁定在 stdio 本機形＝本機使用者，非遠端授權推導）。
  本包不實作任何遠端 transport。
- **貼連結是主路徑**：客戶端 URL elicitation 支援仍少（10-28 報告 §四-③），所以
  交付預設＝回傳填寫連結供貼上（可交對方）；elicitation 開頁是**增強面**，
  僅在 modern（2026-07-28）客戶端宣稱 `elicitation.url` 能力時啟用，
  使用者拒絕即自動降級回貼連結。
- **零自帶加密**：加密原語（P-256 金鑰對、sha256）只 import `journal-core`；
  本包唯一自算面＝requestState 的 HMAC（在 core sha256 上手寫，HMAC 是完整性
  原語不是密碼學協議）。
- **不點名律**（10-28 §四-②）：差異化表述用功能詞（「先驗後交付」——交連結前
  先對公開 SHA256SUMS 驗站點頁），不點任何競品名。

## 工具

### `request`

產生填寫連結＋N3 驗證後交付。流程與 CLI request 一致：

1. （annual 層）解讀 `annual_token_ref`（`env:`/`file:` 參照＋白名單；值不入對話）
2. N3 閘：fetch /sreq 頁＋SHA256SUMS，雙比對；不符＝停止（不交連結、不開 slot、零 API）
3. `out` 白名單預核對（fail-early，零 slot 消耗）
4. 開 slot（core 金鑰對；canonical 相對 URL 斷言；連結以 N3 實取 origin 組裝）
5. 取回 bundle 落盤（白名單＋600；帶私鑰＋token，永不進對話）
6. 交付：

| 條件 | 交付形 |
| --- | --- |
| modern＋client 宣稱 `elicitation.url` | `InputRequiredResult`（MRTR）：`inputRequests.fill`＝`elicitation/create` url mode＋`requestState`；client 帶 `inputResponses.fill`＋`requestState` 重試收口（accept＝開頁＋交連結；decline/cancel＝降級貼連結） |
| 其餘（legacy／未宣稱／無能力） | `CallToolResult`：fill 連結＋bundle 路徑（貼連結主路徑） |

MRTR 依 spec 2026-07-28（`basic/patterns/mrtr`）：頂層 `inputResponses`＋
`requestState`（client MUST NOT 改動、原樣回帶；server 自行判讀）。
**「完成通知」面已隨 2026-07-28 退場**（R1 問 13 第 3 項移除）——本包零殘字面
（閘 `verify` [4] census）。

`requestState` 安全面（MUST integrity；本實現＝HMAC-SHA256）：32B 隨機金鑰
（`~/.tacet-secret/mcp-state.key`，0600）＋TTL 10 分鐘＋principal（本地使用者）＋
原請求參數規範摘要（跨請求重用＝digest mismatch 拒）。

### `verify`

＝CLI verify 子命令語義：/secret＋/sreq 雙頁對 SHA256SUMS 四方帳
（live sha256／sums sha256／verdict 雙列）。**MISMATCH＝verdict 結果，
`isError` 恆 false**（fail-closed 語義由文本承載）。

### 零 `submit` 工具

送出預設關的缺席面：本 server 不送任何內容；投遞＝持祕密者經 CLI
（預設關＋TTY 確認；非 TTY 直接拒）。tool 呼叫面的 confirmation 語義＝
elicitation 同意面（客戶端向人問 accept/decline；本 server 不模擬也不繞過）。

## 協議面（雙時代，零 SDK）

- **modern＝2026-07-28**（spec 源 `schema/2026-07-28/schema.ts` 為形之權威）：
  `server/discover`（`supportedVersions`＋`capabilities`＋`_meta` serverInfo）；
  per-request `_meta`（`protocolVersion`＋`clientCapabilities` 皆必填）；
  結果帶 `resultType`（`"complete"`/`"input_required"`，MUST）＋
  `_meta['io.modelcontextprotocol/serverInfo']`（SHOULD）；
  不支持版本→`-32022`（data 帶 `supported`）。
- **legacy＝2025-11-25**（`initialize` 選定，scoped 到本 stdio 過程）：
  `initialize`（版本協商，legacy 集外版本回 latest legacy）→`notifications/initialized`
  →`tools/list`→`tools/call`；結果無 `resultType`（legacy client 把缺席當 complete）。
- stdio 紀律：newline-delimited JSON；**server MUST NOT 寫 request 到 stdout**
  （server→client 互動面＝`InputRequiredResult`）；stderr 只 log；stdin EOF 退出。
- 零 SDK 的原因：`@modelcontextprotocol/sdk` 最新 stable（1.32.2，2026-10-23 測）
  停在 2025-11-25 線——2026-07-28 MRTR 新流程（頂層 `inputResponses`/
  `requestState`）registry 無 stable SDK 實作（唯一預發布 1.23.0-beta.0）；
  故協議面手寫對 spec 源，加密面照舊 import core。

## 誠實界線（必讀，同 R3b 三條）

1. **工具只驗自己抓到那份**：N3 驗證的是本 server 本機 fetch 拿到的那份內容——
   若伺服器對特定瀏覽器送不同內容（針對性 MitM／DNS 投毒），本工具察覺不到。
   N3 擋的是**大規模替換**（整個站／整個 repo 被換），不是針對性攻擊。
2. **頂層頁無 SRI**：`/sreq`／`/secret` 的頂層 HTML 沒有可用的 SRI 子資源完整性鏈——
   頁面內載入的 script 不在 N3 的 sha256 覆蓋內（整頁檔案 hash 只覆蓋頂層那一份字節）。
3. **信任錨＝GitHub**：N3 的比較基準是公開 repo 所在的 GitHub——該 repo 本身被動
   （改 SHA256SUMS）時，本工具無法察覺。

另外（MCP 面）：**elicitation 支援面依客戶端實況**——URL elicitation 的客戶端
支援仍少；不支援時主路徑＝貼連結（功能不受影響，開頁只是順手面）。

## 使用

### 直接 stdio

```sh
npm run build
node packages/mcp/dist/server.js
# stdin/stdout：newline-delimited JSON-RPC；stderr：日誌
```

### MCP 客戶端（plugin 形）

```
.claude-plugin/plugin.json   plugin manifest（name/version/description）
.mcp.json                    mcpServers：node ${CLAUDE_PLUGIN_ROOT}/dist/server.js
skills/tacet-secret/SKILL.md 使用指引
```

驗證：`claude plugin validate --strict packages/mcp`（e2e [C1]）。

### 開發

```sh
npm run typecheck -w @tacet-ink/journal-mcp   # tsc 零錯
npm run build -w @tacet-ink/journal-mcp
npm run verify -w @tacet-ink/journal-mcp      # 單測閘（含 3 牙毒化）
npm run e2e -w @tacet-ink/journal-mcp         # stdio probe（in-process 網路面＋child 離線面＋shell 面）
```

## 發布 tag 慣例（2026-10-24 裁定，承佔位 README）

多包 tag 形 `<名>-v<version>`（如 `journal-mcp-v0.1.0`）；包名禁 `v` 開頭
（防 tag 撞名）。root 包（journal-core）維持 `v*` 單包形。
`private: true`——本包不上 npm。
