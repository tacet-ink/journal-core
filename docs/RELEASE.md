# Release / 上架動線（RELEASE）

適用範圍：`@tacet-ink/journal-core` monorepo（root＋`packages/cli`＋`packages/mcp`）。
R5 上架（t_7bf0cf9a，0.11.0）定稿；自本版起所有 release 走本文動線。

## 1. 發佈通道：tag → GitHub OIDC CI（唯一）

- 唯一 publish 通路＝`.github/workflows/publish.yml`（OIDC trusted publishing；repo 零長效
  npm 憑證）：tag push → 該 arm 跑 typecheck/build/verify → `npm publish --provenance`
  （Actions OIDC 換短效 token）。
- 任何卡／任何人不於 repo 外持 npm 憑證直發——無此通路且禁（R5 否決案）。
- 0.7.0 實證 run 42480772813（root arm）；0.10.0 同通道（11-12）。

### tag 規約（2026-10-24 裁定；README「發佈 tag 規約」同源）

| tag 形 | 目標包 | 例 |
| --- | --- | --- |
| `v<version>` | `@tacet-ink/journal-core`（root） | `v0.11.0` |
| `journal-cli-v<version>` | `@tacet-ink/journal-cli` | `journal-cli-v0.11.0` |
| `journal-mcp-v<version>` | `@tacet-ink/journal-mcp` | `journal-mcp-v0.11.0` |

- 多包形 `<名>-v<version>`；包名禁 `v` 開頭（防 tag 撞名）。
- tag 尾段（`v`／`-v` 後）＝對應 workspace `package.json` `version`——publish.yml 機械對帳，
  不符即 fail（不發）。
- 一 tag 一 run；推 tag 前該 arm 的本地等價步（typecheck/build/verify）須在 commit tip 綠
  （見 §6 驗證基準）。

## 2. 每包 npmjs.com 前置（Trusted Publisher）

每包各需一組 **Trusted Publisher**（package settings → Trusted Publisher → GitHub
Actions）：repository `tacet-ink/journal-core`、workflow `publish.yml`、environment `npm`。

- `@tacet-ink/journal-core`：已設（0.7.0 起）。
- `@tacet-ink/journal-cli`／`@tacet-ink/journal-mcp`：**0.11.0 新包**——先在 `@tacet-ink`
  scope 建包，再各設 Trusted Publisher（動線＝R5-HANDOFF.md §0）。未完成前，兩包 tag 的
  run 會在 publish 步紅（401/403）；完成後重跑該 run（`gh run rerun <id>`）即發——tag
  與 commit 已就位，零 git 動作。

## 3. tag 檢對帳（R5 時點，2026-11-16）

| 包 | version | tag | npm 狀態 | 備註 |
| --- | --- | --- | --- | --- |
| `@tacet-ink/journal-core` | 0.11.0 | `v0.11.0` | latest 0.10.0（11-12） | 0.11.0 由本卡 tag push 觸發 CI 發 |
| `@tacet-ink/journal-cli` | 0.11.0 | `journal-cli-v0.11.0` | 未建包 | 待 npmjs 建包＋Trusted Publisher（chris）→ run rerun |
| `@tacet-ink/journal-mcp` | 0.11.0 | `journal-mcp-v0.11.0` | 未建包 | 同上；**registry 發表前必完成**（§4 順序） |

歷史 0.1.0–0.10.0：`git tag` 與 `npm view @tacet-ink/journal-core versions` 對帳
（0.1.0–0.1.2 無 tag＝publish-on-tag 慣例 0.1.3 才確立；npm 0.4.1 無對應 tag＝舊手動
通道殘值，不回填）。

## 4. 官方 MCP Registry（io.github.tacet-ink/*）

- `packages/mcp/server.json`（name `io.github.tacet-ink/tacet-secret`；packages[0]＝npm
  `@tacet-ink/journal-mcp` 0.11.0；stdio only——零遠端 MCP 裁定，無 remotes 欄）。
- **名恆等三點**：`package.json` `mcpName` ≡ `server.json` `name` ≡ registry server 名；
  registry 拉 npm 包核 `mcpName`，缺／不符＝publish 拒。
- 順序鐵律：**先 npm（`journal-mcp-v0.11.0` tag run 綠、npm 可查
  `@tacet-ink/journal-mcp@0.11.0`），再 `mcp-publisher publish`**。
- 動線（chris 親行；R5-HANDOFF.md §1）：`mcp-publisher init`（模板已落＝本卡）→
  `login`（GitHub OAuth，tacet-ink 身分——io.github.tacet-ink 命名空間經 GitHub org 核）→
  `publish`（`--dry-run` 本卡已綠）。
- 發表後驗證（免憑證讀）：
  `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.tacet-ink/tacet-secret"`

## 5. 其他上架面（材料皆在本 repo）

- **Claude plugin directory**：bundle＝`packages/mcp`（`.claude-plugin/`＋`skills/`＋
  `.mcp.json`）。提交＝developer portal `claude.ai/directory/manage`（Plugin bundle；
  plugin path＝`packages/mcp`；repo 已公開）——chris 親行（R5-HANDOFF.md §2）；
  Data handling 答案＝「送往 tacet.ink」（逐題文案同節）。本地驗證＝
  `claude plugin validate --strict packages/mcp`（e2e [C1] 同形）。
- **skills.sh／agentskills**：同一份 `packages/mcp/skills/tacet-secret/SKILL.md`
  （frontmatter `name`＋`description`）；投遞清單＝R5-HANDOFF.md §3。
- **awesome-mcp-servers PR**：entry 行＋插入位＋PR 本文＝R5-HANDOFF.md §4（不點名律；
  類別描述形）。
- **one-time-secret topics**：清單（10 個、類別描述形、0→10 對帳）＝R5-HANDOFF.md §5
  ＋ R5 卡 comment（定稿）；本卡無 API 憑證車道＝chris dashboard 手動。

## 6. 驗證基準（本卡執行面）

- `npm pack --dry-run`（cli／mcp 兩包）零錯＋檔案清單含 LICENSE／dist 骨架。
- `mcp-publisher` dry-run 綠（server.json 合 schema 2025-12-11）。
- `claude plugin validate --strict packages/mcp` 綠（R3c 3bis 閘 [C1]）。
- 全閘（root typecheck/verify/build＋dts-fixture＋subpath probe＋cli/mcp typecheck/
  build/verify/e2e）於 commit tip 綠——pass 數記入 handoff。
- 交接清單齊＝R5-HANDOFF.md 逐項（§0–§5）。
