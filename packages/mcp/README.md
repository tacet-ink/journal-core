# @tacet-ink/journal-mcp

**占位空殼**（0.11.0 鋪底；R3a t_c4ecb987；**實作歸 R3c 卡**——本面零程式碼）。

- MCP stdio 工具面：agent 只拿最小能力（10-23 情境文件 §2-2 三原則；值不進模型上下文）。
- 加密一律 `import` `@tacet-ink/journal-core`（root 或子路徑；`./secret/jr5s`／`./secret/jr5e` 在場）——
  自帶加密實作禁（request-secret brief L132 裁定）。
- `private: true`——R3c 實作落地前不上 npm。
- 發佈 tag 規約（2026-10-24 裁定）：多包 tag 形 `<名>-v<version>`（如 `journal-mcp-v0.1.0`）；
  包名禁 `v` 開頭（防 tag 撞名）。root 包（journal-core）維持 `v*` 單包形。
