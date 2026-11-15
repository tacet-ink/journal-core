# @tacet-ink/journal-cli

**占位空殼**（0.11.0 鋪底；R3a t_c4ecb987；**實作歸 R3b 卡**——本面零程式碼）。

- 加密一律 `import` `@tacet-ink/journal-core`（root 或子路徑；`./secret/jr5s`／`./secret/jr5e` 在場）——
  自帶加密實作禁（request-secret brief L132 裁定）；值不進模型上下文（L127-137 設計原則）。
- `private: true`——R3b 實作落地前不上 npm。
- 發佈 tag 規約（2026-10-24 裁定）：多包 tag 形 `<名>-v<version>`（如 `journal-cli-v0.1.0`）；
  包名禁 `v` 開頭（防 tag 撞名）。root 包（journal-core）維持 `v*` 單包形。
