# journal-core（默·Tacet 共享核心）

「一本伺服器連你是誰都不知道的日記」的密碼學與伺服器原語層。以 `@tacet-ink/journal-core` 開源（npm＋GitHub），同時作為 tacet/sennight/vestige 三 fork 的共享核心（tacet 自 t_6ee8eadf 起走 npm 依賴 `@tacet-ink/journal-core@0.1.5` 精確雙鎖＋preprepare `.core-pkg` 手術；sennight/vestige 仍未接 core）。

- **上線（2026-09-11）**：npm `@tacet-ink/journal-core`（public、zero runtime deps、metadata 全齊）＋ GitHub `tacet-ink/journal-core`（public/MIT/main，desc＋homepage＋8 topics 已設）；**現行 registry 0.1.6（2026-10-04 發布，OIDC workflow success）＝外審轉化批載具**（卡A hex fail-closed＋空 identity 拒絕＋ERR_PIN_EMPTY／卡B 限流 UPSERT 單句＋engines >=24.7.0＋CI typecheck＋actions SHA 釘選／卡C 並行 PBKDF2＋b64 分塊＋CORS Max-Age／尾卡 N-7 never-match＋isCipherFor 守衛；verify 249）；tacet consumer＝0.1.6 精確雙鎖（ccc619e）
- **歷史**：已重寫（作者全 `tacet-ink <tacetink.csd@gmail.com>`、跨產品洩漏摘除、tree hash 與重寫前逐位元組一致）；重寫前備份：`/srv/dropbox/csoft/.core-backup-local/`＋`/tmp/hermes/core-oss/backup.git`
- **驗證閘**：`npm run verify`（374 斷言對真模組；t_7710c766 前實值 131——127 是 0.1.2 期漂移字面，t_b91ed07f 後 225、t_7361b68c 後 245、t_580f9c54 後 249、t_2e4b713f 卡①後 337、t_42626eda 卡④後 374）；改任何原語必跑
- **SSH**：`~/.ssh/id_ed25519_tacet_ink`＋Host alias `github-tacet-ink`；remote 名 `github`
- **repo 描述/topics**：REST API＋`GITHUB_TOKEN`（tacet/.env）——SSH 做不了元資料
- **消費者契約**：TS 源碼發行；npm 安裝後**必走打包器**（node strip-types 對 node_modules 內檔案是禁區——真樹落 `.core-pkg` realpath 手術後即解禁）
- **鐵律承襲**：extractable 鐵律／帶內版本化（升級 KDF＝換前綴）／opt-in 未配置即拒／unwrap 跨前綴恆 null 不拋——詳 README「設計」節