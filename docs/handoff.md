# 交棒慣例（card handoff）

卡片（`card/t_*` 分支）交付動線的慣例條目。交付＝實作＋閘＋commit 完成、送審前。

- **tip 恆 push remote refs（`card/t_*` 命名）**：交付前把分支 tip 恆推上 remote 同命名 `card/t_*` ref
  （例：`git push github HEAD:card/t_<id>`）。worktree／共用樹態的分支 git 物只存本地樹——本地樹毀損時物件隨樹滅，
  remote ref 是交付 tip 的唯一恆存證據（2026-11-12 本地樹整滅事故後收斂為本規則；內部細節見團隊記錄）。
- **收尾禁裸 `git add -A`**：worktree 內 symlink（如無尾斜線的 `node_modules`）不吃 `node_modules/` ignore，
  裸 `git add -A` 會把 symlink 收進暫存；收尾用顯式路徑或 `git add -u`。
