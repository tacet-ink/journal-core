# 交棒慣例（card handoff）

卡片（`card/t_*` 分支）交付動線的慣例條目。交付＝實作＋閘＋commit 完成、送審前。

- **tip 恆 push remote refs（card/t_* 命名）**：交付前把分支 tip 恆推上 remote 同命名 `card/t_*` ref
  （例：`git push github HEAD:card/t_<id>`）。worktree／共用樹態的分支 git 物只存本地樹——本地樹毀於
  運維／磁碟事故時物件隨樹滅，remote ref 是交付 tip 的唯一恆存證據（2026-11-12 ops 樹整棵消失事故實證：
  本地 worktree 分支 refs＋物件全滅，交付面靠對照錨重建；tip 在 remote 則事故面收斂為零）。
