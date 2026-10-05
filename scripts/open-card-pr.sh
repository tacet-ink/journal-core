#!/usr/bin/env bash
# open-card-pr.sh — journal-core 同 repo card branch PR 產生器。
#
# Usage: open-card-pr.sh <branch> <title> <body-file>
#   branch     card branch（head），例：card/t_046fe36f-ci-runner
#   title      PR 標題
#   body-file  PR body 純文字檔（完整讀入）
#
# 行為：純 curl POST /repos/tacet-ink/journal-core/pulls
#   （head=<branch>、base=main、Token 取自 /srv/dropbox/csoft/tacet/.env 的
#    GITHUB_TOKEN）。成功時 print PR 編號＋URL；僅 print，不做其他事
#   （不 push branch、不合併、不關閉）。
set -euo pipefail

REPO_URL="https://api.github.com/repos/tacet-ink/journal-core/pulls"
# 位置面：預設為本機絕對路徑（host-specific）；其他環境以 ENV_FILE 覆寫（t_046fe36f r2）
: "${ENV_FILE:=/srv/dropbox/csoft/tacet/.env}"

BRANCH="${1:?usage: open-card-pr.sh <branch> <title> <body-file>}"
TITLE="${2:?missing PR title}"
BODY_FILE="${3:?missing body file}"

[ -f "$BODY_FILE" ] || { echo "body file not found: $BODY_FILE" >&2; exit 1; }

TOKEN="$(grep '^GITHUB_TOKEN=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
[ -n "$TOKEN" ] || { echo "GITHUB_TOKEN not found in $ENV_FILE" >&2; exit 1; }

PAYLOAD="$(jq -n --arg title "$TITLE" --arg head "$BRANCH" --arg base main \
  --rawfile body "$BODY_FILE" \
  '{title: $title, head: $head, base: $base, body: $body}')"

RESP="$(curl -sS -X POST \
  -H "Authorization: token ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -d "$PAYLOAD" \
  "$REPO_URL")"

NUM="$(printf '%s' "$RESP" | jq -r '.number // empty')"
if [ -n "$NUM" ]; then
  URL="$(printf '%s' "$RESP" | jq -r '.html_url')"
  echo "PR number: $NUM"
  echo "PR url: $URL"
else
  # 失敗（422 常見＝branch 已有 PR／無 diff）：print API 訊息不做事
  printf '%s' "$RESP" | jq -r 'if .message then .message
    else . end' >&2
  exit 1
fi