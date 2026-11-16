---
description: 需要某人提供密碼、API 金鑰或 token 時使用——不要讓值貼進對話。呼叫 tacet-secret 的 request 工具開一個零知識填寫 slot（填寫連結只帶公鑰，安全可交；N3 先驗 /sreq 頁對公開 SHA256SUMS）。
---

# tacet-secret（request-secret）

向某人索取祕密（密碼／API 金鑰／token）時：

1. 呼叫 `request`（tacet-secret server）：
   - 先 N3 驗 /sreq 頁對公開 repo SHA256SUMS；不符即停止、不交連結（零 API 消耗）。
   - 通過後產生填寫連結（只帶公鑰）與本地取回連結（600）。
   - 客戶端支援 MCP URL elicitation：客戶端代為向使用者開填充頁（增強面；使用者須同意；
     拒絕即自動降級為交連結）。
   - 其餘客戶端：連結直接回傳供貼上——把**填寫連結**交給你確認過的對象。
2. 站點狀態用 `verify`：四方帳（/secret、/sreq 兩頁的 live sha256／sums sha256／verdict）。
   MISMATCH＝verdict 結果，不是 tool 錯誤。

誠實界線（對使用者照實說）：

- 工具只驗它自取的副本——server 可對特定瀏覽器送不同內容（擋大規模換頁，不擋對你的定向偽裝）；
  top-level 頁無 SRI；信任錨＝公開 repo 所在的 GitHub。
- 取回連結帶私鑰＋token：只寫本地白名單路徑（600），永不貼進對話。
- 本 plugin 的 server 不送任何內容：投遞由持祕密者經 CLI 完成（預設關、TTY＋slot 號確認）。
- stdio only（零遠端 MCP 裁定）：遠端 server 端做加密＝破零知識＋身分綁定衝突。
- MCP URL elicitation 支援面依客戶端實況誠實表述（支援仍少；不支援時主路徑＝貼連結）。
