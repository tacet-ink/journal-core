/**
 * tools.ts — 兩工具定義（request／verify）。
 *
 * 零 submit 工具＝送出預設關的缺席面（R1 問 13：本 server 不送任何內容；
 * 投遞＝持祕密者經 CLI，預設關＋TTY 確認——MCP 面沒有 submit 可調）。
 * 文案不點名律（10-28 報告 §四-②）：差異化表述用「先驗後交付」類功能詞，
 * 不點任何競品名（單測 [7d] 對帳）。
 */
import type { Tool } from './protocol.ts';

const TTL_ENUM: readonly string[] = ['10m', '1h', '3d', '7d', '14d'];

export const TOOL_REQUEST: Tool = {
  name: 'request',
  description:
    '需要某人提供密碼／API 金鑰／token 時使用——不要把值貼進對話。' +
    '工具先對公開 repo SHA256SUMS 驗 /sreq 頁（N3），通過後開一個填寫 slot 並產生填寫連結' +
    '（只帶公鑰，可安全貼給對方）；取回連結（帶私鑰＋token）只寫本地白名單路徑（600），永不進對話。' +
    '在宣稱 MCP URL elicitation 支援的客戶端上，客戶端會代為向使用者開填充頁（增強面，需使用者同意；' +
    '拒絕即自動降級為交連結）；其餘客戶端直接回傳連結供貼上（主路徑）。' +
    '本工具不送任何內容——投遞由 CLI 完成（預設關、TTY 確認）。',
  inputSchema: {
    type: 'object',
    properties: {
      ttl: {
        type: 'string',
        enum: TTL_ENUM,
        description: 'slot 時效（免費：10m/1h/3d/7d，預設 7d；14d 需 annual）',
      },
      annual: { type: 'boolean', description: 'annual 層（14d 必填；需 annual_token_ref）' },
      annual_token_ref: {
        type: 'string',
        description: 'annual token 參照 env:NAME 或 file:PATH（白名單；值不入本對話）',
      },
      out: {
        type: 'string',
        description: '取回 bundle 寫入 PATH 或 file:PATH（白名單；預設＝工具狀態目錄）',
      },
      base: { type: 'string', description: '站點 base（預設 https://tacet.ink）' },
      sums: {
        type: 'string',
        description: 'SHA256SUMS 來源（URL 或本地路徑；預設＝公開 repo main/SHA256SUMS）',
      },
    },
    additionalProperties: false,
  },
};

export const TOOL_VERIFY: Tool = {
  name: 'verify',
  description:
    '驗站點（預設 https://tacet.ink）的 /secret 與 /sreq 兩頁對公開 repo SHA256SUMS 四方帳' +
    '（live sha256／sums sha256／verdict 雙列）。在把填寫連結交給對方前用它確認站點未被換頁。' +
    'verdict 是結果而非錯誤：MISMATCH 時 isError 恆 false（fail-closed 語義，見返回文本）。',
  inputSchema: {
    type: 'object',
    properties: {
      base: { type: 'string', description: '站點 base（預設 https://tacet.ink）' },
      sums: {
        type: 'string',
        description: 'SHA256SUMS 來源（URL 或本地路徑；預設＝公開 repo main/SHA256SUMS）',
      },
    },
    additionalProperties: false,
  },
};

export const TOOLS: readonly Tool[] = [TOOL_REQUEST, TOOL_VERIFY];
