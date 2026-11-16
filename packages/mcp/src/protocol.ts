/**
 * protocol.ts — MCP 雙時代協議面（2026-07-28 modern＋2025-11-25 legacy）。
 *
 * 零 SDK（手寫對 spec 源）：官方 TS SDK 最新 stable（1.32.2，2026-10-23 測）
 * 停在 2025-11-25 線——2026-07-28 MRTR 新流程（頂層 inputResponses/requestState、
 * 完成通知面退場）registry 無 SDK 實作。形以 modelcontextprotocol/specification@main
 * schema/2026-07-28/schema.ts 為權威（2026-11-16 實讀錨定，R3c 卡 comment 記錄）。
 *
 * 雙時代規則（spec 2026-07-28 basic/versioning）：
 *   - modern 請求＝per-request _meta（protocolVersion＋clientCapabilities 皆必填）；
 *     不支持版本 → -32022（data 帶 supported 清單）
 *   - initialize 請求選 legacy 語義（scoped 到本 stdio 過程）
 *   - 結果面：2026-07-28 結果必帶 resultType（"complete"/"input_required"）；
 *     _meta['io.modelcontextprotocol/serverInfo'] SHOULD
 *   - stdio＝newline-delimited JSON；server MUST NOT 寫 request 到 stdout
 *     （server→client 互動面＝InputRequiredResult 結果，MRTR）；stdin EOF → 退出
 */

export const PROTO_MODERN = '2026-07-28';
export const LEGACY_VERSIONS: readonly string[] = [
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
  '2024-10-07',
];
export const LEGACY_LATEST = '2025-11-25';

export const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';
export const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
export const META_CLIENT_INFO = 'io.modelcontextprotocol/clientInfo';
export const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';

/** serverInfo（self-reported；供展示/日誌，非安全判定依據——spec 明訂） */
export const SERVER_INFO = Object.freeze({ name: 'tacet-secret', version: '0.11.0' });

export const SERVER_CAPABILITIES = Object.freeze({ tools: { listChanged: false } });

export const INSTRUCTIONS =
  'tacet-secret — 向某人索取祕密（密碼／API 金鑰／token）而不讓值進入對話：' +
  'request 開填寫 slot（先 N3 驗 /sreq 頁對公開 repo SHA256SUMS；填寫連結只帶公鑰）；' +
  'verify 驗站點兩頁（/secret、/sreq）對公開 SHA256SUMS 四方帳。' +
  '本 server 不送任何內容：投遞由持祕密者經 CLI 完成（預設關、TTY 確認）。';

/** JSON-RPC 錯誤碼（-32022＝MCP UnsupportedProtocolVersionError） */
export const ERR_PARSE = -32700;
export const ERR_INVALID_REQUEST = -32600;
export const ERR_METHOD_NOT_FOUND = -32601;
export const ERR_INVALID_PARAMS = -32602;
export const ERR_INTERNAL = -32603;
export const ERR_UNSUPPORTED_VERSION = -32022;

export class ProtocolError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
    this.data = data;
  }
}

/** 能力旗標：spec 形＝JSONObject 存在式（schema 2026-07-28:769-773；「空物件即代表支援」）；寬鬆 boolean 形兩吃 */
export type CapFlag = boolean | Record<string, unknown>;

/** 客戶端能力（per-request _meta 面；空物件＝無任何選用能力） */
export interface ClientCapabilities {
  elicitation?: { form?: CapFlag; url?: CapFlag };
  [key: string]: unknown;
}

/** elicitation 回應（MRTR 重試經頂層 inputResponses 攜帶） */
export interface ElicitResult {
  action: 'accept' | 'decline' | 'cancel';
  content?: Record<string, string | number | boolean | string[]>;
}

export interface InputRequests {
  [key: string]: { method: string; params: Record<string, unknown> };
}

/** input_required 結果（MRTR：inputRequests 與 requestState 至少一欄在場） */
export interface InputRequiredResult {
  resultType: 'input_required';
  inputRequests?: InputRequests;
  requestState?: string;
  _meta?: Record<string, unknown>;
}

export interface Tool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

/** legacy CallToolResult（2025-11-25：無 resultType；client 把缺席當 "complete"） */
export interface LegacyCallToolResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export function resultResponse(id: number | string, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}

export function errorResponse(
  id: number | string | null,
  code: number,
  message: string,
  data?: unknown,
): Record<string, unknown> {
  const err: Record<string, unknown> = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id, error: err };
}
