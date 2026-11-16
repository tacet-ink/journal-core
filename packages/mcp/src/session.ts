/**
 * session.ts — MCP 會話狀態機（per stdio process）。
 *
 * era 判定（spec 2026-07-28 basic/versioning 雙時代規則）：
 *   - server/discover：恆 modern（無 version negotiation；不支持面由 client 側處理）
 *   - initialize：選 legacy（scoped 到本過程）；protocolVersion=2026-07-28 進 initialize
 *     是 malformed（-32602——modern 走 stateless _meta 流程或 discover）
 *   - 其餘方法：已建 legacy 會話 → legacy；否則 per-request _meta 必填
 *     （protocolVersion＋clientCapabilities）；缺 _meta → -32600（era 歧義）；
 *     _meta 在場但缺欄 → -32602；不支持版本 → -32022（data.supported）
 * 結果面：modern 結果恆帶 resultType（MUST）＋_meta serverInfo（SHOULD）；
 *   legacy 結果無 resultType（2025-11-25 schema）。
 * 通知（無 id）：零回應（spec MUST）；cancelled 記日誌（本 server 請求為單次 fetch
 *   鏈，無可中斷長工作——誠實不聲稱已中止）。
 * server MUST NOT 寫 request 到 stdout（本類只產 response）；stdin EOF → 過程退出。
 */
import {
  ERR_INVALID_PARAMS,
  ERR_INVALID_REQUEST,
  ERR_METHOD_NOT_FOUND,
  ERR_PARSE,
  ERR_UNSUPPORTED_VERSION,
  LEGACY_LATEST,
  LEGACY_VERSIONS,
  META_CLIENT_CAPABILITIES,
  META_PROTOCOL_VERSION,
  META_SERVER_INFO,
  PROTO_MODERN,
  INSTRUCTIONS,
  SERVER_CAPABILITIES,
  SERVER_INFO,
  ProtocolError,
  errorResponse,
  resultResponse,
  type ClientCapabilities,
  type ElicitResult,
  type LegacyCallToolResult,
} from './protocol.ts';
import { TOOLS } from './tools.ts';
import {
  handleRequestTool,
  type Era,
  type RequestOutcome,
} from './request-tool.ts';
import { handleVerifyTool, type VerifyOutcome } from './verify-tool.ts';

export interface SessionDeps {
  onLog?: (line: string) => void;
}

interface EraContext {
  era: Era;
  caps: ClientCapabilities | null;
}

interface InJson {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

export class McpSession {
  private legacyMode = false;
  private legacyVersion: string | null = null;
  private readonly onLog?: (line: string) => void;

  constructor(deps: SessionDeps = {}) {
    this.onLog = deps.onLog;
  }

  /** 處理一行的 JSON-RPC；回傳要寫到 stdout 的一行（response），null＝不寫（通知/空行） */
  async handleLine(raw: string): Promise<string | null> {
    const line = raw.trim();
    if (line.length === 0) return null;
    let msg: InJson;
    try {
      msg = JSON.parse(line) as InJson;
    } catch {
      return JSON.stringify(errorResponse(null, ERR_PARSE, 'Parse error'));
    }
    if (typeof msg !== 'object' || msg === null || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      return JSON.stringify(errorResponse(null, ERR_INVALID_REQUEST, 'Invalid Request'));
    }
    const params: Record<string, unknown> =
      msg.params && typeof msg.params === 'object' && !Array.isArray(msg.params)
        ? (msg.params as Record<string, unknown>)
        : {};
    if (msg.id === undefined || msg.id === null || typeof msg.id === 'object') {
      // 通知：MUST NOT 回應
      this.onLog?.(`notification ${msg.method}（零回應；本 server 請求為單次 fetch 鏈，無可中斷長工作）`);
      return null;
    }
    const id = msg.id as number | string;
    try {
      const result = await this.dispatch(msg.method, params);
      return JSON.stringify(resultResponse(id, result));
    } catch (e) {
      if (e instanceof ProtocolError) {
        return JSON.stringify(errorResponse(id, e.code, e.message, e.data));
      }
      this.onLog?.(`internal error on ${msg.method}: ${e instanceof Error ? e.message : String(e)}`);
      return JSON.stringify(
        errorResponse(id, -32603, 'Internal error', undefined),
      );
    }
  }

  private eraContext(params: Record<string, unknown>): EraContext {
    if (this.legacyMode) return { era: 'legacy', caps: null };
    const meta =
      params._meta && typeof params._meta === 'object' && !Array.isArray(params._meta)
        ? (params._meta as Record<string, unknown>)
        : null;
    if (!meta) {
      throw new ProtocolError(
        ERR_INVALID_REQUEST,
        'modern 請求必帶 _meta（io.modelcontextprotocol/protocolVersion＋clientCapabilities）；legacy 客戶端請先發 initialize',
      );
    }
    const pv = meta[META_PROTOCOL_VERSION];
    const caps = meta[META_CLIENT_CAPABILITIES];
    if (typeof pv !== 'string' || caps === undefined) {
      throw new ProtocolError(
        ERR_INVALID_PARAMS,
        `_meta 必帶 ${META_PROTOCOL_VERSION}（string）與 ${META_CLIENT_CAPABILITIES}（object）`,
      );
    }
    if (typeof caps !== 'object' || caps === null || Array.isArray(caps)) {
      throw new ProtocolError(ERR_INVALID_PARAMS, `${META_CLIENT_CAPABILITIES} 需為物件`);
    }
    if (pv !== PROTO_MODERN) {
      throw new ProtocolError(
        ERR_UNSUPPORTED_VERSION,
        `不支持的協議版本：${pv}`,
        { supported: [PROTO_MODERN], requested: pv },
      );
    }
    return { era: 'modern', caps: caps as ClientCapabilities };
  }

  private wrapModern(core: object): Record<string, unknown> {
    return { resultType: 'complete', ...core, _meta: { [META_SERVER_INFO]: SERVER_INFO } };
  }

  private wrapToolResult(ctx: EraContext, core: LegacyCallToolResult): Record<string, unknown> {
    return ctx.era === 'modern' ? this.wrapModern(core) : { ...core };
  }

  private dispatch(method: string, params: Record<string, unknown>): Promise<unknown> {
    switch (method) {
      case 'server/discover':
        return Promise.resolve({
          resultType: 'complete',
          supportedVersions: [PROTO_MODERN],
          capabilities: SERVER_CAPABILITIES,
          instructions: INSTRUCTIONS,
          _meta: { [META_SERVER_INFO]: SERVER_INFO },
        });
      case 'initialize':
        return Promise.resolve(this.legacyInitialize(params));
      case 'tools/list': {
        const ctx = this.eraContext(params);
        return Promise.resolve(
          ctx.era === 'modern'
            ? this.wrapModern({ tools: [...TOOLS] })
            : { tools: [...TOOLS] },
        );
      }
      case 'tools/call':
        return this.toolsCall(params);
      case 'ping': {
        const ctx = this.eraContext(params);
        return Promise.resolve(ctx.era === 'modern' ? this.wrapModern({}) : {});
      }
      default:
        throw new ProtocolError(ERR_METHOD_NOT_FOUND, `method not found: ${method}`);
    }
  }

  private legacyInitialize(params: Record<string, unknown>): Record<string, unknown> {
    const pv = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    if (pv === PROTO_MODERN) {
      throw new ProtocolError(
        ERR_INVALID_PARAMS,
        `${PROTO_MODERN} 走 stateless 流程（per-request _meta 或 server/discover）；initialize 僅 legacy 語義`,
      );
    }
    const negotiated = (LEGACY_VERSIONS as readonly string[]).includes(pv) ? pv : LEGACY_LATEST;
    this.legacyMode = true;
    this.legacyVersion = negotiated;
    this.onLog?.(`legacy 會話建立（protocolVersion=${negotiated}）`);
    return {
      protocolVersion: negotiated,
      capabilities: SERVER_CAPABILITIES,
      serverInfo: SERVER_INFO,
      instructions: INSTRUCTIONS,
    };
  }

  private async toolsCall(params: Record<string, unknown>): Promise<unknown> {
    const ctx = this.eraContext(params);
    const name = typeof params.name === 'string' ? params.name : '';
    const args: Record<string, unknown> | undefined =
      params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments)
        ? (params.arguments as Record<string, unknown>)
        : undefined;
    if (name !== 'request' && name !== 'verify') {
      return this.wrapToolResult(ctx, {
        content: [{ type: 'text', text: `unknown tool: ${name}（本 server 提供 request／verify）` }],
        isError: true,
      });
    }
    const retry = {
      inputResponses: params.inputResponses as unknown as Record<string, ElicitResult> | undefined,
      requestState: typeof params.requestState === 'string' ? params.requestState : undefined,
    };
    let outcome: RequestOutcome | VerifyOutcome;
    if (name === 'request') {
      outcome = await handleRequestTool(args, ctx.era, ctx.caps, retry);
    } else {
      outcome = await handleVerifyTool(args);
    }
    if (name === 'request' && (outcome as RequestOutcome).kind === 'input_required') {
      const ir = outcome as Extract<RequestOutcome, { kind: 'input_required' }>;
      // MRTR：resultType="input_required"（2026-07-28 MUST）＋inputRequests＋requestState
      // （僅 modern 會產生——legacy 恆走貼連結主路徑）
      return {
        resultType: 'input_required',
        inputRequests: ir.inputRequests,
        requestState: ir.requestState,
        _meta: { [META_SERVER_INFO]: SERVER_INFO },
      };
    }
    const vr = outcome as { isError: boolean; text: string };
    return this.wrapToolResult(ctx, {
      content: [{ type: 'text', text: vr.text }],
      isError: vr.isError,
    });
  }

  /** 當前會話 era（供 e2e/除錯） */
  currentEra(): { era: Era; legacyVersion: string | null } {
    return { era: this.legacyMode ? 'legacy' : 'modern', legacyVersion: this.legacyVersion };
  }
}
