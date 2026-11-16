/**
 * request-tool.ts — request 工具（貼連結主路徑＋2026-07-28 MRTR 增強面）。
 *
 * 語義與 R3b CLI request 一致（import 同一批原語：n3Gate/refs/state/request）；
 * MCP 只加兩層：協議面（session.ts）＋交付決策（本檔 chooseDelivery）：
 *   - MRTR 增強面（2026-07-28）：modern era＋client 宣稱 elicitation.url（spec 形
 *     JSONObject：{} 即支援／寬鬆 true 兩吃，存在式判定）→ 回 InputRequiredResult
 *     （inputRequests.fill＝elicitation/create url mode＋requestState）；client 帶
 *     inputResponses＋requestState 重試 → accept/decline 各自收口（decline 降級貼連結；
 *     本 server 無 submit——accept 也只交連結＋bundle 路徑）。
 *   - 貼連結主路徑（降級／legacy）：直接回 CallToolResult（fill 連結＋bundle 已寫入）。
 *
 * 完成通知面已退場（2026-07-28 規格移除 R1 問 13 第 3 項）——本檔零殘字面（閘 [4] census）。
 */
import os from 'node:os';
import path from 'node:path';
import { generateEnvelopeKeyPair } from '@tacet-ink/journal-core/secret/jr5e';
import { DEFAULT_BASE_URL, DEFAULT_SUMS_URL, n3Gate, type N3Result } from '@tacet-ink/journal-cli/dist/n3.js';
import { RefError, parseRef, resolveRefValue, stateDir } from '@tacet-ink/journal-cli/dist/refs.js';
import { resolveOutPath, writeRetrieveBundle, type RetrieveBundle } from '@tacet-ink/journal-cli/dist/state.js';
import { TTL_CHOICES, resolveTtlMs, type TtlChoice } from '@tacet-ink/journal-cli/dist/request.js';
import {
  canonicalDigest,
  signState,
  verifyState,
  STATE_TTL_MS,
  type StatePayload,
} from './requeststate.ts';
import type { ClientCapabilities, ElicitResult, InputRequests } from './protocol.ts';

export type Era = 'modern' | 'legacy';

export type DeliveryChoice = 'mrtr' | 'paste-link';

/**
 * 交付決策：MRTR 增強面僅在 modern era＋client 宣稱 elicitation.url 時成立；其餘全降級貼連結（主路徑）。
 * url 能力判定＝存在式：spec 形 JSONObject（{} 即支援；schema 2026-07-28:769-773）與寬鬆
 * true 兩吃；false／缺席／非物件不觸發（review r1 R1：舊形 url===true 對 spec 形客戶端恆 false）。
 */
export function chooseDelivery(
  era: Era,
  caps: ClientCapabilities | null | undefined,
): DeliveryChoice {
  const u = caps?.elicitation?.url;
  const urlDeclared = u === true || (typeof u === 'object' && u !== null && !Array.isArray(u));
  return era === 'modern' && urlDeclared ? 'mrtr' : 'paste-link';
}

export interface RetryInfo {
  inputResponses?: Record<string, ElicitResult>;
  requestState?: string;
}

export type RequestOutcome =
  | { kind: 'result'; isError: boolean; text: string }
  | { kind: 'input_required'; inputRequests: InputRequests; requestState: string };

type RawArgs = Record<string, unknown> | undefined;

function fail(text: string): RequestOutcome {
  return { kind: 'result', isError: true, text };
}

function baseFrom(args: Record<string, unknown>): string {
  const b = typeof args.base === 'string' && args.base.length > 0 ? args.base : DEFAULT_BASE_URL;
  try {
    const u = new URL(b);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('proto');
    return b;
  } catch {
    throw new Error(`base 形態錯：${b}（需 http/https URL）`);
  }
}

/** 交付文本共用的 tail（fill 連結＋bundle 路徑＋R1 邊界提醒） */
function deliveryTail(st: StatePayload): string {
  return [
    '填寫連結（只帶公鑰，可貼給對方填寫）：',
    st.fill_link,
    `取回連結已寫入 ${st.out_path}（chmod 600；帶私鑰與 token——勿貼進對話）`,
    '提醒：拿到填寫連結的人都能先填——只交給你確認過的對象（R1 W1/C1 邊界）。',
  ].join('\n');
}

export async function handleRequestTool(
  rawArgs: RawArgs,
  era: Era,
  caps: ClientCapabilities | null | undefined,
  retry?: RetryInfo | null,
): Promise<RequestOutcome> {
  const args = rawArgs ?? {};
  if (retry && (retry.inputResponses !== undefined || retry.requestState !== undefined)) {
    return handleRetry(args, retry);
  }
  return handleFresh(args, era, caps);
}

/** MRTR 重試（頂層 inputResponses＋requestState；spec 2026-07-28 basic/patterns/mrtr） */
async function handleRetry(
  args: Record<string, unknown>,
  retry: RetryInfo,
): Promise<RequestOutcome> {
  if (!retry.requestState) {
    return fail('重試缺 requestState——本 server 不處理不可識別狀態；請重新發 request');
  }
  let expected: string;
  try {
    expected = await canonicalDigest({ name: 'request', arguments: args });
  } catch {
    return fail('重試參數無法摘要（形態錯）——請重新發 request');
  }
  const v = await verifyState(retry.requestState, expected);
  if (!v.ok) {
    const zh: Record<string, string> = {
      format: '形態錯',
      mac: '完整性（HMAC）不符',
      expired: `已過期（TTL ${Math.round(STATE_TTL_MS / 60000)} 分鐘）`,
      principal: 'principal 不符',
      digest: '重試參數與原請求不符（digest mismatch）',
    };
    return fail(
      `requestState 驗證失敗（${zh[v.reason] ?? v.reason}）——本 server 不處理未驗證狀態；請重新發 request`,
    );
  }
  const st = v.payload;
  const resp = retry.inputResponses ? retry.inputResponses['fill'] : undefined;
  if (!resp || typeof resp.action !== 'string') {
    return fail('重試缺 inputResponses.fill（client 的 elicitation 回應）');
  }
  if (resp.action === 'decline' || resp.action === 'cancel') {
    const word = resp.action === 'decline' ? '拒絕' : '取消';
    return {
      kind: 'result',
      isError: false,
      text:
        `客戶端未開填充頁（使用者${word}）——降級貼連結主路徑（連結只帶公鑰，可交對方）：\n` +
        `slot ${st.slot_id}（tier ${st.tier}，到期 ${new Date(st.exp).toISOString()}）\n` +
        deliveryTail(st),
    };
  }
  if (resp.action === 'accept') {
    return {
      kind: 'result',
      isError: false,
      text:
        '填充頁已由客戶端打開（使用者同意；MCP URL elicitation 增強面）。接下來：\n' +
        `1. 把填寫連結交給你確認過的對象（只帶公鑰，可安全貼普通聊天）：\n${st.fill_link}\n` +
        `2. 對方填完後經取回連結取回（已寫入 ${st.out_path}（600）；帶私鑰＋token——勿貼進對話）\n` +
        '3. 站點狀態可用 verify 工具查（SHA256SUMS 四方帳）',
    };
  }
  return fail(`無法辨識的回應 action：${String(resp.action)}（預期 accept/decline/cancel）`);
}

async function handleFresh(
  args: Record<string, unknown>,
  era: Era,
  caps: ClientCapabilities | null | undefined,
): Promise<RequestOutcome> {
  let base: string;
  try {
    base = baseFrom(args);
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
  const sums = typeof args.sums === 'string' && args.sums.length > 0 ? args.sums : DEFAULT_SUMS_URL;
  const tier: 'free' | 'annual' = args.annual === true ? 'annual' : 'free';

  // 1. annual token 參照（白名單；值永不進對話）
  let annualToken: string | null = null;
  if (tier === 'annual') {
    if (typeof args.annual_token_ref !== 'string' || args.annual_token_ref.length === 0) {
      return fail('annual 層需 annual_token_ref（env:NAME 或 file:PATH 參照；值不入本對話）');
    }
    const ref = parseRef(args.annual_token_ref);
    if (!ref) {
      return fail(
        `annual_token_ref 需為 env:NAME 或 file:PATH 參照（值不入本對話）：${args.annual_token_ref}`,
      );
    }
    try {
      annualToken = resolveRefValue(ref);
    } catch (e) {
      if (e instanceof RefError) return fail(e.message);
      throw e;
    }
  }

  // 2. N3 閘（交付前必跑；失敗＝不開 slot、不交連結——零 API）
  const n3: N3Result = await n3Gate(base, sums);
  if (!n3.match) {
    const lines = [
      'N3 停止：/sreq 頁與公開 repo SHA256SUMS 不符（或取不到）——不交連結、不開 slot。',
      `  live:   ${n3.url}`,
    ];
    if (n3.liveSha) lines.push(`  live sha256:   ${n3.liveSha}`);
    if (n3.sumsSha) lines.push(`  sums sha256:   ${n3.sumsSha}`);
    lines.push(`  reason: ${n3.reason} — ${n3.detail}`);
    lines.push('  信任錨＝公開 repo 所在的 GitHub；此停止是 N3 防線正常運作。');
    return fail(lines.join('\n'));
  }
  const n3Line = n3.liveSha
    ? `N3 ok: /sreq sha256 與 SHA256SUMS 一致（${n3.liveSha.slice(0, 12)}…）`
    : 'N3 ok: /sreq sha256 與 SHA256SUMS 一致';

  // ttl（同 CLI 語義：14d 需 annual）
  const ttl = (typeof args.ttl === 'string' && args.ttl.length > 0 ? args.ttl : '7d') as TtlChoice;
  if (!(TTL_CHOICES as readonly string[]).includes(ttl)) {
    return fail(`ttl 需為 ${TTL_CHOICES.join('/')} 之一（得 ${ttl}）`);
  }
  let ttlMs: number;
  try {
    ttlMs = resolveTtlMs(ttl, tier);
  } catch (e) {
    if (e instanceof RefError) return fail(e.message);
    throw e;
  }

  // 3. 交付前預先核對 out（fail-early：越界/已存在＝零 slot 消耗）
  let preOutPath: string | null = null;
  if (args.out !== undefined) {
    if (typeof args.out !== 'string' || args.out.length === 0) {
      return fail('out 需為路徑（PATH 或 file:PATH）');
    }
    try {
      preOutPath = resolveOutPath(args.out, null);
    } catch (e) {
      if (e instanceof RefError) return fail(e.message);
      throw e;
    }
  }

  // 4. 金鑰對（core generateEnvelopeKeyPair；P-256）
  const pair = await generateEnvelopeKeyPair();
  const { privJwk, pubJwk } = pair;

  // 5. 開 slot（canonical 相對 URL 斷言；連結用 N3 實取 origin 組裝）
  const base0 = base.replace(/\/+$/, '');
  const body: Record<string, unknown> = { a_pub_jwk: pubJwk, ttl_ms: ttlMs };
  if (annualToken !== null) body.annual_token = annualToken;
  let slot: Record<string, unknown>;
  try {
    const res = await fetch(`${base0}/api/sreq`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = text;
      try {
        const j = JSON.parse(text) as { error?: unknown };
        if (j && typeof j.error === 'string') msg = j.error;
      } catch {
        /* 非 JSON 錯誤體＝原樣 */
      }
      return fail(`開 slot 失敗：HTTP ${res.status} — ${msg.slice(0, 300)}`);
    }
    slot = JSON.parse(text) as Record<string, unknown>;
  } catch (e) {
    return fail(`開 slot 失敗（網路）：${e instanceof Error ? e.message : String(e)}`);
  }
  const need: Array<[string, (v: unknown) => boolean]> = [
    ['slot_id', (v) => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v)],
    ['token', (v) => typeof v === 'string' && v.length > 0],
    ['exp', (v) => typeof v === 'number' && v > Date.now()],
    ['slot_nonce', (v) => typeof v === 'string' && v.length > 0],
    ['fill_url', (v) => typeof v === 'string'],
    ['retrieve_url', (v) => typeof v === 'string'],
  ];
  for (const [k, f] of need) {
    if (!f(slot[k])) {
      return fail(`server 回應形狀不符（${k} 缺/錯）——誠實停止（不組裝連結）。`);
    }
  }
  const origin = new URL(n3.url).origin;
  const fillPath = `/sreq/?s=${slot.slot_id}`;
  const retrievePath = `/sreq/?s=${slot.slot_id}&t=${slot.token}`;
  if (slot.fill_url !== fillPath || slot.retrieve_url !== retrievePath) {
    return fail(
      `server 回應 URL 欄位不合 canonical 形（預期相對 "${fillPath}"/"${retrievePath}"）——誠實停止（不組裝連結）。`,
    );
  }
  const b64url = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  const fillLink = `${origin}${fillPath}#p=${b64url(pubJwk)}`;
  const retrieveLink = `${origin}${retrievePath}#k=${b64url(privJwk)}`;

  // 6. 取回 bundle 落盤（白名單＋600）
  const slotId = slot.slot_id as string;
  const exp = slot.exp as number;
  const slotNonce = slot.slot_nonce as string;
  const bundle: RetrieveBundle = {
    v: 1,
    slot_id: slotId,
    tier,
    exp,
    opened_at: Date.now(),
    slot_nonce: slotNonce,
    retrieve_link: retrieveLink,
    note: 'retrieve_link 含 A 端私鑰（fragment #k=）與取回 token（&t=）——只供本地取回，勿貼進對話。',
  };
  let outPath: string;
  try {
    const target = preOutPath ?? path.join(stateDir(), `${slot.slot_id}.retrieve.json`);
    outPath = writeRetrieveBundle(target, bundle);
  } catch (e) {
    if (e instanceof RefError) return fail(e.message);
    throw e;
  }

  // 7. 交付決策
  if (chooseDelivery(era, caps) === 'mrtr') {
    const reqDigest = await canonicalDigest({ name: 'request', arguments: args });
    const payload: StatePayload = {
      v: 1,
      tool: 'request',
      slot_id: slotId,
      tier,
      exp,
      origin,
      out_path: outPath,
      fill_link: fillLink,
      req_digest: reqDigest,
      principal: os.userInfo().username,
      iat: Date.now(),
    };
    const requestState = await signState(payload);
    return {
      kind: 'input_required',
      inputRequests: {
        fill: {
          method: 'elicitation/create',
          params: {
            mode: 'url',
            message:
              '請打開這個填寫連結填入祕密。連結只帶公鑰（安全）；內容不經本對話與本 server。' +
              '填完即可關閉頁面；agent 會等你確認後才取回。',
            url: fillLink,
          },
        },
      },
      requestState,
    };
  }
  return {
    kind: 'result',
    isError: false,
    text:
      `${n3Line}\nslot ${slotId}（tier ${tier}，到期 ${new Date(exp).toISOString()}）\n` +
      deliveryTail({
        v: 1,
        tool: 'request',
        slot_id: slotId,
        tier,
        exp,
        origin,
        out_path: outPath,
        fill_link: fillLink,
        req_digest: '',
        principal: os.userInfo().username,
        iat: Date.now(),
      }),
  };
}
