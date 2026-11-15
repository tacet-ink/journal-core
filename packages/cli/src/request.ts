/**
 * request.ts — `tacet-secret request`（主路徑：把填寫連結交給人）。
 *
 * 動線（N3 在一切 API 之前——失敗＝零 API 呼叫、不給連結）：
 *   1. （annual 時）annual-token 參照解析（白名單守衛；值只進程序記憶體）
 *   2. N3 三步：抓 /sreq→sha256→比對 SHA256SUMS；不符＝停、告知、不給連結（exit 1）
 *   3. A 金鑰對（core generateEnvelopeKeyPair；P-256）
 *   4. POST /api/sreq（開 slot；canonical 回應無 fragment）
 *   5. 連結組裝：填寫連結（公鑰 fragment，可交人）；取件連結（私鑰 fragment＋token）
 *   6. 取件連結寫入白名單路徑（600）——stdout 只有「已寫入 <path>」（值零明文）
 *
 * 輸出紀律（L127-129）：stdout 永不含 token 原值／私鑰 JWK／明文內容；
 * 元資料（slot_id／exp／slot_nonce）＝A 端本就有權知道的設計暴露面。
 */

import {
  generateEnvelopeKeyPair,
} from '@tacet-ink/journal-core/secret/jr5e';
import { n3Gate, type N3Result } from './n3.ts';
import { RefError, parseRef, resolveRefValue } from './refs.ts';
import { resolveOutPath, writeRetrieveBundle, type RetrieveBundle } from './state.ts';

export const TTL_CHOICES = ['10m', '1h', '3d', '7d', '14d'] as const;
export type TtlChoice = (typeof TTL_CHOICES)[number];
export const TTL_MS: Record<TtlChoice, number> = {
  '10m': 600_000,
  '1h': 3_600_000,
  '3d': 3 * 86_400_000,
  '7d': 7 * 86_400_000,
  '14d': 14 * 86_400_000,
};

/** 效期檔位（R1 問 8）：free＝10m/1h/3d/7d（預設 7d）；annual 另加 14d。 */
export function resolveTtlMs(ttl: TtlChoice, tier: 'free' | 'annual'): number {
  if (ttl === '14d' && tier !== 'annual') {
    throw new RefError('ref-invalid-form', '效期 14d 僅 annual 層可用（免費層：10m/1h/3d/7d）');
  }
  return TTL_MS[ttl];
}

function b64urlJson(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

export interface RequestOpts {
  base: string;
  sums: string;
  ttl: TtlChoice;
  tier: 'free' | 'annual';
  /** annual 權杖參照（env:NAME｜file:PATH）——annual 必填 */
  annualTokenRef: string | null;
  out: string | null;
  json: boolean;
}

export interface RequestOutcome {
  exit: number;
  lines: string[]; // stdout 行（呼叫端逐行 print）
  jsonOut?: Record<string, unknown>;
}

export async function runRequest(o: RequestOpts): Promise<RequestOutcome> {
  const lines: string[] = [];
  // 1. annual 權杖參照（白名單；值永不上 stdout）
  let annualToken: string | null = null;
  if (o.tier === 'annual') {
    if (!o.annualTokenRef) {
      return fail(lines, 2, 'annual 層需 --annual-token env:NAME 或 file:PATH');
    }
    const ref = parseRef(o.annualTokenRef);
    if (!ref) {
      return fail(lines, 4, `--annual-token 需 env:NAME 或 file:PATH 參照形（值永不進命令行）`);
    }
    try {
      annualToken = resolveRefValue(ref);
    } catch (e) {
      if (e instanceof RefError) return fail(lines, 4, e.message);
      throw e;
    }
  }
  // 2. N3 門（交付前必跑；失敗＝不建 slot、不給連結）
  const n3: N3Result = await n3Gate(o.base, o.sums);
  if (!n3.match) {
    lines.push('N3 停手：/sreq 頁與公開 repo SHA256SUMS 不符（或無法取得）——不給連結、不建 slot。');
    lines.push(`  live:   ${n3.url}`);
    if (n3.liveSha) lines.push(`  live sha256:   ${n3.liveSha}`);
    if (n3.sumsSha) lines.push(`  sums sha256:   ${n3.sumsSha}`);
    lines.push(`  原因: ${n3.reason}——${n3.detail}`);
    lines.push('  信任錨＝公開 repo 所在的 GitHub；此停手＝N3 正常防線運作。');
    return { exit: 1, lines };
  }
  lines.push(`N3 ok：/sreq sha256 對 SHA256SUMS（${n3.liveSha!.slice(0, 12)}…）`);
  // 3. A 金鑰對
  const pair = await generateEnvelopeKeyPair();
  const { privJwk, pubJwk } = pair;
  // 4. 開 slot
  const base0 = o.base.replace(/\/+$/, '');
  const body: Record<string, unknown> = { a_pub_jwk: pubJwk, ttl_ms: resolveTtlMs(o.ttl, o.tier) };
  if (annualToken !== null) body.annual_token = annualToken;
  let slot: any;
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
        const j = JSON.parse(text);
        if (j && typeof j.error === 'string') msg = j.error;
      } catch {
        /* 非 JSON 錯體＝原文 */
      }
      lines.push(`開 slot 失敗：HTTP ${res.status}——${msg.slice(0, 300)}`);
      return { exit: 1, lines };
    }
    slot = JSON.parse(text);
  } catch (e) {
    lines.push(`開 slot 失敗（網路）：${e instanceof Error ? e.message : String(e)}`);
    return { exit: 1, lines };
  }
  // 形檢 fail-closed：canonical 回應必備欄
  const need: Array<[string, (v: unknown) => boolean]> = [
    ['slot_id', (v) => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v)],
    ['token', (v) => typeof v === 'string' && v.length > 0],
    ['slot_nonce', (v) => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v)],
    ['exp', (v) => typeof v === 'number'],
    ['fill_url', (v) => typeof v === 'string' && v.includes('?s=')],
    ['retrieve_url', (v) => typeof v === 'string' && v.includes('?s=')],
  ];
  for (const [k, f] of need) {
    if (!f(slot?.[k])) {
      lines.push(`server 回應形不符（缺/錯欄 ${k}）——誠實停手（不組連結）。`);
      return { exit: 1, lines };
    }
  }
  // 5. 連結組裝（R1 問 3 凍結形：query 定位、fragment 帶金鑰）
  const fillLink = `${slot.fill_url}#p=${b64urlJson(pubJwk)}`;
  const retrieveLink = `${slot.retrieve_url}&t=${slot.token}#k=${b64urlJson(privJwk)}`;
  // 6. 取件連結落檔（白名單＋600）；stdout 只有「已寫入」
  const bundle: RetrieveBundle = {
    v: 1,
    slot_id: slot.slot_id,
    tier: o.tier,
    exp: slot.exp,
    opened_at: Date.now(),
    slot_nonce: slot.slot_nonce,
    retrieve_link: retrieveLink,
    note: 'retrieve_link 含 A 私鑰（fragment #k=）與取件 token（&t=）——只供本機取件，永不貼進對話。',
  };
  let outPath: string;
  try {
    outPath = writeRetrieveBundle(resolveOutPath(o.out, slot.slot_id), bundle);
  } catch (e) {
    if (e instanceof RefError) return fail(lines, 4, e.message);
    throw e;
  }
  lines.push(`slot ${slot.slot_id}（tier ${o.tier}，到期 ${new Date(slot.exp).toISOString()}）`);
  lines.push('填寫連結（只帶公鑰，可交給對方填寫）:');
  lines.push(fillLink);
  lines.push(`取件連結已寫入 ${outPath}（chmod 600；含私鑰與 token，勿貼進對話）`);
  lines.push('提醒：拿到填寫連結的人皆可搶先填入——只交給你確認的人（R1 W1/C1 界線）。');
  const outcome: RequestOutcome = {
    exit: 0,
    lines,
    jsonOut: {
      ok: true,
      n3: { page: n3.page, url: n3.url, sha256: n3.liveSha },
      slot_id: slot.slot_id,
      tier: o.tier,
      ttl_ms: body.ttl_ms,
      exp: slot.exp,
      fill_url: fillLink,
      retrieve_written_to: outPath,
      slot_nonce: slot.slot_nonce,
    },
  };
  return outcome;
}

function fail(lines: string[], exit: number, msg: string): RequestOutcome {
  lines.push(msg);
  return { exit, lines };
}
