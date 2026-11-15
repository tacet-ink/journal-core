/**
 * submit.ts — `tacet-secret submit`（預設關＋人確認才動；R1 問 5/L129）。
 *
 * 動線：
 *   1. 填寫連結形檢（?s=32hex＋#p=<b64url JWK>；公鑰過 core jwkPubRaw）
 *   2. 內容參照（env:/file:，白名單守衛）→ 值進程序記憶體（永不上 stdout）
 *   3. **人確認閘（在一切 API 呼叫之前）**：非 TTY＝直接拒（exit 3，零 API）；
 *      TTY＝印摘要（slot id／目的／來源參照／內容長度——零內容）＋要求輸入 slot id
 *   4. ephemeral 一用一換＋iv 隨機＋sealEnvelope（core；AAD＝jr5e:<slot_id>）
 *   5. POST /api/sreq/fill?s=（write-once；404 三因不可區分直轉；零重試）
 *   6. 成功面＝「已寫入：conf_code=xxxx」（conf_code＝同一性指紋非授權，R1 問 10）
 *
 * 誠實界線：投遞前，內容已從白名單參照進 CLI 程序記憶體；本工具不改變內容此前
 * 已進 agent/模型上下文的事實（I 線界線）。
 */

import {
  JR5E_AAD_DOMAIN,
  JR5E_IV_BYTES,
  generateEnvelopeKeyPair,
  jwkPubRaw,
  openEnvelope,
  sealEnvelope,
  type JwkEC,
} from '@tacet-ink/journal-core/secret/jr5e';
import { RefError, parseRef, resolveRefValue } from './refs.ts';

export interface FillLinkParts {
  slotId: string;
  pubJwk: JwkEC;
  origin: string; // protocol + host（摘要展示用）
  fillUrl: URL;
}

/** 填寫連結形檢；失敗＝null（呼叫端報用法錯，零 API）。 */
export function parseFillLink(s: string): FillLinkParts | null {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.pathname !== '/sreq' && u.pathname !== '/sreq/') return null;
  const slotId = u.searchParams.get('s');
  if (!slotId || !/^[0-9a-f]{32}$/.test(slotId)) return null;
  const frag = u.hash;
  if (!frag.startsWith('#p=')) return null;
  const p = frag.slice('#p='.length);
  let jwk: unknown;
  try {
    jwk = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!jwkPubRaw(jwk as JwkEC)) return null;
  return { slotId, pubJwk: jwk as JwkEC, origin: u.origin, fillUrl: u };
}

export interface SubmitOpts {
  base: string;
  /** 填寫連結（第一參數） */
  fillLink: string;
  /** 內容來源參照（env:NAME｜file:PATH；白名單） */
  sourceRef: string;
  /** 確認輸入（--confirm-input 測試/CI 面；預設走 stdin TTY） */
  confirmInput: string | null;
  /** 非互動測試面：跳過 TTY 要求（仍須 --confirm-input 提供確認值） */
  allowNonTty: boolean;
}

export interface SubmitOutcome {
  exit: number;
  lines: string[];
  stderr?: string[];
}

/** 確認閘判定（獨立可測）：非 TTY 且非 allowNonTty＝'no-tty'；其餘＝'tty'。 */
export function confirmGateState(allowNonTty: boolean): 'no-tty' | 'tty' {
  const tty =
    (typeof process.stdin.isTTY === 'boolean' && process.stdin.isTTY) ||
    (typeof process.stdout.isTTY === 'boolean' && process.stdout.isTTY);
  return tty || allowNonTty ? 'tty' : 'no-tty';
}

/**
 * 讀一行 stdin（data 事件面；不用 for-await——for-await break 會 return() 迭代器、
 * destroy 掉 process.stdin，同程序第二次確認會吃 AbortError；e2e S2 實證）。
 */
function readLineFromStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('確認輸入逾時（30s 無輸入）'));
    }, 30_000);
    timer.unref();
    const onData = (chunk: Buffer | string): void => {
      buf += chunk.toString('utf8');
      const i = buf.indexOf('\n');
      if (i !== -1) {
        cleanup();
        resolve(buf.slice(0, i).trim());
      }
    };
    const onErr = (e: Error): void => {
      cleanup();
      reject(e);
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      process.stdin.removeListener('data', onData);
      process.stdin.removeListener('error', onErr);
      process.stdin.pause();
    };
    process.stdin.resume();
    process.stdin.on('data', onData);
    process.stdin.once('error', onErr);
  });
}

export async function runSubmit(o: SubmitOpts): Promise<SubmitOutcome> {
  const lines: string[] = [];
  const stderr: string[] = [];
  // 1. 填寫連結形檢（零 API）
  const parts = parseFillLink(o.fillLink);
  if (!parts) {
    return { exit: 2, lines: [], stderr: ['submit 拒：填寫連結形不符（需 /sreq?s=<32hex>#p=<b64url 公鑰 JWK>）'] };
  }
  // 2. 內容參照（白名單；值只進程序記憶體）
  const ref = parseRef(o.sourceRef);
  if (!ref) {
    return {
      exit: 2,
      lines: [],
      stderr: ['submit 拒：內容來源需 env:NAME 或 file:PATH 參照形（值永不進命令行）'],
    };
  }
  let content: string;
  try {
    content = resolveRefValue(ref);
  } catch (e) {
    if (e instanceof RefError) {
      return { exit: 4, lines: [], stderr: [e.message] };
    }
    throw e;
  }
  // 3. 人確認閘（一切 API 之前）
  const gate = confirmGateState(o.allowNonTty);
  if (gate === 'no-tty') {
    stderr.push(
      'submit 預設關：本執行非互動 TTY，無法人確認——未送出任何東西（要送：人在終端機跑本命令，或 CI 明式 --allow-non-tty --confirm-input <slot_id>）。',
    );
    return { exit: 3, lines: [], stderr };
  }
  const byteLen = Buffer.byteLength(content, 'utf8');
  const srcLabel = ref.kind === 'env' ? `env 參照（變數 ${ref.value}）` : `file 參照（白名單路徑）`;
  lines.push(`將向 ${parts.origin}/sreq（slot ${parts.slotId}）投遞內容：`);
  lines.push(`  來源: ${srcLabel}，${byteLen} bytes（UTF-8；內容本身永不顯示）`);
  let answer: string;
  if (o.confirmInput !== null) {
    answer = o.confirmInput;
  } else {
    process.stdout.write('輸入 slot 編號確認送出（其餘中止）: ');
    answer = await readLineFromStdin();
  }
  if (answer !== parts.slotId) {
    lines.push('已中止（未送出）。');
    return { exit: 5, lines };
  }
  // 4. 封包（core sealEnvelope；eph 一用一換；iv 隨機 12B；AAD 含 slot 防跨 slot 重放）
  const base0 = o.base.replace(/\/+$/, '');
  const eph = await generateEnvelopeKeyPair();
  const iv = crypto.getRandomValues(new Uint8Array(JR5E_IV_BYTES));
  const aad = JR5E_AAD_DOMAIN + parts.slotId;
  let blob: string;
  try {
    blob = await sealEnvelope(content, parts.pubJwk, eph.privJwk, iv, aad);
  } finally {
    delete (eph.privJwk as Partial<JwkEC>).d; // 私鑰用完即銷（記憶體面）
  }
  // 5. 投遞（write-once；零重試）
  let res: Response;
  try {
    res = await fetch(`${base0}/api/sreq/fill?s=${parts.slotId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ciphertext: blob }),
    });
  } catch (e) {
    lines.push('投遞失敗（網路）：未寫入。' + String(e));
    return { exit: 1, lines };
  }
  const text = await res.text();
  let j: any = null;
  try {
    j = JSON.parse(text);
  } catch {
    /* 非 JSON＝錯面原文 */
  }
  if (res.status === 200 && j && j.ok) {
    lines.push(`已寫入：slot ${parts.slotId} 已填寫。填寫指紋 conf_code=${j.conf_code}（取件端以此比對確認內容身份——指紋非授權，R1 問 10）。`);
    return { exit: 0, lines };
  }
  if (res.status === 404) {
    lines.push('此請求已無法填寫（已填寫／已過期／不存在——三者不可區分，R1 問 9）——未寫入。');
    return { exit: 1, lines };
  }
  if (res.status === 400) {
    lines.push(`server 拒（形檢/帽）：${j && typeof j.error === 'string' ? j.error : text.slice(0, 300)}——未寫入。`);
    return { exit: 1, lines };
  }
  if (res.status === 429) {
    lines.push('rate limit（429）——未寫入（零重試：write-once 語義下重試只製造混淆）。');
    return { exit: 1, lines };
  }
  lines.push(`投遞失敗：HTTP ${res.status}——未寫入。`);
  return { exit: 1, lines };
}
