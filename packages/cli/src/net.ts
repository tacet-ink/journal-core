/**
 * net.ts — 極小 fetch 助（N3 真值抓取面）。
 *
 * 誠實界線：fetch 走平台原生（Node 26 undici）；本檔零重試、零快取、零代理配置——
 * 工具驗的是「它自己抓到的那一份」（README 誠實界線 ①）。timeout＋size cap＝防掛死
 * 與防爆內存（N3 抓取面非機密面；cap 越界＝fetch 失敗→N3 停手，fail-closed）。
 */

export class HttpError extends Error {
  readonly url: string;
  readonly status: number;
  constructor(url: string, status: number, message: string) {
    super(message);
    this.name = 'HttpError';
    this.url = url;
    this.status = status;
  }
}

export class FetchError extends Error {
  readonly url: string;
  readonly reason: 'timeout' | 'network' | 'too-large' | 'bad-url';
  constructor(url: string, reason: 'timeout' | 'network' | 'too-large' | 'bad-url', message: string) {
    super(message);
    this.name = 'FetchError';
    this.url = url;
    this.reason = reason;
  }
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // /sreq 實測 62KB 級；5MB cap 有充足餘量

export interface FetchOpts {
  timeoutMs?: number;
  maxBytes?: number;
  /** 附加請求標頭（verify-site 帶部署端 canary 同字 UA；缺席＝既有行為不變） */
  headers?: Record<string, string>;
}

/**
 * GET → 位元組（redirect 跟隨；非 2xx＝HttpError；timeout/network/size cap＝FetchError）。
 * 回 Uint8Array（呼叫端決定編碼面——N3 側 UTF-8 fatal 解碼，失敗＝fail-closed 停手）。
 */
export async function fetchBytes(url: string, opts: FetchOpts = {}): Promise<Uint8Array> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new FetchError(url, 'bad-url', `網址形錯：${url}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new FetchError(url, 'bad-url', `只收 http/https：${url}`);
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(u, { redirect: 'follow', signal: ctl.signal, headers: opts.headers });
  } catch (e) {
    const isAbort = e instanceof Error && e.name === 'AbortError';
    throw new FetchError(
      url,
      isAbort ? 'timeout' : 'network',
      isAbort ? `fetch timeout（>${timeoutMs}ms）：${url}` : `fetch 失敗：${url}（${String(e)}）`,
    );
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new HttpError(url, res.status, `HTTP ${res.status}：${url}`);
  }
  // size cap：先查 content-length（在場時快拒），再流式累計（不信任 header）
  const cl = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(cl) && cl > maxBytes) {
    throw new FetchError(url, 'too-large', `回應過大（content-length ${cl} > cap ${maxBytes}）：${url}`);
  }
  const reader = res.body?.getReader();
  if (!reader) {
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.length > maxBytes) throw new FetchError(url, 'too-large', `回應過大：${url}`);
    return buf;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > maxBytes) {
        throw new FetchError(url, 'too-large', `回應過大（>cap ${maxBytes}）：${url}`);
      }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** 讀本地檔案（ sums 真值源的本地形；操作者預設路徑，非機密參照——不走白名單面）。 */
export async function readLocalFile(p: string): Promise<Uint8Array> {
  const { readFile } = await import('node:fs/promises');
  try {
    return new Uint8Array(await readFile(p));
  } catch (e) {
    throw new FetchError(p, 'network', `讀本地檔案失敗：${p}（${String(e)}）`);
  }
}

/** sums 參照：http(s) URL 走 fetch；其餘當本地路徑。 */
export async function fetchSumsOrLocal(ref: string): Promise<Uint8Array> {
  if (/^https?:\/\//i.test(ref)) return fetchBytes(ref);
  return readLocalFile(ref);
}
