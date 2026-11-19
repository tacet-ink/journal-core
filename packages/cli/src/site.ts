/**
 * site.ts — `tacet-secret verify-site`（t_b035fe9b）：公開部署紀錄 → live 站逐檔比對。
 *
 * 任何人可自跑（零寫入、零遙測、零重試——重跑一次命令即為重試）：
 *   1. 抓部署紀錄帳本（deploy-log.jsonl；schema tacet-deploy-log/v1）→ 全帳形檢（seq 1..n 連續／
 *      schema／type／manifest 路徑形／append-only 去重；部署端 readLedger 同規）→ 最後一行＝最新一筆。
 *   2. 最新一筆 type=correction＝營運者自己記錄了「現場不符」→ 印更正摘要、零 live 探測、exit 1。
 *   3. deploy/baseline：抓 manifest（new URL(row.manifest, 帳本 URL)）→ 位元組 sha256＝帳行
 *      manifest_sha256（帳鏈）→ 帳行快速核對值與 manifest 內值互核＋manifest 自洽。
 *   4. 逐檔比對：manifest.files 剔除 _headers／_redirects（平台設定檔不在網路上）；候選序＝
 *      [路徑, 去 .html, 去 index.html（留尾斜線）, 再去尾斜線]（部署端 canary 原樣）；
 *      redirect:'manual' 逐候選 GET，首個「200 且 sha256 相符」即過。
 *   5. CSP：GET <base>/privacy 取最後一筆 content-security-policy 值 trim 後 sha256 對 manifest
 *      （manifest 為 null＝live 亦應無；一有一無＝不符）。
 *
 * 逐檔收尾判定序（迴圈跑完全部候選後）：相符→過；任一「200 但 sha 不符」→不符；任一 3xx 轉出
 * 候選集→redirect-skip（揭露不判紅）；其餘非 3xx 回應全為 404/410→不符（缺檔）；其餘
 * （401/403/5xx/擲出/候選間互轉無落點）→取得錯。
 *   轉址歸類（實測 2026-11-19 tacet.ink）：平台把 `x.html` 一律 308/307 到 `x`、`d/index.html`
 *   到 `d`——這種 Location 落在同一檔候選集內的 3xx 是網址規範化，不是轉址來源；若把它算成
 *   skip，任何 .html 頁的漂亮網址 404/5xx 都會被靜默略過（fail-open）。故只有 Location 轉出
 *   候選集的 3xx 才記 redirect-skip（如 `/landing.html` → `/`）；無 Location 的 3xx 歸取得錯。
 *
 * exit（本子命令自訂面）：0 全符；1 不符（檔／CSP／帳鏈破／correction／帳面形不合法）；
 *   2 網路／取得錯（帳本或 manifest 取不到、live 401/403/5xx/逾時/連線拒、CSP 探測面失敗）。
 *   不符與取得錯並存＝1（不符是已確證的發現；取得錯照列）。
 *
 * 雜湊面：文字值（CSP）走 core server/hash sha256Hex。檔案位元組：UTF-8 合法者同走 sha256Hex
 *   （fatal＋ignoreBOM 解碼→TextEncoder 重編碼＝逐位元組恆等）；非 UTF-8（圖片／影片）core 無
 *   位元組入口——sha256Hex 的 UTF-8 重編碼對二進位不保位元組，故改走平台 WebCrypto digest
 *   （sha256Hex 內部同一原語；零新相依、零自帶演算法）。
 */

import { sha256Hex } from '@tacet-ink/journal-core/server/hash';
import { DEFAULT_BASE_URL } from './n3.ts';
import { FetchError, HttpError, fetchBytes } from './net.ts';

/** 公開部署紀錄帳本預設（deploy-log repo main 分支 raw） */
export const DEFAULT_LOG_URL = 'https://raw.githubusercontent.com/tacet-ink/deploy-log/main/deploy-log.jsonl';
/** 部署端 canary 同字 UA（免 CDN 機器人挑戰誤擋）；帳本／manifest／live 一律帶 */
export const SITE_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/152 Safari/537.36';

const SCHEMA = 'tacet-deploy-log/v1';
const HEX64 = /^[0-9a-f]{64}$/;
const MANIFEST_PATH = /^manifests\/[^/]+\.json$/;
const EXCLUDE = new Set(['_headers', '_redirects']);
const UA_HEADERS = { 'user-agent': SITE_UA };
const PROBE_TIMEOUT_MS = 30_000;
const PROBE_MAX_BYTES = 64 * 1024 * 1024; // 站內單檔實測最大 1.6MB 級（worker bundle／mp4）
const LEDGER_MAX_BYTES = 16 * 1024 * 1024; // 帳本 append-only 成長；一行 ~0.5KB
const CONCURRENCY = 6; // 部署端 canary 同並發

export interface VerifySiteOpts {
  url: string;
  log: string;
  json: boolean;
}

export interface VerifySiteOutcome {
  exit: number;
  lines: string[];
  jsonOut: Record<string, unknown>;
}

type Verdict = 'ok' | 'mismatch' | 'correction' | 'network';
const EXIT_OF: Record<Verdict, number> = { ok: 0, mismatch: 1, correction: 1, network: 2 };

type Row = Record<string, unknown>;

interface ManifestFile {
  path: string;
  sha256: string;
  bytes: number;
}

interface Manifest {
  schema: string;
  type: string;
  deployed_at: unknown;
  version: unknown;
  commit: unknown;
  index_html: { path: string; sha256: string };
  rb_bundle: { file: string; path: string; sha256: string };
  csp_header: { source: string; value_sha256: string } | null;
  csp_header_absent: boolean;
  files: ManifestFile[];
  file_count: unknown;
}

/** 帳面形不合法（帳本／manifest 取得 200 但不可解析、schema 不符、空帳）＝exit 1。 */
class ShapeError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const isHex64 = (v: unknown): v is string => typeof v === 'string' && HEX64.test(v);

const UTF8_EXACT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function hexOf(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** 位元組→sha256 hex（見檔頭「雜湊面」）。 */
export async function sha256OfBytes(b: Uint8Array): Promise<string> {
  let text: string | null = null;
  try {
    text = UTF8_EXACT.decode(b);
  } catch {
    text = null;
  }
  if (text !== null) return sha256Hex(text);
  return hexOf(await crypto.subtle.digest('SHA-256', b as Uint8Array<ArrayBuffer>));
}

/** 帳本全帳形檢（部署端 readLedger 同規；不抓歷史 manifest——只驗最新一筆的帳鏈）。 */
export function parseLedger(text: string): Row[] {
  if (text.length === 0) throw new ShapeError('空帳（零行）');
  if (!text.endsWith('\n')) throw new ShapeError('末行未以換行收尾（疑截斷）');
  const rows = text
    .slice(0, -1)
    .split('\n')
    .map((s, i): Row => {
      const n = i + 1;
      if (!s.trim()) throw new ShapeError(`第 ${n} 行為空行`);
      let o: unknown;
      try {
        o = JSON.parse(s);
      } catch {
        throw new ShapeError(`第 ${n} 行非 JSON`);
      }
      if (!isObj(o)) throw new ShapeError(`第 ${n} 行非物件`);
      if (o.seq !== n) throw new ShapeError(`seq 非 1..n 連續：第 ${n} 行 seq=${JSON.stringify(o.seq)}`);
      if (o.schema !== SCHEMA) throw new ShapeError(`第 ${n} 行 schema 非 ${SCHEMA}`);
      if (o.type === 'correction') {
        if (!isHex64(o.references_manifest_sha256)) throw new ShapeError(`第 ${n} 行（correction）references_manifest_sha256 無效`);
      } else if (o.type === 'deploy' || o.type === 'baseline') {
        if (!isHex64(o.manifest_sha256)) throw new ShapeError(`第 ${n} 行 manifest_sha256 無效`);
        if (typeof o.manifest !== 'string' || !MANIFEST_PATH.test(o.manifest)) throw new ShapeError(`第 ${n} 行 manifest 路徑無效`);
      } else {
        throw new ShapeError(`第 ${n} 行 type 無效：${JSON.stringify(o.type)}`);
      }
      return o;
    });
  const seenSha = new Set<unknown>();
  const seenPath = new Set<unknown>();
  for (const o of rows) {
    if (o.type === 'correction') continue;
    if (seenSha.has(o.manifest_sha256)) throw new ShapeError(`manifest_sha256 重複（seq=${o.seq}；append-only 去重破）`);
    if (seenPath.has(o.manifest)) throw new ShapeError(`manifest 路徑重複（seq=${o.seq}）`);
    seenSha.add(o.manifest_sha256);
    seenPath.add(o.manifest);
  }
  return rows;
}

/** manifest 形檢（比對所需欄位；部署端 validateManifest 的比對面子集）。 */
function validateManifest(m: unknown): Manifest {
  const bad = (w: string): never => {
    throw new ShapeError(`manifest 無效：${w}`);
  };
  if (!isObj(m)) return bad('非物件');
  if (m.schema !== SCHEMA) bad(`schema≠${SCHEMA}`);
  if (m.type !== 'deploy' && m.type !== 'baseline') bad(`type=${JSON.stringify(m.type)}`);
  if (!Array.isArray(m.files) || m.files.length === 0) bad('files 空');
  const seen = new Set<string>();
  for (const f of m.files as unknown[]) {
    if (!isObj(f) || typeof f.path !== 'string' || !f.path || f.path.startsWith('/') || f.path.split('/').some((s) => s === '' || s === '.' || s === '..')) {
      bad(`files 路徑：${isObj(f) ? String(f.path) : String(f)}`);
    }
    const ff = f as Record<string, unknown>;
    if (seen.has(ff.path as string)) bad(`files 路徑重複：${String(ff.path)}`);
    seen.add(ff.path as string);
    if (!isHex64(ff.sha256)) bad(`files sha256：${String(ff.path)}`);
    if (!Number.isInteger(ff.bytes) || (ff.bytes as number) < 0) bad(`files bytes：${String(ff.path)}`);
  }
  const ih = m.index_html;
  if (!isObj(ih) || typeof ih.path !== 'string' || !isHex64(ih.sha256)) bad('index_html');
  const rb = m.rb_bundle;
  if (!isObj(rb) || typeof rb.file !== 'string' || typeof rb.path !== 'string' || !isHex64(rb.sha256)) bad('rb_bundle');
  const csp = m.csp_header;
  if (csp !== null && (!isObj(csp) || csp.source !== '_headers' || !isHex64(csp.value_sha256))) bad('csp_header');
  if (typeof m.csp_header_absent !== 'boolean') bad('csp_header_absent');
  return m as unknown as Manifest;
}

/** 帳鏈互核：manifest 自洽（部署端 selfConsistency 同規）＋帳行快速核對值 ＝ manifest 內值。 */
function chainErrors(row: Row, m: Manifest): string[] {
  const errs: string[] = [];
  const fmap = new Map(m.files.map((f) => [f.path, f]));
  const idx = fmap.get('index.html');
  if (!idx || m.index_html.path !== 'index.html' || m.index_html.sha256 !== idx.sha256) errs.push('manifest 自洽：index_html 與 files 條目 index.html 不符');
  const rbf = fmap.get(m.rb_bundle.path);
  const base = m.rb_bundle.path.slice(m.rb_bundle.path.lastIndexOf('/') + 1);
  if (!rbf || m.rb_bundle.sha256 !== rbf.sha256 || m.rb_bundle.file !== base) errs.push('manifest 自洽：rb_bundle 與 files 條目不符');
  if (m.csp_header_absent !== (m.csp_header === null)) errs.push('manifest 自洽：csp_header_absent 與 csp_header 不一致');
  if (m.file_count !== m.files.length) errs.push(`manifest 自洽：file_count（${String(m.file_count)}）≠ files.length（${m.files.length}）`);
  const pairs: [string, unknown, unknown][] = [
    ['rb_hash', row.rb_hash, m.rb_bundle.sha256],
    ['index_html', row.index_html, m.index_html.sha256],
    ['csp_header', row.csp_header, m.csp_header ? m.csp_header.value_sha256 : null],
    ['rb_bundle', row.rb_bundle, m.rb_bundle.file],
    ['version', row.version, m.version],
    ['commit', row.commit, m.commit],
    ['type', row.type, m.type],
    ['deployed_at', row.deployed_at, m.deployed_at],
  ];
  for (const [k, a, b] of pairs) {
    if (a !== b) errs.push(`帳行 ${k}=${JSON.stringify(a)} ≠ manifest ${JSON.stringify(b)}`);
  }
  return errs;
}

/** URL 候選序（部署端 canary 原樣）。 */
export function candidates(p: string): string[] {
  const c = [`/${p}`];
  if (p.endsWith('.html')) c.push(`/${p.slice(0, -'.html'.length)}`);
  if (p === 'index.html' || p.endsWith('/index.html')) {
    const dir = `/${p.slice(0, -'index.html'.length)}`;
    c.push(dir);
    if (dir.length > 1) c.push(dir.replace(/\/+$/, ''));
  }
  return [...new Set(c)];
}

const encodePath = (p: string): string =>
  p
    .split('/')
    .map((s) => encodeURIComponent(s))
    .join('/');

function toFetchError(url: string, e: unknown): FetchError {
  if (e instanceof FetchError) return e;
  const isAbort = e instanceof Error && (e.name === 'AbortError' || e.name === 'TimeoutError');
  return new FetchError(
    url,
    isAbort ? 'timeout' : 'network',
    isAbort ? `timeout（>${PROBE_TIMEOUT_MS}ms）` : `fetch 失敗（${e instanceof Error && e.cause ? String(e.cause) : String(e)}）`,
  );
}

function describe(e: unknown): string {
  if (e instanceof HttpError) return `HTTP ${e.status}`;
  if (e instanceof FetchError) return `${e.reason}：${e.message}`;
  return String(e);
}

interface Probe {
  status: number;
  body: Uint8Array | null;
  location: string | null;
  csp: string | null;
}

/** 單發 GET（redirect:'manual'——3xx 原樣觀測；fetchBytes 恆 follow 不適用）。timeout 涵蓋讀 body。 */
async function probe(url: string, wantBody: boolean): Promise<Probe> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), PROBE_TIMEOUT_MS);
  try {
    const res = await fetch(url, { redirect: 'manual', headers: UA_HEADERS, signal: ctl.signal });
    const out: Probe = {
      status: res.status,
      body: null,
      location: res.headers.get('location'),
      csp: res.headers.get('content-security-policy'),
    };
    if (res.status !== 200 || !wantBody) {
      await res.body?.cancel().catch(() => undefined);
      return out;
    }
    const cl = Number(res.headers.get('content-length') ?? '');
    if (Number.isFinite(cl) && cl > PROBE_MAX_BYTES) {
      await res.body?.cancel().catch(() => undefined);
      throw new FetchError(url, 'too-large', `回應過大（content-length ${cl} > cap ${PROBE_MAX_BYTES}）`);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = res.body?.getReader();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > PROBE_MAX_BYTES) {
          await reader.cancel().catch(() => undefined);
          throw new FetchError(url, 'too-large', `回應過大（>cap ${PROBE_MAX_BYTES}）`);
        }
        chunks.push(value);
      }
    }
    const body = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      body.set(c, off);
      off += c.length;
    }
    out.body = body;
    return out;
  } catch (e) {
    throw toFetchError(url, e);
  } finally {
    clearTimeout(timer);
  }
}

interface Attempt {
  url: string;
  status: number | null;
  sha256: string | null;
  location: string | null;
  error: string | null;
}

interface FileResult {
  file: ManifestFile;
  kind: 'ok' | 'mismatch' | 'skip' | 'network';
  attempts: Attempt[];
}

const is3xx = (s: number | null): boolean => s !== null && s >= 300 && s < 400;

function resolveHref(loc: string, from: string): string | null {
  try {
    return new URL(loc, from).href;
  } catch {
    return null;
  }
}

async function checkFile(base: string, f: ManifestFile): Promise<FileResult> {
  const urls = candidates(f.path).map((c) => base + encodePath(c));
  const inSet = new Set(urls.map((u) => resolveHref(u, u)));
  const attempts: Attempt[] = [];
  for (const url of urls) {
    try {
      const r = await probe(url, true);
      const sha = r.status === 200 && r.body ? await sha256OfBytes(r.body) : null;
      attempts.push({ url, status: r.status, sha256: sha, location: r.location, error: null });
      if (r.status === 200 && sha === f.sha256) return { file: f, kind: 'ok', attempts };
    } catch (e) {
      attempts.push({ url, status: null, sha256: null, location: null, error: describe(e) });
    }
  }
  if (attempts.some((a) => a.status === 200)) return { file: f, kind: 'mismatch', attempts };
  const target = (a: Attempt): string | null => (is3xx(a.status) && a.location !== null ? resolveHref(a.location, a.url) : null);
  if (attempts.some((a) => target(a) !== null && !inSet.has(target(a)))) return { file: f, kind: 'skip', attempts };
  // 規範化 3xx（落點在候選集內）不計；其餘回應全為 404/410＝缺檔
  const rest = attempts.filter((a) => !(target(a) !== null && inSet.has(target(a))));
  if (rest.length > 0 && rest.every((a) => a.status === 404 || a.status === 410)) return { file: f, kind: 'mismatch', attempts };
  return { file: f, kind: 'network', attempts };
}

interface CspResult {
  kind: 'ok' | 'mismatch' | 'network';
  url: string;
  expected: string | null;
  live: string | null;
  detail: string;
}

/** CSP 探測：/privacy 非 200／擲出＝探測面失敗（fail-closed→取得錯）。 */
async function checkCsp(base: string, m: Manifest): Promise<CspResult> {
  const url = `${base}/privacy`;
  const expected = m.csp_header ? m.csp_header.value_sha256 : null;
  let r: Probe;
  try {
    r = await probe(url, false);
  } catch (e) {
    return { kind: 'network', url, expected, live: null, detail: describe(e) };
  }
  if (r.status !== 200) return { kind: 'network', url, expected, live: null, detail: `HTTP ${r.status}` };
  // fetch 把同名標頭以「, 」合併；CSP 單條 policy 的指令值語法不含逗號，故末段＝最後一筆
  const last = r.csp === null ? null : (r.csp.split(',').pop() ?? '').trim();
  const live = last === null ? null : await sha256Hex(last);
  return { kind: live === expected ? 'ok' : 'mismatch', url, expected, live, detail: live === null ? '標頭缺席' : '' };
}

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k]);
    }
  });
  await Promise.all(workers);
  return out;
}

const fmtSha = (s: unknown): string => (typeof s === 'string' ? s : 'null');

export async function runVerifySite(o: VerifySiteOpts): Promise<VerifySiteOutcome> {
  const base = o.url.replace(/\/+$/, '');
  const lines: string[] = [];
  const mismatches: Record<string, unknown>[] = [];
  const networkErrors: Record<string, unknown>[] = [];
  const chainErrs: string[] = [];
  const skips: string[] = [];
  const j: Record<string, unknown> = {
    ok: false,
    verdict: null,
    reason: null,
    url: base,
    log: o.log,
    ledger: null,
    manifest_url: null,
    compared: 0,
    redirect_skip: skips,
    mismatches,
    network_errors: networkErrors,
    chain_errors: chainErrs,
    correction: null,
  };
  const done = (verdict: Verdict, reason: string, marker: string): VerifySiteOutcome => {
    lines.push(marker);
    j.ok = verdict === 'ok';
    j.verdict = verdict;
    j.reason = reason;
    return { exit: EXIT_OF[verdict], lines, jsonOut: j };
  };

  // —— 1. 帳本 ——
  let logBytes: Uint8Array;
  try {
    logBytes = await fetchBytes(o.log, { headers: UA_HEADERS, maxBytes: LEDGER_MAX_BYTES });
  } catch (e) {
    lines.push(`帳本：${o.log}——取得失敗（${describe(e)}）`);
    return done('network', 'ledger-fetch', `VERIFY-SITE-NETWORK (帳本取得失敗：${e instanceof HttpError ? `HTTP ${e.status}` : e instanceof FetchError ? e.reason : 'error'})`);
  }
  let rows: Row[];
  try {
    let text: string;
    try {
      text = UTF8_EXACT.decode(logBytes);
    } catch {
      throw new ShapeError('帳本非 UTF-8');
    }
    rows = parseLedger(text);
  } catch (e) {
    if (!(e instanceof ShapeError)) throw e;
    lines.push(`帳本：${o.log}——帳面形不合法（${e.message}）`);
    return done('mismatch', 'ledger-shape', `VERIFY-SITE-MISMATCH (帳面形不合法：${e.message})`);
  }
  const row = rows[rows.length - 1];
  j.ledger = {
    rows: rows.length,
    seq: row.seq,
    type: row.type,
    version: row.version ?? null,
    commit: row.commit ?? null,
    manifest: row.manifest ?? null,
    manifest_sha256: row.manifest_sha256 ?? null,
  };
  lines.push(`帳本：${o.log}（${rows.length} 行；最新 seq=${String(row.seq)} type=${String(row.type)} version=${String(row.version)}）`);

  // —— 2. 最新一筆＝更正紀錄：營運者已記錄現場不符 ——
  if (row.type === 'correction') {
    const mm = Array.isArray(row.mismatches) ? (row.mismatches as unknown[]) : [];
    j.correction = {
      seq: row.seq,
      observed_at: row.observed_at ?? null,
      references_seq: row.references_seq ?? null,
      references_manifest_sha256: row.references_manifest_sha256,
      mismatches: mm,
    };
    lines.push(
      `更正紀錄：observed_at=${String(row.observed_at)} references_seq=${String(row.references_seq)} references_manifest_sha256=${String(row.references_manifest_sha256)}`,
    );
    if (!Array.isArray(row.mismatches)) lines.push('  （mismatches 欄缺席）');
    for (const x of mm) {
      const r = isObj(x) ? x : {};
      const tail = 'live_sha256' in r ? `live=${fmtSha(r.live_sha256)}` : `http=${String(r.http_status)}`;
      lines.push(`  ✗ ${String(r.path)}（${String(r.url)}）expected=${fmtSha(r.expected_sha256)} ${tail}`);
    }
    lines.push('結論：營運者已在公開帳本記錄「現場不符」——最新已知狀態＝不符（零 live 探測）。');
    return done('correction', 'correction', `VERIFY-SITE-CORRECTION (seq=${String(row.seq)} references_seq=${String(row.references_seq)}；${mm.length} 項不符)`);
  }

  // —— 3. manifest＋帳鏈 ——
  const manifestUrl = new URL(row.manifest as string, o.log).href;
  j.manifest_url = manifestUrl;
  let mBytes: Uint8Array;
  try {
    mBytes = await fetchBytes(manifestUrl, { headers: UA_HEADERS });
  } catch (e) {
    lines.push(`manifest：${manifestUrl}——取得失敗（${describe(e)}）`);
    return done('network', 'manifest-fetch', `VERIFY-SITE-NETWORK (manifest 取得失敗：${e instanceof HttpError ? `HTTP ${e.status}` : e instanceof FetchError ? e.reason : 'error'})`);
  }
  const mSha = await sha256OfBytes(mBytes);
  if (mSha !== row.manifest_sha256) {
    chainErrs.push(`manifest 位元組 sha256 ${mSha} ≠ 帳行 manifest_sha256 ${String(row.manifest_sha256)}`);
    lines.push(`manifest：${manifestUrl}`);
    lines.push(`  ✗ 帳鏈破：${chainErrs[0]}`);
    return done('mismatch', 'chain-broken', 'VERIFY-SITE-MISMATCH (帳鏈破：manifest sha256 ≠ 帳行)');
  }
  lines.push(`manifest：${manifestUrl}（sha256 ${mSha}＝帳行 ✓）`);
  let m: Manifest;
  try {
    let parsed: unknown;
    try {
      parsed = JSON.parse(UTF8_EXACT.decode(mBytes));
    } catch {
      throw new ShapeError('manifest 非 UTF-8 JSON');
    }
    m = validateManifest(parsed);
  } catch (e) {
    if (!(e instanceof ShapeError)) throw e;
    lines.push(`  ✗ 帳面形不合法：${e.message}`);
    return done('mismatch', 'manifest-shape', `VERIFY-SITE-MISMATCH (帳面形不合法：${e.message})`);
  }
  chainErrs.push(...chainErrors(row, m));
  if (chainErrs.length > 0) {
    for (const x of chainErrs) lines.push(`  ✗ 帳鏈破：${x}`);
    return done('mismatch', 'chain-broken', `VERIFY-SITE-MISMATCH (帳鏈破：${chainErrs.length} 項互核不符)`);
  }

  // —— 4＋5. live 逐檔＋CSP ——
  const targets = m.files.filter((f) => !EXCLUDE.has(f.path));
  lines.push(`站：${base}（${targets.length} 檔＋CSP；redirect 不跟隨、不重試）`);
  const results = await pool(targets, CONCURRENCY, (f) => checkFile(base, f));
  const csp = await checkCsp(base, m);
  let okCount = 0;
  for (const r of results) {
    if (r.kind === 'ok') {
      okCount++;
    } else if (r.kind === 'skip') {
      skips.push(r.file.path);
      const out = r.attempts.find((a) => is3xx(a.status) && a.location !== null);
      lines.push(`  skip ${r.file.path}（全候選無 200；3xx 轉出候選集${out ? `：${out.url} → ${String(out.location)}` : ''}）`);
    } else if (r.kind === 'mismatch') {
      const hit = r.attempts.find((a) => a.status === 200);
      if (hit) {
        mismatches.push({ path: r.file.path, url: hit.url, expected_sha256: r.file.sha256, live_sha256: hit.sha256 });
      } else {
        const a = r.attempts.find((x) => x.status === 404 || x.status === 410) ?? r.attempts[0];
        mismatches.push({ path: r.file.path, url: a.url, expected_sha256: r.file.sha256, http_status: a.status });
      }
    } else {
      networkErrors.push({
        path: r.file.path,
        attempts: r.attempts.map((a) => ({ url: a.url, http_status: a.status, error: a.error })),
      });
    }
  }
  if (csp.kind === 'mismatch') {
    mismatches.push({ path: 'csp_header', url: csp.url, expected_sha256: csp.expected, live_sha256: csp.live });
  } else if (csp.kind === 'network') {
    networkErrors.push({ path: 'csp_header', attempts: [{ url: csp.url, http_status: null, error: `CSP 探測面失敗：${csp.detail}` }] });
  }
  j.compared = okCount + (csp.kind === 'ok' ? 1 : 0);

  for (const x of mismatches) {
    const tail = 'live_sha256' in x ? `live=${fmtSha(x.live_sha256)}` : `http=${String(x.http_status)}`;
    lines.push(`  ✗ ${String(x.path)}（${String(x.url)}）expected=${fmtSha(x.expected_sha256)} ${tail}`);
  }
  for (const x of networkErrors) {
    const at = (x.attempts as { url: string; http_status: number | null; error: string | null }[])
      .map((a) => `${a.url} ${a.error ?? `HTTP ${String(a.http_status)}`}`)
      .join('；');
    lines.push(`  ! ${String(x.path)} 取得錯：${at}`);
  }

  const fileMis = mismatches.filter((x) => x.path !== 'csp_header').length;
  const cspMis = csp.kind === 'mismatch';
  if (mismatches.length > 0) {
    const also = networkErrors.length > 0 ? `；另 ${networkErrors.length} 項取得錯` : '';
    const what = fileMis > 0 ? `${fileMis} 檔${cspMis ? '＋CSP ' : ''}` : 'CSP ';
    return done('mismatch', 'files', `VERIFY-SITE-MISMATCH (${what}不符${also})`);
  }
  if (networkErrors.length > 0) {
    const fileNet = networkErrors.length - (csp.kind === 'network' ? 1 : 0);
    const parts = [fileNet > 0 ? `${fileNet} 檔取得錯` : '', csp.kind === 'network' ? `CSP 探測面失敗：${csp.detail}` : ''].filter(Boolean);
    return done('network', csp.kind === 'network' && fileNet === 0 ? 'csp-probe' : 'live-fetch', `VERIFY-SITE-NETWORK (${parts.join('＋')})`);
  }
  lines.push('結論：live 站與公開部署紀錄最新一筆逐檔相符（工具只驗自己抓到的那份；帳本由營運者寫入）。');
  return done('ok', 'ok', `VERIFY-SITE-OK (${j.compared as number} compared / ${skips.length} redirect-skip / seq ${String(row.seq)})`);
}

export { DEFAULT_BASE_URL };
