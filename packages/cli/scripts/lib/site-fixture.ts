/**
 * site-fixture.ts — verify-site hermetic 電池（閘 [8] 與其毒化齒子程序共用；零外網）。
 *
 * node:http 單一 server，帳本 root 與 live root 分路：
 *   /log/<變體>/deploy-log.jsonl、/log/<變體>/manifests/<名>.json   ← 公開帳本 repo raw 面
 *   /live/<變體>/…                                                  ← live 站面
 * manifest／帳本行形＝部署端 deploy-log.cjs buildManifest 原樣（JSON.stringify(m, null, 2)+'\n'；
 * files 依路徑排序）。雜湊 oracle＝部署端同一原語（node 內建 createHash 逐位元組）——與受測的
 * site.ts 雜湊面互相獨立；文字檔面與 core sha256Hex 恆等。
 * live 面模擬實測平台語意（2026-11-19 tacet.ink）：x.html→308 x；d/index.html→307 d；d/→308 d；
 * index.html→308 /；轉址來源 landing（→301 /，落點在候選集外＝redirect-skip）。
 */

import http from 'node:http';
import { createHash } from 'node:crypto';

export const SCHEMA = 'tacet-deploy-log/v1';
export const CSP_VALUE = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'";
const EXCLUDE = new Set(['_headers', '_redirects']);

export const shaB = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex');

/** 現行部署的 dist 樹（含二進位非 UTF-8 檔＋BOM 文字檔：覆蓋 site.ts 雜湊雙面）。 */
function currentFiles(): Map<string, Buffer> {
  const f = new Map<string, Buffer>();
  f.set('index.html', Buffer.from('<!doctype html><html><body id="home">首頁</body></html>\n'));
  f.set('about.html', Buffer.from('<!doctype html><html><body id="about">關於</body></html>\n'));
  f.set('docs/index.html', Buffer.from('<!doctype html><html><body id="docs">文件</body></html>\n'));
  f.set('privacy.html', Buffer.from('<!doctype html><html><body id="privacy">隱私</body></html>\n'));
  f.set('landing.html', Buffer.from('<!doctype html><html><body id="landing">舊落地頁</body></html>\n'));
  f.set('assets/index-gate.js', Buffer.from('console.log("v1.2.3+abcdef0");\n'));
  f.set('assets/bom.css', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('body{color:#111}\n')]));
  f.set('media/pic.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0x9c, 0x01]));
  f.set('_headers', Buffer.from(`/*\n  Content-Security-Policy: ${CSP_VALUE}\n`));
  f.set('_redirects', Buffer.from('/landing / 301\n/landing.html / 301\n'));
  return f;
}

interface Built {
  bytes: Buffer;
  sha: string;
  row: Record<string, unknown>;
}

const VERSION = 'v1.2.3+abcdef0';
const COMMIT = 'abcdef0' + '1'.repeat(33);

function buildManifest(files: Map<string, Buffer>, type: string, deployedAt: string, version: string, commit: string): { bytes: Buffer; manifest: Record<string, unknown> } {
  const entries = [...files.keys()].sort().map((p) => ({ path: p, sha256: shaB(files.get(p)!), bytes: files.get(p)!.length }));
  const rb = entries.find((e) => /^assets\/index-[^/]*\.js$/.test(e.path))!;
  let csp: { source: string; value_sha256: string } | null = null;
  const h = files.get('_headers');
  if (h) {
    const m = /Content-Security-Policy:(.*)/i.exec(h.toString('utf8'));
    if (m) csp = { source: '_headers', value_sha256: shaB(m[1].trim()) };
  }
  const manifest = {
    schema: SCHEMA,
    type,
    deployed_at: deployedAt,
    version,
    commit,
    source_repo: 'https://github.com/tacet-ink/fixture',
    index_html: { path: 'index.html', sha256: entries.find((e) => e.path === 'index.html')!.sha256 },
    rb_bundle: { file: rb.path.slice(rb.path.lastIndexOf('/') + 1), path: rb.path, sha256: rb.sha256 },
    csp_header: csp,
    csp_header_absent: csp === null,
    files: entries,
    file_count: entries.length,
  };
  return { bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'), manifest };
}

function built(seq: number, files: Map<string, Buffer>, type: string, deployedAt: string, version: string, commit: string): Built {
  const { bytes, manifest } = buildManifest(files, type, deployedAt, version, commit);
  const sha = shaB(bytes);
  const m = manifest as { rb_bundle: { file: string; sha256: string }; index_html: { sha256: string }; csp_header: { value_sha256: string } | null };
  const row = {
    seq,
    schema: SCHEMA,
    type,
    deployed_at: deployedAt,
    version,
    commit,
    rb_bundle: m.rb_bundle.file,
    rb_hash: m.rb_bundle.sha256,
    index_html: m.index_html.sha256,
    csp_header: m.csp_header ? m.csp_header.value_sha256 : null,
    manifest: `manifests/${deployedAt.replace(/[-:]/g, '')}-${version}.json`,
    manifest_sha256: sha,
  };
  return { bytes, sha, row };
}

type Route = { status: number; body?: Buffer; location?: string };

/** live 站路由（平台語意模擬；見檔頭）。 */
function siteRoutes(prefix: string, files: Map<string, Buffer>): Map<string, Route> {
  const r = new Map<string, Route>();
  const redir = (status: number, to: string): Route => ({ status, location: prefix + to });
  for (const [f, body] of files) {
    if (EXCLUDE.has(f)) continue;
    if (f === 'landing.html') {
      r.set('/landing.html', redir(301, '/'));
      r.set('/landing', redir(301, '/'));
    } else if (f === 'index.html') {
      r.set('/', { status: 200, body });
      r.set('/index.html', redir(308, '/'));
      r.set('/index', redir(307, '/'));
    } else if (f.endsWith('/index.html')) {
      const dir = '/' + f.slice(0, -'/index.html'.length);
      r.set(dir, { status: 200, body });
      r.set(dir + '/', redir(308, dir));
      r.set(dir + '/index.html', redir(307, dir));
      r.set(dir + '/index', redir(307, dir));
    } else if (f.endsWith('.html')) {
      const pretty = '/' + f.slice(0, -'.html'.length);
      r.set(pretty, { status: 200, body });
      r.set('/' + f, redir(308, pretty));
    } else {
      r.set('/' + f, { status: 200, body });
    }
  }
  return r;
}

export interface SiteFixture {
  origin: string;
  logUrl(variant: string): string;
  liveUrl(variant: string): string;
  /** 每筆請求路徑（判「零 live 探測」用） */
  reqLog: string[];
  liveHits(): number;
  close(): Promise<void>;
  /** 現行部署 seq2 的 manifest_sha256（correction 行 references 面） */
  currentSha: string;
}

export async function startSiteFixture(): Promise<SiteFixture> {
  const cur = currentFiles();
  const old = new Map(cur);
  old.set('index.html', Buffer.from('<!doctype html><html><body id="home">舊首頁</body></html>\n'));
  const b1 = built(1, old, 'baseline', '2026-11-01T00:00:00Z', 'v1.2.2+abcdef0', COMMIT);
  const b2 = built(2, cur, 'deploy', '2026-11-19T00:00:00Z', VERSION, COMMIT);
  const jsonl = (rows: Record<string, unknown>[]) => rows.map((x) => JSON.stringify(x)).join('\n') + '\n';

  // 帳本變體
  const ledgers = new Map<string, Map<string, Buffer>>();
  const okFiles = (): Map<string, Buffer> =>
    new Map([
      ['deploy-log.jsonl', Buffer.from(jsonl([b1.row, b2.row]))],
      [b1.row.manifest as string, b1.bytes],
      [b2.row.manifest as string, b2.bytes],
    ]);
  ledgers.set('ok', okFiles());
  // manifest 位元組毒化（帳行 hash 不動）：攻擊者同換站與 manifest——manifest 改記被竄改的 about.html
  const tampered = new Map(cur);
  tampered.set('about.html', Buffer.from('<!doctype html><html><body id="about">關於（被竄改）</body></html>\n'));
  const bT = built(2, tampered, 'deploy', '2026-11-19T00:00:00Z', VERSION, COMMIT);
  const pm = okFiles();
  pm.set(b2.row.manifest as string, bT.bytes);
  ledgers.set('poison-manifest', pm);
  // 末行 correction（營運者已記錄現場不符）
  const corr = {
    seq: 3,
    schema: SCHEMA,
    type: 'correction',
    observed_at: '2026-11-19T01:00:00Z',
    version: VERSION,
    commit: COMMIT,
    references_seq: 2,
    references_manifest_sha256: b2.sha,
    base_url: 'https://tacet.ink',
    mismatches: [{ path: 'about.html', url: '/about', expected_sha256: shaB(cur.get('about.html')!), live_sha256: shaB('x') }],
  };
  const cl = okFiles();
  cl.set('deploy-log.jsonl', Buffer.from(jsonl([b1.row, b2.row, corr])));
  ledgers.set('correction', cl);
  // 垃圾行（200 但非法 JSON）
  const gl = okFiles();
  gl.set('deploy-log.jsonl', Buffer.from(jsonl([b1.row, b2.row]) + 'this is {not json\n'));
  ledgers.set('garbage', gl);

  // live 變體
  const sites = new Map<string, { routes: Map<string, Route>; csp: boolean }>();
  const mk = (v: string, files: Map<string, Buffer>, csp = true) => {
    const s = { routes: siteRoutes(`/live/${v}`, files), csp };
    sites.set(v, s);
    return s;
  };
  mk('good', cur);
  const pb = new Map(cur);
  const png = Buffer.from(cur.get('media/pic.png')!);
  png[png.length - 1] ^= 0x01; // 一 byte 毒化（二進位面）
  pb.set('media/pic.png', png);
  mk('poison-byte', pb);
  mk('tampered', tampered);
  mk('missing-about', cur).routes.delete('/about'); // .html 候選仍 308 → /about（候選集內＝規範化），漂亮網址 404
  mk('csp-absent', cur, false);
  mk('csp-503', cur).routes.set('/privacy', { status: 503 });
  mk('file-503', cur).routes.set('/assets/index-gate.js', { status: 503 });

  const reqLog: string[] = [];
  const server = http.createServer((req, res) => {
    const p = (req.url ?? '/').split('?')[0];
    reqLog.push(p);
    const lm = /^\/log\/([^/]+)\/(.+)$/.exec(p);
    if (lm) {
      const body = ledgers.get(lm[1])?.get(decodeURIComponent(lm[2]));
      if (!body) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end(body);
      return;
    }
    const sm = /^\/live\/([^/]+)(\/.*)?$/.exec(p);
    const site = sm ? sites.get(sm[1]) : undefined;
    const route = site?.routes.get(sm![2] ?? '/');
    if (!site || !route) {
      res.writeHead(404).end('not found');
      return;
    }
    if (route.location) {
      res.writeHead(route.status, { location: route.location }).end();
      return;
    }
    const headers: Record<string, string> = {};
    if (route.status === 200 && site.csp) headers['content-security-policy'] = CSP_VALUE;
    res.writeHead(route.status, headers).end(route.body ?? '');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    logUrl: (v) => `${origin}/log/${v}/deploy-log.jsonl`,
    liveUrl: (v) => `${origin}/live/${v}`,
    reqLog,
    liveHits: () => reqLog.filter((x) => x.startsWith('/live/')).length,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
    currentSha: b2.sha,
  };
}
