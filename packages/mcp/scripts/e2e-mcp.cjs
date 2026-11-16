/**
 * e2e-mcp.cjs — R3c 過程層 e2e（stdio probe、inspector 形；hermetic：devstack stub＋tmp HOME；零外網）。
 * 跑法：npm run build -w @tacet-ink/journal-mcp 後 node packages/mcp/scripts/e2e-mcp.cjs
 * 全綠印 E2E-MCP-OK(N assertions)（整行＝唯一消費錨）；任一失敗 exit 1。
 *
 * 沙箱紀律（2026-11-16 probe 重驗：子程序→loopback ephemeral port 被 egress 吞，
 * 同 R3b 2026-11-15 形）→ 分層：
 *   A 網路面（in-process）：直載 dist/session.js 餵 JSON-RPC 行（同 process fetch 到 stub）——
 *     modern MRTR 全鏈（fresh→InputRequiredResult→accept/decline/偽造 state/digest 不符；
 *     fresh 雙載體：spec 形 url:{} 臂＋寬鬆 url:true 鏈）、
 *     N3 毒化、白名單毒化（out 越界＋env 越界）、annual 參照、verify 四方帳（雙 MATCH／
 *     MISMATCH／死 base fail-closed）、值零明文 census、legacy era（initialize→貼連結主路徑）
 *   B stdio 面（child 離線）：spawn node dist/server.js（stdio pipe JSON-RPC）——
 *     discover／list／錯誤面（-32022／-32602／-32600／-32700／-32601）／通知零回應／
 *     legacy initialize／N3 停止（127.0.0.1:1 拒連面）／零 server 發起 request／EOF 清退
 *   C shell 面：claude plugin validate --strict＋workspaces 帳
 */
'use strict';
const { spawnSync, spawn } = require('node:child_process');
const cryptoNode = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const PKG = path.resolve(__dirname, '..'); // packages/mcp
const SERVER = path.join(PKG, 'dist', 'server.js');

let assertions = 0;
const failures = [];
function check(cond, label, detail) {
  assertions++;
  if (cond) {
    process.stdout.write(`  ok   ${label}\n`);
  } else {
    failures.push(`${label}${detail !== undefined ? `（${String(detail).slice(0, 200)}）` : ''}`);
    process.stdout.write(`  FAIL ${label}${detail !== undefined ? `（${String(detail).slice(0, 200)}）` : ''}\n`);
  }
}
function sha256HexS(s) {
  return cryptoNode.createHash('sha256').update(s).digest('hex');
}
function phase(t) {
  process.stdout.write(`\n== ${t} ==\n`);
}

const MODERN = (caps) => ({
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientCapabilities': caps,
});
const FILL_RE = /#p=[A-Za-z0-9_-]+/;

async function innerMain() {
  const TMP = {
    home: fs.mkdtempSync(path.join(os.tmpdir(), 'tacet-mcp-e2e-home-')),
    pages: fs.mkdtempSync(path.join(os.tmpdir(), 'tacet-mcp-e2e-pages-')),
  };
  const ORIG_HOME = process.env.HOME;
  process.env.HOME = TMP.home;
  for (const k of Object.keys(process.env)) if (k.startsWith('TACET_SECRET_')) delete process.env[k];
  fs.mkdirSync(path.join(TMP.home, '.tacet-secret'), { recursive: true, mode: 0o700 });

  const SREQ_PAGE = '<html id="sreq-e2e">sreq fill page fixture</html>';
  const SECRET_PAGE = '<html id="secret-e2e">secret page fixture</html>';
  fs.writeFileSync(path.join(TMP.pages, 'sreq.html'), SREQ_PAGE);
  fs.writeFileSync(path.join(TMP.pages, 'secret.html'), SECRET_PAGE);
  const SUMS_FILE = path.join(TMP.home, 'sums-e2e.txt');
  fs.writeFileSync(
    SUMS_FILE,
    `${sha256HexS(SREQ_PAGE)}  sreq.html\n${sha256HexS(SECRET_PAGE)}  secret.html\n`,
  );
  const SUMS_BAD = path.join(TMP.home, 'sums-bad.txt');
  fs.writeFileSync(
    SUMS_BAD,
    `${'0'.repeat(64)}  sreq.html\n${sha256HexS(SECRET_PAGE)}  secret.html\n`,
  );

  const { SreqStub } = require(path.join(PKG, '..', 'cli', 'scripts', 'lib', 'devstack-stub.cjs'));
  const stub = await new SreqStub(TMP.pages).listen();
  const base = stub.base;

  const { McpSession } = await import(pathToFileURL(path.join(PKG, 'dist', 'session.js')));

  let nextId = 1;
  const modernReq = (s, method, params, caps = {}) =>
    s
      .handleLine(
        JSON.stringify({
          jsonrpc: '2.0',
          id: nextId++,
          method,
          params: { ...params, _meta: MODERN(caps) },
        }),
      )
      .then((o) => (o ? JSON.parse(o) : null));
  const retryLine = (s, args, inputResponses, requestState, caps = { elicitation: { url: true } }) =>
    s
      .handleLine(
        JSON.stringify({
          jsonrpc: '2.0',
          id: nextId++,
          method: 'tools/call',
          params: { name: 'request', arguments: args, inputResponses, requestState, _meta: MODERN(caps) },
        }),
      )
      .then((o) => JSON.parse(o));

  const transcript = [];

  // ---- A1 modern 面：discover／list ----
  phase('A modern（in-process 網路面）');
  const sA = new McpSession();
  {
    const disc = await modernReq(sA, 'server/discover', {});
    check(
      disc?.result?.resultType === 'complete' &&
        disc.result.supportedVersions.includes('2026-07-28') &&
        disc.result._meta?.['io.modelcontextprotocol/serverInfo']?.name === 'tacet-secret',
      'A1 server/discover 形（resultType/supportedVersions/serverInfo）',
      disc,
    );
    const tl = await modernReq(sA, 'tools/list', {});
    const names = ((tl?.result?.tools ?? []).map((t) => t.name)).sort();
    check(
      JSON.stringify(names) === JSON.stringify(['request', 'verify']),
      'A1 tools/list = request+verify（零 submit——送出預設關缺席面）',
      names,
    );
    transcript.push(JSON.stringify(disc), JSON.stringify(tl));
  }

  // ---- A2 fresh（url 能力）→ InputRequiredResult ----
  let fillA = null;
  let stateA = null;
  let tokenA = null;
  let privD = null;
  let outA = null;
  {
    stub.reqLog.length = 0;
    const r = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_FILE } }, { elicitation: { url: true } });
    const ir = r?.result;
    transcript.push(JSON.stringify(r));
    check(
      ir?.resultType === 'input_required' &&
        ir?.inputRequests?.fill?.method === 'elicitation/create' &&
        ir.inputRequests.fill.params.mode === 'url' &&
        typeof ir.inputRequests.fill.params.message === 'string' &&
        String(ir.inputRequests.fill.params.message).length > 10,
      'A2 fresh（url 能力）→ InputRequiredResult（elicitation/create url mode＋message）',
      ir,
    );
    const url = ir?.inputRequests?.fill?.params?.url;
    check(
      typeof url === 'string' && url.startsWith(`${base}/sreq/?s=`) && /#p=/.test(url) && !url.includes('&t=') && !url.includes('#k='),
      'A2 fill 連結 canonical 形（?s=32hex＋#p=；零 &t= 零 #k=）',
      url,
    );
    fillA = url;
    stateA = ir?.requestState;
    check(typeof stateA === 'string' && stateA.split('.').length === 2, 'A2 requestState opaque blob 形（body.mac）', stateA);
    check(stub.countPaths((p) => p === '/api/sreq') === 1, 'A2 server 恰一 POST /api/sreq');
    const iPage = stub.reqLog.findIndex((x) => x.method === 'GET' && x.path === '/sreq');
    const iApi = stub.reqLog.findIndex((x) => x.method === 'POST' && x.path === '/api/sreq');
    check(iPage !== -1 && iApi !== -1 && iPage < iApi, 'A2 N3（GET /sreq）先於開 slot');
    const ids = stub.slotIds();
    check(ids.length === 1, 'A2 stub 恰一 slot');
    const bundleFile = path.join(TMP.home, '.tacet-secret', `${ids[0]}.retrieve.json`);
    check(fs.existsSync(bundleFile) && (fs.statSync(bundleFile).mode & 0o777) === 0o600, 'A2 取回 bundle 落盤（600）');
    const bundle = JSON.parse(fs.readFileSync(bundleFile, 'utf8'));
    tokenA = String(bundle.retrieve_link).match(/&t=([^&#]+)/)?.[1] ?? null;
    privD = JSON.parse(Buffer.from(String(bundle.retrieve_link).split('#k=')[1], 'base64url').toString('utf8')).d;
    outA = bundleFile;
  }

  // ---- A2s spec 形 caps 臂（2026-07-28 schema:769-773：elicitation.url＝JSONObject，{}＝支援）----
  {
    stub.reqLog.length = 0;
    const r = await modernReq(
      sA,
      'tools/call',
      { name: 'request', arguments: { base, sums: SUMS_FILE } },
      { elicitation: { url: {} } },
    );
    const ir = r?.result;
    transcript.push(JSON.stringify(r));
    check(
      ir?.resultType === 'input_required' &&
        ir?.inputRequests?.fill?.method === 'elicitation/create' &&
        ir.inputRequests.fill.params.mode === 'url' &&
        typeof ir.inputRequests.fill.params.url === 'string' &&
        typeof ir.requestState === 'string' &&
        String(ir.requestState).split('.').length === 2,
      'A2s spec 形 {elicitation:{url:{}}} fresh → InputRequiredResult（spec 形客戶端觸發 MRTR 面）',
      ir,
    );
    check(stub.countPaths((p) => p === '/api/sreq') === 1, 'A2s spec 形臂恰一 POST /api/sreq');
  }

  // ---- A3 accept 重試 ----
  {
    const r = await retryLine(sA, { base, sums: SUMS_FILE }, { fill: { action: 'accept' } }, stateA);
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(
      r?.result?.resultType === 'complete' &&
        r.result.isError === false &&
        /已由客戶端打開/.test(text) &&
        text.includes(String(fillA)) &&
        text.includes(String(outA)),
      'A3 accept 重試 → 最終結果（開頁＋連結＋bundle 路徑）',
      text,
    );
    check(stub.countPaths((p) => p === '/api/sreq/fill') === 0, 'A3 零投遞（accept 後無 /api/sreq/fill）');
  }

  // ---- A4 decline 重試 → 降級貼連結 ----
  {
    stub.reqLog.length = 0;
    const r1 = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_FILE } }, { elicitation: { url: true } });
    transcript.push(JSON.stringify(r1));
    const r2 = await retryLine(sA, { base, sums: SUMS_FILE }, { fill: { action: 'decline' } }, r1?.result?.requestState);
    transcript.push(JSON.stringify(r2));
    const text = r2?.result?.content?.[0]?.text ?? '';
    check(
      r2?.result?.isError === false &&
        /降級貼連結主路徑/.test(text) &&
        FILL_RE.test(text) &&
        /已寫入/.test(text),
      'A4 decline 重試 → 降級貼連結主路徑（連結＋已寫入）',
      text,
    );
  }

  // ---- A5 偽造 requestState → 拒 ----
  {
    const r1 = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_FILE } }, { elicitation: { url: true } });
    const st = r1?.result?.requestState;
    const [b, m] = String(st).split('.');
    const bad = b + '.' + (m[0] === 'A' ? 'B' : 'A') + m.slice(1);
    const r2 = await retryLine(sA, { base, sums: SUMS_FILE }, { fill: { action: 'accept' } }, bad);
    transcript.push(JSON.stringify(r2));
    const text = r2?.result?.content?.[0]?.text ?? '';
    check(
      r2?.result?.isError === true && /requestState 驗證失敗/.test(text),
      'A5 偽造 requestState → isError（不處理未驗證狀態）',
      text,
    );
  }

  // ---- A6 digest 不符（重試改參數）→ 拒 ----
  {
    const r1 = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_FILE, ttl: '1h' } }, { elicitation: { url: true } });
    transcript.push(JSON.stringify(r1));
    const r2 = await retryLine(sA, { base, sums: SUMS_FILE, ttl: '3d' }, { fill: { action: 'accept' } }, r1?.result?.requestState);
    transcript.push(JSON.stringify(r2));
    const text = r2?.result?.content?.[0]?.text ?? '';
    check(
      r2?.result?.isError === true && /digest mismatch/.test(text),
      'A6 重試改參數 → digest mismatch 拒（跨請求重用面）',
      text,
    );
  }

  // ---- A7 N3 毒化 ----
  {
    stub.reqLog.length = 0;
    const r = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_BAD } }, {});
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(
      r?.result?.isError === true && /N3 停止/.test(text) && /不交連結/.test(text) && !FILL_RE.test(text),
      'A7 N3 毒化 → 停止交付＋零連結',
      text,
    );
    check(stub.countPaths((p) => p === '/api/sreq') === 0, 'A7 毒化零 API（不開了 slot 面：無 POST /api/sreq）');
  }

  // ---- A8 out 越界（白名單毒化面）----
  {
    const outside = path.join(TMP.home, 'outside', 'evil.retrieve.json');
    stub.reqLog.length = 0;
    const r = await modernReq(sA, 'tools/call', { name: 'request', arguments: { base, sums: SUMS_FILE, out: outside } }, {});
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(r?.result?.isError === true && /不在白名單/.test(text), 'A8 out 越界 → 白名單拒', text);
    check(stub.countPaths((p) => p === '/api/sreq') === 0, 'A8 拒絕零 API（fail-early）');
    check(!fs.existsSync(outside), 'A8 越界路徑零落盤');
  }

  // ---- A9 env 越界（白名單毒化面：值零洩露）----
  {
    process.env.RAW_TOKEN_E2E = 'RAW-VALUE-SHOULD-NOT-PASS';
    const r = await modernReq(
      sA,
      'tools/call',
      { name: 'request', arguments: { base, sums: SUMS_FILE, annual: true, annual_token_ref: 'env:RAW_TOKEN_E2E' } },
      {},
    );
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(
      r?.result?.isError === true &&
        /不在白名單/.test(text) &&
        !text.includes('RAW-VALUE-SHOULD-NOT-PASS'),
      'A9 env 越界 → 白名單拒＋值零洩露',
      text,
    );
    delete process.env.RAW_TOKEN_E2E;
  }

  // ---- A10 annual 14d 正常 ----
  {
    process.env.TACET_SECRET_ANNUAL_E2E = 'annual-e2e-token-XYZ';
    const r = await modernReq(
      sA,
      'tools/call',
      { name: 'request', arguments: { base, sums: SUMS_FILE, ttl: '14d', annual: true, annual_token_ref: 'env:TACET_SECRET_ANNUAL_E2E' } },
      {},
    );
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(
      r?.result?.isError === false &&
        /tier annual/.test(text) &&
        !text.includes('annual-e2e-token-XYZ'),
      'A10 annual 14d 正常（stub 接受非空 annual_token）＋token 零明文',
      text,
    );
    delete process.env.TACET_SECRET_ANNUAL_E2E;
  }

  // ---- A11-A13 verify 四方帳 ----
  {
    const r = await modernReq(sA, 'tools/call', { name: 'verify', arguments: { base, sums: SUMS_FILE } }, {});
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(
      r?.result?.isError === false &&
        (text.match(/MATCH/g) || []).length >= 2 &&
        text.includes(sha256HexS(SREQ_PAGE)),
      'A11 verify 雙 MATCH（四方帳：live sha256＋sums sha256＋verdict）',
      text,
    );
  }
  {
    const r = await modernReq(sA, 'tools/call', { name: 'verify', arguments: { base, sums: SUMS_BAD } }, {});
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(r?.result?.isError === false && /MISMATCH/.test(text), 'A12 verify MISMATCH＝verdict（isError 恆 false）', text);
  }
  {
    const r = await modernReq(sA, 'tools/call', { name: 'verify', arguments: { base: 'http://127.0.0.1:1', sums: SUMS_FILE } }, {});
    transcript.push(JSON.stringify(r));
    const text = r?.result?.content?.[0]?.text ?? '';
    check(r?.result?.isError === false && /MISMATCH/.test(text), 'A13 verify 死 base → fail-closed MISMATCH', text);
  }

  // ---- A14 值零明文 census ----
  {
    const all = transcript.join('\n');
    check(
      !all.includes(tokenA) && !all.includes('&t=') && !all.includes('#k=') && !all.includes(String(privD)),
      'A14 值零明文 census（A 層全部回應文本：零 token 零 &t= 零 #k= 零私鑰 d）',
    );
  }

  // ---- A15 legacy era ----
  {
    const sL = new McpSession();
    const init = await sL
      .handleLine(
        JSON.stringify({
          jsonrpc: '2.0',
          id: nextId++,
          method: 'initialize',
          params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'e2e-legacy', version: '0' } },
        }),
      )
      .then((o) => JSON.parse(o));
    check(
      init?.result?.protocolVersion === '2025-11-25' &&
        init.result.serverInfo?.name === 'tacet-secret' &&
        !!init.result.capabilities?.tools,
      'A15 legacy initialize → 2025-11-25 echo＋serverInfo',
      init,
    );
    const notifOut = await sL.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    check(notifOut === null, 'A15 notifications/initialized → 零回應（notification）');
    const tl = await sL
      .handleLine(JSON.stringify({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} }))
      .then((o) => JSON.parse(o));
    check(
      (tl?.result?.tools ?? []).length === 2 && tl.result.resultType === undefined,
      'A15 legacy tools/list（無 resultType＝2025-11-25 schema）',
      tl?.result,
    );
    const rc = await sL
      .handleLine(
        JSON.stringify({
          jsonrpc: '2.0',
          id: nextId++,
          method: 'tools/call',
          params: { name: 'request', arguments: { base, sums: SUMS_FILE } },
        }),
      )
      .then((o) => JSON.parse(o));
    const text = rc?.result?.content?.[0]?.text ?? '';
    check(
      rc?.result?.resultType === undefined &&
        rc.result.isError === false &&
        FILL_RE.test(text) &&
        /已寫入/.test(text),
      'A15 legacy request → 貼連結主路徑（無 MRTR）',
      text,
    );
    const ping = await sL
      .handleLine(JSON.stringify({ jsonrpc: '2.0', id: nextId++, method: 'ping', params: {} }))
      .then((o) => JSON.parse(o));
    check(
      ping?.result && typeof ping.result === 'object' && !('resultType' in ping.result),
      'A15 legacy ping → EmptyResult（無 resultType）',
      ping,
    );
  }

  // ---- B child stdio 面（離線）----
  phase('B stdio 面（child）');
  const child = spawn(process.execPath, [SERVER], {
    cwd: PKG,
    env: { ...process.env, HOME: TMP.home },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const childLines = [];
  const waiters = [];
  let childBuf = '';
  child.stdout.on('data', (d) => {
    childBuf += d.toString('utf8');
    let i;
    while ((i = childBuf.indexOf('\n')) !== -1) {
      const line = childBuf.slice(0, i);
      childBuf = childBuf.slice(i + 1);
      if (!line.trim()) continue;
      childLines.push(line);
      let parsed = null;
      try {
        parsed = JSON.parse(line);
      } catch {
        /* census 面會咬 */
      }
      const w = waiters.shift();
      if (w) w(parsed, line);
    }
  });
  const childErr = [];
  child.stderr.on('data', (d) => childErr.push(d.toString('utf8')));
  const childReq = (obj) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`child 回應逾時：${obj.method}`)), 90_000);
      waiters.push((parsed) => {
        clearTimeout(t);
        resolve(parsed);
      });
      child.stdin.write(JSON.stringify(obj) + '\n');
    });
  const childRaw = (text) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('child 回應逾時（raw）')), 90_000);
      waiters.push((parsed) => {
        clearTimeout(t);
        resolve(parsed);
      });
      child.stdin.write(text);
    });
  await new Promise((r) => setTimeout(r, 500)); // 起程寬限（無 ready 訊號；啟動崩潰會由首個回應逾時顯形）
  {
    const d = await childReq({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: MODERN({}) } });
    check(
      d?.result?.resultType === 'complete' && d.result.supportedVersions.includes('2026-07-28'),
      'B1 child stdio：server/discover',
      d,
    );
    const tl = await childReq({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: MODERN({}) } });
    check((tl?.result?.tools ?? []).length === 2, 'B2 child stdio：tools/list＝2', tl);
    const e1 = await childReq({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'request', arguments: { base, sums: SUMS_FILE }, _meta: { 'io.modelcontextprotocol/protocolVersion': '2099-01-01', 'io.modelcontextprotocol/clientCapabilities': {} } },
    });
    check(
      e1?.error?.code === -32022 && Array.isArray(e1?.error?.data?.supported),
      'B3 不支持版本 → -32022（data.supported）',
      e1,
    );
    const e2 = await childReq({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/list',
      params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } },
    });
    check(e2?.error?.code === -32602, 'B4 缺 clientCapabilities → -32602', e2);
    const e3 = await childReq({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} });
    check(e3?.error?.code === -32600, 'B5 bare request（無 _meta）→ -32600', e3);
    const e4 = await childRaw('{not-json\n');
    check(e4?.error?.code === -32700, 'B6 malformed JSON → -32700', e4);
    const e5 = await childReq({ jsonrpc: '2.0', id: 7, method: 'no/such/method', params: { _meta: MODERN({}) } });
    check(e5?.error?.code === -32601, 'B7 未知方法 → -32601', e5);
    const before = childLines.length;
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 999 } }) + '\n');
    const p8 = await childReq({ jsonrpc: '2.0', id: 8, method: 'ping', params: { _meta: MODERN({}) } });
    check(
      p8?.result?.resultType === 'complete' && childLines.length === before + 1,
      'B8 通知 → 零回應（僅 ping 一筆 response 行）',
      childLines.slice(before),
    );
    const init = await childReq({
      jsonrpc: '2.0',
      id: 9,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'e2e-child', version: '0' } },
    });
    check(init?.result?.protocolVersion === '2025-11-25', 'B9 child legacy initialize → 2025-11-25', init);
    const n3stop = await childReq({
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: { name: 'request', arguments: { base: 'http://127.0.0.1:1', sums: SUMS_FILE }, _meta: MODERN({}) },
    });
    const t10 = n3stop?.result?.content?.[0]?.text ?? '';
    check(n3stop?.result?.isError === true && /N3 停止/.test(t10), 'B10 child N3 停止（127.0.0.1:1 拒連面；零掛死）', t10.slice(0, 120));
    check(
      childLines.every((l) => {
        try {
          const j = JSON.parse(l);
          return j && j.jsonrpc === '2.0' && (j.result !== undefined || j.error !== undefined);
        } catch {
          return false;
        }
      }),
      'B11 全 stdout 行皆 response（零 server 發起 request——stdio MUST 面）',
      childLines.filter((l) => {
        try {
          const j = JSON.parse(l);
          return !(j.result !== undefined || j.error !== undefined);
        } catch {
          return true;
        }
      }),
    );
  }
  // ---- B12 EOF 清退 ----
  {
    child.stdin.end();
    const exitCode = await new Promise((res) => {
      const t = setTimeout(() => {
        child.kill('SIGKILL');
        res('timeout');
      }, 20_000);
      child.on('exit', (c) => {
        clearTimeout(t);
        res(c);
      });
    });
    check(exitCode === 0, `B12 stdin EOF → 乾淨 exit 0（got ${exitCode}）`, childErr.join('').slice(0, 200));
  }

  // ---- C shell 面 ----
  phase('C shell 面');
  {
    const r = spawnSync('claude', ['plugin', 'validate', '--strict', PKG], {
      encoding: 'utf8',
      timeout: 180_000,
      cwd: PKG,
    });
    const out = (r.stdout || '') + (r.stderr || '');
    check(
      r.status === 0 && /Validation passed/i.test(out),
      `C1 claude plugin validate --strict rc0（got rc=${r.status}）`,
      out.slice(0, 300),
    );
  }
  {
    const r = spawnSync('npm', ['ls', '--depth=1'], {
      encoding: 'utf8',
      timeout: 120_000,
      cwd: path.join(PKG, '..', '..'),
    });
    const out = r.stdout || '';
    check(
      r.status === 0 &&
        /@tacet-ink\/journal-core@0\.11\.0/.test(out) &&
        /@tacet-ink\/journal-cli@0\.11\.0/.test(out) &&
        /@tacet-ink\/journal-mcp@0\.11\.0/.test(out),
      'C2 workspaces 帳（core/cli/mcp 0.11.0 全數在場）',
      out.slice(0, 300),
    );
    check(
      fs.existsSync(path.join(PKG, '..', '..', 'node_modules', '@tacet-ink', 'journal-cli')),
      'C2 依賴解析面（node_modules/@tacet-ink/journal-cli 連結在場）',
    );
  }

  await stub.close();
  process.env.HOME = ORIG_HOME;

  if (failures.length > 0) {
    process.stderr.write(`\nE2E-MCP-FAIL (${failures.length}/${assertions} 失敗)\n`);
    for (const f of failures) process.stderr.write('  - ' + f + '\n');
    process.exit(1);
  }
  process.stdout.write(`\nE2E-MCP-OK(${assertions} assertions)\n`);
}

innerMain().catch((e) => {
  process.stderr.write(`E2E-MCP-FAIL (unexpected): ${e && e.stack ? e.stack : String(e)}\n`);
  process.exit(1);
});
