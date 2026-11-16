/**
 * verify-mcp.ts — R3c packages/mcp 驗證閘（直載 src 真模組；鏡像禁——可提取教訓）。
 * 跑法：npm run build -w @tacet-ink/journal-mcp（dist import 面）後
 *       node --experimental-strip-types packages/mcp/scripts/verify-mcp.ts
 * 全綠印 MCP-VERIFY-OK(N assertions)（整行＝唯一消費錨）；任一失敗 exit 1。
 *
 * 段帳（執行帳＝secOpen 進段即記；缺段＝靜默驗失，尾段對帳咬）：
 *   [1] 協議面（5）：discover 形／tools 列表 modern（零 submit）／bare request -32600／
 *       缺 clientCapabilities -32602／不支持版本 -32022
 *   [2] 交付決策（6）：modern+spec形 url:{}→MRTR／modern+寬鬆 url:true→MRTR／
 *       modern+spec形 form-only:{}→貼連結／modern+寬鬆 form:true→貼連結／
 *       modern 無能力→貼連結／legacy→貼連結
 *   [3] requestState（5）：sign/verify 回環／MAC 偽造→mac／過期→expired／
 *       principal 不符→principal／digest 不符→digest
 *   [4] 舊流程殘字面 census=0（4）：elicitationId／elicitation/complete／-32042／
 *       notifications/elicitation/complete（2026-07-28 完成通知面退場）
 *   [5] 零自帶加密＋零遠端 MCP（3）：src 零 node:crypto 零原語 API／
 *       零 SDK 零 SSE 零 WebSocket 零子程序／state 金鑰 0600
 *   [6] 值紀律（2）：貼連結文本零 token 零 #k= 零 &t= 零私鑰 d／
 *       MRTR 面 URL 形＋requestState 形＋零 &t=
 *   [7] 毒化牙（6，designated-RED；3 牙 × pristine-GREEN＋毒化 dedicated RED）：
 *       N3 閘移除→毒 sums「通過」／白名單守衛移除→越界「通過」／MAC 驗證移除→偽造 state「受理」。
 *       每牙：pristine 必綠臂先 → 變異 → 專屬 exit code＋marker（crash≠變異生效）→ 還原 → hash 驗證。
 *
 * hermetic：全程零外網（in-process hermetic SreqStub＋127.0.0.1:1 拒連面）；
 * HOME 指暫存目錄；啟動清 TACET_SECRET_* 環境（防白名單段被 ambient 污染）。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from '@tacet-ink/journal-core/server/hash';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.dirname(__dirname); // packages/mcp
const REQ = createRequire(import.meta.url);
const { SreqStub } = REQ(path.join(PKG, '..', 'cli', 'scripts', 'lib', 'devstack-stub.cjs'));

const META_SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';

let passed = 0;
let curSec = 0;
const failures: string[] = [];

type CheckFn = (cond: boolean, label: string, detail?: unknown) => void;
let check: CheckFn = (cond, label, detail) => {
  if (cond) {
    passed++;
    process.stdout.write(`  ok   [${curSec}] ${label}\n`);
  } else {
    failures.push(`[${curSec}] ${label}${detail !== undefined ? `（${JSON.stringify(detail)}）` : ''}`);
    process.stdout.write(`  FAIL [${curSec}] ${label}${detail !== undefined ? `（${JSON.stringify(detail)}）` : ''}\n`);
  }
};

const SEC_CASES: Record<number, number> = { 1: 5, 2: 6, 3: 5, 4: 4, 5: 3, 6: 2, 7: 6 };
const secRan: Record<number, number> = {};
function secOpen(sec: number, title: string): void {
  curSec = sec;
  secRan[sec] = 0;
  process.stdout.write(`\n== [${sec}] ${title} ==\n`);
}
const origCheck: CheckFn = check;
check = (cond, label, detail) => {
  if (curSec > 0) secRan[curSec] = (secRan[curSec] ?? 0) + 1;
  origCheck(cond, label, detail);
};

// —— hermetic 環境 ——
const TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-gate-home-'));
const ORIG_HOME = process.env.HOME;
process.env.HOME = TMP_HOME;
for (const k of Object.keys(process.env)) if (k.startsWith('TACET_SECRET_')) delete process.env[k];
fs.mkdirSync(path.join(TMP_HOME, '.tacet-secret'), { recursive: true, mode: 0o700 });

const PAGES = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-gate-pages-'));
const SREQ_PAGE = '<html id="sreq-mcp">sreq fill page fixture</html>';
const SECRET_PAGE = '<html id="secret-mcp">secret page fixture</html>';
fs.writeFileSync(path.join(PAGES, 'sreq.html'), SREQ_PAGE);
fs.writeFileSync(path.join(PAGES, 'secret.html'), SECRET_PAGE);
const SREQ_SHA = await sha256Hex(SREQ_PAGE);
const SECRET_SHA = await sha256Hex(SECRET_PAGE);
const SUMS_OK = path.join(TMP_HOME, 'sums-ok.txt');
fs.writeFileSync(SUMS_OK, `${SREQ_SHA}  sreq.html\n${SECRET_SHA}  secret.html\n`);
const SUMS_POISON = path.join(TMP_HOME, 'sums-poison.txt');
const poisoned = SREQ_SHA[0] === '0' ? '1' + SREQ_SHA.slice(1) : '0' + SREQ_SHA.slice(1);
fs.writeFileSync(SUMS_POISON, `${poisoned}  sreq.html\n${SECRET_SHA}  secret.html\n`);

async function main(): Promise<void> {
  const stub = await new SreqStub(PAGES).listen();
  const base = stub.base;

  const { McpSession } = await import('../src/session.ts');
  const { chooseDelivery } = await import('../src/request-tool.ts');
  const { signState, verifyState, STATE_TTL_MS } = await import('../src/requeststate.ts');
  const { SERVER_INFO, PROTO_MODERN, META_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES } = await import(
    '../src/protocol.ts'
  );

  const modernMeta = (caps: Record<string, unknown> = {}) => ({
    _meta: { [META_PROTOCOL_VERSION]: PROTO_MODERN, [META_CLIENT_CAPABILITIES]: caps },
  });
  let nextId = 1;
  const call = async (
    s: InstanceType<typeof McpSession>,
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, any> | null> => {
    const id = nextId++;
    const out = await s.handleLine(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    return out === null ? null : (JSON.parse(out) as Record<string, any>);
  };

  // —— [1] 協議面（5）——
  secOpen(1, '協議面');
  {
    const s = new McpSession();
    const disc = await call(s, 'server/discover', modernMeta());
    check(
      disc?.result?.resultType === 'complete' &&
        Array.isArray(disc.result.supportedVersions) &&
        disc.result.supportedVersions.includes('2026-07-28') &&
        !!disc.result.capabilities?.tools &&
        typeof disc.result.instructions === 'string' &&
        disc.result._meta?.[META_SERVER_INFO_KEY]?.name === SERVER_INFO.name,
      '1a server/discover 形（resultType/supportedVersions/capabilities/instructions/serverInfo）',
      disc,
    );
    const tl = await call(s, 'tools/list', modernMeta());
    const tools = (tl?.result?.tools ?? []) as Array<Record<string, any>>;
    check(
      tl?.result?.resultType === 'complete' &&
        tools.length === 2 &&
        tools.some((t) => t.name === 'request') &&
        tools.some((t) => t.name === 'verify') &&
        !tools.some((t) => /submit|fill|deliver/i.test(String(t.name))) &&
        tools.every(
          (t) =>
            typeof t.description === 'string' &&
            t.description.length > 10 &&
            t.inputSchema?.type === 'object' &&
            t.inputSchema.additionalProperties === false,
        ),
      '1b tools/list modern（request/verify 兩工具；零 submit＝送出預設關缺席面；schema 面齊）',
      tools.map((t) => t.name),
    );
    const bare = await call(new McpSession(), 'tools/list', {});
    check(bare?.error?.code === -32600, `1c bare request（無 _meta）→ -32600 era 歧義（got ${bare?.error?.code}）`);
    const nocaps = await call(new McpSession(), 'tools/list', {
      _meta: { [META_PROTOCOL_VERSION]: PROTO_MODERN },
    });
    check(nocaps?.error?.code === -32602, `1d 缺 clientCapabilities → -32602（got ${nocaps?.error?.code}）`);
    const badver = await call(new McpSession(), 'tools/list', {
      _meta: { [META_PROTOCOL_VERSION]: '2099-01-01', [META_CLIENT_CAPABILITIES]: {} },
    });
    check(
      badver?.error?.code === -32022 &&
        Array.isArray(badver?.error?.data?.supported) &&
        badver.error.data.supported.includes('2026-07-28'),
      `1e 不支持版本 → -32022（data.supported 在場；got ${badver?.error?.code}）`,
    );
  }

  // —— [2] 交付決策（6）——
  secOpen(2, '交付決策（貼連結主路徑／MRTR 增強面）');
  check(
    chooseDelivery('modern', { elicitation: { url: {} } }) === 'mrtr',
    '2a modern＋spec 形 elicitation.url＝{}（JSONObject 存在式；schema 2026-07-28:769-773）→ MRTR 增強面',
  );
  check(
    chooseDelivery('modern', { elicitation: { url: true } }) === 'mrtr',
    '2b modern＋寬鬆 elicitation.url＝true → MRTR 增強面（寬鬆面兩吃）',
  );
  check(
    chooseDelivery('modern', { elicitation: { form: {} } }) === 'paste-link',
    '2c modern＋spec 形 form-only＝{} → 貼連結主路徑（降級；url 未宣稱）',
  );
  check(
    chooseDelivery('modern', { elicitation: { form: true } }) === 'paste-link',
    '2d modern＋寬鬆 form-only＝true → 貼連結主路徑（降級）',
  );
  check(chooseDelivery('modern', {}) === 'paste-link', '2e modern 無能力 → 貼連結主路徑');
  check(chooseDelivery('legacy', null) === 'paste-link', '2f legacy → 貼連結主路徑（無 MRTR）');

  // —— [3] requestState（5）——
  secOpen(3, 'requestState 完整性');
  const mkPayload = (over: Record<string, unknown> = {}) => ({
    v: 1 as const,
    tool: 'request' as const,
    slot_id: 'a'.repeat(32),
    tier: 'free' as const,
    exp: Date.now() + 3_600_000,
    origin: 'http://example.invalid',
    out_path: '/tmp/x.retrieve.json',
    fill_link: 'http://example.invalid/sreq/?s=' + 'a'.repeat(32) + '#p=eyJhIjoxfQ',
    req_digest: 'd'.repeat(64),
    principal: os.userInfo().username,
    iat: Date.now(),
    ...over,
  });
  {
    const DIGEST = 'd'.repeat(64);
    const tok = await signState(mkPayload());
    const v1 = await verifyState(tok, DIGEST);
    check(v1.ok === true, '3a sign/verify 回環（MAC＋TTL＋principal＋digest 全過）', v1);
    const [b, m] = tok.split('.');
    const tampered = (m[0] === 'A' ? 'B' : 'A') + m.slice(1);
    const v2 = await verifyState(b + '.' + tampered, DIGEST);
    check(v2.ok === false && v2.reason === 'mac', `3b MAC 偽造 → mac（got ${JSON.stringify(v2)}）`);
    const v3 = await verifyState(await signState(mkPayload({ iat: Date.now() - STATE_TTL_MS - 60_000 })), DIGEST);
    check(v3.ok === false && v3.reason === 'expired', `3c TTL 過期 → expired（got ${JSON.stringify(v3)}）`);
    const v4 = await verifyState(await signState(mkPayload({ principal: 'someone-else' })), DIGEST);
    check(v4.ok === false && v4.reason === 'principal', `3d principal 不符 → principal（got ${JSON.stringify(v4)}）`);
    const v5 = await verifyState(tok, 'e'.repeat(64));
    check(v5.ok === false && v5.reason === 'digest', `3e 重試參數不符 → digest（got ${JSON.stringify(v5)}）`);
  }

  // —— [4] 舊流程殘字面 census=0（4）——
  secOpen(4, '舊流程殘字面 census=0（完成通知面退場）');
  {
    const files: string[] = [
      ...fs.readdirSync(path.join(PKG, 'src')).filter((f) => f.endsWith('.ts')).map((f) => path.join(PKG, 'src', f)),
      path.join(PKG, 'README.md'),
      path.join(PKG, 'skills', 'tacet-secret', 'SKILL.md'),
      path.join(PKG, '.claude-plugin', 'plugin.json'),
      path.join(PKG, '.mcp.json'),
    ];
    const all = files.map((f) => fs.readFileSync(f, 'utf8')).join('\n');
    const lits = ['elicitationId', 'elicitation/complete', '-32042', 'notifications/elicitation/complete'];
    for (let i = 0; i < lits.length; i++) {
      check(!all.includes(lits[i]), `4${'abcd'[i]} 舊流程字面「${lits[i]}」census=0（2026-07-28 移除面）`);
    }
  }

  // —— [5] 零自帶加密＋零遠端 MCP（3）——
  secOpen(5, '零自帶加密＋零遠端 MCP');
  {
    const srcText = fs
      .readdirSync(path.join(PKG, 'src'))
      .filter((f) => f.endsWith('.ts'))
      .map((f) => fs.readFileSync(path.join(PKG, 'src', f), 'utf8'))
      .join('\n');
    const cryptoHit =
      /node:crypto/.test(srcText) ||
      /createCipheriv|createDecipheriv|createHmac|createSign|createVerify|scryptSync|pbkdf2Sync|argon2/.test(srcText);
    check(!cryptoHit, '5a 零自帶加密面（src 零 node:crypto 零密碼原語 API——HMAC 在 core sha256 上手寫）');
    const remoteHit =
      /@modelcontextprotocol\/sdk|streamableHttp|WebSocket|EventSource|child_process|node:worker/.test(srcText);
    check(!remoteHit, '5b 零遠端 MCP 面（src 零 SDK 零 SSE 零 WebSocket 零子程序——stdio only 裁定）');
    const keyPath = path.join(TMP_HOME, '.tacet-secret', 'mcp-state.key');
    check(
      fs.existsSync(keyPath) && (fs.statSync(keyPath).mode & 0o777) === 0o600,
      `5c state 金鑰在 stateDir（0600；mode=${fs.existsSync(keyPath) ? (fs.statSync(keyPath).mode & 0o777).toString(8) : 'absent'}）`,
    );
  }

  // —— [6] 值紀律（2）——
  secOpen(6, '值紀律（零明文）');
  {
    stub.reqLog.length = 0;
    const s = new McpSession();
    const r = await call(s, 'tools/call', {
      name: 'request',
      arguments: { base, sums: SUMS_OK },
      ...modernMeta({ elicitation: { url: false } }),
    });
    const text = r?.result?.content?.[0]?.text ?? '';
    const slotIds = stub.slotIds();
    const bundleFile =
      slotIds.length > 0 ? path.join(TMP_HOME, '.tacet-secret', `${slotIds[slotIds.length - 1]}.retrieve.json`) : null;
    const bundle = bundleFile ? (JSON.parse(fs.readFileSync(bundleFile, 'utf8')) as Record<string, any>) : null;
    const tok = bundle?.retrieve_link?.match(/&t=([^&#]+)/)?.[1] ?? null;
    const priv = bundle
      ? (JSON.parse(Buffer.from(String(bundle.retrieve_link).split('#k=')[1], 'base64url').toString('utf8')) as Record<string, any>)
      : null;
    check(
      r?.result?.resultType === 'complete' &&
        r.result.isError === false &&
        /填寫連結/.test(text) &&
        /已寫入/.test(text) &&
        !!tok &&
        !text.includes(tok) &&
        !text.includes('&t=') &&
        !text.includes('#k=') &&
        !!priv?.d &&
        !text.includes(String(priv.d)),
      '6a 貼連結文本：連結＋已寫入語義＋零 token 零 &t= 零 #k= 零私鑰 d',
      text.slice(0, 200),
    );
    stub.reqLog.length = 0;
    const s2 = new McpSession();
    const r2 = await call(s2, 'tools/call', {
      name: 'request',
      arguments: { base, sums: SUMS_OK },
      ...modernMeta({ elicitation: { url: true } }),
    });
    const ir = r2?.result;
    const irJson = JSON.stringify(ir ?? {});
    const fillUrl = ir?.inputRequests?.fill?.params?.url;
    check(
      ir?.resultType === 'input_required' &&
        ir?.inputRequests?.fill?.method === 'elicitation/create' &&
        ir.inputRequests.fill.params.mode === 'url' &&
        typeof fillUrl === 'string' &&
        /#p=/.test(String(fillUrl)) &&
        typeof ir.inputRequests.fill.params.message === 'string' &&
        String(ir.inputRequests.fill.params.message).length > 10 &&
        typeof ir.requestState === 'string' &&
        /^\S+\.\S+$/.test(String(ir.requestState)) &&
        !irJson.includes('&t=') &&
        !irJson.includes('#k='),
      '6b MRTR 面：InputRequiredResult（elicitation/create url mode＋message＋requestState；零 &t= 零 #k=）',
      ir,
    );
  }

  // —— [7] 毒化牙（6：3 牙 × pristine-GREEN＋毒化 dedicated RED）——
  secOpen(7, '毒化牙（designated-RED）');
  const checksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-gate-checks-'));
  const SRC = (rel: string) => path.join(PKG, 'src', rel);
  const TOOTH1_POISON_ANCHOR = 'if (false) await n3Gate(base, sums);';
  const TOOTH2_POISON_ANCHOR = 'if (false && !allowed) {';
  const TOOTH3_POISON_ANCHOR = 'if (false && !ctEqual(expectedMac, token.slice(dot + 1)))';

  const TOOTH1_CHECK = `
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const REQ = createRequire(import.meta.url);
const MCPPKG = ${JSON.stringify(PKG)};
const { SreqStub } = REQ(${JSON.stringify(path.join(PKG, '..', 'cli', 'scripts', 'lib', 'devstack-stub.cjs'))});
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-tooth1-home-'));
process.env.HOME = HOME;
for (const k of Object.keys(process.env)) if (k.startsWith('TACET_SECRET_')) delete process.env[k];
fs.mkdirSync(path.join(HOME, '.tacet-secret'), { recursive: true, mode: 0o700 });
const PAGES = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-tooth1-pages-'));
const SREQ_PAGE = '<html id="sreq-tooth1">sreq fixture</html>';
const SECRET_PAGE = '<html id="secret-tooth1">secret fixture</html>';
fs.writeFileSync(path.join(PAGES, 'sreq.html'), SREQ_PAGE);
fs.writeFileSync(path.join(PAGES, 'secret.html'), SECRET_PAGE);
// sha256：直接手算（WebCrypto 全域；與 core sha256Hex 同算法）
async function sha(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
const SUMS_POISON = path.join(HOME, 'sums-poison.txt');
fs.writeFileSync(SUMS_POISON, ${JSON.stringify('0'.repeat(64))} + '  sreq.html\\n' + ${JSON.stringify('1'.repeat(64))} + '  secret.html\\n');
const stub = await new SreqStub(PAGES).listen();
const { handleRequestTool } = await import(pathToFileURL(path.join(MCPPKG, 'src', 'request-tool.ts')).href);
const r = await handleRequestTool({ base: stub.base, sums: SUMS_POISON }, 'modern', { elicitation: { url: false } }, null);
const text = r.kind === 'result' ? r.text : JSON.stringify(r);
const poisonInSrc = fs.readFileSync(path.join(MCPPKG, 'src', 'request-tool.ts'), 'utf8').includes(${JSON.stringify(TOOTH1_POISON_ANCHOR)});
if (r.kind === 'result' && r.isError === true && /N3 停止/.test(text) && !/#p=/.test(text)) {
  console.log('TOOTH1-OK（pristine 不變量：毒 sums → N3 停止、零連結）');
  await stub.close();
  process.exit(0);
}
if (poisonInSrc) {
  console.error('TOOTH-N-RED 不變量被毒化打破（毒 sums「通過」了 N3 閘）：' + text.slice(0, 160));
  await stub.close().catch(() => {});
  process.exit(11);
}
console.error('TOOTH1-ENV-FAIL（不變量破但毒化錨不在場——環境病，非毒化）：' + text.slice(0, 160));
process.exit(1);
`;

  // P2：env 白名單守衛移除（cli dist/refs.js＝運行時路徑）→ 越界 env「通過」（pristine：
  // 越界 env 參照必拒＋零 API；值不入 API body）。out 路徑面是雙層守衛（resolveOutPath
  // 預核＋writeRetrieveBundle 複驗，R3b 既有）——單摘被次層接住（記憶 t_7710c766 雙毒化
  // 母型），故牙打單層且值攔截面。毒化落點＝dist（mcp import 的是 cli dist 運行時面）。
  const TOOTH2_CHECK = `
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const REQ = createRequire(import.meta.url);
const MCPPKG = ${JSON.stringify(PKG)};
const REFS = ${JSON.stringify(path.join(PKG, '..', 'cli', 'dist', 'refs.js'))};
const { SreqStub } = REQ(${JSON.stringify(path.join(PKG, '..', 'cli', 'scripts', 'lib', 'devstack-stub.cjs'))});
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-tooth2-home-'));
process.env.HOME = HOME;
for (const k of Object.keys(process.env)) if (k.startsWith('TACET_SECRET_')) delete process.env[k];
process.env.RAW_TOKEN_E2E = 'RAW-E2E-VALUE';
fs.mkdirSync(path.join(HOME, '.tacet-secret'), { recursive: true, mode: 0o700 });
const PAGES = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-tooth2-pages-'));
const SREQ_PAGE = '<html id="sreq-tooth2">sreq fixture</html>';
const SECRET_PAGE = '<html id="secret-tooth2">secret fixture</html>';
fs.writeFileSync(path.join(PAGES, 'sreq.html'), SREQ_PAGE);
fs.writeFileSync(path.join(PAGES, 'secret.html'), SECRET_PAGE);
async function sha(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
const SUMS_OK = path.join(HOME, 'sums-ok.txt');
fs.writeFileSync(SUMS_OK, (await sha(SREQ_PAGE)) + '  sreq.html\\n' + (await sha(SECRET_PAGE)) + '  secret.html\\n');
const stub = await new SreqStub(PAGES).listen();
const { handleRequestTool } = await import(pathToFileURL(path.join(MCPPKG, 'src', 'request-tool.ts')).href);
const r = await handleRequestTool(
  { base: stub.base, sums: SUMS_OK, annual: true, annual_token_ref: 'env:RAW_TOKEN_E2E' },
  'modern',
  { elicitation: { url: false } },
  null,
);
const text = r.kind === 'result' ? r.text : JSON.stringify(r);
const apiCalls = stub.countPaths((p) => p === '/api/sreq');
const poisonInSrc = fs.readFileSync(REFS, 'utf8').includes(${JSON.stringify(TOOTH2_POISON_ANCHOR)});
if (r.kind === 'result' && r.isError === true && /不在白名單/.test(text) && apiCalls === 0) {
  console.log('TOOTH2-OK（pristine 不變量：越界 env 參照 → 白名單拒、零 API）');
  await stub.close();
  process.exit(0);
}
if (poisonInSrc) {
  console.error('TOOTH-W-RED 不變量被毒化打破（越界 env「通過」了白名單守衛）：' + text.slice(0, 160) + ' apiCalls=' + apiCalls);
  await stub.close().catch(() => {});
  process.exit(12);
}
console.error('TOOTH2-ENV-FAIL（不變量破但毒化錨不在場——環境病，非毒化）：' + text.slice(0, 160));
process.exit(1);
`;

  // P3：MAC 驗證移除 → 偽造 state「受理」（pristine：偽造 MAC 必拒）
  const TOOTH3_CHECK = `
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const MCPPKG = ${JSON.stringify(PKG)};
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-tooth3-home-'));
process.env.HOME = HOME;
for (const k of Object.keys(process.env)) if (k.startsWith('TACET_SECRET_')) delete process.env[k];
fs.mkdirSync(path.join(HOME, '.tacet-secret'), { recursive: true, mode: 0o700 });
const { signState, verifyState } = await import(pathToFileURL(path.join(MCPPKG, 'src', 'requeststate.ts')).href);
const payload = {
  v: 1, tool: 'request', slot_id: 'b'.repeat(32), tier: 'free', exp: Date.now() + 3600000,
  origin: 'http://example.invalid', out_path: '/tmp/x', fill_link: 'http://example.invalid/sreq/?s=' + 'b'.repeat(32) + '#p=eyJhIjoxfQ',
  req_digest: 'f'.repeat(64), principal: os.userInfo().username, iat: Date.now(),
};
const tok = await signState(payload);
const [b, m] = tok.split('.');
const tampered = b + '.' + ((m[0] === 'A' ? 'B' : 'A') + m.slice(1));
const v = await verifyState(tampered, 'f'.repeat(64));
const poisonInSrc = fs.readFileSync(path.join(MCPPKG, 'src', 'requeststate.ts'), 'utf8').includes(${JSON.stringify(TOOTH3_POISON_ANCHOR)});
if (v.ok === false && v.reason === 'mac') {
  console.log('TOOTH3-OK（pristine 不變量：偽造 MAC → mac 拒）');
  process.exit(0);
}
if (poisonInSrc) {
  console.error('TOOTH-S-RED 不變量被毒化打破（偽造 MAC 的 state 被受理）：' + JSON.stringify(v));
  process.exit(13);
}
console.error('TOOTH3-ENV-FAIL（不變量破但毒化錨不在場——環境病，非毒化）：' + JSON.stringify(v));
process.exit(1);
`;

  const checkPath = (n: number) => path.join(checksDir, `check-${n}.mjs`);
  fs.writeFileSync(checkPath(1), TOOTH1_CHECK);
  fs.writeFileSync(checkPath(2), TOOTH2_CHECK);
  fs.writeFileSync(checkPath(3), TOOTH3_CHECK);

  const runCheck = (n: number) =>
    spawnSync(process.execPath, ['--experimental-strip-types', checkPath(n)], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env },
    });

  async function tooth(
    n: number,
    file: string,
    from: string,
    to: string,
    redCode: number,
    marker: string,
  ): Promise<void> {
    const orig = fs.readFileSync(file, 'utf8');
    const origSha = await sha256Hex(orig);
    if (!orig.includes(from)) {
      failures.push(`[7] 牙${n}：錨不在場（src 形態已變）——拒絕變異`);
      process.stdout.write(`  FAIL [7] 牙${n}：錨不在場\n`);
      return;
    }
    const p1 = runCheck(n);
    check(
      p1.status === 0,
      `7.${n * 2 - 1} 牙${n} pristine 臂（不變量必綠；rc=${p1.status}）`,
      (p1.stdout || '') + (p1.stderr || ''),
    );
    fs.writeFileSync(file, orig.split(from).join(to));
    try {
      const p2 = runCheck(n);
      check(
        p2.status === redCode && (p2.stderr || '').includes(marker),
        `7.${n * 2} 牙${n} 毒化臂（dedicated rc=${redCode}＋${marker}；got rc=${p2.status}）`,
        (p2.stdout || '') + (p2.stderr || ''),
      );
    } finally {
      fs.writeFileSync(file, orig);
      const restoredSha = await sha256Hex(fs.readFileSync(file, 'utf8'));
      if (restoredSha !== origSha) {
        failures.push(`[7] 牙${n}：還原 hash 不符（${restoredSha} ≠ ${origSha}）`);
        process.stdout.write(`  FAIL [7] 牙${n}：還原 hash 不符\n`);
      }
    }
  }

  await tooth(
    1,
    SRC('request-tool.ts'),
    'const n3: N3Result = await n3Gate(base, sums);',
    'const n3: N3Result = { page: \'sreq.html\', url: \'http://127.0.0.1:1/sreq\', liveSha: \'l\', sumsSha: \'s\', match: true, reason: \'ok\', detail: \'\' }; if (false) await n3Gate(base, sums);',
    11,
    'TOOTH-N-RED',
  );
  await tooth(
    2,
    path.join(PKG, '..', 'cli', 'dist', 'refs.js'),
    'if (!allowed) {',
    'if (false && !allowed) {',
    12,
    'TOOTH-W-RED',
  );
  await tooth(
    3,
    SRC('requeststate.ts'),
    'if (!ctEqual(expectedMac, token.slice(dot + 1))) return { ok: false, reason: \'mac\' };',
    'if (false && !ctEqual(expectedMac, token.slice(dot + 1))) return { ok: false, reason: \'mac\' };',
    13,
    'TOOTH-S-RED',
  );

  // —— 收尾 ——
  await stub.close();
  process.env.HOME = ORIG_HOME;

  // 段帳對帳（缺段／多段＝靜默驗失）
  for (const [sec, want] of Object.entries(SEC_CASES)) {
    const got = secRan[Number(sec)] ?? 0;
    if (got !== want) {
      failures.push(`[帳] 段 ${sec} 計數不符（記 ${want}，實跑 ${got}）`);
    }
  }

  if (failures.length > 0) {
    process.stderr.write(`\nMCP-VERIFY-FAIL (${failures.length} 失敗)\n`);
    for (const f of failures) process.stderr.write('  - ' + f + '\n');
    process.exit(1);
  }
  process.stdout.write(`\nMCP-VERIFY-OK(${passed} assertions)\n`);
}

main().catch((e) => {
  process.stderr.write(`MCP-VERIFY-FAIL (unexpected): ${e && e.stack ? e.stack : String(e)}\n`);
  process.exit(1);
});
