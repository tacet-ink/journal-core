/**
 * verify-cli.ts — R3b packages/cli 驗證閘（對真模組直載 src——禁鏡像，extractable 教訓）。
 * 執行：node --experimental-strip-types scripts/verify-cli.ts（先 npm run build 供 [5]/[4] 子程序段用 dist）
 * 全綠輸出 CLI-VERIFY-OK(N assertions)（整行＝唯一消費錨）；任何失敗 exit 1。
 *
 * 段帳（執行帳＝secOpen 進段即記；欠額＝靜默驗證流失，尾段對帳咬）：
 *   [1] N3 fail-closed（9）：MATCH 放行／sums 一字毒→mismatch 停／missing-entry／live 抓取失敗／
 *       sums 抓取失敗／runRequest 毒化＝停且零 API／runRequest MATCH＝交連結＋bundle 600＋POST 恰一＋stdout 零 token
 *   [2] 白名單 refs（7）：env 前綴規則／env 越界拒／env 明列白名單／file 內建 stateDir／
 *       file 越界拒／file TACET_SECRET_WHITELIST／realpath 分隔符界（/wh 不匹配 /wh-evil）
 *   [3] state/out（4）：預設路徑帳／--out 越界拒（fail-early）／O_EXCL 覆蓋先拒／權限 600+700
 *   [4] 確認閘（4）：allowNonTty 測試縫／非 TTY 子程序 rc3 零 API（預設關）／
 *       錯答 rc5 零 API／正答 rc0 conf_code＋fill 一次
 *   [5] CLI 面（8）：dist 在場／--self-test rc0／無參數 rc2／未知子命令 rc2／bad ttl rc2／
 *       I3 排除面（零 deliver 子命令）／零自帶加密面（src 零 node:crypto 零原語 API）／package 面（private+bin）
 *   [6] README 帳（6）：誠實界線三條逐條在場／不點名律（零競品名）／tag 規約面／送出預設關面
 *   [7] 毒化齒（3，designated-RED）：n3 比對摘除→[1] 毒面翻「放行」＝RED／
 *       refs 白名單守衛摘除→越界翻「放行」＝RED／submit 非 TTY 拒摘除→rc3 翻 rc5＝RED
 *       每齒：變異→子程序跑不變式檢查（期望 RED）→還原→hash 核對還原。
 *
 * hermetic：全段零外網（hermetic SreqStub＋127.0.0.1:1 不可達面）；HOME 指向 temp 目錄；
 * 啟動時清空環境 TACET_SECRET_*（防 ambient 污染白名單段）。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { sha256Hex } from '@tacet-ink/journal-core/server/hash';
import { generateEnvelopeKeyPair } from '@tacet-ink/journal-core/secret/jr5e';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.dirname(__dirname);
const REQ = createRequire(import.meta.url);
const { SreqStub } = REQ(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'));

// —— 斷言面＋段帳（check 掛在當前段；欠額＝靜默驗證流失，尾段對帳咬）——
let passed = 0;
let curSec = 0;
const failures: string[] = [];
function check(cond: boolean, label: string): void {
  if (secRan[curSec] !== undefined) secRan[curSec] += 1;
  if (cond) {
    passed++;
    console.log(`  ok   ${label}`);
  } else {
    failures.push(label);
    console.log(`  FAIL ${label}`);
  }
}

// —— 段帳 ——
const SEC_CASES: Record<number, number> = { 1: 9, 2: 7, 3: 4, 4: 4, 5: 8, 6: 6, 7: 3 };
const secRan: Record<number, number> = {};
function secOpen(sec: number, title: string): void {
  secRan[sec] = 0;
  curSec = sec;
  console.log(`\n[段 ${sec}] ${title}`);
}

// —— setup：temp HOME＋環境清空＋hermetic stub＋sums ——
const TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-gate-home-'));
const ORIG_HOME = process.env.HOME;
process.env.HOME = TMP_HOME;
for (const k of Object.keys(process.env)) {
  if (k.startsWith('TACET_SECRET_')) delete process.env[k];
}
fs.mkdirSync(path.join(TMP_HOME, '.tacet-secret'), { recursive: true, mode: 0o700 });

const PAGES = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-gate-pages-'));
const SREQ_PAGE = '<html id="sreq-gate">sreq 填寫頁</html>';
const SECRET_PAGE = '<html id="secret-gate">secret 說明頁</html>';
fs.writeFileSync(path.join(PAGES, 'sreq.html'), SREQ_PAGE);
fs.writeFileSync(path.join(PAGES, 'secret.html'), SECRET_PAGE);
const SREQ_SHA = await sha256Hex(SREQ_PAGE);
const SECRET_SHA = await sha256Hex(SECRET_PAGE);
const SUMS_OK = path.join(TMP_HOME, 'sums-ok');
fs.writeFileSync(SUMS_OK, `${SREQ_SHA}  sreq.html\n${SECRET_SHA}  secret.html\n`);
const SUMS_POISON = path.join(TMP_HOME, 'sums-poison');
// 一字毒（翻首字元）
const poisoned = SREQ_SHA[0] === '0' ? '1' + SREQ_SHA.slice(1) : '0' + SREQ_SHA.slice(1);
fs.writeFileSync(SUMS_POISON, `${poisoned}  sreq.html\n${SECRET_SHA}  secret.html\n`);
const SUMS_MISSING = path.join(TMP_HOME, 'sums-missing');
fs.writeFileSync(SUMS_MISSING, `${SECRET_SHA}  secret.html\n`);
const UNREACHABLE = 'http://127.0.0.1:1'; // discard 埠：連線即拒（hermetic fail 面）

async function main(): Promise<void> {
  const stub = await new SreqStub(PAGES).listen();
  const base = stub.base;

  const { n3Gate, checkPage, checkAll } = await import('../src/n3.ts');
  const { RefError, parseRef, resolveRefValue, stateDir, loadWhitelist } = await import('../src/refs.ts');
  const { resolveOutPath, writeRetrieveBundle } = await import('../src/state.ts');
  const { runRequest } = await import('../src/request.ts');
  const { runSubmit, confirmGateState, parseFillLink } = await import('../src/submit.ts');

  // ============ [1] N3 fail-closed（7）============
  secOpen(1, 'N3 fail-closed');
  const r1a = await n3Gate(base, SUMS_OK);
  check(r1a.match === true && r1a.reason === 'ok', '1a MATCH→放行（reason ok）');
  const r1b = await n3Gate(base, SUMS_POISON);
  check(r1b.match === false && r1b.reason === 'mismatch', '1b sums 一字毒→mismatch 停');
  const r1c = await n3Gate(base, SUMS_MISSING);
  check(r1c.match === false && r1c.reason === 'missing-entry', '1c sums 缺席 entry→missing-entry 停');
  const r1d = await n3Gate(UNREACHABLE, SUMS_OK);
  check(r1d.match === false && r1d.reason === 'live-fetch-fail', '1d live 抓取失敗→停（fail-closed）');
  const r1e = await n3Gate(base, 'http://127.0.0.1:1/SHA256SUMS');
  check(r1e.match === false && r1e.reason === 'sums-fetch-fail', '1e sums 抓取失敗→停（fail-closed）');

  stub.reqLog.length = 0;
  const rrPoison = await runRequest({ base, sums: SUMS_POISON, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
  const outP = rrPoison.lines.join('\n');
  check(
    rrPoison.exit === 1 && !/sreq\/\?s=[0-9a-f]{32}#p=/.test(outP) && !stub.reqLog.some((r: any) => r.method === 'POST' && r.path === '/api/sreq'),
    '1f runRequest 毒化＝停＋零 API（N3 先於一切）',
  );

  stub.reqLog.length = 0;
  const rrOk = await runRequest({ base, sums: SUMS_OK, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
  const outOk = rrOk.lines.join('\n');
  const fillLink = outOk.match(/(https?:\/\/127\.0\.0\.1:\d+\/sreq\/\?s=[0-9a-f]{32}#p=[A-Za-z0-9_-]+)/);
  const bundleFile = fs.existsSync(path.join(TMP_HOME, '.tacet-secret'))
    ? fs.readdirSync(path.join(TMP_HOME, '.tacet-secret')).find((f) => f.endsWith('.retrieve.json'))
    : undefined;
  let bundleOk = false;
  let stdoutZero = false;
  let postCount = 0;
  if (rrOk.exit === 0 && fillLink && bundleFile) {
    const b = JSON.parse(fs.readFileSync(path.join(TMP_HOME, '.tacet-secret', bundleFile), 'utf8'));
    const mode = (fs.statSync(path.join(TMP_HOME, '.tacet-secret', bundleFile)).mode & 0o777).toString(8);
    postCount = stub.reqLog.filter((r: any) => r.method === 'POST' && r.path === '/api/sreq').length;
    stdoutZero = !outOk.includes(b.slot_nonce) && !outOk.includes('&t=') && /已寫入/.test(outOk);
    bundleOk = b.v === 1 && mode === '600' && postCount === 1;
  }
  check(rrOk.exit === 0 && !!fillLink, '1g runRequest MATCH＝交填寫連結');
  check(bundleOk, '1g-bundle 落檔 600＋POST 恰一');
  check(stdoutZero, '1g-stdout 零 token／零 &t=（只「已寫入」）');

  // ============ [2] 白名單 refs（7）============
  secOpen(2, '白名單 refs');
  process.env['TACET_SECRET_GATE_X'] = 'gate-value-x';
  const ref2a = parseRef('env:TACET_SECRET_GATE_X');
  check(!!ref2a && resolveRefValue(ref2a) === 'gate-value-x', '2a env: 預設前綴規則命中');
  process.env['PLAIN_GATE_TOKEN'] = 'plain-value';
  const ref2b = parseRef('env:PLAIN_GATE_TOKEN');
  let err2b: unknown = null;
  try {
    if (ref2b) resolveRefValue(ref2b);
  } catch (e) {
    err2b = e;
  }
  check(err2b instanceof RefError && err2b.code === 'ref-env-not-whitelisted', '2b env: 越界名→拒（ref-env-not-whitelisted）');
  process.env['TACET_SECRET_ENV_WHITELIST'] = 'PLAIN_GATE_TOKEN';
  const ref2c = parseRef('env:PLAIN_GATE_TOKEN');
  check(!!ref2c && resolveRefValue(ref2c) === 'plain-value', '2c env: 明列白名單命中');
  delete process.env['TACET_SECRET_ENV_WHITELIST'];
  const payloadIn = path.join(TMP_HOME, '.tacet-secret', 'payload.txt');
  fs.writeFileSync(payloadIn, 'in-state\n');
  const ref2d = parseRef(`file:${payloadIn}`);
  check(!!ref2d && resolveRefValue(ref2d) === 'in-state\n', '2d file: 內建 stateDir 命中');
  const outside = path.join(TMP_HOME, 'outside.txt');
  fs.writeFileSync(outside, 'outside\n');
  const ref2e = parseRef(`file:${outside}`);
  let err2e: unknown = null;
  try {
    if (ref2e) resolveRefValue(ref2e);
  } catch (e) {
    err2e = e;
  }
  check(err2e instanceof RefError && err2e.code === 'ref-file-not-whitelisted', '2e file: 越界→拒（ref-file-not-whitelisted）');
  const wlDir = path.join(TMP_HOME, 'wl');
  fs.mkdirSync(wlDir, { recursive: true });
  fs.writeFileSync(path.join(wlDir, 'data.txt'), 'wl-data\n');
  process.env['TACET_SECRET_WHITELIST'] = wlDir;
  const ref2f = parseRef(`file:${path.join(wlDir, 'data.txt')}`);
  check(!!ref2f && resolveRefValue(ref2f) === 'wl-data\n', '2f file: TACET_SECRET_WHITELIST 命中');
  delete process.env['TACET_SECRET_WHITELIST'];
  const wh = path.join(TMP_HOME, 'wh');
  const whEvil = path.join(TMP_HOME, 'wh-evil');
  fs.mkdirSync(wh, { recursive: true });
  fs.mkdirSync(whEvil, { recursive: true });
  fs.writeFileSync(path.join(whEvil, 'x.txt'), 'evil\n');
  const sets = loadWhitelist();
  sets.dirs.push(wh);
  const ref2g = parseRef(`file:${path.join(whEvil, 'x.txt')}`);
  let err2g: unknown = null;
  try {
    if (ref2g) resolveRefValue(ref2g, sets);
  } catch (e) {
    err2g = e;
  }
  check(err2g instanceof RefError && err2g.code === 'ref-file-not-whitelisted', '2g realpath 分隔符界（/wh 不匹配 /wh-evil）');

  // ============ [3] state/out（4）============
  secOpen(3, 'state/out');
  const slotId3 = 'a'.repeat(32);
  check(
    resolveOutPath(null, slotId3) === path.join(stateDir(), `${slotId3}.retrieve.json`),
    '3a 預設路徑＝<stateDir>/<slot_id>.retrieve.json',
  );
  let err3b: unknown = null;
  try {
    resolveOutPath(outside, slotId3);
  } catch (e) {
    err3b = e;
  }
  check(err3b instanceof RefError, '3b --out 越界→拒');
  const out3c = path.join(TMP_HOME, '.tacet-secret', `${slotId3}.retrieve.json`);
  const mkBundle = (note: string) => ({ v: 1 as const, slot_id: slotId3, tier: 'free' as const, exp: 0, opened_at: 0, slot_nonce: 'n', retrieve_link: 'http://x', note });
  writeRetrieveBundle(out3c, mkBundle('first'));
  let err3c: unknown = null;
  try {
    writeRetrieveBundle(out3c, mkBundle('second'));
  } catch (e) {
    err3c = e;
  }
  check(err3c !== null, '3c O_EXCL 覆蓋先拒（已存在→拒）');
  const dirMode = (fs.statSync(path.join(TMP_HOME, '.tacet-secret')).mode & 0o777).toString(8);
  const fileMode = (fs.statSync(out3c).mode & 0o777).toString(8);
  check(dirMode === '700' && fileMode === '600', '3d 權限面（dir 700＋file 600）');

  // ============ [4] 確認閘（4）============
  secOpen(4, '確認閘');
  check(confirmGateState(true) === 'tty', '4a allowNonTty 測試縫（非 TTY 仍可過閘）');
  // 4b 子程序非 TTY：stdin pipe＝非 TTY→rc3 零 API（base 不可達：若誤走 API 會 rc1 非 rc3）
  const eph4 = await generateEnvelopeKeyPair();
  const pubB64 = Buffer.from(JSON.stringify(eph4.pubJwk)).toString('base64url');
  const fakeFillLink = `${UNREACHABLE}/sreq/?s=${'b'.repeat(32)}#p=${pubB64}`;
  const distCli = path.join(PKG, 'dist', 'cli.js');
  const sp4b = spawnSync(process.execPath, [distCli, 'submit', fakeFillLink, `file:${payloadIn}`], {
    encoding: 'utf8',
    timeout: 30_000,
    env: { ...process.env, HOME: TMP_HOME },
    stdio: ['pipe', 'pipe', 'pipe'],
    input: '',
  });
  check(
    sp4b.status === 3 && /預設關/.test(sp4b.stderr ?? ''),
    `4b 非 TTY submit→rc3 預設關（零 API；實際 rc=${sp4b.status}）`,
  );
  // 4c/4d 同程序（stub 在場）：錯答 rc5 零 API／正答 rc0 conf_code
  if (!fillLink) throw new Error('gate internal: 1g 未產出 fill link');
  const parts = parseFillLink(fillLink[1]);
  if (!parts) throw new Error('gate internal: fill link 形檢失敗');
  stub.reqLog.length = 0;
  const sr4c = await runSubmit({ base, fillLink: fillLink[1], sourceRef: `file:${payloadIn}`, confirmInput: 'wrong-answer', allowNonTty: true });
  const fillPosts = stub.reqLog.filter((r: any) => r.path === '/api/sreq/fill').length;
  check(sr4c.exit === 5 && fillPosts === 0, '4c 錯答→rc5 中止＋零 API');
  stub.reqLog.length = 0;
  const sr4d = await runSubmit({ base, fillLink: fillLink[1], sourceRef: `file:${payloadIn}`, confirmInput: parts.slotId, allowNonTty: true });
  const fillPosts2 = stub.reqLog.filter((r: any) => r.path === '/api/sreq/fill').length;
  check(
    sr4d.exit === 0 && /conf_code=[0-9a-f]{4}/.test(sr4d.lines.join('\n')) && fillPosts2 === 1,
    '4d 正答→rc0 conf_code＋fill 恰一',
  );

  // ============ [5] CLI 面（7）============
  secOpen(5, 'CLI 面');
  check(fs.existsSync(distCli), '5a dist 在場（先 build）');
  const sp5a = fs.existsSync(distCli)
    ? spawnSync(process.execPath, [distCli, '--self-test'], { encoding: 'utf8', timeout: 180_000, env: { ...process.env, HOME: TMP_HOME } })
    : { status: 1, stdout: 'dist missing' };
  check(sp5a.status === 0 && /SELF-TEST-OK/.test(sp5a.stdout ?? ''), `5a --self-test rc0（KAT 27 斷言；實際 rc=${sp5a.status}）`);
  const sp5b = spawnSync(process.execPath, [distCli], { encoding: 'utf8', timeout: 30_000 });
  check(sp5b.status === 2, '5b 無參數→rc2 用法');
  const sp5c = spawnSync(process.execPath, [distCli, 'frobnicate'], { encoding: 'utf8', timeout: 30_000 });
  check(sp5c.status === 2, '5c 未知子命令→rc2');
  const sp5d = spawnSync(process.execPath, [distCli, 'request', '--ttl', '99x'], { encoding: 'utf8', timeout: 30_000 });
  check(sp5d.status === 2, '5d bad ttl→rc2（用法先於網路）');
  const cliSrc = fs.readFileSync(path.join(PKG, 'src', 'cli.ts'), 'utf8');
  const srcFiles = fs.readdirSync(path.join(PKG, 'src')).filter((f) => f.startsWith('deliver'));
  check(!srcFiles.length && !/\bdeliver\b/.test(cliSrc), '5e I3 排除面（零 deliver 子命令——I 線停車）');
  const srcText = fs
    .readdirSync(path.join(PKG, 'src'))
    .filter((f) => f.endsWith('.ts'))
    .map((f) => fs.readFileSync(path.join(PKG, 'src', f), 'utf8'))
    .join('\n');
  const cryptoHit = /node:crypto/.test(srcText) || /createCipheriv|createDecipheriv|scryptSync|scrypt\(|pbkdf2Sync|argon2/.test(srcText);
  check(!cryptoHit, '5f 零自帶加密面（src 零 node:crypto 零原語 API——加密只 import core）');
  const pkg = JSON.parse(fs.readFileSync(path.join(PKG, 'package.json'), 'utf8'));
  check(pkg.private === true && !!pkg.bin && !!pkg.bin['tacet-secret'], '5g package 面（private 不上 npm＋bin tacet-secret）');

  // ============ [6] README 帳（6）============
  secOpen(6, 'README 帳');
  const readme = fs.readFileSync(path.join(PKG, 'README.md'), 'utf8');
  check(/只驗自己抓到/.test(readme), '6a 誠實界線①（工具只驗自己抓到那份）在場');
  check(/SRI/.test(readme), '6b 誠實界線②（頂層頁無 SRI）在場');
  check(/信任錨/.test(readme), '6c 誠實界線③（信任錨＝GitHub）在場');
  check(!/agent-secret/.test(readme) && !/Vaulted/.test(readme), '6d 不點名律（README 零競品名）');
  check(/journal-cli-v0\.1\.0/.test(readme), '6e 發佈 tag 規約面（<名>-v<version>）在場');
  check(/預設關/.test(readme), '6f 送出預設關面在場');

  // ============ [7] 毒化齒（3，designated-RED）============
  secOpen(7, '毒化齒');
  const checksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-gate-checks-'));
  const SRC = (rel: string) => path.join(PKG, 'src', rel);
  const sha = (p: string) => sha256Hex(fs.readFileSync(p, 'utf8'));
  async function tooth(
    id: string,
    file: string,
    from: string,
    to: string,
    checkSrc: string,
  ): Promise<void> {
    const orig = fs.readFileSync(file, 'utf8');
    if (!orig.includes(from)) throw new Error(`tooth ${id}: 變異錨缺席（src 已漂移）`);
    const h0 = await sha(file);
    fs.writeFileSync(file, orig.replace(from, to));
    const checkFile = path.join(checksDir, `check-${id}.mjs`);
    fs.writeFileSync(checkFile, checkSrc);
    const sp = spawnSync(process.execPath, ['--experimental-strip-types', checkFile], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, HOME: TMP_HOME },
    });
    fs.writeFileSync(file, orig);
    const restored = (await sha(file)) === h0;
    // 齒義：毒化後不變式檢查必 RED（rc≠0）；若 GREEN＝守衛未咬（齒腐）；timeout/kill（status null）亦非可接受 RED
    check(sp.status !== null && sp.status !== 0 && restored, `7${id} 毒化 RED（${file.split('/').pop()} 守衛摘除→不變式檢查翻紅；還原核對=${restored}）`);
  }

  // P1：n3 比對摘除→毒化 sums 翻「放行」
  await tooth(
    '1',
    SRC('n3.ts'),
    'if (res.liveSha !== res.sumsSha) {',
    'if (false && res.liveSha !== res.sumsSha) {',
    `import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
const { n3Gate } = await import(${JSON.stringify(pathToFileURL(SRC('n3.ts')).href)});
const { SreqStub } = createRequire(${JSON.stringify(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'))})(${JSON.stringify(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'))});
const pages = fs.mkdtempSync(path.join(os.tmpdir(), 'tooth1-pages-'));
fs.writeFileSync(path.join(pages, 'sreq.html'), '<html>t1</html>');
fs.writeFileSync(path.join(pages, 'secret.html'), '<html>s1</html>');
const stub = await new SreqStub(pages).listen();
const sums = path.join(os.tmpdir(), 'tooth1-sums');
fs.writeFileSync(sums, '0'.repeat(64) + '  sreq.html\\n');
const r = await n3Gate(stub.base, sums);
if (r.reason !== 'mismatch') { console.error('tooth1: 不變式破（reason=' + r.reason + '）'); process.exit(1); }
await stub.close(); process.exit(0);
`,
  );
  // P2：refs 白名單守衛摘除→越界 file 翻「放行」
  await tooth(
    '2',
    SRC('refs.ts'),
    'if (!withinWhitelist(real, wl)) {',
    'if (false && !withinWhitelist(real, wl)) {',
    `import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'tooth2-home-'));
const { RefError, parseRef, resolveRefValue } = await import(${JSON.stringify(pathToFileURL(SRC('refs.ts')).href)});
const out = path.join(process.env.HOME, 'outside.txt');
fs.writeFileSync(out, 'secret\n');
try {
  const v = resolveRefValue(parseRef('file:' + out));
  console.error('tooth2: 不變式破（越界放行=' + v.trim() + '）');
  process.exit(1);
} catch (e) {
  if (!(e instanceof RefError)) { console.error('tooth2: 非 RefError', e); process.exit(1); }
}
process.exit(0);
`,
  );
  // P3：submit 非 TTY 拒摘除→rc3 翻 rc5（錯答面）
  await tooth(
    '3',
    SRC('submit.ts'),
    "if (gate === 'no-tty') {",
    "if (false && gate === 'no-tty') {",
    `import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'tooth3-home-'));
process.env.HOME = home;
fs.mkdirSync(path.join(home, '.tacet-secret'), { recursive: true });
const { SreqStub } = createRequire(${JSON.stringify(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'))})(${JSON.stringify(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'))});
const pages = fs.mkdtempSync(path.join(os.tmpdir(), 'tooth3-pages-'));
fs.writeFileSync(path.join(pages, 'sreq.html'), '<html>t3</html>');
fs.writeFileSync(path.join(pages, 'secret.html'), '<html>s3</html>');
const { sha256Hex } = await import(${JSON.stringify(pathToFileURL(path.join(PKG, '..', 'src', 'server', 'hash.ts')).href)});
const stub = await new SreqStub(pages).listen();
const sums = path.join(home, 'sums');
fs.writeFileSync(sums, sha256Hex('<html>t3</html>') + '  sreq.html\\n');
const { runRequest } = await import(${JSON.stringify(pathToFileURL(SRC('request.ts')).href)});
const { runSubmit } = await import(${JSON.stringify(pathToFileURL(SRC('submit.ts')).href)});
const rr = await runRequest({ base: stub.base, sums, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
const link = rr.lines.join('\\n').match(/(https?:\\/\\/127\\.0\\.0\\.1:\\d+\\/sreq\\/\\?s=[0-9a-f]{32}#p=[A-Za-z0-9_-]+)/);
if (!link) { console.error('tooth3: fill link 缺席'); process.exit(1); }
const payload = path.join(home, '.tacet-secret', 'p.txt');
fs.writeFileSync(payload, 'x');
const out = await runSubmit({ base: stub.base, fillLink: link[1], sourceRef: 'file:' + payload, confirmInput: 'wrong', allowNonTty: false });
if (out.exit !== 3) { console.error('tooth3: 不變式破（非 TTY rc=' + out.exit + '，期望 3）'); process.exit(1); }
await stub.close(); process.exit(0);
`,
  );

  // ============ 帳面收口 ============
  await stub.close();
  process.env.HOME = ORIG_HOME;
  const ledgerOk = Object.entries(SEC_CASES).every(([s, n]) => secRan[Number(s)] === n);
  const totals = Object.values(secRan).reduce((a, b) => a + b, 0);
  if (!ledgerOk) {
    console.error('\n段帳欠額（靜默驗證流失）：期望 ' + JSON.stringify(SEC_CASES) + ' 實跑 ' + JSON.stringify(secRan));
  }
  if (failures.length > 0 || !ledgerOk || totals !== Object.values(SEC_CASES).reduce((a, b) => a + b, 0)) {
    console.error(`\nCLI-VERIFY-FAIL（${failures.length} 失敗／${totals} 斷言）`);
    for (const f of failures) console.error('  ✗ ' + f);
    process.exit(1);
  }
  console.log(`\nCLI-VERIFY-OK(${totals} assertions)`);
}

main().catch((e) => {
  console.error('CLI-VERIFY-FAIL（gate internal error）', e);
  process.exit(1);
});
