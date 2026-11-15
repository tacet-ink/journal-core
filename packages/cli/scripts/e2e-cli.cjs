/**
 * e2e-cli.cjs — R3b 過程層 e2e（hermetic：devstack stub＋tmp HOME＋PTY submit；零外網）。
 *
 * 沙箱紀律（實測，2026-11-15）：本機 egress guard 對「子程序→環回臨時埠」的連線吞
 * SYN（ESTABLISHED 假象、伺服器零收包）；「同程序 fetch→環回」與「子程序→白名單
 * 遠端」皆正常。故本 e2e 雙層：
 *   - 網路面（N3／API／全鏈）＝in-process（dist 模組直載＋同程序 fetch 到 stub）
 *   - 離線面（argv／exit code／非 TTY 拒／白名單拒）＝子程序（零網路，sandbox 可達）
 * 全程自 re-exec 於真 PTY（pty-run.py）：submit 人確認走真 TTY stdin（答列由
 * answers mailbox 檔供給——內層在觸發每個 prompt 前依序補答）。
 *
 * 覆蓋（card §5）：request 全形＋N3 毒化（改一字→停手不給連結、零 API）＋verify
 * 四方帳（MATCH／MISMATCH／fail-closed／--json）＋白名單毒化（file 越界/env 非名單）
 * ＋annual 參照＋submit 人確認（非 TTY 拒零 API；TTY 正確＝送出＋conf_code＋burn
 * 取件＋全鏈解密；錯答中止；write-once；token 單用）＋--out 碰撞＋用法錯面
 * ＋fresh HOME 首跑（clean-HOME walkthrough：無 .tacet-secret→CLI 自建 700＋bundle 600＋POST 恰一）
 * ＋request --help 網路前攔截（rc0 零網路）。
 */

'use strict';

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const PKG = path.resolve(__dirname, '..'); // packages/cli
const CLI = path.join(PKG, 'dist', 'cli.js');
const PYTHON3 = process.env.PYTHON3 || 'python3';
const PTY_RUN = path.join(PKG, 'scripts', 'lib', 'pty-run.py');
const PROMPT_MARKER = '輸入 slot 編號確認送出';
const FILL_RE = /^(https?:\/\/127\.0\.0\.1:\d+\/sreq\/\?s=[0-9a-f]{32}#p=[A-Za-z0-9_-]+)$/m;

let assertions = 0;
const failures = [];
function check(cond, label, detail) {
  assertions++;
  if (!cond) {
    failures.push(label + (detail ? `（${detail}）` : ''));
    process.stderr.write(`  ✗ ${label}${detail ? `（${detail}）` : ''}\n`);
  }
}
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// ============ 外層：無 PTY 時自 re-exec 於真 PTY ============
function outerRun() {
  const answers = path.join(os.tmpdir(), `e2e-cli-answers-${process.pid}-${Date.now()}.txt`);
  fs.writeFileSync(answers, '');
  const r = spawnSync(
    PYTHON3,
    [PTY_RUN, PROMPT_MARKER, answers, '600', '--', process.execPath, __filename],
    { encoding: 'utf8', timeout: 630_000, env: { ...process.env, E2E_UNDER_PTY: '1', E2E_ANSWERS_FILE: answers }, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const strip = (s) => (s || '').replace(/\r/g, '');
  process.stdout.write(strip(r.stdout));
  process.stderr.write(strip(r.stderr));
  try {
    fs.unlinkSync(answers);
  } catch {
    /* 殘檔不致命 */
  }
  process.exit(r.status === null ? 1 : r.status);
}

function phase(name) {
  process.stderr.write(`[e2e] ${name}\n`);
}

// ============ 內層（PTY 下）============
async function innerMain() {
  const TMP = {
    home: fs.mkdtempSync(path.join(os.tmpdir(), 'tacet-cli-e2e-home-')),
    pages: fs.mkdtempSync(path.join(os.tmpdir(), 'tacet-cli-e2e-pages-')),
  };
  TMP.answers = process.env.E2E_ANSWERS_FILE; // mail-box 由外層（pty-run 的供給方）指定
  if (!TMP.answers) {
    process.stderr.write('E2E-CLI-FAIL：E2E_ANSWERS_FILE 缺席（須經外層 re-exec 進入）\n');
    process.exit(1);
  }
  fs.writeFileSync(TMP.answers, '');
  process.env.HOME = TMP.home; // in-process os.homedir() 面
  fs.mkdirSync(path.join(TMP.home, '.tacet-secret'), { recursive: true, mode: 0o700 });

  const SREQ_PAGE = '<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>tacet.ink — 索取祕密</title></head><body><h1>索取祕密</h1><p>e2e fixture page（sreq）</p></body></html>';
  const SECRET_PAGE = '<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>tacet.ink — 祕密連結</title></head><body><h1>祕密連結</h1><p>e2e fixture page（secret）</p></body></html>';
  fs.writeFileSync(path.join(TMP.pages, 'sreq.html'), SREQ_PAGE);
  fs.writeFileSync(path.join(TMP.pages, 'secret.html'), SECRET_PAGE);
  const sumsGood = `${sha256Hex(SREQ_PAGE)}  sreq.html\n${sha256Hex(SECRET_PAGE)}  secret.html\n`;
  const sumsFile = path.join(TMP.home, 'SHA256SUMS.good');
  fs.writeFileSync(sumsFile, sumsGood);

  const { SreqStub } = require(path.join(PKG, 'scripts', 'lib', 'devstack-stub.cjs'));
  const stub = await new SreqStub(TMP.pages).listen();
  const base = stub.base;

  // in-process dist 模組（網路面）
  const { runRequest } = await import(pathToFileURL(path.join(PKG, 'dist', 'request.js')));
  const { runVerify } = await import(pathToFileURL(path.join(PKG, 'dist', 'verify.js')));
  const { runSubmit, confirmGateState } = await import(pathToFileURL(path.join(PKG, 'dist', 'submit.js')));

  // 內容來源（白名單內）＋annual 權杖
  // canary（claude Q2②）：隨機值，任何 fixture 天然不該含它——掃 submit 全路徑 stdout+stderr+burn 回應
  const canary = 'CANARY-' + crypto.randomBytes(8).toString('hex');
  const secretContent = `e2e 祕密內容 ${canary}\n第 2 行（UTF-8 多行＋換行原樣）\n`;
  const secretFile = path.join(TMP.home, '.tacet-secret', 'payload.txt');
  fs.writeFileSync(secretFile, secretContent, { mode: 0o600 });
  const annualToken = 'annual-e2e-token-XYZ';

  /** 子程序（離線面；零網路）：回 {status, stdout, stderr} */
  const child = (args, { env = {}, input } = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: PKG,
      encoding: 'utf8',
      timeout: 60_000,
      env: { ...process.env, HOME: TMP.home, ...env },
      input,
    });
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  };
  /** 補一答（mail-box）：在觸發下一個互動 prompt 前呼叫 */
  const pushAnswer = (line) => fs.appendFileSync(TMP.answers, line + '\n');

  try {
    // ---- B1 self-test（子程序；離線）----
    phase('B1 self-test');
    {
      const r = child(['--self-test']);
      check(r.status === 0, 'B1 self-test rc0', `rc=${r.status} err=${r.stderr.slice(0, 200)}`);
      check(/SELF-TEST-OK/.test(r.stdout), 'B1 self-test SELF-TEST-OK 行');
    }

    // ---- N2 verify 雙 MATCH（in-process）----
    phase('N2-N5 verify');
    {
      const r = await runVerify({ base, sums: sumsFile, json: false });
      const out = r.lines.join('\n');
      check(r.exit === 0, 'N2 verify rc0（雙 MATCH）', `exit=${r.exit}`);
      check((out.match(/MATCH/g) || []).length >= 2, 'N2 verify 兩頁 MATCH');
      check(out.includes(sha256Hex(SREQ_PAGE)), 'N2 verify live sha 在帳（sreq）');
      check(out.includes(sha256Hex(SECRET_PAGE)), 'N2 verify live sha 在帳（secret）');
    }

    // ---- N3 verify 毒化（sums 一字改）----
    {
      const sumsBad = path.join(TMP.home, 'SHA256SUMS.bad');
      fs.writeFileSync(sumsBad, sumsGood.replace(sha256Hex(SECRET_PAGE), '0'.repeat(64)));
      const r = await runVerify({ base, sums: sumsBad, json: false });
      const out = r.lines.join('\n');
      check(r.exit === 1, 'N3 verify 毒化 rc1（MISMATCH）', `exit=${r.exit}`);
      check(/MISMATCH/.test(out), 'N3 verify MISMATCH 判定在場');
      check(/MATCH/.test(out), 'N3 verify 未毒頁仍 MATCH（sreq 面）');
    }

    // ---- N4 verify fail-closed（dead base；抓取失敗＝不過）----
    {
      const r = await runVerify({ base: 'http://127.0.0.1:1', sums: sumsFile, json: false });
      check(r.exit === 1, 'N4 verify dead base rc1（fail-closed）', `exit=${r.exit}`);
      const out = r.lines.join('\n');
      check(/MISMATCH/.test(out), 'N4 verify 失敗面判 MISMATCH');
    }

    // ---- N5 verify --json 形 ----
    {
      const r = await runVerify({ base, sums: sumsFile, json: true });
      check(!!r.jsonOut && Array.isArray(r.jsonOut.results) && r.jsonOut.results.length === 2, 'N5 verify --json results[2]');
      check(!!r.jsonOut && r.jsonOut.ok === true, 'N5 verify --json ok=true');
    }

    // ---- R1 request 全形（free 預設 7d；N3 先於 API）----
    let r1fill = null;
    phase('R1 request full');
    {
      stub.reqLog.length = 0;
      const r = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: true });
      const out = r.lines.join('\n');
      check(r.exit === 0, 'R1 request rc0', `exit=${r.exit} out=${out.slice(0, 300)}`);
      check(/^N3 ok：/m.test(out), 'R1 N3 ok 行在場');
      const m = out.match(FILL_RE);
      check(!!m, 'R1 填寫連結正規形（?s=＋#p=）');
      r1fill = m ? m[1] : null;
      check(/取件連結已寫入/.test(out), 'R1「已寫入」語義在場');
      check(stub.countPaths((p) => p === '/api/sreq') === 1, 'R1 server 恰一 POST /api/sreq');
      const iPage = stub.reqLog.findIndex((x) => x.method === 'GET' && x.path === '/sreq');
      const iApi = stub.reqLog.findIndex((x) => x.method === 'POST' && x.path === '/api/sreq');
      check(iPage !== -1 && iApi !== -1 && iPage < iApi, 'R1 N3（GET /sreq）先於建 slot');
      const slots = stub.slotIds();
      const outFile = path.join(TMP.home, '.tacet-secret', `${slots[0]}.retrieve.json`);
      check(fs.existsSync(outFile), 'R1 取件包落檔（stateDir 預設路徑）');
      const st = fs.statSync(outFile);
      check((st.mode & 0o777) === 0o600, 'R1 取件包 mode 600', `mode=${(st.mode & 0o777).toString(8)}`);
      const bundle = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      const token = bundle.retrieve_link.match(/&t=([^&#]+)/)[1];
      check(bundle.retrieve_link.includes('#k='), 'R1 retrieve_link 含 #k=');
      check(!out.includes(token), 'R1 token 原值零明文（stdout 無 token）');
      const priv = JSON.parse(Buffer.from(bundle.retrieve_link.split('#k=')[1], 'base64url').toString('utf8'));
      check(priv.d && !out.includes(priv.d), 'R1 私鑰 d 零明文（stdout 無私鑰）');
      check(!out.includes(secretContent), 'R1 內容零明文');
      check(/只交給你確認的人/.test(out), 'R1 W1 提醒行在場');
      check(!!r.jsonOut && r.jsonOut.fill_url === r1fill, 'R1 --json fill_url＝stdout 連結');
      // 真形釘住（MAJOR-3）：連結＝N3 實抓 origin＋正規路徑；server 欄位只做一致性斷言
      const rl = bundle.retrieve_link;
      const rlT = (rl.match(/&t=/g) || []).length;
      check(rlT === 1 && /#k=/.test(rl), 'R1 retrieve_link 真形（&t= 恰一＋#k=；零雙 token）');
      const rlUrl = new URL(rl);
      check(
        rlUrl.origin === new URL(base).origin && rlUrl.pathname.replace(/\/$/, '') === '/sreq' && rlUrl.searchParams.get('s') === slots[0],
        'R1 retrieve_link origin＝N3 實抓 origin＋/sreq/?s=<slot>',
      );
      check(
        r1fill && new URL(r1fill).origin === new URL(base).origin && new URL(r1fill).pathname.replace(/\/$/, '') === '/sreq',
        'R1 填寫連結 origin＋路徑真形',
      );
    }

    // ---- R2 request N3 毒化（sums 一字改→停手不給連結、零 API）----
    phase('R2-R3 request N3 poison / annual');
    {
      const sumsBad = path.join(TMP.home, 'SHA256SUMS.bad2');
      fs.writeFileSync(sumsBad, sumsGood.replace(sha256Hex(SREQ_PAGE), 'f'.repeat(64)));
      stub.reqLog.length = 0;
      const r = await runRequest({ base, sums: sumsBad, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
      const out = r.lines.join('\n');
      check(r.exit === 1, 'R2 N3 毒化 rc1（停手）', `exit=${r.exit}`);
      check(/N3 停手/.test(out) && /不給連結/.test(out), 'R2 停手告知＋不給連結語義');
      check(!/#p=/.test(out), 'R2 無填寫連結（零 #p=）');
      check(stub.countPaths((p) => p === '/api/sreq') === 0, 'R2 零 API 呼叫（不建 slot）');
    }

    // ---- R3 annual 正常（env 白名單形＋14d）----
    {
      process.env.TACET_SECRET_ANNUAL_TOKEN = annualToken;
      try {
        const r = await runRequest({ base, sums: sumsFile, ttl: '14d', tier: 'annual', annualTokenRef: 'env:TACET_SECRET_ANNUAL_TOKEN', out: null, json: false });
        const out = r.lines.join('\n');
        check(r.exit === 0, 'R3 annual 14d rc0', `exit=${r.exit} out=${out.slice(0, 300)}`);
        check(!out.includes(annualToken), 'R3 annual token 零明文');
        check(/tier annual/.test(out), 'R3 tier annual 落帳');
      } finally {
        delete process.env.TACET_SECRET_ANNUAL_TOKEN;
      }
    }

    // ---- W1 白名單毒化（file: 越界；零 API）----
    phase('W1-W3 whitelist / out');
    {
      const outside = path.join(TMP.home, 'outside-annual.txt');
      fs.writeFileSync(outside, 'OUTSIDE-TOKEN-SECRET');
      stub.reqLog.length = 0;
      const r = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'annual', annualTokenRef: `file:${outside}`, out: null, json: false });
      const out = r.lines.join('\n');
      check(r.exit === 4, 'W1 file 越界 rc4（白名單拒）', `exit=${r.exit}`);
      check(/不在白名單/.test(out), 'W1 白名單拒告知');
      check(!out.includes('OUTSIDE-TOKEN-SECRET'), 'W1 值零外洩');
      check(stub.countPaths((p) => p === '/api/sreq') === 0, 'W1 拒後零 API 呼叫');
    }

    // ---- W2 白名單毒化（env: 非白名單名）----
    {
      process.env.RAW_TOKEN = 'RAW-VALUE-SHOULD-NOT-PASS';
      try {
        const r = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'annual', annualTokenRef: 'env:RAW_TOKEN', out: null, json: false });
        const out = r.lines.join('\n');
        check(r.exit === 4, 'W2 env 非白名單名 rc4', `exit=${r.exit}`);
        check(/不在白名單/.test(out), 'W2 env 白名單拒告知');
        check(!out.includes('RAW-VALUE-SHOULD-NOT-PASS'), 'W2 env 值零外洩');
      } finally {
        delete process.env.RAW_TOKEN;
      }
    }

    // ---- W3 --out 碰撞（不覆蓋）----
    {
      const outp = path.join(TMP.home, '.tacet-secret', 'fixed-out.retrieve.json');
      const r1 = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: `file:${outp}`, json: false });
      check(r1.exit === 0, 'W3 首寫 rc0', `exit=${r1.exit}`);
      const r2 = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: `file:${outp}`, json: false });
      check(r2.exit === 4 && /已存在/.test(r2.lines.join('\n')), 'W3 二寫 rc4（不覆蓋）', `exit=${r2.exit}`);
    }

    // ---- R4 fresh HOME 首跑（clean-HOME walkthrough；in-process——沙箱吞子程序環回）----
    {
      const freshHome = fs.mkdtempSync(path.join(os.tmpdir(), 'tacet-cli-e2e-freshhome-'));
      const prevHome = process.env.HOME;
      const prevUmask = process.umask();
      stub.reqLog.length = 0;
      let rr = null;
      let freshErr = null;
      try {
        process.env.HOME = freshHome;
        process.umask(0o077);
        rr = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
      } catch (e) {
        freshErr = e;
      } finally {
        process.env.HOME = prevHome;
        process.umask(prevUmask);
      }
      const dir = path.join(freshHome, '.tacet-secret');
      const dirMode = fs.existsSync(dir) ? (fs.statSync(dir).mode & 0o777) : null;
      const names = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
      const bname = names.find((f) => f.endsWith('.retrieve.json'));
      const fileMode = bname ? (fs.statSync(path.join(dir, bname)).mode & 0o777) : null;
      check(freshErr === null && rr !== null && rr.exit === 0, 'R4 fresh HOME 首跑 rc0（不崩潰、不 orphan slot）', `err=${freshErr ? String(freshErr).slice(0, 160) : `exit=${rr && rr.exit}`}`);
      check(dirMode === 0o700, 'R4 stateDir 自建 700（umask 077 下）', `mode=${dirMode === null ? 'absent' : dirMode.toString(8)}`);
      check(fileMode === 0o600, 'R4 取件包 600', `mode=${fileMode === null ? 'absent' : fileMode.toString(8)}`);
      check(stub.countPaths((p) => p === '/api/sreq') === 1, 'R4 恰一 POST /api/sreq（無重試、無 orphan）');
    }

    // ---- S1 submit 非 TTY＝拒（子程序；零網路）----
    phase('S1 submit non-TTY');
    {
      const r0 = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
      const fillLink = r0.lines.join('\n').match(FILL_RE)[1];
      const r = child(['submit', fillLink, `file:${secretFile}`], { input: '' });
      check(r.status === 3, 'S1 submit 非 TTY rc3', `rc=${r.status}`);
      check(/未送出/.test(r.stderr), 'S1「未送出」告知');
      check(!r.stdout.includes(canary) && !r.stderr.includes(canary), 'S1 canary 零洩漏（rc3 面 stdout+stderr）');
    }

    // ---- S1b 確認閘判定（in-process 雙態）----
    {
      check(confirmGateState(false) === 'tty' && true, 'S1b PTY 下 gate＝tty（本 e2e 於真 TTY 執行）', `got=${confirmGateState(false)}`);
      const wasIn = process.stdin.isTTY, wasOut = process.stdout.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
      Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
      let g = null;
      try {
        g = confirmGateState(false);
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: wasIn, configurable: true });
        Object.defineProperty(process.stdout, 'isTTY', { value: wasOut, configurable: true });
      }
      check(g === 'no-tty', 'S1b 非 TTY 態 gate＝no-tty（決定面）', `got=${g}`);
    }

    // ---- S2 submit TTY 正確（互動 stdin；全鏈）----
    phase('S2 submit TTY full chain');
    {
      const r0 = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
      const fillLink = r0.lines.join('\n').match(FILL_RE)[1];
      const sid = fillLink.match(/s=([0-9a-f]{32})/)[1];
      const outFile = path.join(TMP.home, '.tacet-secret', `${sid}.retrieve.json`);
      const bundle = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      const token = bundle.retrieve_link.match(/&t=([^&#]+)/)[1];
      stub.reqLog.length = 0;
      pushAnswer(sid); // mail-box：下一 prompt 的答
      const r = await runSubmit({ base, fillLink, sourceRef: `file:${secretFile}`, confirmInput: null, allowNonTty: false });
      const out = r.lines.join('\n');
      check(r.exit === 0, 'S2 submit TTY rc0（互動確認過）', `exit=${r.exit} out=${out.slice(0, 300)}`);
      check(!out.includes(canary), 'S2 canary 零洩漏（成功面 stdout）');
      const confMatch = out.match(/conf_code=([0-9a-f]{4})/);
      check(!!confMatch, 'S2 conf_code 在場（「已寫入」面）');
      check(stub.countPaths((p) => p === '/api/sreq/fill') === 1, 'S2 fill 恰一呼叫（零重試）');
      // burn 取件（in-process 同程序 fetch）
      const burnRes = await (await fetch(`${base}/api/sreq/${sid}?t=${encodeURIComponent(token)}`)).json();
      check(burnRes.ciphertext && String(burnRes.ciphertext).startsWith('jr5e.'), 'S2 burn 取件 ciphertext 在場（jr5e. 形）');
      check(!JSON.stringify(burnRes).includes(canary), 'S2 canary 零洩漏（burn 回應密文面）');
      check(confMatch && burnRes.conf_code === confMatch[1], 'S2 burn conf_code＝submit conf_code');
      // 全鏈解密（core 真模組＋取件包私鑰）
      const { openEnvelope } = await import(pathToFileURL(path.join(PKG, '..', '..', 'dist', 'secret', 'jr5e.js')));
      const priv = JSON.parse(Buffer.from(bundle.retrieve_link.split('#k=')[1], 'base64url').toString('utf8'));
      const opened = await openEnvelope(burnRes.ciphertext, priv, `jr5e:${sid}`);
      check(opened === secretContent, 'S2 全鏈解密還原原文（request→submit→burn→open）');
      // token 單用：二取＝404
      const burn2 = await fetch(`${base}/api/sreq/${sid}?t=${encodeURIComponent(token)}`);
      check(burn2.status === 404, 'S2 token 單用（二取 404）', `status=${burn2.status}`);
      // write-once：二送（互動正確答）＝404 不可區分
      pushAnswer(sid);
      const r2 = await runSubmit({ base, fillLink, sourceRef: `file:${secretFile}`, confirmInput: null, allowNonTty: false });
      check(r2.exit === 1 && /已無法填寫/.test(r2.lines.join('\n')), 'S2 write-once 二送 rc1「已無法填寫」', `exit=${r2.exit}`);
    }

    // ---- S3 submit TTY 錯答＝中止（互動 stdin）----
    phase('S3 submit TTY wrong answer');
    {
      const r0 = await runRequest({ base, sums: sumsFile, ttl: '7d', tier: 'free', annualTokenRef: null, out: null, json: false });
      const fillLink = r0.lines.join('\n').match(FILL_RE)[1];
      stub.reqLog.length = 0;
      pushAnswer('wrong-answer-not-the-slot');
      const r = await runSubmit({ base, fillLink, sourceRef: `file:${secretFile}`, confirmInput: null, allowNonTty: false });
      check(r.exit === 5, 'S3 錯答 rc5（中止）', `exit=${r.exit}`);
      check(/已中止（未送出）/.test(r.lines.join('\n')), 'S3「已中止（未送出）」告知');
      check(!r.lines.join('\n').includes(canary) && !(r.stderr ?? []).join('\n').includes(canary), 'S3 canary 零洩漏（rc5 面 stdout+stderr）');
      check(stub.countPaths((p) => p === '/api/sreq/fill') === 0, 'S3 中止零 fill 呼叫');
    }

    // ---- U1 用法錯面（子程序；離線）----
    {
      const r1 = child([]);
      check(r1.status === 2 && /用法/.test(r1.stdout), 'U1 無參 rc2＋usage', `rc=${r1.status}`);
      const r2 = child(['request', '--base', base, '--sums', sumsFile, '--bogus-flag']);
      check(r2.status === 2, 'U1 未知旗標 rc2', `rc=${r2.status}`);
      const r3 = child(['request', '--base', base, '--sums', sumsFile, '--ttl', '9x']);
      check(r3.status === 2, 'U1 壞 ttl rc2', `rc=${r3.status}`);
      const r4 = child(['request', '--base', base, '--sums', sumsFile, '--ttl', '14d']);
      check(r4.status === 2, 'U1 14d 缺 --annual rc2', `rc=${r4.status}`);
      const r5 = child(['frobnicate']);
      check(r5.status === 2, 'U1 未知子命令 rc2', `rc=${r5.status}`);
      const r6 = child(['submit', 'not-a-url', 'env:whatever']);
      check(r6.status === 2, 'U1 submit 壞連結 rc2（零網路前拒）', `rc=${r6.status}`);
      const r7 = child(['request', '--base', base, '--sums', sumsFile, '--help']);
      check(r7.status === 0 && /用法:/.test(r7.stdout), 'U1 request --help rc0＋usage（網路前攔截、零網路）', `rc=${r7.status} out=${r7.stdout.slice(0, 80)}`);
    }
  } finally {
    await stub.close();
  }

  if (failures.length > 0) {
    process.stderr.write(`E2E-CLI-FAIL（${failures.length}/${assertions} 失敗）\n`);
    process.exit(1);
  }
  console.log(`E2E-CLI-OK（${assertions} 斷言；request/verify/submit/N3 毒化/白名單/真 TTY 確認全過）`);
}

if (!process.env.E2E_UNDER_PTY) {
  outerRun();
} else {
  innerMain().catch((e) => {
    process.stderr.write(`E2E-CLI-FAIL（未預期）：${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
}
