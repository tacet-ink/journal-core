// .d.ts 消費端 fixture（0.3.x 小債批）：pack → 臨時安裝 → skipLibCheck:false 兩組 moduleResolution tsc。
// 動線（session 收案面跑法；CI 等價步在 verify workflow——node scripts/dts-fixture.cjs）：
//   npm pack → mkdtemp → npm install <tarball> --ignore-scripts → 寫 smoke tsconfig →
//   node_modules/typescript/bin/tsc --noEmit 兩組（nodenext／bundler）皆綠＝exit 0。
// 跑法：node scripts/dts-fixture.cjs（本 repo 根；需要 node_modules/typescript 在場）。
const { execFileSync, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = __dirname + '/..';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dts-fixture-'));
let packFile;
try {
  packFile = execSync('npm pack --json --pack-destination ' + TMP, { cwd: ROOT, encoding: 'utf8' });
  const pkgName = JSON.parse(packFile)[0].filename;
  const tarball = path.join(TMP, pkgName);
  execFileSync('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', tarball], { cwd: TMP, stdio: 'pipe' });
  // env.d.ts 帶 /// <reference types="@cloudflare/workers-types" />——消費者責任面（README 契約）：
  // fixture 沿 README 路徑裝同款 dev-type dep（與 repo package.json 同 version family——registry 真值）。
  const rootPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const wT = rootPkg.devDependencies['@cloudflare/workers-types'];
  execFileSync('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', '--save-dev', '@cloudflare/workers-types@' + wT], { cwd: TMP, stdio: 'pipe' });

  const TSC = path.join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');
  const fixtureTs = path.join(TMP, 'use.ts');
  const indexDts = path.join(TMP, 'node_modules', '@tacet-ink', 'journal-core', 'dist', 'index.d.ts');

  // 煙樣本：主入口（barrel）＋vault 子路徑（vault.d.ts 相對 import .ts 鏈是本 fixture 的主訴）
  fs.writeFileSync(fixtureTs, 'import { createVault } from \'@tacet-ink/journal-core/client/vault\';\nexport const v = typeof createVault;\n');
  // bundler 態（DOM lib 姿態）的 workers-types 全域型別 shim——真消費者在 bundler 專案的
  // 常見做法＝局部宣告 workers 專屬型別（workers-types experimental 全集只進 nodenext 態）
  fs.writeFileSync(path.join(TMP, 'workers-shim.d.ts'),
    'interface D1Database { prepare(query: string): { bind(...vals: unknown[]): { first(): Promise<unknown> }; run(): Promise<unknown>; all(): Promise<{ results: unknown[] }> } }\n');

  let failed = false;
  for (const res of ['nodenext', 'bundler']) {
    // copy into tmp so relative extends works; check the real consumed .d.ts files
    const cfg = path.join(TMP, `tsconfig.${res}.json`);
    fs.writeFileSync(cfg, JSON.stringify({
      compilerOptions: {
        target: 'ES2023', module: res === 'nodenext' ? 'nodenext' : 'esnext',
        moduleResolution: res,
        // 双姿態 lib：nodenext（node 消費者）也要 DOM——client .d.ts 的 CryptoKey/
        // Transferable/WebStream 等全域型別由 DOM lib 承載（node TS 預設 lib 無 DOM＝
        // lib.es2023 全集不含 webcrypto 面）；workers-types 全集只在 nodenext+帶套件態
        // 吃（env.d.ts 的 D1Database import type 面）。
        lib: ['ES2023', 'DOM'],
        strict: true, skipLibCheck: false, noEmit: true,
      },
      include: ['use.ts', 'node_modules/@tacet-ink/journal-core/dist/**/*.d.ts'],
    }));
    try {
      execFileSync('node', [TSC, '--noEmit', '-p', cfg], { cwd: TMP, stdio: 'pipe' });
      console.log(`dts-fixture ${res}: OK`);
    } catch (e) {
      failed = true;
      console.error(`dts-fixture ${res}: FAIL\n` + String(e.stdout ?? '').slice(0, 1500));
    }
  }
  if (failed) process.exit(1);
  console.log('DTS-FIXTURE-OK (2 resolution modes, skipLibCheck:false)');
} finally {
  fs.rmSync(TMP, { recursive: true, force: true });
}