// 子路徑 runtime import 探針（0.5.3 J4，t_4115dd83）：pack → 臨時安裝 → package.json exports 每鍵
// 以 `node -e "import('<pkg><key>')"` 子行程各 import 一次（一鍵 crash 不拖整批）。
// 動線（CI 步在 verify workflow——node scripts/ci-subpath-probe.cjs；dts-fixture.cjs 母型）：
//   npm pack → mkdtemp → npm install <tarball> --ignore-scripts → 逐鍵子行程 import →
//   全鍵 rc=0＝尾行 SUBPATH-PROBE-OK N/N；任一 rc≠0＝FAIL 帶鍵名＋stderr 尾 160 字元，exit 1。
// 背景：0.5.0 漏載 ./client/keyring exports（dist 在場、types 可解、runtime ESM 拒 subpath）——
// dts-fixture 只證型別面（types 條件）；本探針證 runtime 解析面（default 條件 ↔ dist 檔逐鍵對齊）。
// 錨＝repo package.json 的 exports 字面（非 tarball 內副本——兩者同面，以 repo 面為錨）。
// 只判 import 成功（types-only 模組如 ./server/env 的 namespace 可為空＝合法）。
// 不需 node_modules/typescript（純 runtime import）；dist 須先建（npm pack 不觸發 prepublishOnly）。
// 跑法：node scripts/ci-subpath-probe.cjs（本 repo 根；scripts/ 不入 tarball——dist-only 母型）。
//
// root 具名 import 斷言（0.8.0 K5，t_eb3cd413；外審 2026-11-10）：逐鍵動態 import 只證「模組可解析」——
//   namespace 缺某具名匯出不咬（import() 成功、屬性 undefined 靜默）；0.7.0/0.8.0 keyring 新 API 在
//   src/index.ts 滯後（keyRingBumpEpoch／RingMacConfig 等 root 缺席、子路徑在場＝根入口無法產生 v2 blob）
//   即此盲區。補兩腿（keys 含 '.' 時）：
//   值腿＝TMP 內臨時 .mjs 以**靜態**具名 import 清單載入 root（ESM link 期缺匯出＝SyntaxError rc≠0 即紅；
//     動態 import 抓不到）＋typeof 全 'function' 為正碼面（尾行 ROOT-NAMED-OK）；
//   型腿＝type-only 匯出無 runtime namespace 承載——讀 TMP 安裝樹內 exports['.'].types 指向之 .d.ts
//     字面含 RingMacConfig／RingHighWater（唯一可驗證面；讀安裝樹非 repo 直讀＝證 tarball 面）。
//   兩腿失敗入 failed（tag '.(named)'／'.(types)'），沿既有 SUBPATH-FAIL 行＋exit 1 動線。
const { execFileSync, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const rootPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const keys = Object.keys(rootPkg.exports || {});
if (keys.length === 0) {
  console.error('SUBPATH-PROBE-FAIL: package.json exports 缺席/空');
  process.exit(1);
}
// root 具名匯出清單（值腿）＋ type-only 匯出清單（型腿）——0.7.0/0.8.0 keyring 新 API root 滯後面的回歸網
const ROOT_NAMED = ['keyRingBumpEpoch', 'keyRingMeetsHighWater', 'generateRingMacKey', 'ringMacKeyHexOf', 'keyRingWrappedMacKey',
  'serializeKeyRing', 'parseKeyRing', 'initKeyRing', 'keyRingAddEntry', 'keyRingRetire',
  'wrapNoteKeyPinLockPrf', 'unwrapNoteKeyPinLockPrf', 'isPinLockWrapPrf',
  'wrapNoteKeyPinLockPrfSolo', 'unwrapNoteKeyPinLockPrfSolo', 'isPinLockWrapPrfSolo'];
const ROOT_TYPES = ['RingMacConfig', 'RingHighWater', 'PinLockConfig'];
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'subpath-probe-'));
const failed = [];
try {
  const packJson = execSync('npm pack --json --pack-destination ' + TMP, { cwd: ROOT, encoding: 'utf8' });
  const tarball = path.join(TMP, JSON.parse(packJson)[0].filename);
  execFileSync('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', tarball], { cwd: TMP, stdio: 'pipe' });

  keys.forEach((key, i) => {
    const spec = rootPkg.name + (key === '.' ? '' : key.slice(1)); // '.' → 主入口；'./x' → '<pkg>/x'
    const tag = `${i + 1}/${keys.length} ${key}`;
    const code =
      `import(${JSON.stringify(spec)}).then(` +
      `() => { console.log(${JSON.stringify('SUBPATH-OK ' + tag)}); }, ` +
      `(e) => { console.error(String((e && e.stack) || e)); process.exit(1); })`;
    try {
      const out = execFileSync('node', ['-e', code], { cwd: TMP, encoding: 'utf8', stdio: 'pipe', timeout: 30000 });
      if (!out.includes('SUBPATH-OK ' + tag)) throw Object.assign(new Error('no SUBPATH-OK line'), { status: 1, stderr: out });
      process.stdout.write(out);
    } catch (e) {
      failed.push(key);
      const tail = String(e.stderr || e.message || '').trim().slice(-160);
      console.error(`SUBPATH-FAIL ${tag} rc=${e.status == null ? '?' : e.status} ${tail}`);
    }
  });

  if (keys.includes('.')) {
    // 值腿：靜態具名 import（link 期缺匯出＝SyntaxError 子行程 rc≠0——動態 import 抓不到的缺匯出面）
    const namedTag = '.(named)';
    const probeMjs = path.join(TMP, 'root-named-probe.mjs');
    fs.writeFileSync(probeMjs,
      `import { ${ROOT_NAMED.join(', ')} } from ${JSON.stringify(rootPkg.name)};\n` +
      `const fns = { ${ROOT_NAMED.join(', ')} };\n` +
      `const bad = Object.keys(fns).filter(k => typeof fns[k] !== 'function');\n` +
      `if (bad.length) { console.error('ROOT-NAMED-BAD ' + bad.join(',')); process.exit(1); }\n` +
      `console.log('ROOT-NAMED-OK ' + Object.keys(fns).length + '/${ROOT_NAMED.length}');\n`, 'utf8');
    try {
      const out = execFileSync('node', [probeMjs], { cwd: TMP, encoding: 'utf8', stdio: 'pipe', timeout: 30000 });
      if (!out.includes('ROOT-NAMED-OK')) throw Object.assign(new Error('no ROOT-NAMED-OK line'), { status: 1, stderr: out });
      process.stdout.write(out);
    } catch (e) {
      failed.push(namedTag);
      const tail = String(e.stderr || e.message || '').trim().slice(-160);
      console.error(`SUBPATH-FAIL ${namedTag} rc=${e.status == null ? '?' : e.status} ${tail}`);
    }
    // 型腿：安裝樹內 root types .d.ts 字面（type-only 匯出的唯一可驗證面）
    const typesTag = '.(types)';
    try {
      const typesRel = rootPkg.exports['.'] && rootPkg.exports['.'].types;
      if (typeof typesRel !== 'string') throw Object.assign(new Error('exports["."].types 缺席'), { status: 1 });
      const dts = fs.readFileSync(path.join(TMP, 'node_modules', rootPkg.name, typesRel), 'utf8');
      const missing = ROOT_TYPES.filter(t => !new RegExp('\\b' + t + '\\b').test(dts));
      if (missing.length) throw Object.assign(new Error('root .d.ts 缺型別匯出: ' + missing.join(',')), { status: 1 });
      console.log(`ROOT-TYPES-OK ${ROOT_TYPES.length}/${ROOT_TYPES.length} (${typesRel})`);
    } catch (e) {
      failed.push(typesTag);
      console.error(`SUBPATH-FAIL ${typesTag} rc=${e.status == null ? '?' : e.status} ${String(e.message || '').trim().slice(-160)}`);
    }
  }
} finally {
  fs.rmSync(TMP, { recursive: true, force: true });
}
if (failed.length) {
  const subFailed = failed.filter(k => keys.includes(k)).length;
  console.error(`SUBPATH-PROBE-FAIL ${keys.length - subFailed}/${keys.length}: ${failed.join(', ')}`);
  process.exit(1);
}
console.log(`SUBPATH-PROBE-OK ${keys.length}/${keys.length}`);
