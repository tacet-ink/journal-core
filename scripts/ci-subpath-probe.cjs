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
} finally {
  fs.rmSync(TMP, { recursive: true, force: true });
}
if (failed.length) {
  console.error(`SUBPATH-PROBE-FAIL ${keys.length - failed.length}/${keys.length}: ${failed.join(', ')}`);
  process.exit(1);
}
console.log(`SUBPATH-PROBE-OK ${keys.length}/${keys.length}`);
