// t_c18a95ce 修復 A：prepare-core-pkg.cjs 斷鏈防線——@scure/bip39 鏡相依閉包 vendor 進 .core-pkg
// 方案 (a) 真 vendor（裁定）：以 REF_DEPS 為根、聲明面 dependencies 遞迴窮舉閉包 → .core-pkg/node_modules
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC_DIR = path.join(ROOT, 'node_modules', '@tacet-ink', 'journal-core');
const VENDOR_DIR = path.join(ROOT, '.core-pkg');
const LINK_TARGET = '../../.core-pkg';

// 斷鏈封閉集：閘 scripts 參照的 devDeps @scure 與其宣告 runtime deps（@noble/hashes——
// bip39 的 sha256/pbkdf2 面，npm 平坦安裝在根 node_modules，無嵌套副本）→ 遞迴鏡相依
// 閉包全 vendor：只 vendor @scure 本體時，vendored bip39 內部 import '@noble/hashes/*'
// 走父層查不到＝[19] 面在消費者手術環境恆紅（鏡相依閉包非單件）。
// — prepare 時閉包全 vendor，realpath 與 SRC_DIR 同構逃出 node_modules 禁區。
const REF_DEPS = ['@scure/bip39'];

try {
  const st = fs.lstatSync(SRC_DIR);
  if (st.isSymbolicLink()) {
    const cur = fs.readlinkSync(SRC_DIR);
    if (cur.replace(/\/+$/, '') === LINK_TARGET) {
      if (!fs.existsSync(VENDOR_DIR)) {
        console.error('ABORT: symlink 已在場但 .core-pkg 缺席：rm node_modules 後重跑 npm ci（plain）');
        process.exit(1);
      }
      console.log('CORE-PKG-PREPARE-OK (idempotent)');
      process.exit(0);
    }
    console.error('ABORT: node_modules 條目是指向他人的 symlink： ' + cur);
    process.exit(1);
  }
} catch (e) {
  if (e && e.code !== 'ENOENT') { console.error('ABORT: ' + e.message); process.exit(1); }
  console.error('ABORT: node_modules/@tacet-ink/journal-core 缺席：先跑 npm ci（plain，非 --ignore-scripts）');
  process.exit(1);
}

// 真樹還原 → 複製 → symlink 手術
fs.rmSync(VENDOR_DIR, { recursive: true, force: true });
fs.cpSync(SRC_DIR, VENDOR_DIR, { recursive: true });
// 參照依賴 vendor：.core-pkg/node_modules/<ref>（realpath 在 .core-pkg 樹內＝
// strip-types 判準 realpath 之外；斷鏈防線——tarball 環境（.core-pkg/node_modules 自帶）
// 與本樹手術環境（外部 vendor 直拷）同構＝閘 [16] pristine 全綠）。
const vendoredRefs = [];
const vendoredSet = new Set();
const vendorQueue = [...REF_DEPS];
while (vendorQueue.length) {
  const ref = vendorQueue.pop();
  if (vendoredSet.has(ref)) continue;
  vendoredSet.add(ref);
  const refAbs = path.join(ROOT, 'node_modules', ...ref.split('/'));
  if (!fs.existsSync(refAbs)) {
    console.error('ABORT: 參照閉包缺席（' + ref + '）：npm ci 未裝齊參照組依賴？');
    process.exit(1);
  }
  fs.cpSync(refAbs, path.join(VENDOR_DIR, 'node_modules', ...ref.split('/')), { recursive: true });
  vendoredRefs.push(ref);
  // runtime deps 閉包遞迴（聲明面為準；嵌套副本由 cpSync 遞迴一併帶入，root 派為同構直拷）
  try {
    const depPkg = JSON.parse(fs.readFileSync(path.join(refAbs, 'package.json'), 'utf8'));
    const deps = depPkg.dependencies && typeof depPkg.dependencies === 'object' ? Object.keys(depPkg.dependencies) : [];
    vendorQueue.push(...deps);
  } catch { /* 無法讀 package.json 的 vendored 件仍依序入帳——封閉集以聲明面窮舉為準 */ }
}

const a = fs.readFileSync(path.join(SRC_DIR, 'package.json'), 'utf8');
const b = fs.readFileSync(path.join(VENDOR_DIR, 'package.json'), 'utf8');
if (a !== b) { console.error('ABORT: .core-pkg 複製不一致'); process.exit(1); }
fs.rmSync(SRC_DIR, { recursive: true, force: true });
fs.symlinkSync(LINK_TARGET, SRC_DIR, 'dir');

const ver = b.match(/"version": "([^"]+)"/)[1];
console.log('CORE-PKG-PREPARE-OK ' + ver + '（vendored: ' + vendoredRefs.join(' ') + '）');