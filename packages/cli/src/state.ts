/**
 * state.ts — 本機狀態面（retrieve 連結包）。
 *
 * 取件連結含 A 私鑰（fragment #k=）——永不進 stdout／stderr（「已寫入」語義）；
 * 落檔＝whitelist 守衛（refs.ts）＋chmod 600＋state 目錄 chmod 700。
 */

import fs from 'node:fs';
import path from 'node:path';
import { RefError, loadWhitelist, parseRef, stateDir, withinWhitelist } from './refs.ts';

export interface RetrieveBundle {
  v: 1;
  slot_id: string;
  tier: 'free' | 'annual';
  exp: number;
  opened_at: number;
  /** 確認碼（conf_code）比對用——取件端以 eph_pub＋slot_nonce 重算（R1 問 10） */
  slot_nonce: string;
  /** 取件連結（含 &t= token 與 #k= 私鑰）——只供本機取件頁使用 */
  retrieve_link: string;
  note: string;
}

/**
 * 決定輸出路徑（fail-early 白名單守衛——越界在「已寫入」語義輸出之前就拒，零誤導）：
 *   - 無 --out → <stateDir>/<slot_id>.retrieve.json（內建白名單內）
 *   - --out file:PATH 或 --out PATH → realpath 後必落白名單（拒＝RefError，exit 4）
 * stateDir 保證在場（700）；檔寫 600（O_EXCL 語意＝覆蓋已有檔先拒——防撞掉別 slot 的包：
 * 同 slot 重開＝新 slot_id，同名檔只可能是殘留同 id 包→覆蓋前先拒，人處理）。
 */
export function resolveOutPath(outArg: string | null, slotId: string): string {
  if (outArg === null) return path.join(stateDir(), `${slotId}.retrieve.json`);
  const p = stripOutRef(outArg);
  const wl = loadWhitelist();
  const abs = path.resolve(p);
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    // 目標檔可尚不存在（正常）——父目錄必存在且 realpath 可解
    real = path.join(fs.realpathSync(path.dirname(abs)), path.basename(abs));
  }
  if (!withinWhitelist(real, wl)) {
    throw new RefError(
      'ref-file-not-whitelisted',
      `--out 被拒：${p} 不在白名單（內建 ${stateDir()}/；TACET_SECRET_WHITELIST；${stateDir()}/whitelist）`,
    );
  }
  return p;
}

function stripOutRef(outArg: string): string {
  if (outArg.startsWith('file:')) {
    const ref = parseRef(outArg);
    if (!ref) throw new RefError('ref-invalid-form', `--out 形錯：${outArg}`);
    return ref.value;
  }
  return outArg;
}

/** 白名單＋寫入（600）；同一路徑已存在＝拒（RefError 形，呼叫端 exit 4）。 */
export function writeRetrieveBundle(p: string, bundle: RetrieveBundle): string {
  const wl = loadWhitelist();
  const abs = path.resolve(p);
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    // 目標檔可尚不存在（正常）——但父目錄必存在且 realpath 可解
    const parent = path.dirname(abs);
    real = path.join(fs.realpathSync(parent), path.basename(abs));
  }
  const inWl = withinWhitelist(real, wl);
  if (!inWl) {
    throw new RefError(
      'ref-file-not-whitelisted',
      `--out 被拒：${p} 不在白名單（內建 ${stateDir()}/；TACET_SECRET_WHITELIST；${stateDir()}/whitelist）`,
    );
  }
  if (fs.existsSync(real)) {
    throw new RefError('ref-file-missing', `--out 被拒：路徑已存在（不覆蓋）：${p}`);
  }
  // state 目錄面（預設路徑時保證 700 在場）
  const parent = path.dirname(real);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  if (parent === stateDir()) {
    try {
      fs.chmodSync(parent, 0o700);
    } catch {
      /* 既有目錄權限面——不強改（誠實：mkdir mode 受 umask 影響，chmod 補齊） */
    }
  }
  fs.writeFileSync(real, JSON.stringify(bundle, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(real, 0o600); // mode 受 umask 影響——顯式補齊
  return real;
}
