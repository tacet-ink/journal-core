/**
 * state.ts — 本機狀態面（retrieve 連結包）。
 *
 * 取件連結含 A 私鑰（fragment #k=）——永不進 stdout／stderr（「已寫入」語義）；
 * 落檔＝whitelist 守衛（refs.ts）＋chmod 600＋state 目錄 chmod 700。
 *
 * 乾淨機首跑（stateDir 不存在）：mkdir 700 先於 realpath 界線解析（2026-11-16 審查 r1
 * MAJOR-2：舊形 realpathSync(parent) 在 mkdir 前跑→ENOENT 崩潰於 slot 已建之後＝
 * orphan slot＋rc-1 與 N3 停手撞碼）。--out 越界／已存在拒在 request.ts 的 POST 之前
 * 跑（fail-early＝零誤導＋零 slot 灼燒）；本面的寫入守衛是第二線（同斷言複核）。
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

/** stateDir 保證在場（mkdir 700；既有目錄 chmod 補齊 umask 面）——乾淨機首跑前提。 */
export function ensureStateDir(): string {
  const d = stateDir();
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(d, 0o700); // mkdir mode 受 umask 影響——顯式補齊
  } catch {
    /* 既有目錄權限面——不強改（誠實） */
  }
  return d;
}

/**
 * 決定輸出路徑（白名單守衛；越界／已存在兩拒同面）：
 *   - 無 --out → <stateDir>/<slot_id>.retrieve.json（內建白名單內）
 *   - --out file:PATH 或 --out PATH → realpath 後必落白名單（拒＝RefError，exit 4）
 * slotId=null（POST 前驗收面）：預設路徑無 slot_id 可解——只保證 stateDir 700 在場、
 * 回 null；explicit --out 全驗（越界／已存在）＝fail-early 零 slot 灼燒。
 * 父目錄缺席＝以 abs 為界（驗收面不建目錄；寫入面 writeRetrieveBundle 保證在場）。
 */
export function resolveOutPath(outArg: string | null, slotId: string | null): string | null {
  if (outArg === null) {
    ensureStateDir();
    return slotId === null ? null : path.join(stateDir(), `${slotId}.retrieve.json`);
  }
  const p = stripOutRef(outArg);
  const wl = loadWhitelist();
  const abs = path.resolve(p);
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    // 目標檔可尚不存在（正常）——父目錄在場＝父 realpath 解；父缺席＝abs 為界（驗收不建目錄）
    const parent = path.dirname(abs);
    try {
      real = path.join(fs.realpathSync(parent), path.basename(abs));
    } catch {
      real = abs;
    }
  }
  if (!withinWhitelist(real, wl)) {
    throw new RefError(
      'ref-file-not-whitelisted',
      `--out 被拒：${p} 不在白名單（內建 ${stateDir()}/；TACET_SECRET_WHITELIST；${stateDir()}/whitelist）`,
    );
  }
  if (fs.existsSync(real)) {
    throw new RefError('ref-file-missing', `--out 被拒：路徑已存在（不覆蓋）：${p}`);
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
  // mkdir 先於 realpath（乾淨機首跑：父缺席＝先建 700，界線才有得解——不再 ENOENT 崩潰）
  const parent = path.dirname(abs);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  if (parent === stateDir()) {
    try {
      fs.chmodSync(parent, 0o700);
    } catch {
      /* 既有目錄權限面——不強改（mkdir mode 受 umask 影響，chmod 補齊） */
    }
  }
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    // 目標檔可尚不存在（正常）——父目錄剛保證在場，realpath 必可解
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
  fs.writeFileSync(real, JSON.stringify(bundle, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(real, 0o600); // mode 受 umask 影響——顯式補齊
  return real;
}
