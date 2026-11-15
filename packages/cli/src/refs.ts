/**
 * refs.ts — env:/file: 參照解析＋白名單（request-secret brief §四 L128-129 設計原則：
 * 值永不回模型上下文——輸入以參照（env 變數名／檔案路徑）進 CLI，參照路徑採白名單
 * （外洩通道風險面）；參照值只進 CLI 程序記憶體、永不上 stdout）。
 *
 * 白名單來源（合併，全數 realpath 後比對）：
 *   1. 內建：<home>/.tacet-secret（工具狀態目錄——retrieve 連結包與內容暫存預設位）
 *   2. env：TACET_SECRET_WHITELIST（':' 分隔路徑；目錄＝前綴匹配、檔案＝精確匹配）
 *   3. 檔：<home>/.tacet-secret/whitelist（每行一路徑；'#' 註解；空白行跳過）
 *
 * file: 參照：resolve＋realpath 後必落在白名單目錄內（分隔符界）或恰等白名單檔案；
 *   目錄／設備／缺席一律拒（/dev/stdin 等管道形被 realpath 界線天然擋下）。
 * env: 參照：變數名必在白名單內——TACET_SECRET_ENV_WHITELIST（',' 分隔，在場即為唯一
 *   真相）；未設時預設規則＝名字以 TACET_SECRET_ 開頭。值缺席或空串＝拒。
 *
 * 誠實界線：白名單由操作者在 agent 啟動環境／狀態檔預設——agent 能自設 env 就能自讀
 *   該 env（同信任域）；白名單的紀律面＝把「參照路徑」收進可稽核的有限集，模型上下文
 *   永遠只出現參照字面、不出現值。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const ENV_WHITELIST_VAR = 'TACET_SECRET_WHITELIST';
export const ENV_NAME_WHITELIST_VAR = 'TACET_SECRET_ENV_WHITELIST';
/** env: 參照預設前綴規則（未設 TACET_SECRET_ENV_WHITELIST 時生效） */
export const ENV_NAME_DEFAULT_PREFIX = 'TACET_SECRET_';

export type RefKind = 'env' | 'file';

export interface Ref {
  kind: RefKind;
  /** env: 變數名；file: 原始路徑（未 resolve） */
  value: string;
}

export class RefError extends Error {
  readonly code:
    | 'ref-invalid-form'
    | 'ref-file-not-whitelisted'
    | 'ref-file-missing'
    | 'ref-file-not-regular'
    | 'ref-env-not-whitelisted'
    | 'ref-env-missing';
  constructor(
    code:
      | 'ref-invalid-form'
      | 'ref-file-not-whitelisted'
      | 'ref-file-missing'
      | 'ref-file-not-regular'
      | 'ref-env-not-whitelisted'
      | 'ref-env-missing',
    message: string,
  ) {
    super(message);
    this.name = 'RefError';
    this.code = code;
  }
}

/** 解析 'env:NAME'／'file:PATH'；其餘字面＝null（呼叫端報用法錯） */
export function parseRef(s: string): Ref | null {
  if (s.startsWith('env:')) {
    const name = s.slice('env:'.length);
    if (name.length === 0 || /[:/\s]/.test(name)) return null;
    return { kind: 'env', value: name };
  }
  if (s.startsWith('file:')) {
    const p = s.slice('file:'.length);
    if (p.length === 0) return null;
    return { kind: 'file', value: p };
  }
  return null;
}

export function stateDir(): string {
  return path.join(os.homedir(), '.tacet-secret');
}

interface WhitelistSets {
  dirs: string[]; // realpath 目錄
  files: string[]; // realpath 檔案
}

function readWhitelistFile(dir: string): string[] {
  const f = path.join(dir, 'whitelist');
  let raw: string;
  try {
    raw = fs.readFileSync(f, 'utf8');
  } catch {
    return []; // 檔缺席＝零條（非錯）
  }
  const out: string[] = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (t.length === 0 || t.startsWith('#')) continue;
    out.push(t);
  }
  return out;
}

/** 組白名單（realpath 後；不存在的路徑靜默略過＝不構成界線）。 */
export function loadWhitelist(homeDir: string = os.homedir()): WhitelistSets {
  const entries: string[] = [path.join(homeDir, '.tacet-secret')];
  const envWl = process.env[ENV_WHITELIST_VAR];
  if (envWl) {
    for (const p of envWl.split(':')) {
      const t = p.trim();
      if (t.length > 0) entries.push(t);
    }
  }
  entries.push(...readWhitelistFile(path.join(homeDir, '.tacet-secret')));
  const sets: WhitelistSets = { dirs: [], files: [] };
  for (const e of entries) {
    let real: string;
    try {
      real = fs.realpathSync(path.resolve(homeDir, e));
    } catch {
      continue; // 路徑不存在＝不構成界線（誠實：缺席的白名單項不擋任何事）
    }
    const st = fs.statSync(real);
    if (st.isDirectory()) {
      if (!sets.dirs.includes(real)) sets.dirs.push(real);
    } else if (st.isFile()) {
      if (!sets.files.includes(real)) sets.files.push(real);
    }
  }
  return sets;
}

export function withinWhitelist(real: string, sets: WhitelistSets): boolean {
  if (sets.files.includes(real)) return true;
  for (const d of sets.dirs) {
    if (real === d) return false; // 目錄本身不是「目錄內的檔案」
    if (real.startsWith(d + path.sep)) return true;
  }
  return false;
}

/**
 * 解析參照→值（白名單守衛；拒＝RefError，永不外洩值）。
 * file: 讀 UTF-8 fatal（非法編碼＝拒，不送半解值）；內容按位元組原樣（零 trim）。
 */
export function resolveRefValue(ref: Ref, sets?: WhitelistSets): string {
  const wl = sets ?? loadWhitelist();
  if (ref.kind === 'env') {
    let allowed: boolean;
    const nameWl = process.env[ENV_NAME_WHITELIST_VAR];
    if (nameWl !== undefined) {
      const names = nameWl.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
      allowed = names.includes(ref.value);
    } else {
      allowed = ref.value.startsWith(ENV_NAME_DEFAULT_PREFIX);
    }
    if (!allowed) {
      throw new RefError(
        'ref-env-not-whitelisted',
        `env 參照被拒：變數名 ${ref.value} 不在白名單（預設規則＝${ENV_NAME_DEFAULT_PREFIX} 前綴；或以 ${ENV_NAME_WHITELIST_VAR} 明列）`,
      );
    }
    const v = process.env[ref.value];
    if (v === undefined || v.length === 0) {
      throw new RefError('ref-env-missing', `env 參照被拒：變數 ${ref.value} 缺席或為空`);
    }
    return v;
  }
  // file:
  const abs = path.resolve(ref.value);
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    throw new RefError('ref-file-missing', `file 參照被拒：路徑不存在（${ref.value}）`);
  }
  let st: fs.Stats;
  try {
    st = fs.statSync(real);
  } catch {
    throw new RefError('ref-file-missing', `file 參照被拒：路徑不存在（${ref.value}）`);
  }
  if (!st.isFile()) {
    throw new RefError('ref-file-not-regular', `file 參照被拒：非一般檔案（${ref.value}）`);
  }
  if (!withinWhitelist(real, wl)) {
    throw new RefError(
      'ref-file-not-whitelisted',
      `file 參照被拒：${ref.value} 不在白名單（內建 ${stateDir()}/；${ENV_WHITELIST_VAR}；${stateDir()}/whitelist）`,
    );
  }
  const buf = fs.readFileSync(real);
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    throw new RefError('ref-file-not-regular', `file 參照被拒：非 UTF-8 內容（${ref.value}）`);
  }
  return text;
}
