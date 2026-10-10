/**
 * argon-auto.ts — Argon2id 載體平台預設（0.3.1 批 A3）。
 *
 * 優先序（向後相容鐵律：setArgonLoader 照舊優先）：
 *   1. 呼叫端已 setArgonLoader 注入（非本模組自裝）＝'injected'——本模組零介入。
 *   2. 回退鏈 chain（可覆寫；預設 ['node','worker','inline']）逐項取第一個可用者：
 *      - 'node'：node:crypto.argon2 在場（argon2.ts 原生腿；本模組不注入）。
 *      - 'worker'：Web Worker（argon-worker.ts 內嵌 blob 形）；執行期失效＝若 chain 於其後含
 *        'inline' 則回退 inline（onFallback 通知＋currentArgonCarrier 翻 'inline'＝行為顯形），否則 throw。
 *      - 'inline'：同執行緒 vendor hash-wasm（WebAssembly 在場即可）。
 *   3. 皆不可用＝ERR_VAULT_KDF_UNSUPPORTED（zero-fallback：禁 PBKDF2／zeros 兜底）。
 * 裝載即 KAT：每個載體首用前跑 RFC 9106 KAT（verifyArgonKat）——錯值載體＝拒用，不只是缺席才拒。
 *
 * 'worker'／'inline' 經 setArgonLoader 全域注入（argon2.ts 派生本體唯一入口）：同頁其他 argon2.ts
 * 呼叫端共享此載體；呼叫端之後自行 setArgonLoader 即覆寫（下次 ensure 判 'injected'）。
 * resetArgonCarrier() 撤除本模組自裝載體（不動呼叫端注入）並終止 Worker。
 */

import { getArgonLoader, setArgonLoader, verifyArgonKat, type ArgonLoader, type HashWasmArgon2id } from './argon2.ts';
import { makeWorkerArgon2id, createBlobArgonWorker, type ArgonWorkerLike } from './argon-worker.ts';
import { hashWasmArgon2Factory } from './vendor/hash-wasm-argon2.ts';
import { VaultError } from './vault-error.ts';

export type ArgonCarrierKind = 'injected' | 'node' | 'worker' | 'inline';
export type ArgonCarrierChoice = 'node' | 'worker' | 'inline';
export type { ArgonWorkerLike };

export interface ArgonFallbackEvent {
  from: 'worker';
  to: 'inline';
  error: unknown;
}

export interface ArgonCarrierOptions {
  /** 回退鏈（預設 ['node','worker','inline']）。例：['worker']＝只准 Worker（失效即拒，不回退）。 */
  chain?: readonly ArgonCarrierChoice[];
  /** Worker 工廠覆寫（預設瀏覽器 blob Worker；測試／特殊宿主注入轉接層）。 */
  createWorker?: () => ArgonWorkerLike;
  /** Worker → inline 回退通知（行為顯形；不提供＝靜默回退但 currentArgonCarrier 仍翻 'inline'）。 */
  onFallback?: (ev: ArgonFallbackEvent) => void;
}

export const DEFAULT_ARGON_CHAIN: readonly ArgonCarrierChoice[] = ['node', 'worker', 'inline'];

function nodeArgonAvailable(): boolean {
  const nodeCrypto = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { argon2?: unknown } | undefined };
  }).process?.getBuiltinModule?.('node:crypto');
  return typeof nodeCrypto?.argon2 === 'function';
}

function workerAvailable(opts: ArgonCarrierOptions): boolean {
  if (opts.createWorker) return true;
  const g = globalThis as unknown as { Worker?: unknown; Blob?: unknown; URL?: { createObjectURL?: unknown } };
  return typeof g.Worker === 'function' && typeof g.Blob === 'function' && typeof g.URL?.createObjectURL === 'function';
}

function wasmAvailable(): boolean {
  return typeof (globalThis as unknown as { WebAssembly?: unknown }).WebAssembly === 'object';
}

// ── 狀態 ────────────────────────────────────────────────────────────────────

interface AutoState {
  loader: ArgonLoader;
  kind: 'worker' | 'inline';
  chainKey: string;
  createWorker: ArgonCarrierOptions['createWorker'];
  onFallback: ArgonCarrierOptions['onFallback'];
  dispose(): void;
}

let auto: AutoState | null = null;
let nodeVerified = false;
const verified = new WeakSet<ArgonLoader>();
let failures = 0;

/** 載體終端失效累計（拋出派生本體的失效才計；回退成功不計）。vault 以前後差分辨
 *  「解包 null＝密語錯」與「載體失效」（低階 unwrap 吞錯回 null，邊界還原真因）。 */
export function argonCarrierFailures(): number {
  return failures;
}

/** 現行載體（未 ensure 過且無注入、非 node＝null）。 */
export function currentArgonCarrier(): ArgonCarrierKind | null {
  const cur = getArgonLoader();
  if (cur) return auto && cur === auto.loader ? auto.kind : 'injected';
  return nodeArgonAvailable() ? 'node' : null;
}

/** 撤除本模組自裝載體（呼叫端 setArgonLoader 注入不動）＋終止 Worker。 */
export function resetArgonCarrier(): void {
  if (!auto) return;
  const a = auto;
  auto = null;
  if (getArgonLoader() === a.loader) setArgonLoader(null);
  a.dispose();
}

// ── inline 載體（同執行緒 vendor hash-wasm；串行） ────────────────────────────

function makeInlineArgon2id(): HashWasmArgon2id {
  let mod: { argon2id: HashWasmArgon2id } | null = null;
  let queue: Promise<unknown> = Promise.resolve();
  return (params) => {
    const job = queue.then(() => {
      if (!mod) mod = hashWasmArgon2Factory();
      return mod.argon2id(params);
    });
    queue = job.catch(() => undefined);
    return job;
  };
}

function terminal(e: unknown, what: string): VaultError {
  failures++;
  return new VaultError('ERR_VAULT_KDF_UNSUPPORTED', what, { cause: e });
}

function installInline(chainKey: string, opts: ArgonCarrierOptions): AutoState {
  const inline = makeInlineArgon2id();
  const argon2id: HashWasmArgon2id = async (params) => {
    try { return await inline(params); } catch (e) { throw terminal(e, 'inline carrier failed'); }
  };
  const mod = { argon2id };
  const st: AutoState = {
    loader: () => Promise.resolve(mod),
    kind: 'inline',
    chainKey,
    createWorker: opts.createWorker,
    onFallback: opts.onFallback,
    dispose: () => {},
  };
  return st;
}

function installWorker(chainKey: string, opts: ArgonCarrierOptions, fallbackInline: boolean): AutoState {
  const w = makeWorkerArgon2id(opts.createWorker ?? createBlobArgonWorker);
  let inline: HashWasmArgon2id | null = null;
  const st: AutoState = {
    loader: () => Promise.resolve(mod),
    kind: 'worker',
    chainKey,
    createWorker: opts.createWorker,
    onFallback: opts.onFallback,
    dispose: () => w.terminate(),
  };
  const argon2id: HashWasmArgon2id = async (params) => {
    if (st.kind === 'worker') {
      try {
        return await w.argon2id(params);
      } catch (e) {
        if (!fallbackInline) throw terminal(e, 'worker carrier failed (chain has no inline fallback)');
        // 回退：整載體翻 inline（不再試 Worker）——顯形：kind 翻面＋onFallback 通知。
        if (st.kind === 'worker') {
          st.kind = 'inline';
          w.terminate();
          try { opts.onFallback?.({ from: 'worker', to: 'inline', error: e }); } catch { /* 通知面不影響派生 */ }
        }
      }
    }
    inline ??= makeInlineArgon2id();
    try { return await inline(params); } catch (e) { throw terminal(e, 'inline carrier failed'); }
  };
  const mod = { argon2id };
  return st;
}

async function katOrThrow(): Promise<void> {
  let ok = false;
  try { ok = await verifyArgonKat(); } catch (e) {
    if (e instanceof VaultError) throw e;
    throw terminal(e, 'carrier KAT threw');
  }
  if (!ok) throw terminal(null, 'carrier KAT mismatch (RFC 9106)');
}

/**
 * 確保 Argon2id 載體可用並回報種類。冪等：同選項重呼沿用既裝載體（Worker 不重建）；
 * 選項（chain／createWorker／onFallback）改變＝撤除重裝。首用載體必過 RFC 9106 KAT。
 */
export async function ensureArgonCarrier(opts: ArgonCarrierOptions = {}): Promise<ArgonCarrierKind> {
  const cur = getArgonLoader();
  if (cur && (!auto || cur !== auto.loader)) {
    // 呼叫端覆寫優先：自裝殘留（若有）撤除但不碰全域注入。
    if (auto) { const a = auto; auto = null; a.dispose(); }
    if (!verified.has(cur)) { await katOrThrow(); verified.add(cur); }
    return 'injected';
  }
  const chain = opts.chain ?? DEFAULT_ARGON_CHAIN;
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((c) => c === 'node' || c === 'worker' || c === 'inline')) {
    throw new VaultError('ERR_VAULT_CONFIG', 'carrier.chain');
  }
  const chainKey = chain.join(',');
  if (auto && cur === auto.loader && auto.chainKey === chainKey && auto.createWorker === opts.createWorker && auto.onFallback === opts.onFallback) {
    return auto.kind;
  }
  resetArgonCarrier();
  for (let i = 0; i < chain.length; i++) {
    const choice = chain[i];
    if (choice === 'node') {
      if (!nodeArgonAvailable()) continue;
      if (!nodeVerified) { await katOrThrow(); nodeVerified = true; }
      return 'node';
    }
    if (choice === 'worker') {
      if (!workerAvailable(opts)) continue;
      const st = installWorker(chainKey, opts, chain.slice(i + 1).includes('inline') && wasmAvailable());
      auto = st;
      setArgonLoader(st.loader);
      try { await katOrThrow(); } catch (e) { resetArgonCarrier(); throw e; }
      return st.kind;
    }
    if (choice === 'inline') {
      if (!wasmAvailable()) continue;
      const st = installInline(chainKey, opts);
      auto = st;
      setArgonLoader(st.loader);
      try { await katOrThrow(); } catch (e) { resetArgonCarrier(); throw e; }
      return st.kind;
    }
  }
  throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', 'no Argon2id carrier in chain [' + chainKey + ']');
}
