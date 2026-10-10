/**
 * argon-worker.ts — Argon2id Web Worker 載體（0.3.1 批 A3）：登入不卡畫面。
 *
 * Worker 本體＝內嵌 blob 形（免 bundle 步）：vendor 工廠 hashWasmArgon2Factory 的原文
 *（Function#toString）＋訊息膠水組成 Worker 源碼字串 → Blob → object URL → new Worker。
 * 協定：main → { id, password, salt, iterations, parallelism, memorySize, hashLength }；
 *       worker → { id, ok: true, out: Uint8Array } | { id, ok: false, error }。
 * 串行：main 端單一佇列（hash-wasm Argon2 禁並行——argon2.ts deriveKek2Argon 註同理），
 * worker 端亦以 promise 鏈串行（雙防線）。
 * 失敗態：建構拋出／error 事件／ok:false 回應＝本載體失效（dead），佇列內與後續請求一律 reject——
 * 回退與否由 argon-auto.ts 回退鏈決定（本檔不自帶回退，行為顯形）。
 */

import type { HashWasmArgon2id } from './argon2.ts';
import { hashWasmArgon2Factory } from './vendor/hash-wasm-argon2.ts';

/** Worker 最小介面（瀏覽器 Worker 直接相容；node worker_threads 等可包轉接層注入）。 */
export interface ArgonWorkerLike {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

/** Worker 源碼字串（self.onmessage 形；瀏覽器 DedicatedWorkerGlobalScope 語意）。 */
export function argonWorkerSource(): string {
  return [
    "'use strict';",
    'const factory = (' + hashWasmArgon2Factory.toString() + ');',
    'let mod = null;',
    'let q = Promise.resolve();',
    'self.onmessage = (ev) => {',
    '  const m = ev.data;',
    '  q = q.then(async () => {',
    '    try {',
    '      if (!mod) mod = factory();',
    "      const r = await mod.argon2id({ password: m.password, salt: m.salt, iterations: m.iterations, parallelism: m.parallelism, memorySize: m.memorySize, hashLength: m.hashLength, outputType: 'binary' });",
    '      const out = new Uint8Array(r);',
    '      self.postMessage({ id: m.id, ok: true, out }, [out.buffer]);',
    '    } catch (e) {',
    '      self.postMessage({ id: m.id, ok: false, error: String((e && e.message) || e) });',
    '    }',
    '  });',
    '};',
    '',
  ].join('\n');
}

/** 瀏覽器預設 Worker 工廠：blob URL（CSP 需 worker-src blob:；不允許時建構拋出或 error 事件→回退鏈接手）。 */
export function createBlobArgonWorker(): ArgonWorkerLike {
  const url = URL.createObjectURL(new Blob([argonWorkerSource()], { type: 'text/javascript' }));
  let w: Worker;
  try {
    w = new Worker(url);
  } catch (e) {
    URL.revokeObjectURL(url);
    throw e;
  }
  const like: ArgonWorkerLike = {
    postMessage: (m, t) => w.postMessage(m, t ?? []),
    terminate: () => { w.terminate(); URL.revokeObjectURL(url); },
    onmessage: null,
    onerror: null,
  };
  w.onmessage = (ev) => like.onmessage?.({ data: ev.data });
  w.onerror = (ev) => like.onerror?.(ev);
  w.onmessageerror = (ev) => like.onerror?.(ev);
  return like;
}

interface Pending {
  resolve: (v: Uint8Array) => void;
  reject: (e: unknown) => void;
}

/** Worker 載體：回 hash-wasm 同形 argon2id（argon2.ts ArgonLoader 契約）＋terminate。 */
export function makeWorkerArgon2id(createWorker: () => ArgonWorkerLike): { argon2id: HashWasmArgon2id; terminate(): void } {
  let worker: ArgonWorkerLike | null = null;
  let dead: unknown = null;
  let seq = 0;
  const pending = new Map<number, Pending>();
  let queue: Promise<unknown> = Promise.resolve();

  const die = (e: unknown): void => {
    if (!dead) dead = e ?? new Error('ERR_ARGON_WORKER_DEAD');
    for (const p of pending.values()) p.reject(dead);
    pending.clear();
    if (worker) { try { worker.terminate(); } catch { /* 已終止 */ } }
    worker = null;
  };

  const boot = (): ArgonWorkerLike => {
    if (worker) return worker;
    const w = createWorker();
    w.onmessage = (ev) => {
      const d = ev.data as { id?: number; ok?: boolean; out?: Uint8Array; error?: string } | null;
      const p = d && typeof d.id === 'number' ? pending.get(d.id) : undefined;
      if (!p || !d) return;
      pending.delete(d.id!);
      if (d.ok && d.out instanceof Uint8Array) p.resolve(d.out);
      else {
        const err = new Error('ERR_ARGON_WORKER: ' + (d.error ?? 'bad response'));
        p.reject(err);
        die(err); // ok:false＝worker 內 wasm 失效（CSP wasm-eval／記憶體）——整載體 dead，交回退鏈
      }
    };
    w.onerror = (ev) => die(new Error('ERR_ARGON_WORKER_ERROR', { cause: ev }));
    worker = w;
    return w;
  };

  const run = (params: Parameters<HashWasmArgon2id>[0]): Promise<Uint8Array> =>
    new Promise<Uint8Array>((resolve, reject) => {
      if (dead) { reject(dead); return; }
      let w: ArgonWorkerLike;
      try { w = boot(); } catch (e) { die(e); reject(dead); return; }
      const id = ++seq;
      pending.set(id, { resolve, reject });
      try {
        w.postMessage({
          id,
          password: params.password,
          salt: params.salt,
          iterations: params.iterations,
          parallelism: params.parallelism,
          memorySize: params.memorySize,
          hashLength: params.hashLength,
        });
      } catch (e) {
        pending.delete(id);
        die(e);
        reject(dead);
      }
    });

  const argon2id: HashWasmArgon2id = (params) => {
    const job = queue.then(() => run(params));
    queue = job.catch(() => undefined);
    return job.then((out) => {
      if (params.outputType === 'binary') return out;
      if (params.outputType === 'hex') return Array.from(out).map((b) => b.toString(16).padStart(2, '0')).join('');
      throw new Error('ERR_ARGON_WORKER_OUTPUT_TYPE');
    });
  };

  return { argon2id, terminate: () => die(new Error('ERR_ARGON_WORKER_TERMINATED')) };
}
