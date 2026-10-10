/**
 * argon-auto.ts — Argon2id 載體平台預設（0.3.1 批 A3；CP1 草形：injected／node 兩腿）。
 */

import { getArgonLoader, verifyArgonKat } from './argon2.ts';
import { VaultError } from './vault-error.ts';

export type ArgonCarrierKind = 'injected' | 'node' | 'worker' | 'inline';

export interface ArgonCarrierOptions {
  /** 預留（CP2 接回退鏈）。 */
  chain?: readonly ('node' | 'worker' | 'inline')[];
}

function nodeArgonAvailable(): boolean {
  const nodeCrypto = (globalThis as unknown as {
    process?: { getBuiltinModule?: (id: string) => { argon2?: unknown } | undefined };
  }).process?.getBuiltinModule?.('node:crypto');
  return typeof nodeCrypto?.argon2 === 'function';
}

let failures = 0;

/** 載體失效累計（vault 以前後差分辨「解包 null＝密語錯」與「載體失效」）。 */
export function argonCarrierFailures(): number {
  return failures;
}

export async function ensureArgonCarrier(_opts?: ArgonCarrierOptions): Promise<ArgonCarrierKind> {
  let kind: ArgonCarrierKind;
  if (getArgonLoader()) kind = 'injected';
  else if (nodeArgonAvailable()) kind = 'node';
  else throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', 'no Argon2id carrier');
  let ok = false;
  try { ok = await verifyArgonKat(); } catch (e) { failures++; throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', 'carrier KAT threw', { cause: e }); }
  if (!ok) { failures++; throw new VaultError('ERR_VAULT_KDF_UNSUPPORTED', 'carrier KAT mismatch (RFC 9106)'); }
  return kind;
}
