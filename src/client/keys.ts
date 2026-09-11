/**
 * keys.ts — storage key 命名空間。各產品以 config 指定前綴（如 journal 的 <brand>_）。
 * 理由：fork diff 證實 noteCrypto 差異一半在 localStorage key 前綴——參數化收進 core。
 */

export interface KeyStoreConfig {
  /** 產品前綴，如 'tacet'（不含底線）。 */
  brand: string;
}

export function makeKeyStore(config: KeyStoreConfig) {
  const wrapKey = (soulKey: string) => `${config.brand}_notekey:${soulKey}`;
  return {
    get: (k: string): string | null => {
      try { return localStorage.getItem(k); } catch { return null; }
    },
    set: (k: string, v: string): void => {
      try { localStorage.setItem(k, v); } catch { /* private mode：不阻擋主流程 */ }
    },
    remove: (k: string): void => {
      try { localStorage.removeItem(k); } catch { /* noop */ }
    },
    noteKeyWrap: wrapKey,
  };
}

export type KeyStore = ReturnType<typeof makeKeyStore>;