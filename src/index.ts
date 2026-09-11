/**
 * index.ts — 公開 API barrel。
 *
 * 客戶端原語（WebCrypto；Argon2id 瀏覽器載體見 argon2.ts 檔頭 setArgonLoader）：
 */
export {
  makeHeldKey,
  generateNoteKey,
  encryptNote,
  decryptNote,
  wrapNoteKey,
  unwrapNoteKey,
  wrapNoteKeyWithRecToken,
  unwrapNoteKeyWithRecToken,
  wrapNoteKeyDual,
  unwrapNoteKeyDual,
  storeLocalWrap,
  ph1Of,
  normalizePin,
  recTokenHash,
  generateRecToken,
  PBKDF2_ITERATIONS,
  PIN_PBKDF2_ITERATIONS,
  type NoteCryptoConfig,
  type IdentityProvider,
  type HeldKey,
} from './client/note-crypto.ts';
export {
  setArgonLoader,
  verifyArgonKat,
  wrapNoteKey3,
  unwrapNoteKey3,
  wrapNoteKeyDual3,
  unwrapNoteKeyDual3,
  wrapNoteKeyShare3,
  unwrapNoteKeyShare3,
  derivePh1Argon,
  ARGON_MEMORY_KIB,
  ARGON_ITERATIONS,
  ARGON_PARALLELISM,
  ARGON_TAG_LEN,
  type Argon3Config,
} from './client/argon2.ts';
export {
  wrapNoteKeyPinLock,
  unwrapNoteKeyPinLock,
  PINLOCK_ITERATIONS,
  type PinLockConfig,
} from './client/pinlock.ts';
export {
  generateBip39Words,
  wordsToRecToken,
  recTokenToWords,
  spotCheckIndexes,
} from './client/bip39.ts';
export { makeKeyStore, type KeyStore, type KeyStoreConfig } from './client/keys.ts';
export { wordlist } from './client/wordlist.ts';

/** 伺服器端原語（Cloudflare Workers + D1）。 */
export {
  makeInboundCipher,
  isCipherFor,
  validWrappedKey,
  validHash64,
  validSalt,
  pickKeyPackage,
  loginRouteCore,
  errResponse,
  AUTH_RATE,
  type AuthRow,
  type AuthStore,
  type CipherFormats,
  type KeyPackage,
} from './server/auth.ts';
export { checkRate, type RateWindow } from './server/ratelimit.ts';
export { corsResponse, CORS_HEADERS } from './server/cors.ts';
export {
  sha256Hex,
  hashString,
  generateSessionToken,
  timingSafeEq,
} from './server/hash.ts';
export type { Env } from './server/env.ts';