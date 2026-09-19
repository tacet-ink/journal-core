# @tacet-ink/journal-core

[![npm](https://img.shields.io/npm/v/@tacet-ink/journal-core.svg)](https://www.npmjs.com/package/@tacet-ink/journal-core)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/%40tacet-ink%2Fjournal-core.svg)](./package.json)
[![verify](https://img.shields.io/github/actions/workflow/status/tacet-ink/journal-core/verify.yml?branch=main&label=verify)](https://github.com/tacet-ink/journal-core/actions/workflows/verify.yml)

零知識日記核心：端對端加密、密語即身份的 auth、傳輸與限流原語。
伺服器看不到任何一個字：passphrase 永不過線，密鑰包裹與密文都在客戶端完成。

這是 [默·Tacet（tacet.ink）](https://tacet.ink) 的客戶端/伺服端核心原語層，
從多個姊妹產品共用的密碼學本體抽取而成，以品牌前綴參數化（前綴契約見下表）。

## 設計

- **兩時代金鑰模型**：未綁定（guest）時代以 `K_u = SHA-256(guestKdfPrefix ‖ identity)`
  純客戶端派生（混淆級）；綁定後改用隨機 256-bit noteKey 加密，
  noteKey 再以 passphrase（KEK）與復原套件（KEK_rec）雙重包裹上傳。
  此後 passphrase 不再過線：線上只送 PH1（雜湊形），伺服器存 PH2 = SHA-256(PH1)。
- **帶內版本化**：升級 KDF 參數 = 換新前綴（舊前綴照解、原地改語意是禁手）。
  前綴全部可配置，AAD（防搬移繫結）由呼叫端傳入。
- **extractable 鐵律**：要被 exportKey/wrap 的 key（noteKey 全部產生路徑），
  import 當下就必須 `extractable=true`；KEK/guest key 恆 nonextractable。
- **opt-in 原語**：選配契約（cipherGuest／wrapDual／wrapShare／pinLock／cipherAttach／cipherLocal）
  未配置即拒絕，各 fork 未選用的原語行為不受影響（cipherGuest 未配置時 bound 路徑不受牽連，
  解密面 guest 家族整面拒絕、不明字串與畸形空字串配置不當明文顯示）。

## 模組

| 模組 | 內容 |
| --- | --- |
| `src/client/note-crypto.ts` | 兩時代加解密、passphrase/復原套件/本機三路包裹、PIN 第二因子合鑰（jr2w.） |
| `src/client/argon2.ts` | Argon2id 包裹原語（jr3w./jr3d./jr3s.）、PH1 v2 派生、RFC 9106 KAT、雙載體（node:crypto＋hash-wasm） |
| `src/client/pinlock.ts` | 本機 PIN 鎖定包裹（jr1p.，開啟時鎖定） |
| `src/client/bip39.ts` | 復原套件 24 詞 ⇄ hex64 轉寫層（BIP39，零依賴自製） |
| `src/client/keys.ts` | 品牌前綴 localStorage 命名空間 |
| `src/server/auth.ts` | 零知識 auth 核心：PH1/PH2 hash-ladder、PH2 UNIQUE、session 撤銷、包裹欄組成對契約 |
| `src/server/ratelimit.ts` | per-IP 滑動視窗限流（D1 計數，併發安全版） |
| `src/server/cors.ts`／`hash.ts` | 共用 CORS／雜湊工具（`src/server/env.ts` 為內部 Env 介面，不入 exports） |

## 前綴契約（家族表：10 個資料前綴＋閘對照組 jr1g.）

前綴是版本契約：payload 佈局與 KDF 由前綴界定，升級 = 新前綴。
Tacet 部署實例（config 傳入）：

| 前綴 | 語意 | KDF | payload |
| --- | --- | --- | --- |
| `jr1u.` | guest 時代密文 | K_u = SHA-256(guestKdfPrefix ‖ identity) | AES-GCM |
| `jr1b.` | 綁定時代密文 | 隨機 256-bit noteKey | AES-GCM，AAD 綁 noteId |
| `jr1c.` | 附件密文（image attachments；選配） | 同筆記金鑰（noteKey／guest key 由呼叫端決定） | AES-GCM，AAD `jr1a:<noteId>:<attachId>` |
| `jr1d.` | 本機 IDB stored 密文（notes store；選配） | 同筆記金鑰（呼叫端注入） | AES-GCM，AAD 綁 note_id，payload 自帶 `v` 欄 |
| `jr1w.` | passphrase 包裹＋復原套件包裹 | PBKDF2-SHA256 600k | b64(iv[12] ‖ GCM(hex(noteKey)))，AAD `notekey` |
| `jr2w.` | PIN 第二因子合鑰（PBKDF2 版） | PBKDF2 600k(pass)＋2M(pin) → HKDF-SHA256 | pinSalt[16] ‖ iv[12] ‖ GCM，108B，AAD `notekey2` |
| `jr3w.` | passphrase 包裹（Argon2id 版） | Argon2id m=64MiB t=3 p=1 tag=32B | 同 jr1w. 形，AAD `notekey` |
| `jr3d.` | PIN 第二因子合鑰（Argon2id 版） | Argon2id(pass)＋Argon2id(pin) → HKDF-SHA256 | 同 jr2w. 形，108B，AAD `notekey2` |
| `jr3s.` | 單篇分享連結包裹 | Argon2id（同上參數） | 同 jr1w. 形，AAD `notekey-share` |
| `jr1p.` | 本機 PIN 鎖定（開啟時鎖定） | PBKDF2-SHA256 600k（刻意不用 Argon2id：解鎖要即時） | 同 jr2w. 形，AAD `notekey-pinlock` |

guest 密文前綴在閘對照組另驗 `jr1g.`（閘自造前綴，驗證品牌參數化本身；tacet 部署實例 guest 用 `jr1u.`）。
跨前綴呼叫一律回 null（前綴守衛＋AAD＋長度把關），不拋、不降級。

## 驗證

```sh
npm run verify   # 127 斷言對真模組（禁鏡像）：roundtrip/AAD 防搬移/extractable/時代隔離/
                 # 跨前綴家族隔離/payload 竄改/RFC 9106 KAT/BIP39 @scure 對照 200 組
```

- 產品碼**零執行時依賴**（WebCrypto 原語）；devDependencies 僅閘用（typescript、@scure/bip39 對照、workers types）。
- Argon2id 雙載體：node 走 `node:crypto`（Node 26+ 原生）、瀏覽器走 hash-wasm（wasm 內嵌），
  RFC 9106 標準向量逐位元一致；無載體即 throw（禁 fallback 鐵律）。
- BIP39 原語自製零依賴，與 @scure/bip39 參照 200 組雙向對照（僅 entropy↔words 轉寫層，禁用其 seed 派生）。

## 使用

TypeScript 原始碼發行（exports 直指 .ts）。**注意**：Node 的 strip-types 不適用於
node_modules 內的檔案，npm 安裝的消費者請走打包器；源碼 clone 可直接 node --experimental-strip-types。

```ts
import { makeKeyStore, makeHeldKey, generateNoteKey, encryptNote, decryptNote } from '@tacet-ink/journal-core';
// 或子路徑：'@tacet-ink/journal-core/client/note-crypto'
```

```ts
import { generateNoteKey, encryptNote, decryptNote, makeHeldKey,
         wrapNoteKey, unwrapNoteKey } from '@tacet-ink/journal-core/client/note-crypto';
import { makeKeyStore } from '@tacet-ink/journal-core/client/keys';

const cfg = {
  guestKdfPrefix: 'myapp-note-u1',
  recSaltPrefix: 'myapp-note-rec1:',
  cipherGuest: 'jr1g.',      // 換成你自己的品牌前綴家族
  cipherBound: 'jr1b.',
  wrap: 'jr1w.',
  store: makeKeyStore({ brand: 'myapp' }),
  // cipherGuest / wrapDual / wrapShare / pinLock / cipherAttach / cipherLocal：選配，未配置即拒絕
};

const held = makeHeldKey();
const identity = { current: () => 'acct-xxxxxxxxxxxxxxxx' };
const cipher = await encryptNote(cfg, held, '今天寫了一點東西。', 'noteId:n1', identity);
```

打包器（vite/esbuild）可直接 alias 到源碼目錄使用；Argon2id 瀏覽器載體需另裝
hash-wasm 並以 `setArgonLoader()` 注入（詳 `src/client/argon2.ts` 檔頭）。

## 界限（誠實面）

- guest 時代是混淆級不是 e2e（K_u 由 identity 可派生）；e2e 承諾從綁定（隨機 noteKey）起。
- PH1 派生方式由各產品自定義（快雜湊或 Argon2id 派生皆可），本層只驗 hex64 形。
- 本 repo 不含產品層：路由/配額/訂閱/GC/webhook 在各產品 fork。
- 未經第三方正式稽核；密語遺失設計上無救援（伺服器零知識的代價）。

## 授權

MIT。安全問題聯絡 tacetink.csd@gmail.com。
