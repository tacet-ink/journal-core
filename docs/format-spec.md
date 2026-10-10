# journal-core 線上格式規格（wire format spec）

> 適用版本：`@tacet-ink/journal-core` 0.3.0。
> 規格源＝`src/client/note-crypto.ts`／`src/client/argon2.ts`／`src/client/pinlock.ts`／`src/client/bip39.ts`
> 檔頭契約註解與函式本體，以及 README 前綴家族表；本文只錄源碼現行行為，不新增契約。
> 規格與源碼若有出入，以源碼行為為準，並視為本文缺陷回報。
> 測試向量：[`docs/vectors/`](./vectors/)（由 `scripts/generate-vectors.ts` 呼叫真原語一次性產生、凍結入 repo；
> 向量檔格式見文末「向量檔格式」節）。

## 0. 通則

### 0.1 編碼與記號

- `‖`：位元組串接。
- `UTF8(s)`：字串 `s` 的 UTF-8 位元組（`TextEncoder`）。
- `hex(b)`：小寫十六進位字串（每位元組 2 字元，`0-9a-f`）。
- `b64(b)`：標準 Base64（RFC 4648 §4 字母表 `A-Z a-z 0-9 + /`，帶 `=` 補位；`btoa` 形，非 URL-safe）。
- 線上字串形一律為 `prefix + b64(payload)`：前綴是 ASCII 字面（Tacet 部署值如 `jr1w.`），
  前綴之後整段是 payload 的 Base64。
- 前綴全部由呼叫端 config 注入；本文的前綴字面是 Tacet 部署實例（README 家族表同值）。
  他產品可換自己的字面，**位元組布局與 KDF 由「家族」界定而不隨字面改變**。

### 0.2 對稱原語

- AEAD：AES-256-GCM（WebCrypto `AES-GCM`，金鑰 256-bit）、IV 12 位元組（每次加密隨機）、
  tag 16 位元組（附於密文尾；WebCrypto 輸出即 `ct ‖ tag`）。
- AAD：`UTF8(aad 字串)`，每家族固定字串或由呼叫端傳入（見各家族）。
- 本文把 `GCM(K, m, aad)` 記為 WebCrypto `encrypt` 的輸出：`ciphertext(len(m)) ‖ tag(16)`。

### 0.3 noteKey 與包裹明文

- noteKey＝隨機 32 位元組 AES-256-GCM 金鑰（綁定時代資料金鑰）。
- **包裹明文不是 raw 32 位元組，而是 `UTF8(hex(noteKey))`＝64 個 ASCII 小寫 hex 字元＝64 位元組。**
  因此所有金鑰包裹的密文段固定 `64 + 16 = 80` 位元組。
- 解包成功的判準：GCM 驗證通過 **且** 明文恰 64 字元 **且** 全為 `[0-9a-f]`；否則視同失敗。
- 解包輸出的 noteKey 一律 `extractable=true`（extractable 鐵律：要能再包裹）；KEK 一律 nonextractable。

### 0.4 共通失敗契約

- 所有 unwrap／decrypt 函式：前綴不符、Base64 非法、payload 長度不符、鹽欄形不符、GCM 驗證失敗、
  明文形不符——**一律回 `null`，不拋例外、不降級成他家族解讀**（跨前綴呼叫恆 `null`）。
- 外置鹽欄（`salt`／`salt1`）形檢：恰 32 個小寫 hex 字元（`/^[0-9a-f]{32}$/`）＝16 位元組。
- 未配置（opt-in 前綴缺席）：寫面拋 `ERR_*_NOT_CONFIGURED`、讀面回 `null`（詳 README 例外契約表）。

### 0.5 帶內版本化（世代契約，全家族共通）

- **前綴即版本**：payload 布局、KDF、KDF 參數、AAD 由前綴（家族）界定。
- **升級＝換新前綴**：KDF 參數、KDF 輸入正規化、AAD 任一改變都必須開新前綴；
  **禁止在既有前綴上原地改語意**。
- **舊前綴永久可解**：既有前綴的解包路徑永不移除、永不變更派生方式（舊 blob 逐位可解）。
- 新舊世代並存時由前綴分流；讀面可「讀舊寫新」（如 `jr1r.`／`jr1l.` 的回落），寫面只產生新前綴。

## 1. 家族總覽

payload 三種布局：

| 布局代號 | payload 位元組序 | payload 長度 |
| --- | --- | --- |
| `content` | `iv[12] ‖ ct[n] ‖ tag[16]` | `28 + n`（n＝明文 UTF-8 位元組數） |
| `salt-external` | `iv[12] ‖ ct[64] ‖ tag[16]` | 恰 92 |
| `salt-embedded` | `pinSalt[16] ‖ iv[12] ‖ ct[64] ‖ tag[16]` | 恰 108 |

`salt-external`：鹽（若有）不在 payload 內，由呼叫端另存（如 `users.salt`／`shares.salt`）或由 config 承載。
`salt-embedded`：16 位元組 pinSalt 內嵌 payload 頭（自描述），另可能有外置 `salt1`。

家族逐條（payload 長度欄為 Base64 解碼後位元組數；線上字串長＝前綴長＋b64 長；92B → 124 字元、108B → 144 字元）：

| 前綴 | 家族 | 布局 | payload 位元組 | KDF | AAD |
| --- | --- | --- | --- | --- | --- |
| `jr1u.` | guest 時代密文 | content | 28+n | `K_u = SHA-256(UTF8(guestKdfPrefix ‖ identity))` | 呼叫端傳入 |
| `jr1b.` | 綁定時代密文 | content | 28+n | 無（noteKey 直用） | 呼叫端傳入（綁 noteId） |
| `jr1c.` | 附件密文 | content | 28+n | 無（noteKey 或 guest key，呼叫端決定） | 呼叫端傳入（`jr1a:<noteId>:<attachId>`） |
| `jr1d.` | 本機 IDB 密文 | content | 28+n | 無（呼叫端注入金鑰） | 呼叫端傳入（綁 note_id） |
| `jr1w.` | passphrase 包裹 | salt-external | 92 | PBKDF2-SHA256 600000 | `notekey` |
| `jr1w.`（復原，未配置世代） | 復原套件包裹 | salt-external | 92 | PBKDF2-SHA256 600000（鹽＝`recSaltPrefix ‖ identity`） | `notekey` |
| `jr1r.` | 復原套件包裹（HKDF 世代） | salt-external | 92 | HKDF-SHA256 | `notekey-rec` |
| `jr1l.` | 本機包裹 | salt-external | 92 | `K_u`（同 guest） | `notekey-local` |
| `jrsw.` | 分享包裹 V1（建立面退役） | salt-external | 92 | PBKDF2-SHA256 600000 | `notekey-share` |
| `jr3w.` | passphrase 包裹（Argon2id） | salt-external | 92 | Argon2id m=65536 KiB t=3 p=1 | `notekey` |
| `jr4w.` | passphrase 包裹（密語正規化 v3） | salt-external | 92 | Argon2id（輸入 NFKC） | `notekey` |
| `jr3s.` | 分享包裹 V2（Argon2id） | salt-external | 92 | Argon2id m=65536 KiB t=3 p=1 | `notekey-share` |
| `jr2w.` | PIN 第二因子合鑰（PBKDF2） | salt-embedded | 108 | PBKDF2 600000＋2000000 → HKDF-SHA256 | `notekey2` |
| `jr3d.` | PIN 第二因子合鑰（Argon2id） | salt-embedded | 108 | Argon2id×2 → HKDF-SHA256 | `notekey2` |
| `jr4d.` | PIN 第二因子合鑰（密語正規化 v3） | salt-embedded | 108 | Argon2id×2（pass 段 NFKC） → HKDF-SHA256 | `notekey2` |
| `jr1p.` | 本機 PIN 鎖定 | salt-embedded | 108 | PBKDF2-SHA256 600000 | 呼叫端 config（Tacet＝`notekey-pinlock`） |

驗證閘另以 `jr1g.` 當 guest 前綴對照組（驗證品牌參數化本身）；與 `jr1u.` 同一家族、同布局。

## 2. 正規化函式

| 名稱 | 定義 | 消費面 |
| --- | --- | --- |
| raw | 原字串不處理 | `jr1w.`／`jr3w.`／`jrsw.`／`jr3s.`／`jr2w.` 與 `jr3d.` 的 pass 段；PH1 legacy／v2 |
| `normalizePassphrase` | `s.normalize('NFKC')`（不 trim、不摺疊大小寫） | `jr4w.`；`jr4d.` 的 pass 段；PH1 v3 |
| `normalizePin` | `s.normalize('NFKC').trim().toLowerCase()`；結果為空字串＝拒絕 | `jr2w.`／`jr3d.`／`jr4d.`／`jr1p.` 的 PIN 段 |

兩正規化契約正交、互不替代；改任一語意＝換世代（新前綴），禁原地改。

## 3. 金鑰派生原語

### 3.1 PBKDF2 KEK（`jr1w.`／`jrsw.`／復原未配置世代）

```
KEK = PBKDF2-HMAC-SHA256(password = UTF8(secret), salt, iterations = 600000, dkLen = 32) → AES-256-GCM
```

- `jr1w.`：`secret`＝passphrase（raw），`salt`＝16 隨機位元組（外置，hex 存 `users.salt`）。
- `jrsw.`：`secret`＝分享密語（raw），`salt`＝16 隨機位元組（外置，hex 存 `shares.salt`）。
- 復原套件未配置世代：`secret`＝recToken（64 字元 hex 字串本身的 UTF-8，非解碼後 32 位元組），
  `salt`＝`UTF8(recSaltPrefix ‖ identity)`（無外置鹽）。

### 3.2 Argon2id KEK（`jr3w.`／`jr4w.`／`jr3s.`）

```
KEK = Argon2id(password = UTF8(input), salt = 16B, m = 65536 KiB (64 MiB), t = 3, p = 1, tagLength = 32, version = 0x13) → AES-256-GCM
```

- `jr3w.`／`jr3s.`：`input`＝raw 密語。`jr4w.`：`input`＝`normalizePassphrase(密語)`。
- 無 secret、無 associated data。實作正確性錨＝RFC 9106 §5.3 向量（`docs/vectors/kat.json` 之 `rfc9106`）。
- 無 Argon2id 載體即拋 `ERR_ARGON2_UNAVAILABLE`——禁降級 PBKDF2 或零值兜底。

### 3.3 雙因子 KEK2（`jr2w.`／`jr3d.`／`jr4d.`）

```
passBits = KDF_pass(pass段輸入, salt1)                         // 32B
pinBits  = KDF_pin(normalizePin(pin), UTF8(pinSaltPrefix ‖ hex(pinSalt)))   // 32B
ikm      = passBits ‖ pinBits                                   // 64B，序固定：pass 在前
KEK2     = HKDF-SHA256(ikm, salt = pinSalt (16B raw), info = UTF8('journal-kek2-v1:' + 家族前綴), L = 32) → AES-256-GCM
```

| 家族 | KDF_pass | pass 段輸入 | KDF_pin | pinSaltPrefix（Tacet） | info 尾綴 |
| --- | --- | --- | --- | --- | --- |
| `jr2w.` | PBKDF2-SHA256 600000 | raw | PBKDF2-SHA256 2000000 | `tacet-note-pin1:`（config `pinSaltPrefix`） | `wrapDual`（`jr2w.`） |
| `jr3d.` | Argon2id 64MiB/3/1 | raw | Argon2id 64MiB/3/1 | `tacet-note-pin3:`（config `pinSalt3Prefix`） | `wrapDual3`（`jr3d.`） |
| `jr4d.` | Argon2id 64MiB/3/1 | `normalizePassphrase` | Argon2id 64MiB/3/1 | `tacet-note-pin3:`（config `pinSalt3Prefix`） | `wrapDual4`（`jr4d.`） |

- `salt1`：16 隨機位元組，外置（hex 存 `users.salt`，由 login 回應帶回）。
- `pinSalt`：16 隨機位元組，內嵌 payload 頭，同時當 HKDF salt。
- HKDF info 的尾綴是 config 的前綴字面本身——`jr3d.` 與 `jr4d.` 即使 bits 段同值（NFKC 不變的密語），
  KEK2 也因 info 域不同而互斥。

### 3.4 復原套件 HKDF 世代 KEK_rec（`jr1r.`）

```
KEK_rec = HKDF-SHA256(ikm = UTF8(recToken), salt = recKekSalt ? hexToBytes(recKekSalt) (16B) : 空, info = UTF8('journal-kek-rec-v1:' + recKekHkdf), L = 32) → AES-256-GCM
```

- `recToken`：64 字元小寫 hex（256-bit 實體因子；BIP39 24 詞可逆轉寫，見 §6）；ikm 是 hex 字串本身的 UTF-8（64 位元組）。
- `recKekSalt`：config 16 位元組 hex（未配置＝空鹽）；非 32 hex 字元＝拋 `ERR_REC_KEK_SALT`。
- identity 不入 KEK_rec（HKDF 世代刻意 identity-free；舊世代 identity 綁在 PBKDF2 鹽）。
- `wrapRec` 與 `recKekHkdf` 兩欄一體：部分配置＝寫面拋 `ERR_REC_CFG_PARTIAL`。

### 3.5 guest 金鑰 K_u（`jr1u.`／`jr1l.`）

```
K_u = SHA-256(UTF8(guestKdfPrefix ‖ identity)) → AES-256-GCM（raw 32B 直接當金鑰）
```

- 混淆級、非 e2e（identity 可得即可派生）。identity 空字串＝加密拋 `ERR_NO_IDENTITY`、解密回 `null`。

### 3.6 PIN 鎖定 KEK（`jr1p.`）

```
KEK = PBKDF2-HMAC-SHA256(UTF8(normalizePin(pin)), UTF8(pinLockSaltPrefix ‖ hex(pinSalt)), 600000, 32) → AES-256-GCM
```

- Tacet：`pinLockSaltPrefix`＝`tacet-pinlock-v1:`、`pinLockAad`＝`notekey-pinlock`。三欄（`pinLock`／`pinLockSaltPrefix`／`pinLockAad`）缺一即拒。

## 4. 家族逐條

### 4.1 `content` 布局：`jr1u.`／`jr1b.`／`jr1c.`／`jr1d.`

```
wire    = prefix + b64(payload)
payload = iv[12] ‖ GCM(K, UTF8(plaintext), UTF8(aad))      // = iv[12] ‖ ct[n] ‖ tag[16]
```

| 前綴 | 金鑰 K | 入口 | 備註 |
| --- | --- | --- | --- |
| `jr1u.` | `K_u`（§3.5） | `encryptNote`／`decryptNote`（held 為空且無本機包裹時） | `cipherGuest` 選配；未配置＝寫面 `ERR_GUEST_NOT_CONFIGURED`、讀面不明字串一律 `null` |
| `jr1b.` | noteKey | `encryptNote`／`decryptNote`（held 有鑰） | 必配；AAD 慣例綁 noteId |
| `jr1c.` | noteKey 或 `K_u`（呼叫端） | `encryptAttach`／`decryptAttach` | `cipherAttach` 選配 |
| `jr1d.` | 呼叫端注入（bound＝noteKey、Era 0＝`K_u`） | `encryptLocal`／`decryptLocal` | `cipherLocal` 選配；明文是呼叫端 JSON，自帶 `{v:1,...}` 版本欄 |

- 解密面相容層（`decryptNote`）：字串既非 guest 前綴也非 bound 前綴時——`cipherGuest` 有配置＝視為舊版明文原樣回傳；
  未配置＝回 `null`。
- 世代契約：content 家族的 AEAD 形（iv 12／tag 16／AAD 由呼叫端）凍結；改金鑰派生或布局＝新前綴。

### 4.2 `jr1w.` passphrase 包裹

```
salt    = random(16)                                // 外置：hex(salt) 回傳呼叫端存 users.salt
KEK     = PBKDF2-SHA256(UTF8(passphrase), salt, 600000)   // §3.1
wire    = 'jr1w.' + b64(iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), 'notekey'))   // payload 92B
```

- 入口：`wrapNoteKey`／`unwrapNoteKey(cfg, wrapped, passphrase, saltHex)`。
- 同前綴另承載「復原套件未配置世代」（§4.4）：AAD 同為 `notekey`、KEK 來源不同（呼叫端依欄位分辨，非 payload 分辨）。
- 世代：PBKDF2 600000 永凍結；Argon2id 升級走 `jr3w.`、正規化升級走 `jr4w.`。

### 4.3 `jr1r.` 復原套件包裹（HKDF 世代，選配）

```
KEK_rec = §3.4
wire    = 'jr1r.' + b64(iv[12] ‖ GCM(KEK_rec, UTF8(hex(noteKey)), 'notekey-rec'))   // payload 92B
```

- 入口：`wrapNoteKeyWithRecToken`／`unwrapNoteKeyWithRecToken(cfg, wrapped, recToken, identity)`。
- 寫面：兩欄齊備才寫 `jr1r.`；讀面先試 `jr1r.`，失敗或前綴不符再回落 §4.4 舊契約面（讀舊寫新雙試）。
- 世代：v0.2.0 起的 KEK 派生世代；舊契約（§4.4）永久可解。

### 4.4 `jr1w.` 復原套件包裹（未配置世代／舊契約）

```
KEK_rec = PBKDF2-SHA256(UTF8(recToken), UTF8(recSaltPrefix ‖ identity), 600000)   // 無外置鹽
wire    = 'jr1w.' + b64(iv[12] ‖ GCM(KEK_rec, UTF8(hex(noteKey)), 'notekey'))   // payload 92B
```

- `recSaltPrefix`：Tacet＝`tacet-note-rec1:`。伺服器只收 `recTokenHash = hex(SHA-256(UTF8(recToken)))`。
- 世代：舊契約永不變（`wrapRec`／`recKekHkdf` 兩欄皆缺席時寫面仍走此形）。

### 4.5 `jr1l.` 本機包裹（選配）

```
wire = 'jr1l.' + b64(iv[12] ‖ GCM(K_u, UTF8(hex(noteKey)), 'notekey-local'))   // payload 92B
```

- 儲存：瀏覽器 localStorage，key＝`<brand>_notekey:<identity>`（`makeKeyStore`）。不上伺服器。
- 讀面自癒：命中借用期舊形（同 payload 但前綴為 `cfg.wrap`＝`jr1w.`、AAD 同為 `notekey-local`）解出後，以 `jr1l.` 重寫一次。
- `wrapLocal` 未配置＝寫面退場（不寫入），讀面照走舊形回落。

### 4.6 `jrsw.` 分享包裹 V1（建立面退役註記）

```
salt = random(16)                 // 外置：shares.salt
KEK  = PBKDF2-SHA256(UTF8(sharePass), salt, 600000)
wire = 'jrsw.' + b64(iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), 'notekey-share'))   // payload 92B
```

- 入口：`wrapNoteKeyShare`／`unwrapNoteKeyShare`（`wrapShare` 選配）。
- **退役註記**：分享 KDF 已升級為 `jr3s.`（Argon2id）；部署端建立面只收 `jr3s.`（關閉弱 KDF 建立面），
  `jrsw.` 讀取面與兩代並行永久保留（舊連結可解）。core 仍匯出 `wrapNoteKeyShare`（opt-in 原語不移除）——
  新部署不應配置 `wrapShare` 寫入。

### 4.7 `jr3w.` passphrase 包裹（Argon2id）

```
salt = random(16)                 // 外置：users.salt
KEK  = Argon2id(UTF8(passphrase raw), salt, 65536 KiB, t=3, p=1, 32)   // §3.2
wire = 'jr3w.' + b64(iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), 'notekey'))   // payload 92B
```

- 入口：`wrapNoteKey3`／`unwrapNoteKey3`（`wrap3` 選配）。payload 不含 salt（salt 外置，與 `jr1w.` 同形）。
- 世代：raw 密語契約永不變；正規化升級走 `jr4w.`。

### 4.8 `jr4w.` passphrase 包裹（密語正規化 v3）

```
KEK  = Argon2id(UTF8(normalizePassphrase(passphrase)), salt, 65536 KiB, t=3, p=1, 32)
wire = 'jr4w.' + b64(iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), 'notekey'))   // payload 92B
```

- 入口：`wrapNoteKey4`／`unwrapNoteKey4`（`wrap4` 選配）。與 `jr3w.` 唯一差異＝KDF 輸入經 NFKC。
- 寫法差（全形／NFD／NFC）收容為同一 KEK；首尾空白與大小寫仍分流。

### 4.9 `jr3s.` 分享包裹 V2（Argon2id）

```
salt = random(16)                 // 外置：shares.salt
KEK  = Argon2id(UTF8(sharePass raw), salt, 65536 KiB, t=3, p=1, 32)
wire = 'jr3s.' + b64(iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), 'notekey-share'))   // payload 92B
```

- 入口：`wrapNoteKeyShare3`／`unwrapNoteKeyShare3`（`wrapShare3` 選配）。AAD 與 `jrsw.` 同；跨代誤用由 KDF 差與前綴守衛把關。

### 4.10 `jr2w.` PIN 第二因子合鑰（PBKDF2）

```
salt1   = random(16)              // 外置：users.salt
pinSalt = random(16)              // 內嵌
KEK2    = §3.3（jr2w. 列）
wire    = 'jr2w.' + b64(pinSalt[16] ‖ iv[12] ‖ GCM(KEK2, UTF8(hex(noteKey)), 'notekey2'))   // payload 108B
```

- 入口：`wrapNoteKeyDual`／`unwrapNoteKeyDual(cfg, wrapped, passphrase, pin, salt1Hex)`（`wrapDual`＋`pinSaltPrefix` 選配）。
- PIN 正規化後為空＝寫面 `ERR_PIN_EMPTY`、讀面 `null`。

### 4.11 `jr3d.` PIN 第二因子合鑰（Argon2id）

- 布局同 `jr2w.`（108B），KEK2 依 §3.3 `jr3d.` 列；入口 `wrapNoteKeyDual3`／`unwrapNoteKeyDual3`（`wrapDual3`＋`pinSalt3Prefix`）。
- 世代：raw 密語契約永不變；正規化升級走 `jr4d.`。

### 4.12 `jr4d.` PIN 第二因子合鑰（密語正規化 v3）

- 布局同 `jr2w.`（108B），KEK2 依 §3.3 `jr4d.` 列；入口 `wrapNoteKeyDual4`／`unwrapNoteKeyDual4`
  （另 `unwrapNoteKeyDual4WithSalt`＝同體，承載 ladder 遷移後重取 salt1 的語意位）。

### 4.13 `jr1p.` 本機 PIN 鎖定

```
pinSalt = random(16)              // 內嵌；無外置鹽
KEK     = §3.6
wire    = 'jr1p.' + b64(pinSalt[16] ‖ iv[12] ‖ GCM(KEK, UTF8(hex(noteKey)), UTF8(pinLockAad)))   // payload 108B
```

- 入口：`wrapNoteKeyPinLock`／`unwrapNoteKeyPinLock(cfg, wrapped, pin)`。
- 刻意用 PBKDF2 600000（解鎖要即時）；本機裝置閘，與登入第二因子契約分離。

## 5. 登入憑證（非前綴形，供第三方對帳）

| 名稱 | 定義 | 輸出 |
| --- | --- | --- |
| PH1 legacy | `hex(SHA-256(UTF8(passphrase)))`（`ph1Of`） | 64 hex |
| PH1 v2 | `hex(Argon2id(UTF8(passphrase raw), saltArg ?? UTF8('tacet-ph1-v1'), 65536 KiB, 3, 1, 32))`（`derivePh1Argon`） | 64 hex |
| PH1 v3 | `hex(Argon2id(UTF8(normalizePassphrase(passphrase)), saltArg ?? UTF8('tacet-ph1-v2'), 65536 KiB, 3, 1, 32))`（`derivePh1ArgonV3`） | 64 hex |
| PH2（伺服器存） | `hex(SHA-256(UTF8(PH1 hex 字串)))` | 64 hex |
| recTokenHash | `hex(SHA-256(UTF8(recToken hex 字串)))` | 64 hex |

PH1 鹽是 per-product 固定域鹽（PH2 UNIQUE 約束）；v2／v3 鹽域值必須互異。

## 6. BIP39 復原套件轉寫

- recToken（64 hex）⇄ entropy 32 位元組 ⇄ 24 個英文詞（BIP39 英文詞表 2048 詞）。
- checksum＝`SHA-256(entropy)[0]` 全 8 bits；`entropy ‖ checksum` 共 264 bits，切 24 段 11-bit 索引（大端位序）。
- 只收 24 詞；輸入正規化 NFKC→trim→lowercase、空白收斂；任何不符（字數／詞表外／checksum）回 `null`。
- 轉寫層非 KDF：線上契約仍是 recToken 本身（§3.1／§3.4）。與 @scure/bip39 `entropyToMnemonic`／`mnemonicToEntropy` 逐詞一致（驗證閘 [9] 200 組；本 repo 向量檔抽樣 34 組）。

## 7. 向量檔格式（`docs/vectors/`）

三檔，皆 UTF-8 JSON，頂層共通欄：

| 欄位 | 意義 |
| --- | --- |
| `format` | 向量檔格式識別字（`journal-core-vectors/1`） |
| `package_version` | 產生時的 package 版本 |
| `spec` | 本規格檔路徑（`docs/format-spec.md`） |
| `generator` | 產生器路徑（`scripts/generate-vectors.ts`） |
| `note` | 說明（凍結證據：不隨 CI 重算） |

### 7.1 `families.json`——各前綴家族 wrap／encrypt 一組

`vectors`（陣列）每筆：

| 欄位 | 意義 |
| --- | --- |
| `prefix` | 前綴字面 |
| `family` | 家族名 |
| `layout` | `content`／`salt-external`／`salt-embedded` |
| `kdf` | KDF 敘述（同 §3） |
| `aad` | AAD 字串 |
| `inputs` | 產生時的輸入（密語、PIN、identity、config 欄、外置鹽 `salt_hex`／`salt1_hex`、`note_key_hex` 或 `plaintext`） |
| `wire` | 完整線上字串（`prefix + b64(payload)`） |
| `payload_len` | Base64 解碼後位元組數 |
| `fields` | payload 欄位切分陣列，每項 `fields[].name`（`pinSalt`／`iv`／`ct`／`tag`）、`fields[].offset`、`fields[].len`、`fields[].hex`；`fields[].len` 總和＝`payload_len` |

金鑰包裹家族的 `inputs.note_key_hex` 固定 `c3`×32（驗證閘 KAT 母型），以此 wire 依本規格解包須得回之；
content 家族以 `inputs.plaintext`／`inputs.aad` 解密須得回原文。

### 7.2 `kat.json`——已知答案向量

| 欄位 | 意義 |
| --- | --- |
| `rfc9106` | Argon2id RFC 9106 §5.3 參數：`rfc9106.algorithm`、`rfc9106.version`、`rfc9106.memory_kib`、`rfc9106.iterations`、`rfc9106.parallelism`、`rfc9106.tag_len`、`rfc9106.password_hex`、`rfc9106.salt_hex`、`rfc9106.secret`／`rfc9106.associated_data`（恆 null），與 `rfc9106.expected_tag_hex` |
| `frozen_blobs` | 驗證閘凍結 blob（[14] `jr2w.`、[17] `jr3w.`／`jr3d.`／`jr4w.`／`jr4d.`、[20] `jr1r.`／`jr1w.` 復原舊契約）：`frozen_blobs[].prefix`、`frozen_blobs[].wire`、`frozen_blobs[].payload_len`、`frozen_blobs[].inputs`（解包輸入）、`frozen_blobs[].expected_note_key_hex`、`frozen_blobs[].source`（閘段號） |
| `credentials` | §5 憑證派生樣本：`credentials[].kind`、`credentials[].input`、`credentials[].input_nfkc`（僅 `ph1_v3`：`input` 經 `normalizePassphrase` 後的值）、`credentials[].salt`、`credentials[].expected_hex` |

### 7.3 `bip39.json`——BIP39 抽樣

`samples`（陣列）每筆：`samples[].entropy_hex`、`samples[].checksum_hex`、`samples[].words`（24 詞陣列）、`samples[].source`（`seeded:<n>`／`edge`）。
