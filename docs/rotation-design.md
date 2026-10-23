# rotateNoteKey 主鑰輪替設計（階段 1，doc-only）

> **狀態**：階段 1 設計定稿，待用戶裁定；裁定後開階段 2 實作卡（server＋client 實作、tacet 接線、進度 UI、部署窗，均**不在本文件範圍**）。
> **來源**：外部審查 `journal-core-review-2026-10-18.md` 第 J4 項（主鑰無輪替）、J3 項（本機 PIN 鎖實測強度）、J9 項（jr1l. deprecated）、D1 項（文件數字校正）；J1 既有分享的真正止血前提（報告 J4：「只撤銷舊分享沒有用，要靠 J4 的主鑰輪替才能真正收回」）。
> **裁定點總表**見 §9；本文對所有高裁量面給**建議案**而非定案，階段 2 以裁定結果為準。
> **對齊基準**（2026-10-23）：core main `0c87718`（J14/15 已上 main；registry latest 當時一手＝0.4.2，0.4.3 載具面隨本批尾發布窗）；tacet main `4886274`（J8 CP2 已上；login v3-first、PH2 pepper、粗桶限流皆已收案）。
> **鐵律承襲**（全文適用，不逐段重述）：帶內版本化＝KDF/契約升級＝換新前綴，舊前綴照解永不移語意；unwrap/decrypt 任何不符回 `null` 不拋；extractable 鐵律（noteKey 輸出恆 extractable=true、KEK nonextractable）；cfg 選配律（未配置＝API 拒絕，兄弟 fork 零影響）；server 零知識（不碰金鑰本體，只搬運包裹與密文）。

## 1. 問題與目標

### 1.1 問題（J4）

`changePassphrase`／`upgrade` 的現行語意是「**同一 noteKey 重包（資料零換鑰）**」（vault.ts 本體註解）；`note-crypto.ts` 全模組無「換一把新 noteKey＋逐篇重加密」原語（grep rotate＝0 命中）。後果：

- 主鑰任何管道外流（J1 舊分享、J3 被爆裝置、舊密語＋舊 wrapped、外流匯出檔、外流復原套件）＝**永久無補救**：舊的 `wrapped`／`wrappedRec`／匯出檔只要有人留著，永遠解得開。
- 換密語、換 PIN、升 KDF 全都不動資料面＝只換「鎖」不換「門」。

### 1.2 目標

1. 新增 `rotateNoteKey` 原語族：產生新 noteKey → 逐篇解密→新鑰重加密（筆記、附件、本機 IDB）→ 重包所有包裹面 → 舊包裹面退場。
2. **輪替中斷可續跑**：新舊鑰並存的過渡契約（§3）＋進度 cursor（§5）。
3. **J1 既有分享止血**：輪替完成＝J1 舊分享持有的主鑰對「輪替後新寫」徹底無效（§6）。
4. 併案收 J3 面：`jr2p.` Argon2id pinlock 設計＋PIN 政策＋存量 PIN 殘面＋WebAuthn PRF 深案（§7）；J8 收尾面現值（§8）；J9 jr1l. deprecated 導向（§10，README 側）。

### 1.3 非目標（階段 2 卡面也不含）

- 不設計 OPAQUE／伺服器參與 PIN 驗證（J6 另一設計鏈，否決案：OPAQUE 已在 argon2.ts 檔頭「後續精益求精」位）。
- 不改 guest 時代（Era 0）任何語意。
- 不強制既有分享立即失效的「主動收回」——輪替是**前止**（前止血），不是回收（§6.3 誠實界線）。

## 2. 現行原語盤點（設計對齊面）

| 原語 | 位置 | 與輪替的關係 |
|---|---|---|
| `generateNoteKey()` | note-crypto.ts | 新鑰產生＝直接複用（random 256-bit、extractable=true） |
| `wrapNoteKey`／`unwrapNoteKey`（jr1w.） | note-crypto.ts | 舊 passphrase 包裹面；新包裹走 v3 家族（`wrapNoteKey4`） |
| `wrapNoteKey4`／`unwrapNoteKey4`（jr4w.） | argon2.ts | 新鑰 passphrase 包裹（Argon2id 64MiB t=3 p=1） |
| `wrapNoteKeyDual`／`wrapNoteKey4Dual`（jr2w./jr4d.） | note-crypto.ts/argon2.ts | 雙因子帳戶的新包裹（pass＋PIN 合鑰）；前綴＝dual 偵測面 |
| `wrapNoteKeyWithRecToken`（jr1r.×HKDF 或未配置世代 jr1w.×PBKDF2） | note-crypto.ts | 復原套件面；recToken 256-bit 實體因子，KDF 強度無意義＝新鑰重包走**同一 recToken** |
| `wrapNoteKeyPinLock`／`unwrapNoteKeyPinLock`（jr1p.） | pinlock.ts | 本機鎖定面；新鑰重包走同一 PIN（§7.3 換 PIN 引導面） |
| `encryptNote`／`decryptNote`（cipherBound） | note-crypto.ts | 筆記密文面；新前綴 `jr2b.<kid>.` 的 decrypt 路由（§3.2） |
| `encryptAttach`／`decryptAttach`（jr1c.） | note-crypto.ts | 附件密文面（同 noteKey，AAD `jr1a:<noteId>:<attachId>`） |
| `encryptLocal`／`decryptLocal`（jr1d.） | note-crypto.ts | 本機 IDB stored 密文面（同 noteKey，AAD 綁 note_id） |
| `storeLocalWrap`／`loadLocalWrap`（jr1l.） | note-crypto.ts | 本機 session 包裹；**混淆級**（J9），輪替面＝重包或清除，不升強度（§10） |
| doPush（BATCH=25 `/notes/batch`） | tacet sync.ts | 批次重寫推送母型（§4.3） |
| `/notes/batch` version CAS | tacet backend notes.ts | 現行守衛＝**LWW 位序**（`version<?`：低版本重放 no-op；高版本覆蓋；同/低＝`ERR_VERSION_CONFLICT` 回帶現值）＝**已具備**輪替需要的防併發覆寫面（§4.1） |
| rekey wire（`wrapped`/`salt`/kit 三態語句） | tacet backend auth.ts | 包裹更新動線母型；`KIT_ONLY` 三態＝「只換套件不動憑證」先例（§4.2） |

## 3. 金鑰識別與過渡契約

### 3.1 kid（key id）契約

- **形態**：`kid` = 隨機 4 bytes → 8 位小寫 hex（`[0-9a-f]{8}`），client 端 `crypto.getRandomValues` 產生。碰撞域＝單帳戶（ring 內），8 字元＝10⁴⁸ 空間；碰撞即拒（ring add 時查重，重複＝`ERR_KID_COLLISION` 重試）。
- **產生點**：只由輪替流程產生（`generateKeyId()` 原語）；**不**用於任何新綁定（新綁定仍是裸 `jr1b.`＋單一主鑰，ring 初值＝{current: 無 kid 的 legacy 位}）。
- ** kid 絕非秘密**：進帶（ciphertext 前綴區）＋進 ring 欄位；安全靠 GCM，不靠 kid 隱匿。
- **ring 的 kid 編址**：ring 以 `kid→wrapped` 對；**現行主鑰**（綁定時產生、無 kid）在 ring 中佔保留位 `kid='legacy'`。`jr1b.`（無 kid 標記）密文的解鑰＝ring 內**全部**金鑰逐一試（§3.2）；`jr2b.<kid>.` 密文＝直查該 kid。

### 3.2 密文前綴過渡契約

**新前綴家族**：`jr2b.<kid>.`（Tacet 部署值；`cfg.cipherBound2` 注入基前綴 `jr2b.`，完整字串＝`cfg.cipherBound2 + kid + '.'`，由 core 原語組裝，呼叫端不手拼）。

| 密文形 | 產生時點 | 解鑰路由 |
|---|---|---|
| `jr1b.<b64>` | 輪替前（含輪替中未輪到的篇） | ring 全鑰逐一試（GCM tag＝oracle），命中即停。ring 恆 ≤2 鑰（過渡期）→ ≤2 次試解 |
| `jr2b.<kid>.<b64>` | 輪替後（新寫＋已輪替篇） | 直查 `ring[kid]`；缺席（該鑰已退場）＝`null`（不降級、不盲試） |

- **附件**同構新前綴 `jr2c.<kid>.`（`cfg.cipherAttach2`）；**本機 IDB** 同構 `jr2d.<kid>.`（`cfg.cipherLocal2`）。三面對稱（「一個前綴一份契約」律：kid 標記面獨立前綴，不污染 jr1c./jr1d.）。
- **decrypt 路由收口**：`decryptNote`（及 attach/local 同構）前綴判定序＝`jr2b.<kid>.` 族 → `jr1b.` → guest → 舊明文相容層。`jr2b.` 判定用基前綴 `startsWith`＋kid 欄形檢（`^[0-9a-f]{8}\.`），kid 欄畸形＝`null`（fail-closed，不回落盲試＝防 junk 前綴面）。
- **過渡期寫入**：`encryptNote` 在 ring 在場時**恆用 active 鑰＋`jr2b.<active-kid>.`**（不再寫裸 `jr1b.`）。ring 未初始化（新綁定）＝現行 `jr1b.` 零變。此即「寫入恆新」：過渡期結束的充分條件＝全量 `jr1b.` 消失（§5.4）。
- **AAD 零動**：三面 AAD 照舊（`jr1:<noteId>`／`jr1a:<noteId>:<attachId>`／note_id 綁定）——輪替換鑰不換 AAD 域（跨列搬移守衛不漂移）。

### 3.3 ring（金鑰環）資料模型

```
KeyRing = {
  activeKid: string          // 'legacy'（初態）或 kid
  entries: { [kid: string]: KeyEntry }   // kid ∈ 'legacy' ∪ [0-9a-f]{8}
}
KeyEntry = {
  wrappedForms: {            // 與舊鑰同款全包裹面（§4.2），至少含：
    wrapped: string          // jr4w.（或帳戶現行 passphrase 包裹前綴）＋salt
    salt: string
    wrappedRec?: string      // 有復原套件時
  }
}
```

- **持久化**：server 端＝新 migration（§4.2，`users` 表 ring 欄，**server 只存 opaque blob**＝client 序列化的 ring JSON 的 base64，零知識不解析）；client 端＝per-account localStorage（`tacet_keyring:<acc>` 母型，per-device 鏡像，過線 face 以 server blob 為準——新裝置登入拉 server ring 重建本地鏡像，與 held-key 載入同動線）。
- **ring 上限**：恆 ≤2 entries（active＋至多 1 個待退場）。`addEntry` 超限＝`ERR_RING_FULL`（先退場舊鑰再加新鑰；輪替是串行動作，並行輪替禁）。
- **retire（退場）**：§5.4 收斂後，`retireKey(legacy)`＝從 ring 移除 legacy entry＋**同步**寫 server ring 欄（舊包裹欄清除＝§4.2 二階段）。退場後 `jr1b.` 密文＝`null`（不可能存在＝收斂已驗；若存在＝bug 面，誠實面：該篇對主人不可解＝資料損失告警面，UI 明示）。

## 4. 批次重寫 API

### 4.1 防覆寫面（server）

**現行 `/notes/batch` 已具備所需 CAS 面**（tacet backend notes.ts：`version<?` 位序守衛＋`ERR_VERSION_CONFLICT` 回帶現值 version/seq），core 層不需新 server 原語。輪替寫入的契約＝**复用 doPush 同形**：

- 每篇輪替寫＝`{ note_id, version: <pull 時現值> + 1, ciphertext: jr2b.<kid>.<b64>, deleted: 0 }`。
- **衝突面**：另一裝置在 pull 與寫之間改了該篇＝`ERR_VERSION_CONFLICT`＋回帶現值。client 處理＝**該篇重拉→以新現值 version+1 重加密→重推**（輪替是 idempotent 重加密：同明文同 AAD，只換鑰；重拉到的新明文直接以新鑰加密＝語義正確）。
- **低版本重放**＝no-op（現行守衛天然覆蓋：輪替殘留批次重放被 `version<?` 吃掉）。
- **附件**同構（附件列同款 version 欄，`/notes/batch` 同形推送或附件端點同 CAS——依 tacet 附件端點現形，階段 2 對齊）。

### 4.2 包裹面（server）：兩階段 ring 收口

動機：ring blob 與逐篇重寫之間存在時間窗。若 ring 先更新而篇未輪完，**新裝置**登入（拉到新 ring）遇到殘留 `jr1b.` 篇→ring 已無 legacy→不可解。故：

- **階段 A（rotate_start）**：client 產生新 kid＋新鑰＋全套新包裹面→POST 新動線（tacet：`/auth/rotate` 或 rekey wire 擴欄——階段 2 裁定端點形；core 不承載 server 路由，此為 tacet 面）。server 行為＝**ring 欄寫入 {legacy, newkid}**（legacy 保留）＋`wrapped_key`/`salt` 等現行包裹欄**指向新鑰面**（新裝置登入即拿新鑰包裹；舊裝置 ring 未同步前仍用舊鑰，互不干擾）。
  - **冪等**：同 kid 重發＝同值覆寫；不同 kid 且 ring 已有待退場鑰＝拒（`ERR_ROTATION_IN_PROGRESS`）。
- **階段 B（rotate_finish）**：§5.4 收斂驗證通過後，client POST finish→server 行為＝ring 欄＝{newkid}（legacy 退場）＋**清除舊包裹欄殘值**（legacy 的 `wrapped_key` 舊值覆寫為新值，不留第二份可解舊鑰的線上面；`wrapped_rec` 同形覆寫＝同一 recToken 新包）。
  - **finish 的 server 端校驗（零知識前提下可做的最小面）**：ring 欄 current=={legacy,newkid}＋kid 匹配；**server 不驗篇數**（零知識＋無密文解析能力）＝收斂驗證是 **client 職責**（§5.4），finish 只收 client 的收斂聲明。誠實面：惡意 client 可早 finish＝自己把 legacy 鑰退場＝自傷面（非攻擊面），server 不設防。
- **舊裝置相容窗**：階段 A 後、B 前，舊版 App（不識 ring）登入＝拿到新鑰包裹＋新 ring 欄不讀→用新鑰寫入？否：舊 App 的 held 載入走現行 `wrapped` 欄（已指新鑰）＝舊 App 也拿新鑰＝**舊 App 在過渡期寫 `jr1b.`（它不識 jr2b.）＝殘留 jr1b. 由新鑰加密＝收斂掃描（§5.4）認得出（新鑰解得）＝不阻塞收斂**（收斂判據＝「ring active 鑰解得所有篇」，非「前綴全 jr2b.」——§5.4 判據以此為準）。
  - **反向**（新裝置過渡期寫 `jr2b.<newkid>.`、舊裝置讀）：舊 App 不識 kid 族→該篇對舊 App 不可解。**裁定點 R1**：過渡期禁混用裝置（UI 明示「輪替完成前請用最新 App」）vs 強行相容（不可行：舊 App 不識新前綴是版本本質）。本文建議＝**UI 明示＋收斂完成前舊裝置該篇顯示「不可用（輪替中）」**，輪替完成後舊裝置仍不識 kid 族＝**強制升級面**（與現行「舊版 App 單欄登入 7 天帽」同構的升級引導，階段 2 定時點）。

### 4.3 client 批次母型

複用 doPush 形（BATCH=25）：

```
rotateNotes(ring, oldKey, newKey, lister, pusher):
  for chunk in chunks(pendingOldNotes(), 25):
    items = chunk.map(n => {
      plain = decryptNote(oldKey, n.ciphertext, aadForNote(n.note_id))   // null＝該篇已非舊鑰（被別處輪過或他裝置已改）→skip 重拉
      if plain == null: return { skip: n }
      cipher = encryptNote2(newKey, plain, aadForNote(n.note_id), kid)   // jr2b.<kid>.
      return { note_id: n.note_id, version: n.version + 1, ciphertext: cipher }
    })
    results = pusher(items)   // /notes/batch 同形
    results.filter(conflict).forEach(n => requeue(n, freshFromPull()))
  advanceCursor(...)
```

- **附件同構**（`decryptAttach`→`encryptAttach2`，AAD `jr1a:<noteId>:<attachId>` 零動）。
- **本機 IDB 同構**（`decryptLocal`→`encryptLocal2`，本地寫、不推 server；IDB 無 version＝純重寫）。
- **零明文過線**：重加密只在 client 記憶體；server 只收新密文（與現行推送零差異）。

## 5. 斷點續跑與進度面

### 5.1 進度狀態（client 端持久化）

```
RotationProgress = {
  kid: string              // 本輪 kid
  stage: 'rotating' | 'converging'
  cursor: {                // 照 tacet sync cursor 母型（per-account LS key 帶 acc）
    nextSeq: number        // 下一篇的 change_seq 起點
    total: number          // 開輪時全量清單長（開輪時點快照）
    done: number
  }
  conflicts: number        // 累計衝突重試篇數（進度 UI 透明面）
}
```

- 存 `tacet_rotation:<acc>`（LS）；**server 不存進度**（零知識；ring 欄只有兩態）。
- 中斷恢復＝讀 progress→`lister(cursor.nextSeq)` 續拉（`/notes?cursor=` 現行 face）→從 nextSeq 續跑。progress 遺失（清 LS）＝重開全量掃描（§5.4 掃描本身 idempotent）＝**可重入**。

### 5.2 斷點安全矩陣

| 中斷點 | 恢復後狀態 | 語義 |
|---|---|---|
| 階段 A 前（未 start） | 零痕跡 | 現行世界 |
| 階段 A 後、首批前 | ring={legacy,new}＋全篇 jr1b.（雙鑰皆解） | 兩鑰並存＝**全篇兩鑰皆解**（legacy 還在）＝零損失 |
| 批次中（部分 jr2b.） | 混合前綴；jr2b. 只新鑰解、jr1b. 雙鑰解 | ring 在場＝**全篇可解**（路由 §3.2）＝零損失 |
| 收斂掃描中 | 同上 | 同上 |
| finish 後 | ring={new}；jr1b. 應不存 | 若殘 jr1b.＝該篇對主人不可解（收斂漏判 bug 面，§5.4 雙重掃描防） |

**不變量**：finish 之前，ring 恆含 legacy→**任意中斷點，主人（任一裝置，ring 同步後）可解全篇**。唯一損失點＝finish 漏判，由 §5.4 防。

### 5.3 並行裝置

- 輪替期間另一裝置寫某篇＝該篇 CAS 衝突→重拉重加密（§4.1）＝**語義正確**（該篇最終是新鑰＋新明文）。
- 兩裝置**同時開輪**：後到者階段 A 被 `ERR_ROTATION_IN_PROGRESS` 拒（server ring 已有待退場鑰）→UI 提示「另裝置輪替中，等待或重同步」。
- **舊裝置在過渡期寫 jr1b.（新鑰加密）**：收斂掃描以「active 鑰解得」判據（§4.2）→不阻塞。

### 5.4 收斂驗證（finish 前置）

雙重全量掃描（防增量面漏「server 列失蹤」類缺口，sync cursor 同族教訓）：

1. **前綴面**：全量 pull，計 `ciphertext LIKE 'jr1b.%'`（附件 `jr1c.%`、IDB 本地掃 `jr1d.%`）篇數。
2. **可解面**：對每篇以 **active 鑰**試解（jr1b. 篇＝active 鑰或 legacy 鑰任一解得即過——新裝置寫的 jr1b.-newKey 篇由 active 解；jr2b. 篇＝active 解）。任一解不開＝**不收斂**，回 rotating 重跑該篇（解不開＝該篇被舊鑰加密且 active 解不開＝它仍是 legacy 鑰篇→重加密）。
3. 兩面皆過→`stage='converging'` 完成→POST finish。
4. **掃描成本**：N 篇×≤2 次 GCM 試解＝與一次全量同步同級（GCM 解密是本機操作，非 KDF）；不觸 Argon。

## 6. 分享面與止血界線

### 6.1 輪替對分享的效應

- **J1 舊分享**（包裹的是**舊主鑰**）：輪替後舊主鑰退場→舊分享金鑰對「輪替後新寫」全無效（新寫＝`jr2b.<newkid>.`，舊鑰解不開）。**但**對「輪替前已存在的篇的密文副本」：若分享者**持有那些篇的密文**（他拉過那篇）＝舊鑰仍解得那些**舊密文**＝**前止非回收**（§6.3）。
- **新分享**（J1 修復後：一次性 shareKey）：與 noteKey 無關→輪替**不影響**新分享（shareKey 解的是該篇快照密文；輪替重加密該篇後，**舊分享快照密文變 stale**＝分享者看到的仍是舊快照（他手上有密文副本）＝快照語義不變，但**不再隨該篇更新**（本來就不隨動）＝語義零變。
  - **裁定點 R2**：輪替是否**主動撤銷該篇的既有分享**（server 端 shares 列刪除）？建議＝**是**（輪替＝該篇密文全面換代，舊分享快照基於舊密文，保留＝「輪替都做了還留個後門」的誠實缺口）；撤銷＝shares 列 DELETE（現行撤銷動線同形），通知面＝分享者開啟見 410（現行 410 形）。
- **分享包裹面重包**：新分享建檔用現行 `createShareEnvelope`（shareKey 一次性）→與輪替正交，零動。

### 6.2 止血動線（J1 既有分享的完整止血序）

1. 撤銷全部既有分享（現行動線）；
2. 執行輪替（本設計）；
3. 完成後：舊分享金鑰＝死鑰（對新寫）＋僅對「分享者已持有的舊密文副本」有效（誠實界線 §6.3）；
4. 重新建立需要的分享（新動線，一次性 shareKey）。

### 6.3 誠實界線（寫進 threat-model 的句）

> 主鑰輪替是**前止**：輪替之後新寫的日記，舊分享金鑰解不開。但輪替**收不回**「分享者手上已有的舊密文副本」——那是他合法取得過的資料。輪替＋撤銷合起來的保證＝「舊分享金鑰從輪替完成時起對帳戶失效」，不等於「分享者已讀的內容消失」。

## 7. J3 併案：jr2p. pinlock＋PIN 政策＋WebAuthn PRF

### 7.1 jr2p.（Argon2id pinlock）設計

- **前綴**：`jr2p.`（`PinLockConfig.pinLock2` 注入；未配置＝API 拒絕，jr1p. 面零變——cfg 選配律）。
- **payload**（與 jr1p. 同構，鹽內嵌族）：`jr2p. + b64( pinSalt[16] ‖ iv[12] ‖ GCM(KEK, hex(noteKey), aad=<cfg.pinLockAad>) )`，嚴格 108B。**AAD 零動**（沿用 cfg.pinLockAad＝同 AAD 串——新前綴新 KDF 同 AAD，前綴已負版本空間，AAD 不需再帶 kid；與 jr2w.→jr3d. 同先例）。
- **KEK**：`Argon2id(pinNorm, pinLockSaltPrefix + hex(pinSalt), m, t, p=1) → AES-256`（nonextractable；normalizePin 入口；Argon2 載體同 argon2.ts 雙載體——hash-wasm 瀏覽器/node:crypto，禁 fallback 鐵律）。
- **雙檔位參數**（裁定點 R3；動機＝解鎖延遲實測 120-240ms 平、記憶體困難跨裝置穩定）：
  - **fast 檔**（預設，行動裝置優先）：m=256MiB（262144 KiB）、t=1、p=1。hash-wasm 64MiB 實測 ~180ms（argon2.ts 檔頭），256MiB 外推 ~500-700ms（行動）/~150-250ms（桌面）——**需階段 2 前實測校準**（實測計畫：桌面 Chrome＋iOS Safari＋Android Chrome 三點，KAT 凍結前取真值）。
  - **heavy 檔**（可選，tacet 若實測 fast 檔延遲可接受而强度不足時升級）：m=1GiB、t=1。
  - **參數凍結律**：檔位參數定案後凍結進 KAT 向量（docs/vectors 新段，母型＝ARGON_RFC9106_PARAMS＋正式參數向量 J14 先例）；改參數＝換新前綴（jr3p.），帶內版本化。
  - **強度帳（fast 檔，對 6 位數字 PIN 離線爆破）**：Argon2id 256MiB 單張 RTX 4090 實測/估計 ≈ 每秒 200-1000 猜（記憶體頻寬受限；PoC 底：64MiB≈500-2000 猜/s，256MiB 按頻寬折算降 3-5 倍）→6 位（10⁶ 空間）≈ **17-83 分鐘**（對比 jr1p. 的 68 秒＝**×150-700**）；8 位數字≈4-21 小時；**但人選 PIN（生日/連號）仍遠快於此**→PIN 政策（§7.2）是主防線，KDF 升檔是成本乘數。
- **讀舊寫新**：`unwrapNoteKeyPinLock2` 先試 `jr2p.`、回落 `jr1p.`（過渡保護承諾：舊 blob 恆可解；摘回落時點＝遷移率裁定，非日曆——argon2 家族同律）。**重包觸發**：每次成功解鎖（jr1p. 命中）→以同一 PIN 重包 jr2p. 回寫（lock-store `enableLock` 的 rewrap 語意內建位＝現成接線點）。**jr1p. 讀契約保留**（否決案：禁直接禁解存量——帶劇版本化母型：解舊寫新）。

### 7.2 PIN 政策面

- **現行**（tacet `checkPinStrength`）：6-12 位、可含字母、排 top20/全同/三連號。**6 位純數字≈單 GPU 68 秒**（PoC C 實證：4 位 16 核 28.7s 命中；RTX 4090 外推 68 秒）＝**門檻不是牆**——文件面已校正（core README 界限段、tacet 註解，本卡落）。
- **建議政策**（裁定點 R4）：
  - **新設/改 PIN**：≥8 碼**且含字母**（`[a-z]` ≥1）；或純數字 ≥10 位（10 位=10¹⁰，jr2p. fast 檔下 GPU 單卡≈28 天-2 個月，多卡併行縮短——數字-only 只允許更長不允許更短）。UI 面＝設 PIN 對話列強度提示（現行三腿結構同形）。
  - **理由**：PIN 是裝置上主鑰**唯一靜態保護**（lock-store 鐵律：bound 帳戶鎖定恆在、raw key 恆不落地）→PIN 強度＝裝置被拔走時的全部防線。
- **存量 PIN 殘面**（裁定點 R5）：政策改變**不自動救存量**（存量 6 位數字 PIN 照用——強改＝用戶解鎖失敗風險＋無 PIN 就進不去重設面＝死鎖）。建議動線＝**非強制引導**：每次解鎖後輕提示「加強 PIN」；**輪替動線是天然強點**——rotate_start 前可選「順手換 PIN」一步（新 PIN 包新鑰，一步完成兩件強化；不換也放行）。**強制 rewrap 不建議**（無逃生梯的強制變更＝死鎖面，pin-lock 設計 Q1 先例：逃生路必須在）。

### 7.3 WebAuthn PRF 深案（併案收 t_59239934 停車卡）

> t_59239934＝PRF 支援面真機探針卡（scheduled 停車，未執行）。本節收它的**設計面**；真機實測仍是實作前置（探針卡恢復觸發＝實作卡開卡前）。

- **定位**：把本機鎖綁到**不可匯出的裝置秘密**（J3 根本面）——無硬體則無法離線爆破（PIN 仍落 LS，但 KEK 需要 PRF 輸出＝攻擊者拿到 LS＋IDB 也組不出 KEK）。
- **KEK 深案**（報告建議形，本設計採納為建議案）：`KEK = HKDF-SHA256( ikm = prfOutput[32] ‖ Argon2id(pinNorm, pinSalt)[32], salt = pinSalt, info = 'journal-pinlock-prf-v1:' + <prefix> )`
  - `prfOutput`＝WebAuthn PRF extension 的 `prfResults.first`（assertion 時 `extensions: { prf: { eval: true } }`；create 時 `prf: { }`）。
  - **PIN 不從 PRF 路徑省略**：PRF 是裝置綁定因子，PIN 是知識因子——兩因子合成（同 jr4d. 合鑰母型），**禁**「PRF 替代 PIN」（報告/J6 否決面：授權釋放 PIN 快取＝raw key 落地鐵律違例）。
  - **fallback 鐵律**：PRF 不可用（`prfResults` 缺席/裝置不支援）＝**回落純 PIN 形（jr2p.）**，絕非「PRF-only 無 PIN」；PRF 面是**加速/加固層非取代層**。
  - **前綴**：`jr2q.`（PRF 形；與 jr2p. 並列，同 PinLockConfig 新欄 `pinLockPrf` 選配）。
  - **lost authenticator 回落**：PIN/復原套件（既有契約）——passkey 丟失不鎖死帳戶（PIN 形包裹仍在 ring）。
  - **零知識相容**：PRF assertion 只在 client↔platform authenticator 之間；server 零參與（探針卡否決案「伺服器端 credential 註冊」照守）。
  - **前置**：t_59239934 真機探針（iOS Safari/iOS PWA/macOS Chrome/Android Chrome 四格 PRF 支援矩陣）結果回收後才定實作排程——**本設計不預設支援面**。

## 8. J8 收尾面現值（S2-S6 後）

| J8 子項 | 現值（2026-10-23 一手） |
|---|---|
| core `buildBindPayload4`（jr4w.） | **已收口**（S6 CP1，core 0.4.2 上 registry；dist 消費面在場） |
| tacet 匯出寫入端切 jr4w. | **已收口**（S6 CP2，`transfer.ts` v3 匯出；`wrapped_rec`/`rec_hash` 欄自匯出檔**摘除**＝dead rec 欄退場） |
| `verify.html` Argon 腿 | **已收口**（v1 jr1w.／v3 jr3w.／v4 jr4w. 三前綴分流，hash-wasm 載體） |
| 匯入端 jr4w. 支援 | 既有（S6 前已支援，白名單 v1\|v2\|v3） |
| 「備份格式自第一版 jr1w.」文案 | verify.html 已補 v3 世代口徑（399 行） |

**J8 全收口，無殘留**（legacy jr1w./jr3w. 檔照解＝過渡保護，非待辦）。

## 9. 裁定點總表（階段 1 交付用戶裁定）

| # | 裁定點 | 本文建議 | 裁量空間 |
|---|---|---|---|
| R1 | 過渡期混用裝置策略 | UI 明示「輪替完成前用最新 App」＋舊裝置該篇顯示「輪替中不可用」＋收斂後舊裝置強制升級引導 | 可裁「直接禁混用」（更嚴）或「收斂前不強制升級」（更寬） |
| R2 | 輪替是否主動撤銷該篇既有分享 | **是**（輪替＝密文全面換代，舊分享快照 stale；撤銷＝shares DELETE＋410） | 可裁「否，只前止」（保留舊快照分享至自然到期） |
| R3 | jr2p. 雙檔位參數定值 | fast＝256MiB/t1/p1（預設）；heavy＝1GiB 備選；**階段 2 前三點實測校準 120-240ms 平** | 參數可調；凍結進 KAT 後改＝換前綴 |
| R4 | PIN 政策新設/改動門檻 | ≥8 碼含字母，或純數字 ≥10 位 | 可裁更嚴（如含字母強制）/更寬 |
| R5 | 存量 PIN 殘面處理 | 非強制引導＋輪替動線可選「順手換 PIN」強點；**禁強制 rewrap** | 可裁「輪替時強制換 PIN」（需逃生梯設計） |
| R6 | ring server 欄形（migration） | 新欄 `users.keyring`（opaque blob）＋階段 A/B 兩階段語句 | 欄名/端點形（/auth/rotate vs rekey 擴欄）階段 2 定 |
| R7 | WebAuthn PRF 排程 | 本設計併案收；實作待 t_59239934 真機探針回收後另排 | 可裁「PRF 移出本鏈」 |
| R8 | finish 的收斂聲明信任面 | server 不驗篇數（零知識）；client 雙重掃描自證 | 可裁「server 加前綴 COUNT 驗」（D1 端 `SELECT COUNT WHERE ciphertext LIKE 'jr1b.%'`＝零知識可做，防 client 早 finish 自傷——**成本 1 條 COUNT，建議加**） |

## 10. J9：jr1l. deprecated 導向（README 側落）

- `jr1l.`（本機 session 包裹）＝KEK 由 identity 派生（passphrase-free）＝**混淆級**（J9 PoC E：讀得到 localStorage 就能還原主鑰）。
- **tacet 現況**：未配置 `wrapLocal`（無實際暴露面）；但 `loadLocalWrap` 仍讀借用期 jr1w. 形殘留。
- **導向**：README 界限段標 `jr1l.`＝混淆級＋deprecated＋`wrapLocal` 選配註記（**階段 1 本卡已落**）；`storeLocalWrap` JSDoc 補 `@deprecated`＝**階段 2 core 半**（src/ 註解面）；**讀面照走**（舊 blob 可解承諾不破），**寫面**＝新整合不配置 wrapLocal（退場自然完成）。

## 11. 階段 2 實作卡面（依裁定開卡，本文件不實作）

- **core 半**：`generateKeyId`／`KeyRing` 原語族／`encryptNote2`/`decryptNote` 路由擴（jr2b./jr2c./jr2d. 族）／`wrapNoteKeyPinLock2`（jr2p.）＋KAT 向量段／`storeLocalWrap` JSDoc 補 `@deprecated`（README 界限段＋家族表 deprecated 標＝**階段 1 已落**，不在本清單）。
- **tacet 半**：ring LS 鏡像＋server ring 欄 migration＋`/auth/rotate` 端點（階段 A/B）／doPush 輪替驅動＋進度 UI／lock-store jr2p. 接線＋PIN 政策 UI／threat-model 輪替界線句（三語）＋trust-gate 斷言。
- **部署窗**：migration 0019+（ring 欄）＋canary。

## 12. 威脅模型界線（輪替後，誠實面）

- 輪替**能**止：主鑰新外流（輪替後裝置被爆、輪替後新建分享、輪替後新匯出檔）——全部新鑰，舊金鑰副本無效。
- 輪替**不能**收：外流者**已持有**的舊密文副本（分享者已讀的篇、已下载的舊匯出檔、已截圖的復原套件）——那些資料他已合法取得，輪替不抹除。
- 輪替**不保護**：輪替期間的中斷窗——但 §5.2 不變量保證中斷窗內主人仍可解全篇（雙鑰並存），風險只在「外流者恰好在中斷窗內且持有舊密文」＝與未輪替同態（輪替不讓事情變差，只讓它變好）。
