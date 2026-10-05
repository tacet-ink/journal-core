# 更新日誌（Changelog）

本專案版本的歷史摘要。格式仿 [Keep a Changelog](https://keepachangelog.com/)、
語言從專案慣例（zh）；日期取各版 git tag 指向 commit 的實際日期。

## [0.2.0] — 2026-10-05

wrappedRec 專用前綴 jr1r.＋recToken HKDF 世代（與 recKekHkdf 兩欄一體——部分配置拒寫，
新面先行舊面回落雙試）；本機包裹專用前綴 jr1l.（wrapLocal opt-in，讀舊寫新自癒）；
密語正規化 v3 世代（normalizePassphrase NFKC-only＋jr4w./jr4d. 前綴家族＋PH1 v3 鹽域）；
ladder 表原語（ph2_ladder＋AuthStore v3 re-key 介面＋0011 遷移樣本）。

## [0.1.6] — 2026-10-04

外審轉化批載具：hex fail-closed（ERR_BAD_HEX）＋空 identity 拒絕＋ERR_PIN_EMPTY；
限流改 UPSERT…RETURNING 單句（四次往返寫入鏈收口）；engines 下限 >=24.7.0＋
CI 加固（typecheck＋actions SHA 釘選）；PBKDF2 並行＋b64 分塊效能批；
N-7 空字首組裝守衛。

## [0.1.5] — 2026-09-20

guest 前綴空字串畸形正規化（加密面同拒、解密面整面收斂）＋README 措辭收斂。

## [0.1.4] — 2026-09-19

本機 IDB stored 密文前綴 jr1d.（cipherLocal opt-in）＋cipherGuest 轉選配＋
bip39 閘固定種子（樣本可重放）。

## [0.1.3] — 2026-09-12

README 徽章（npm／MIT／node／verify）＋CI verify／publish workflows。

## [0.1.2] — 2026-09-11

npm metadata 補齊（homepage／repository／bugs——npm 頁側欄 repo 連結）。

## [0.1.1] — 2026-09-11

消費者摩擦修正——README 誠實標註 strip-types 禁用面（node_modules 內禁 strip-types）、
摘零價值 postinstall。

## [0.1.0] — 2026-09-07

初版：brand-parameterized e2e crypto＋zero-knowledge auth core——
兩時代金鑰模型、帶內版本化前綴契約、pinlock／雙因子合鑰／分享包裹原語、
Argon2id 與 RFC 9106 KAT、復原套件 24 詞轉寫層。

[0.2.0]: https://github.com/tacet-ink/journal-core/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/tacet-ink/journal-core/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/tacet-ink/journal-core/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/tacet-ink/journal-core/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/tacet-ink/journal-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/tacet-ink/journal-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tacet-ink/journal-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tacet-ink/journal-core/releases/tag/v0.1.0