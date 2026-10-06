# 安全政策（Security Policy）

## 適用範圍

本政策適用於本 repo 的加密核心原語（`@tacet-ink/journal-core` npm 套件與其源碼）。

tacet.ink 產品面（部署實例）的漏洞屬產品 fork 的職責範圍——請循 tacet.ink 網站公布的
安全聯絡管道回報；本 repo 只收核心原語面（加解密、包裹、auth 原語、限流）的回報。

## 回報管道

聯絡信箱：[security@tacet.ink](mailto:security@tacet.ink)
（email 標題建議前綴 `[security]`）

- 72 小時內確認收到。
- 修復時程與公開揭露安排，依個案嚴重度評估後告知你。

## 支援版本

| 版本 | 支援狀態 |
| --- | --- |
| 0.2.x | 支援中 |
| 0.1.x | 盡力而為 |

## 誠實界線

- 本 repo 未經第三方正式稽核。
- 密語遺失設計上無救援（伺服器零知識的代價：伺服器存不了你不知道的鑰匙）；
  隨套件附帶的復原套件（24 詞轉寫層）是唯一的復原途徑，請離線妥善保存。
- guest 時代（未綁定帳戶）的加密是混淆級，不是端對端加密；
  綁定時代（隨機 noteKey）起即為可對外公開宣稱的端對端加密。

## 我們不承諾的東西

- 沒有賞金（bounty）計畫。
- 沒有 PGP key，因此不提供 PGP 加密回報管道——請透過上述信箱回報。

## English Summary

This policy covers the cryptographic core primitives of this repository
(`@tacet-ink/journal-core`); vulnerabilities in the tacet.ink product instance belong to the
product fork — report via the security contact published on tacet.ink. Reports go to
[security@tacet.ink](mailto:security@tacet.ink) with a subject prefixed `[security]`;
we acknowledge within 72 hours and agree on fix timelines case-by-case. Supported: 0.2.x
(0.1.x best-effort). Honest limits: no third-party audit yet; a lost passphrase is
unrecoverable by design — the offline recovery package (24-word transcription layer) is the
only recovery path, keep it safe; guest-era encryption is obfuscation-grade, not E2E;
end-to-end encryption holds from the bound era (random noteKey). No bug-bounty program and no PGP
reporting channel — please use the email above.