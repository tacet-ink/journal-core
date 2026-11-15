/**
 * selftest.ts — `tacet-secret --self-test`（可選自檢；card 目標 6）。
 *
 * 向量來源＝core 0.11.0 的 docs/vectors/kat.json（隨 package 出貨；workspaces symlink
 * 時＝repo 內同一份）。全走真模組（import journal-core）——本檔零加密鏡像：
 *   - jr5e：KAT 封包逐位元組相等＋KAT 解包＋負向量 n1-n4 全拒＋新生成金鑰對 sanity＋
 *           隨機 eph/iv 回圈＋AAD 敏感性
 *   - jr5s：KAT 加密逐字元相等＋KAT 解密＋負向量 n1-n7 全拒＋secretIdOfKey
 * 任一斷言失敗＝SELF-TEST-FAIL（exit 1）——agent 可先跑自檢再跑主命令。
 *
 * 向量結構（kat.json 現形）：jr5e_kat／jr5s_kat 各自含 negatives（name→blob 物件）；
 * iv 皆 12B（JR5E_IV_BYTES＝JR5S_IV_BYTES＝12）；jr5s key 欄＝key_b64url（43 字元）。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  JR5E_AAD_DOMAIN,
  JR5E_IV_BYTES,
  JR5E_PREFIX,
  generateEnvelopeKeyPair,
  jwkPubRaw,
  openEnvelope,
  sealEnvelope,
  type JwkEC,
} from '@tacet-ink/journal-core/secret/jr5e';
import {
  JR5S_IV_BYTES,
  jr5sDecrypt,
  jr5sEncrypt,
  secretIdOfKey,
} from '@tacet-ink/journal-core/secret/jr5s';

export interface SelfTestOutcome {
  ok: boolean;
  assertions: number;
  failures: string[];
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** 定位 journal-core package 根（workspaces symlink／npm 安裝形皆成立）。 */
export function corePackageRoot(): string {
  const url = import.meta.resolve('@tacet-ink/journal-core/secret/jr5e');
  const p = fileURLToPath(url);
  // …/<root>/dist/secret/jr5e.js → <root>（dirname＝<root>/dist/secret，上兩層）
  return path.resolve(path.dirname(p), '..', '..');
}

export async function runSelfTest(): Promise<SelfTestOutcome> {
  const failures: string[] = [];
  let assertions = 0;
  const check = (cond: boolean, label: string): void => {
    assertions++;
    if (!cond) failures.push(label);
  };

  const root = corePackageRoot();
  const katRaw = fs.readFileSync(path.join(root, 'docs', 'vectors', 'kat.json'), 'utf8');
  const kat = JSON.parse(katRaw) as {
    jr5e_kat: {
      a_pub_jwk: JwkEC;
      a_priv_jwk: JwkEC;
      eph_priv_jwk: JwkEC;
      iv_hex: string;
      aad: string;
      plaintext: string;
      blob: string;
      negatives: Record<string, string>;
    };
    jr5s_kat: {
      key_b64url: string;
      id: string;
      iv_hex: string;
      plaintext: string;
      wire: string;
      negatives: Record<string, string>;
    };
  };

  // ---- jr5e 正向（KAT 逐位元組）----
  const { jr5e_kat: k } = kat;
  const ivBytes = hexToBytes(k.iv_hex);
  check(ivBytes.length === JR5E_IV_BYTES, `jr5e KAT iv＝${JR5E_IV_BYTES}B`);
  const sealed = await sealEnvelope(k.plaintext, k.a_pub_jwk, k.eph_priv_jwk, ivBytes, k.aad);
  check(sealed === k.blob, `jr5e KAT 封包逐位元組（got ${sealed.slice(0, 24)}…, want ${k.blob.slice(0, 24)}…）`);
  check(sealed.startsWith(JR5E_PREFIX), 'jr5e KAT blob 前綴 jr5e.');
  const opened = await openEnvelope(k.blob, k.a_priv_jwk, k.aad);
  check(opened === k.plaintext, 'jr5e KAT 解包還原明文');

  // ---- jr5e 負向量（n1-n4 必全拒）----
  const jr5eNegs = Object.entries(k.negatives);
  check(jr5eNegs.length === 4, `jr5e 負向量在場（n1-n4；實得 ${jr5eNegs.length}）`);
  for (const [name, blob] of jr5eNegs) {
    const r = await openEnvelope(blob, k.a_priv_jwk, k.aad);
    check(r === null, `jr5e 負向量 ${name} 拒（GCM AUTH）`);
  }

  // ---- jr5e 金鑰對 sanity＋隨機回圈＋AAD 敏感性 ----
  const pair = await generateEnvelopeKeyPair();
  const pubRaw = jwkPubRaw(pair.pubJwk);
  check(pubRaw?.length === 65, 'jr5e 公鑰 raw＝65B（0x04 前綴 uncompressed）');
  check(pubRaw?.[0] === 0x04, 'jr5e 公鑰 raw 前綴 0x04（uncompressed point）');
  const privPubRaw = jwkPubRaw(pair.privJwk);
  check(
    privPubRaw !== null && privPubRaw.length === 65 && Buffer.compare(Buffer.from(privPubRaw), Buffer.from(pubRaw!)) === 0,
    'jr5e 金鑰對一致（私鑰 JWK 的公鑰成分＝公鑰 JWK）',
  );
  const random = `隨機回圈-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const iv2 = crypto.getRandomValues(new Uint8Array(JR5E_IV_BYTES));
  const aad2 = JR5E_AAD_DOMAIN + 'selftest';
  const s2 = await sealEnvelope(random, pair.pubJwk, pair.privJwk, iv2, aad2);
  const o2 = await openEnvelope(s2, pair.privJwk, aad2);
  check(o2 === random, 'jr5e 隨機 eph/iv 回圈');
  const o2bad = await openEnvelope(s2, pair.privJwk, aad2 + 'x');
  check(o2bad === null, 'jr5e AAD 不同＝拒');

  // ---- jr5s KAT（逐字元）＋負向量 ----
  const { jr5s_kat: s } = kat;
  const key = new Uint8Array(Buffer.from(s.key_b64url, 'base64url')); // key_b64url 欄即 b64url 字面
  check(key.length === 32, 'jr5s KAT key＝32B');
  const sIv = hexToBytes(s.iv_hex);
  check(sIv.length === JR5S_IV_BYTES, `jr5s KAT iv＝${JR5S_IV_BYTES}B`);
  const wire = await jr5sEncrypt(s.plaintext, key, s.id, sIv);
  check(wire === s.wire, 'jr5s KAT 加密逐字元');
  const d = await jr5sDecrypt(s.wire, key, s.id);
  check(d === s.plaintext, 'jr5s KAT 解密還原明文');
  check((await secretIdOfKey(s.key_b64url)) === s.id, 'jr5s secretIdOfKey＝KAT id');
  const jr5sNegs = Object.entries(s.negatives);
  check(jr5sNegs.length === 7, `jr5s 負向量在場（n1-n7；實得 ${jr5sNegs.length}）`);
  for (const [name, blob] of jr5sNegs) {
    const r = await jr5sDecrypt(blob, key, s.id);
    check(r === null, `jr5s 負向量 ${name} 拒`);
  }

  return { ok: failures.length === 0, assertions, failures };
}
