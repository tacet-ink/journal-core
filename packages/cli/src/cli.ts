#!/usr/bin/env node
/**
 * cli.ts — `tacet-secret` 入口（R3b t_8b19f126）。
 *
 * 子命令：
 *   request  — 主路徑：開 slot＋N3 先驗證＋把填寫連結交給人（取件連結只落檔）
 *   verify   — 人可自跑：/secret＋/sreq 對公開 repo SHA256SUMS（四方帳）
 *   submit   — 預設關：人在 TTY 確認才投遞（非 TTY 零 API）
 *   --self-test — core 0.11.0 向量自檢（可選）
 *
 * exit code：0 ok；1 執行失敗（N3 不符／API 錯／verify MISMATCH）；2 用法錯；
 *            3 submit 非 TTY 拒；4 參照／白名單拒；5 確認中止。
 *
 * 值紀律：命令行只進參照（env:NAME／file:PATH）與公開連結；stdout 永不含 token
 * 原值／私鑰 JWK／明文內容——輸出面只「已寫入 <path>」。
 */

import { DEFAULT_BASE_URL, DEFAULT_SUMS_URL } from './n3.ts';
import { TTL_CHOICES, runRequest, type TtlChoice } from './request.ts';
import { runSelfTest } from './selftest.ts';
import { runSubmit } from './submit.ts';
import { runVerify } from './verify.ts';

export const EXIT_OK = 0;
export const EXIT_RUNTIME = 1;
export const EXIT_USAGE = 2;
export const EXIT_NON_TTY = 3;
export const EXIT_REF = 4;
export const EXIT_ABORT = 5;

const USAGE = `tacet-secret — tacet.ink 索取祕密本機 CLI（加密全部來自 journal-core；值永不回模型上下文）

用法:
  tacet-secret request [--ttl 10m|1h|3d|7d|14d] [--annual] [--annual-token env:NAME|file:PATH]
                       [--out file:PATH|PATH] [--base URL] [--sums URL|PATH] [--json]
      主路徑：N3 先驗證 /sreq（對 SHA256SUMS），再建 slot；stdout 給填寫連結（公鑰面），
      取件連結（私鑰＋token）只寫入白名單路徑（600）。N3 不符＝停、告知、不給連結。

  tacet-secret verify [--base URL] [--sums URL|PATH] [--json]
      同時驗 /secret 與 /sreq，印四方帳（live sha／sums sha／判定）。

  tacet-secret submit <fill-link> <env:NAME|file:PATH>
                       [--base URL] [--confirm-input <slot_id>] [--allow-non-tty]
      預設關：非 TTY 直接拒（exit 3，零 API）；TTY 需輸入 slot 編號確認。

  tacet-secret --self-test
      core 0.11.0 向量自檢（jr5e/jr5s KAT＋負向量；走真模組，零鏡像）。

預設：--base https://tacet.ink；--sums＝公開 repo main/SHA256SUMS（raw.githubusercontent）。
exit code：0 ok｜1 執行失敗｜2 用法錯｜3 非 TTY 拒｜4 參照/白名單拒｜5 確認中止。`;

interface ParsedOpts {
  base?: string;
  sums?: string;
  ttl?: string;
  annual?: boolean;
  annualToken?: string;
  out?: string;
  json?: boolean;
  confirmInput?: string;
  allowNonTty?: boolean;
  positional: string[];
}

/** 極小參數解析（零依賴）；未知旗標／缺值＝null（呼叫端 usage 錯）。
 *  注意：for-loop 的 i++ 會再進一步，故取值分支必設 i = t[1] - 1（下一枚＝值之後的旗標；
 *  審查 r1 M-2 補實測：舊形 i = t[1] 會吃掉下一枚——`--base X --help` 的 --help 被吞、
 *  `--base X --ttl 9x` 的 9x 被當位置參數＝strict parse 破洞）。 */
export function parseArgs(args: string[]): ParsedOpts | null {
  const o: ParsedOpts = { positional: [] };
  const take = (i: number, flag: string): [string, number] | null => {
    if (i + 1 >= args.length) return null;
    return [args[i + 1], i + 2];
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--base') {
      const t = take(i, a);
      if (!t) return null;
      o.base = t[0];
      i = t[1] - 1;
    } else if (a === '--sums') {
      const t = take(i, a);
      if (!t) return null;
      o.sums = t[0];
      i = t[1] - 1;
    } else if (a === '--ttl') {
      const t = take(i, a);
      if (!t) return null;
      o.ttl = t[0];
      i = t[1] - 1;
    } else if (a === '--annual-token') {
      const t = take(i, a);
      if (!t) return null;
      o.annualToken = t[0];
      i = t[1] - 1;
    } else if (a === '--out') {
      const t = take(i, a);
      if (!t) return null;
      o.out = t[0];
      i = t[1] - 1;
    } else if (a === '--confirm-input') {
      const t = take(i, a);
      if (!t) return null;
      o.confirmInput = t[0];
      i = t[1] - 1;
    } else if (a === '--annual') {
      o.annual = true;
    } else if (a === '--json') {
      o.json = true;
    } else if (a === '--allow-non-tty') {
      o.allowNonTty = true;
    } else if (a === '--help' || a === '-h') {
      o.positional.push('--help');
    } else if (a.startsWith('--')) {
      return null; // 未知旗標
    } else {
      o.positional.push(a);
    }
  }
  return o;
}

function checkBase(base: string | undefined): string {
  const b = base ?? DEFAULT_BASE_URL;
  try {
    const u = new URL(b);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('proto');
    return b;
  } catch {
    process.stderr.write(`--base 形錯：${b}\n`);
    process.exit(EXIT_USAGE);
  }
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === '--help') {
    process.stdout.write(USAGE + '\n');
    return args.length === 0 ? EXIT_USAGE : EXIT_OK;
  }
  if (args[0] === '--self-test') {
    const r = await runSelfTest();
    if (r.ok) {
      process.stdout.write(`SELF-TEST-OK（${r.assertions} 斷言；jr5e/jr5s KAT＋負向量全過）\n`);
      return EXIT_OK;
    }
    for (const f of r.failures) process.stderr.write(`  ✗ ${f}\n`);
    process.stderr.write(`SELF-TEST-FAIL（${r.failures.length}/${r.assertions} 失敗）\n`);
    return EXIT_RUNTIME;
  }
  const o = parseArgs(args.slice(1));
  if (!o) {
    process.stderr.write('參數錯（未知旗標或缺值）——tacet-secret --help\n');
    return EXIT_USAGE;
  }
  // --help/-h 在一切網路之前攔截（任何子命令）——零網路、零 slot、零副作用
  if (o.positional.includes('--help')) {
    process.stdout.write(USAGE + '\n');
    return EXIT_OK;
  }
  // strict parse：request/verify 不收位置參數（submit 的兩位置參數在其分支內驗）——零網路前拒
  if ((args[0] === 'request' || args[0] === 'verify') && o.positional.length !== 0) {
    process.stderr.write(`${args[0]} 不收位置參數（tacet-secret --help）\n`);
    return EXIT_USAGE;
  }
  const base = checkBase(o.base);
  const sums = o.sums ?? DEFAULT_SUMS_URL;

  if (args[0] === 'request') {
    const ttl = (o.ttl ?? '7d') as TtlChoice;
    if (!(TTL_CHOICES as readonly string[]).includes(ttl)) {
      process.stderr.write(`--ttl 需 ${TTL_CHOICES.join('/')}（實得 ${ttl}）\n`);
      return EXIT_USAGE;
    }
    if (o.ttl === '14d' && !o.annual) {
      process.stderr.write('--ttl 14d 需 --annual（免費層效期 10m/1h/3d/7d）\n');
      return EXIT_USAGE;
    }
    const r = await runRequest({
      base,
      sums,
      ttl,
      tier: o.annual ? 'annual' : 'free',
      annualTokenRef: o.annualToken ?? null,
      out: o.out ?? null,
      json: !!o.json,
    });
    for (const line of r.lines) process.stdout.write(line + '\n');
    if (r.exit === 0 && o.json && r.jsonOut) process.stdout.write(JSON.stringify(r.jsonOut, null, 2) + '\n');
    return r.exit;
  }

  if (args[0] === 'verify') {
    const r = await runVerify({ base, sums, json: !!o.json });
    for (const line of r.lines) process.stdout.write(line + '\n');
    if (o.json && r.jsonOut) process.stdout.write(JSON.stringify(r.jsonOut, null, 2) + '\n');
    return r.exit;
  }

  if (args[0] === 'submit') {
    if (o.positional.length !== 2) {
      process.stderr.write('submit 需 <fill-link> <env:NAME|file:PATH> 兩參數\n');
      return EXIT_USAGE;
    }
    const r = await runSubmit({
      base,
      fillLink: o.positional[0],
      sourceRef: o.positional[1],
      confirmInput: o.confirmInput ?? null,
      allowNonTty: !!o.allowNonTty,
    });
    for (const line of r.stderr ?? []) process.stderr.write(line + '\n');
    for (const line of r.lines) process.stdout.write(line + '\n');
    return r.exit;
  }

  process.stderr.write(`未知子命令：${args[0]}（tacet-secret --help）\n`);
  return EXIT_USAGE;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e) => {
    process.stderr.write(`未預期錯誤：${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
    process.exitCode = EXIT_RUNTIME;
  });
