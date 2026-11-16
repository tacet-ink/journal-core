#!/usr/bin/env node
/**
 * server.ts — tacet-secret MCP stdio 入口（唯一 transport；零遠端 MCP 裁定——
 * 遠端＝加密只能在 server 端做→破零知識＋身分綁定衝突，10-28 報告 §二）。
 *
 * stdio 紀律（spec 2026-07-28 transports/stdio）：
 *   - newline-delimited JSON（每行一訊息）
 *   - server MUST NOT 寫 request 到 stdout（server→client 互動面＝InputRequiredResult 結果）
 *   - stderr 只作 log/diagnostic
 *   - stdin EOF → 過程退出（MUST NOT 保持運行）
 * 行序：串列排隊（單 in-flight；JSON-RPC 按 id 相關聯，串列化＝確定性＋零交織）。
 */
import { McpSession } from './session.ts';

function main(): void {
  const session = new McpSession({
    onLog: (l) => process.stderr.write(`[tacet-secret-mcp] ${l}\n`),
  });
  let buf = '';
  let chain: Promise<void> = Promise.resolve();
  const processLine = (line: string): void => {
    chain = chain
      .then(() => session.handleLine(line))
      .then((out) => {
        if (out !== null) process.stdout.write(out + '\n');
      })
      .catch((e: unknown) => {
        process.stderr.write(
          `[tacet-secret-mcp] internal error: ${e instanceof Error ? e.message : String(e)}\n`,
        );
      });
  };
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk: string) => {
    buf += chunk;
    let i: number;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      processLine(line);
    }
  });
  process.stdin.on('end', () => {
    // 排隊消化完再退（不丟在途 response）
    chain
      .then(() => process.exit(0))
      .catch(() => process.exit(0));
  });
  process.stdin.resume();
}

main();
