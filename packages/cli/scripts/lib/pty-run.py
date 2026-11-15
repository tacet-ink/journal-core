#!/usr/bin/env python3
"""pty-run.py — 在真 PTY 下跑子程序（submit 人確認閘的 e2e 載具）。

用法: pty-run.py <marker> <answers_file|-> <timeout_s> -- <cmd> [args...]
每次子程序輸出出現 <marker>：從 answers_file 讀第 <已觸發次數> 行（0-based）寫入；
answers_file＝'-'＝從不寫（純捕獲）。答列未就緒＝輪詢 2s 再試（mail-box 形——
內層 e2e 在觸發 prompt 前依序補答）。rc＝子程序 exit code；124＝timeout。
讀取紀律：EIO＝slave 側已關——收 waitpid 狀態再收尾，不丟已讀字元。
"""
import os
import pty
import select
import sys
import time


def read_answer(path: str, idx: int, wait_ms: int = 2000):
    deadline = time.time() + wait_ms / 1000.0
    while True:
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [ln.rstrip("\n") for ln in f.readlines()]
            if idx < len(lines):
                return lines[idx]
        except OSError:
            pass
        if time.time() >= deadline:
            return None
        time.sleep(0.1)


def main() -> None:
    marker = sys.argv[1].encode("utf-8")
    answers_path = sys.argv[2]
    timeout = float(sys.argv[3])
    rest = sys.argv[4:]
    if not rest or rest[0] != "--":
        sys.stderr.write("pty-run: need '--' before command\n")
        sys.exit(2)
    cmd = rest[1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out = b""
    fired = 0
    deadline = time.time() + timeout
    exited = False
    status = 0
    while True:
        if time.time() > deadline and not exited:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
            os.waitpid(pid, 0)
            sys.stderr.write("PTY-TIMEOUT\n")
            sys.stdout.write(out.decode("utf-8", "replace"))
            sys.exit(124)
        r, _, _ = select.select([fd], [], [], 0.5)
        if fd in r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = None  # EIO：slave 側已關
            if chunk is None or chunk == b"":
                if not exited:
                    try:
                        p, st = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        p, st = 0, 0
                    if p == pid:
                        exited = True
                        status = st
                if exited:
                    break
                continue
            out += chunk
            if answers_path != "-":
                # 出現次數語意：out 內 marker 總數 > 已觸發數＝有新 prompt——
                # 不可用「marker in out」（首次出現後恆真，會重覆補答吞後續 prompt）
                cnt = out.count(marker)
                while cnt > fired:
                    ans = read_answer(answers_path, fired)
                    if ans is not None:
                        os.write(fd, ans.encode("utf-8") + b"\n")
                    fired += 1
        else:
            if not exited:
                try:
                    p, st = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    p, st = 0, 0
                if p == pid:
                    exited = True
                    status = st
                    while True:
                        r2, _, _ = select.select([fd], [], [], 0.3)
                        if fd not in r2:
                            break
                        try:
                            c = os.read(fd, 65536)
                        except OSError:
                            break
                        out += c
                    break

    code = os.waitstatus_to_exitcode(status)
    sys.stdout.write(out.decode("utf-8", "replace"))
    sys.exit(code)


if __name__ == "__main__":
    main()
