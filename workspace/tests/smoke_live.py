"""真实进程冒烟脚本：
  启动网关 → 注册设备 → 创建并确认指令 → 设备取走不回执 →
  重启网关 → 旧代号回执被拒 → 在途 INTERRUPTED / 已执行 COMPLETED 保留 → 审计核对
用法: python tests/smoke_live.py
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DB = "/tmp/gw-live.db"
BIZ_URL, SAFE_URL, DEV_URL = ("http://127.0.0.1:18080",
                              "http://127.0.0.1:18081", "http://127.0.0.1:18082")


def call(url, method="GET", token=None, dev=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if dev:
        req.add_header("X-Device-Id", dev[0])
        req.add_header("X-Device-Token", dev[1])
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def start(wipe: bool = False):
    if wipe:
        for f in (DB, DB + "-wal", DB + "-shm", DB + ".tokens.json"):
            Path(f).unlink(missing_ok=True)
    log = open("/tmp/gw-live.log", "ab")
    proc = subprocess.Popen([sys.executable, "-u", "-m", "gateway.app",
                             "--db", DB], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(40):
        try:
            call(BIZ_URL + "/health")
            break
        except OSError:
            time.sleep(0.1)
    return proc


def tokens():
    t = json.loads(Path(DB + ".tokens.json").read_text())
    return t["business_token"], t["safety_token"]


def main():
    proc = start(wipe=True)
    ok = True
    try:
        biz, safe = tokens()
        now = time.time

        # 1) 注册
        _, d1 = call(BIZ_URL + "/devices", "POST", biz,
                     body={"name": "进料阀-A"})
        _, d2 = call(BIZ_URL + "/devices", "POST", biz,
                     body={"name": "进料阀-B"})
        A, B = (d1["device_id"], d1["token"]), (d2["device_id"], d2["token"])
        print(f"设备 A={A[0]}  B={B[0]}")

        def make(action, ids):
            t = now()
            return call(BIZ_URL + "/commands", "POST", biz, body={
                "creator": "scada", "action": action,
                "params": {"valve": "feed", "open_pct": 100},
                "device_ids": ids,
                "confirm_deadline": t + 4,
                "execute_after": t + 5,
                "execute_deadline": t + 300})[1]

        # 2) 指令1：两设备完整执行
        c1 = make("FEED_OPEN", [A[0], B[0]])
        assert "command_id" in c1, f"创建失败: {c1}"
        _, cf = call(f"{SAFE_URL}/commands/{c1['command_id']}/confirm", "POST",
                     safe, body={"role": "SAFETY_OFFICER",
                                 "digest": c1["param_digest"]})
        assert cf["status"] == "CONFIRMED_READY", cf
        time.sleep(6)  # 到 execute_after
        call(DEV_URL + "/hello", "POST", dev=A, body={})
        call(DEV_URL + "/hello", "POST", dev=B, body={})
        _, pA = call(DEV_URL + "/poll", "POST", dev=A, body={})
        _, pB = call(DEV_URL + "/poll", "POST", dev=B, body={})
        ep1 = pA["delivery"]["epoch"]
        call(DEV_URL + "/receipt", "POST", dev=A,
             body={"epoch": ep1, "seq": 1, "status": "OK"})
        _, rB = call(DEV_URL + "/receipt", "POST", dev=B,
                     body={"epoch": pB["delivery"]["epoch"], "seq": 1,
                           "status": "OK"})
        print(f"[1] FEED_OPEN 两设备回执 → {rB['command_status']}")
        ok &= rB["command_status"] == "COMPLETED"

        # 3) 指令2：设备A取走不回执（在途）
        c2 = make("FEED_CLOSE", [A[0]])
        call(f"{SAFE_URL}/commands/{c2['command_id']}/confirm", "POST", safe,
             body={"digest": c2["param_digest"]})
        time.sleep(6)
        _, p = call(DEV_URL + "/poll", "POST", dev=A, body={})
        inflight = p["delivery"]
        print(f"[2] FEED_CLOSE 已下发在途 epoch={inflight['epoch']} "
              f"seq={inflight['seq']}，设备A不回执")

        # 4) 重启网关
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
        proc = start()
        _, h = call(BIZ_URL + "/health")
        ep_new = h["epoch"]
        print(f"[3] 网关重启完成 epoch={ep_new}（旧={inflight['epoch']}）")
        ok &= ep_new == inflight["epoch"] + 1

        # 5) 旧代号回执必须被拒，状态不改变
        code, rej = call(DEV_URL + "/receipt", "POST", dev=A,
                         body={"epoch": inflight["epoch"],
                               "seq": inflight["seq"], "status": "OK"})
        print(f"[4] 旧代号回执 → HTTP {code} {rej['error']}")
        ok &= code == 409 and rej["error"] == "REJECTED_STALE_EPOCH"

        # 6) 事实核对
        _, v1 = call(f"{SAFE_URL}/commands/{c1['command_id']}", token=safe)
        _, v2 = call(f"{SAFE_URL}/commands/{c2['command_id']}", token=safe)
        print(f"[5] FEED_OPEN  = {v1['status']} "
              f"{[d['status'] for d in v1['deliveries']]}（已执行事实保留）")
        print(f"[6] FEED_CLOSE = {v2['status']} "
              f"{[d['status'] for d in v2['deliveries']]}（在途作废，未误执行）")
        ok &= v1["status"] == "COMPLETED"
        ok &= v2["status"] == "INTERRUPTED"

        # 7) 审计
        _, aud = call(SAFE_URL + "/audit/receipts?limit=10", token=safe)
        verdicts = {x["verdict"] for x in aud["receipts"]}
        print(f"[7] 回执审计结论集合: {sorted(verdicts)}")
        ok &= "REJECTED_STALE_EPOCH" in verdicts and "ACCEPTED" in verdicts

        print("\n冒烟结论:", "✅ 全部符合预期" if ok else "❌ 存在失败")
        return 0 if ok else 1
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
