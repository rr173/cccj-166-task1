"""现场设备模拟器：演示正确握手/轮询/回执，以及乱序、旧代号等异常回执行为。

用法：
  python -m gateway.device_sim --url http://127.0.0.1:18082 \
      --device-id D-xxxx --token TOKEN
  --mode normal|stale-epoch|out-of-order|duplicate|nack
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request


class SimError(Exception):
    pass


def call(url: str, method: str = "GET", token_headers: dict | None = None,
         body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (token_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": "BAD_RESPONSE"}


def run(base: str, device_id: str, token: str, mode: str,
        fail_seq: int | None = None, interval: float = 1.0) -> None:
    hdr = {"X-Device-Id": device_id, "X-Device-Token": token}
    _, hello = call(f"{base}/hello", "POST", hdr, {})
    epoch = hello.get("epoch")
    print(f"[sim] hello ok, epoch={epoch}")

    while True:
        _, polled = call(f"{base}/poll", "POST", hdr, {})
        d = polled.get("delivery")
        if not d:
            time.sleep(interval)
            continue
        seq = d["seq"]
        print(f"[sim] 收到下发 epoch={d['epoch']} seq={seq} action={d['action']} "
              f"params={d['params']}")

        receipt = {"epoch": d["epoch"], "seq": seq, "status": "OK",
                   "note": f"executed by {device_id}"}
        if mode == "stale-epoch":
            receipt["epoch"] = d["epoch"] - 1
        elif mode == "out-of-order" and (fail_seq is None or seq == fail_seq):
            receipt["seq"] = seq + 5  # 跳到未来序号
        elif mode == "nack":
            receipt["status"] = "FAULT: interlock open"
        elif mode == "duplicate":
            pass  # 先正常回执一次，随后再重复发一次（见下）
        code, resp = call(f"{base}/receipt", "POST", hdr, receipt)
        print(f"[sim] 回执({mode}) -> HTTP {code} {json.dumps(resp, ensure_ascii=False)}")

        if mode == "duplicate":
            time.sleep(0.3)
            code, resp = call(f"{base}/receipt", "POST", hdr, receipt)
            print(f"[sim] 重复回执 -> HTTP {code} {json.dumps(resp, ensure_ascii=False)}")
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:18082")
    p.add_argument("--device-id", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--mode", default="normal",
                   choices=["normal", "stale-epoch", "out-of-order", "duplicate", "nack"])
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()
    run(args.url, args.device_id, args.token, args.mode, interval=args.interval)


if __name__ == "__main__":
    main()
