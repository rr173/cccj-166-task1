"""网关启动入口。

用法：
  python -m gateway.app --db gateway.db \
      --business-port 18080 --safety-port 18081 --device-port 18082

令牌策略：
  首次启动自动生成业务/安全通道令牌并写入 <db>.tokens.json（权限 0600）；
  也可用 --business-token / --safety-token 覆盖。
每次启动 epoch（启动代号）自动 +1，设备需用新代号重新握手。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path

from .channels import (BUSINESS_PORT, DEVICE_PORT, SAFETY_PORT, serve_all,
                       shutdown_all)
from .gateway import Gateway


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="工业控制指令双通道确认网关")
    p.add_argument("--db", default="gateway.db")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--business-port", type=int, default=BUSINESS_PORT)
    p.add_argument("--safety-port", type=int, default=SAFETY_PORT)
    p.add_argument("--device-port", type=int, default=DEVICE_PORT)
    p.add_argument("--business-token", default=None)
    p.add_argument("--safety-token", default=None)
    p.add_argument("--offline-after", type=float, default=8.0)
    args = p.parse_args(argv)

    token_file = Path(args.db + ".tokens.json")
    persisted: dict[str, str] = {}
    if token_file.exists():
        persisted = json.loads(token_file.read_text(encoding="utf-8"))

    gw = Gateway(
        db_path=args.db,
        business_token=args.business_token or persisted.get("business_token"),
        safety_token=args.safety_token or persisted.get("safety_token"),
        offline_after=args.offline_after,
    )

    token_file.write_text(json.dumps({
        "business_token": gw.business_token,
        "safety_token": gw.safety_token,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(token_file, 0o600)

    gw.start_sweeper()
    servers = serve_all(gw, args.business_port, args.safety_port,
                        args.device_port, args.bind)

    print("=" * 72)
    print(" 工业控制指令双通道确认网关已启动   epoch(启动代号) =", gw.epoch)
    print("-" * 72)
    print(f"  业务通道 : http://{args.bind}:{args.business_port}  (创建/撤销指令)")
    print(f"             Authorization: Bearer {gw.business_token}")
    print(f"  安全通道 : http://{args.bind}:{args.safety_port}  (第二角色确认/审计)")
    print(f"             工作台: http://{args.bind}:{args.safety_port}/ui")
    print(f"             Authorization: Bearer {gw.safety_token}")
    print(f"  设备通道 : http://{args.bind}:{args.device_port}  (hello/poll/回执)")
    print(f"             X-Device-Id / X-Device-Token（注册时下发，一机一令）")
    print("=" * 72)

    stop = {"v": False}

    def _sig(_n, _f):
        stop["v"] = True
        shutdown_all(servers)
        gw.stop_sweeper()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    try:
        while not stop["v"]:
            signal.pause()
    except AttributeError:  # Windows
        import time
        while not stop["v"]:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
