"""端到端测试：三个独立 HTTP 通道 + 可控时钟 + 重启恢复。

覆盖：
- 指令冻结创建、第二角色摘要确认、正常多设备下发回执
- 旧启动代号 / 未知序号 / 乱序 / 重复 / 冲突回执拒绝且不改状态
- 撤销仅允许在确认前；已执行事实不可撤销
- 确认超时、执行窗口过期（迟到回执无效）
- 网关重启：在途作废、已执行不可回退、未确认不误执行、新代号要求重新握手
- 设备离线 HELD → 恢复后在窗口内执行 / 窗口外过期
- 设备忙时排队、顺序序号
- 摘要篡改拒绝、三通道凭证隔离、数据库冻结/只追加触发器
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.channels import serve_all, shutdown_all  # noqa: E402
from gateway.gateway import Gateway, digest_params  # noqa: E402

PASS, FAIL = 0, 0
FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name} :: {detail}")
        print(f"  ✗ {name}  {detail}")


class Clock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class Harness:
    def __init__(self, clock: Clock):
        self.clock = clock
        self.tmp = tempfile.mkdtemp(prefix="gw-test-")
        self.db = os.path.join(self.tmp, "g.db")
        self.biz_token = "biz-token-X"
        self.safe_token = "safe-token-Y"
        self.gw = Gateway(self.db, self.biz_token, self.safe_token,
                          offline_after=5.0, now_fn=clock.now)
        self.servers = serve_all(self.gw, 0, 0, 0, "127.0.0.1")
        self.biz = f"http://127.0.0.1:{self.servers['business'].server_port}"
        self.safe = f"http://127.0.0.1:{self.servers['safety'].server_port}"
        self.dev = f"http://127.0.0.1:{self.servers['device'].server_port}"

    def restart(self) -> None:
        """模拟网关进程重启：同一数据库、同一通道令牌，启动代号 +1。"""
        shutdown_all(self.servers)
        self.gw.conn.close()
        self.gw = Gateway(self.db, self.biz_token, self.safe_token,
                          offline_after=5.0, now_fn=self.clock.now)
        self.servers = serve_all(self.gw, 0, 0, 0, "127.0.0.1")
        self.biz = f"http://127.0.0.1:{self.servers['business'].server_port}"
        self.safe = f"http://127.0.0.1:{self.servers['safety'].server_port}"
        self.dev = f"http://127.0.0.1:{self.servers['device'].server_port}"

    def close(self) -> None:
        shutdown_all(self.servers)
        self.gw.conn.close()


def req(url: str, method: str = "GET", token: str | None = None,
        device: tuple[str, str] | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if device:
        r.add_header("X-Device-Id", device[0])
        r.add_header("X-Device-Token", device[1])
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "application/json" in ctype else raw)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def register(h: Harness, name: str) -> dict:
    code, body = req(f"{h.biz}/devices", "POST", token=h.biz_token,
                     body={"name": name})
    assert code == 201, body
    return body


def make_command(h: Harness, clock: Clock, devices: list[str],
                 cd: float = 10, ea: float | None = None, ed: float = 100,
                 action: str = "SET_VALVE_OPEN", params=None) -> dict:
    params = params if params is not None else {"valve": "V-101", "open_pct": 100}
    body = {"creator": "scada-op-1", "action": action, "params": params,
            "device_ids": devices,
            "confirm_deadline": clock.t + cd,
            "execute_after": clock.t + (ea if ea is not None else cd),
            "execute_deadline": clock.t + ed}
    code, r = req(f"{h.biz}/commands", "POST", token=h.biz_token, body=body)
    assert code == 201, r
    return r


def hello_poll(h: Harness, cred: tuple[str, str]):
    code, hi = req(f"{h.dev}/hello", "POST", device=cred, body={})
    assert code == 200, hi
    return req(f"{h.dev}/poll", "POST", device=cred, body={})


def confirm(h: Harness, cid: str, digest: str, role: str = "SAFETY_OFFICER"):
    return req(f"{h.safe}/commands/{cid}/confirm", "POST", token=h.safe_token,
               body={"digest": digest, "role": role})


def ack(h: Harness, cred, epoch: int, seq: int, status: str = "OK", note="done"):
    return req(f"{h.dev}/receipt", "POST", device=cred,
               body={"epoch": epoch, "seq": seq, "status": status, "note": note})


# ====================================================================== 测试用例

def test_happy_path(h: Harness, clock: Clock):
    print("\n[1] 冻结创建 → 第二角色确认 → 布防 → 多设备执行 → 重复回执无效")
    d1 = register(h, "调节阀-101")
    d2 = register(h, "调节阀-102")
    c1, c2 = d1["device_id"], d2["device_id"]
    r = make_command(h, clock, [c1, c2])
    cid = r["command_id"]
    check("创建即冻结摘要", len(r["param_digest"]) == 64)

    # 未确认：设备轮询无下发
    code, _ = hello_poll(h, (c1, d1["token"]))
    code2, polled = hello_poll(h, (c2, d2["token"]))
    check("确认前不下发", polled["delivery"] is None)

    # 第二角色在独立安全通道用核对摘要确认
    code, cmd = confirm(h, cid, r["param_digest"])
    check("确认后布防 CONFIRMED_READY", code == 200 and cmd["status"] == "CONFIRMED_READY",
          str(cmd))

    # 到最早下发时刻后扫描器激活，在线设备立即得到投递（各自 seq=1）
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p1 = req(f"{h.dev}/poll", "POST", device=(c1, d1["token"]), body={})
    _, p2 = req(f"{h.dev}/poll", "POST", device=(c2, d2["token"]), body={})
    check("d1 收到 seq=1", p1["delivery"] and p1["delivery"]["seq"] == 1
          and p1["delivery"]["epoch"] == h.gw.epoch, str(p1))
    check("d2 收到 seq=1", p2["delivery"] and p2["delivery"]["seq"] == 1, str(p2))

    code, a1 = ack(h, (c1, d1["token"]), h.gw.epoch, 1)
    check("d1 回执成功", code == 200 and a1["command_status"] == "ACTIVE", str(a1))
    code, a2 = ack(h, (c2, d2["token"]), h.gw.epoch, 1)
    check("全部成功后 COMPLETED", code == 200 and a2["command_status"] == "COMPLETED",
          str(a2))

    # 重复回执不得改变状态
    code, dup = ack(h, (c1, d1["token"]), h.gw.epoch, 1)
    check("重复回执被拒 REJECTED_DUPLICATE",
          code == 409 and dup["error"] == "REJECTED_DUPLICATE", str(dup))
    # 冲突回执（同一序号声称不同结果）同样拒绝
    code, conf = ack(h, (c1, d1["token"]), h.gw.epoch, 1, status="OTHER")
    check("冲突回执被拒 REJECTED_CONFLICT",
          code == 409 and conf["error"] == "REJECTED_CONFLICT", str(conf))
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("状态仍 COMPLETED/DELIVERED", cmd["status"] == "COMPLETED"
          and all(d["status"] == "DELIVERED" for d in cmd["deliveries"]))

    # 已执行指令不可撤销
    code, rev = req(f"{h.biz}/commands/{cid}/revoke", "POST", token=h.biz_token,
                    body={"by": "op", "reason": "反悔"})
    check("已执行事实不可撤销", code == 409 and rev["error"] == "COMMAND_NOT_REVOCABLE",
          str(rev))


def test_stale_epoch_order(h: Harness, clock: Clock):
    print("\n[2] 旧启动代号 / 未知序号 / 乱序回执拒绝且不改状态")
    d = register(h, "泵-201")
    did, tok = d["device_id"], d["token"]

    # 第一条指令执行完毕，设备 last_seq=1
    r = make_command(h, clock, [did], cd=10, ed=200, action="PUMP_START")
    cid1 = r["command_id"]
    confirm(h, cid1, r["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p = hello_poll(h, (did, tok))
    ack(h, (did, tok), h.gw.epoch, p["delivery"]["seq"])

    # 第二条指令下发 seq=2
    r2 = make_command(h, clock, [did], cd=10, ed=300, action="PUMP_STOP")
    cid2 = r2["command_id"]
    confirm(h, cid2, r2["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p2 = req(f"{h.dev}/poll", "POST", device=(did, tok), body={})
    check("第二指令 seq=2", p2["delivery"] and p2["delivery"]["seq"] == 2, str(p2))

    # 回退序号（乱序）：seq=1 已不是当前期待
    code, ooo = ack(h, (did, tok), h.gw.epoch, 1)
    check("回退乱序 REJECTED_OUT_OF_ORDER",
          code == 409 and ooo["error"] == "REJECTED_OUT_OF_ORDER", str(ooo))
    # 跳跃未知序号
    code, unk = ack(h, (did, tok), h.gw.epoch, 99)
    check("未知序号 REJECTED_UNKNOWN_SEQ",
          code == 409 and unk["error"] == "REJECTED_UNKNOWN_SEQ", str(unk))
    # 旧启动代号
    code, stale = ack(h, (did, tok), h.gw.epoch - 1, 1)
    check("旧代号 REJECTED_STALE_EPOCH",
          code == 409 and stale["error"] == "REJECTED_STALE_EPOCH", str(stale))
    # 非法载荷
    code, bad = req(f"{h.dev}/receipt", "POST", device=(did, tok),
                    body={"epoch": "one", "seq": 1, "status": "OK"})
    check("畸形回执 REJECTED_MALFORMED",
          code == 400 and bad["error"] == "REJECTED_MALFORMED", str(bad))

    # 当前状态未被任何坏回执改变：seq=2 仍在途，正确回执后完成
    _, cmd = req(f"{h.safe}/commands/{cid2}", token=h.safe_token)
    check("第二指令仍 ACTIVE/PENDING", cmd["status"] == "ACTIVE"
          and any(x["status"] == "PENDING" for x in cmd["deliveries"]), str(cmd))
    code, ok = ack(h, (did, tok), h.gw.epoch, 2)
    check("正确 seq=2 后完成", code == 200 and ok["command_status"] == "COMPLETED", str(ok))

    # 审计中可查到全部拒收记录（append-only）
    _, aud = req(f"{h.safe}/audit/receipts?limit=50", token=h.safe_token)
    verdicts = {x["verdict"] for x in aud["receipts"]}
    check("审计含全部拒收类别",
          {"REJECTED_STALE_EPOCH", "REJECTED_UNKNOWN_SEQ",
           "REJECTED_OUT_OF_ORDER", "REJECTED_MALFORMED", "ACCEPTED"} <= verdicts,
          str(verdicts))


def test_revoke_policy(h: Harness, clock: Clock):
    print("\n[3] 撤销策略：仅确认前可撤，确认后不可撤")
    d = register(h, "阀门-301")
    did = d["device_id"]
    r = make_command(h, clock, [did])
    cid = r["command_id"]
    code, rev = req(f"{h.biz}/commands/{cid}/revoke", "POST", token=h.biz_token,
                    body={"by": "op", "reason": "计划取消"})
    check("确认前撤销成功", code == 200 and rev["status"] == "REVOKED", str(rev))
    code, rev2 = req(f"{h.biz}/commands/{cid}/revoke", "POST", token=h.biz_token,
                     body={"by": "op"})
    check("重复撤销拒绝", code == 409, str(rev2))
    code, cf = confirm(h, cid, r["param_digest"])
    check("已撤销不能再确认", code == 409 and cf["error"] == "COMMAND_NOT_PENDING", str(cf))

    # 已确认（未下发）也不可撤销
    r2 = make_command(h, clock, [did], action="SET_B", cd=10, ed=200)
    cid2 = r2["command_id"]
    confirm(h, cid2, r2["param_digest"])
    code, rev3 = req(f"{h.biz}/commands/{cid2}/revoke", "POST", token=h.biz_token,
                     body={"by": "op"})
    check("确认后撤销拒绝 COMMAND_NOT_REVOCABLE",
          code == 409 and rev3["error"] == "COMMAND_NOT_REVOCABLE", str(rev3))
    _, cmd2 = req(f"{h.safe}/commands/{cid2}", token=h.safe_token)
    check("指令仍保持 CONFIRMED_READY", cmd2["status"] == "CONFIRMED_READY")


def test_confirm_timeout(h: Harness, clock: Clock):
    print("\n[4] 确认超时：指令失效，永不执行")
    d = register(h, "阀门-401")
    did = d["device_id"]
    r = make_command(h, clock, [did], cd=5, ed=300)
    cid = r["command_id"]
    clock.advance(6)
    h.gw.sweeper_tick()
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("超时后 EXPIRED", cmd["status"] == "EXPIRED", str(cmd))
    code, cf = confirm(h, cid, r["param_digest"])
    check("超时后确认拒绝", code == 409, str(cf))
    hello_poll(h, (did, d["token"]))
    clock.advance(100)
    _, polled = req(f"{h.dev}/poll", "POST", device=(did, d["token"]), body={})
    check("过期指令永不下发", polled["delivery"] is None, str(polled))


def test_restart_recovery(h: Harness, clock: Clock):
    print("\n[5] 网关重启：在途作废、已执行不可回退、未确认不误执行、代号+1")
    d1, d2 = register(h, "阀门-501"), register(h, "阀门-502")
    r = make_command(h, clock, [d1["device_id"], d2["device_id"]], cd=10, ed=400)
    cid = r["command_id"]
    confirm(h, cid, r["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p1 = hello_poll(h, (d1["device_id"], d1["token"]))
    _, p2 = hello_poll(h, (d2["device_id"], d2["token"]))
    seq1 = h.gw.epoch
    ack(h, (d1["device_id"], d1["token"]), seq1, 1)  # d1 已执行
    # d2 未回执（在途）

    epoch_before = h.gw.epoch
    h.restart()
    check("重启后启动代号 +1", h.gw.epoch == epoch_before + 1,
          f"{h.gw.epoch} vs {epoch_before+1}")

    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    dl = {x["device_id"]: x for x in cmd["deliveries"]}
    check("已执行 d1 事实保留 DELIVERED", dl[d1["device_id"]]["status"] == "DELIVERED")
    check("在途 d2 被 INTERRUPTED", dl[d2["device_id"]]["status"] == "INTERRUPTED")
    check("指令判定 PARTIAL（事实不被撤销覆盖）", cmd["status"] == "PARTIAL", str(cmd))

    # 旧代号回执：设备未在新代号握手，且代号已失效 → 拒绝
    code, stale = ack(h, (d2["device_id"], d2["token"]), epoch_before, 1)
    check("旧代号回执拒绝", code == 409 and stale["error"] == "REJECTED_STALE_EPOCH",
          str(stale))

    # 新代号必须先 hello 握手
    code, nosync = ack(h, (d2["device_id"], d2["token"]), h.gw.epoch, 1)
    check("未握手回执拒绝", code == 409
          and nosync["error"] == "REJECTED_EPOCH_NOT_SYNCHRONIZED", str(nosync))

    # 再次重启不改变既成事实
    h.restart()
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("再次重启仍 PARTIAL", cmd["status"] == "PARTIAL")
    check("重启事件入链", req(f"{h.safe}/audit/events?limit=50",
                              token=h.safe_token)[1]["events"][0]["kind"]
          == "GATEWAY_RESTART")

    # 数据库层：DELIVERED 不可回退
    raw = sqlite3.connect(h.db)
    try:
        blocked = False
        try:
            raw.execute("UPDATE deliveries SET status='PENDING' "
                        "WHERE device_id=?", (d1["device_id"],))
        except sqlite3.IntegrityError:
            blocked = True
        check("触发器阻断 DELIVERED 回退", blocked)
    finally:
        raw.close()


def test_unconfirmed_survives_restart(h: Harness, clock: Clock):
    print("\n[6] 重启后未确认指令保留但不会误执行；确认后按新代号下发")
    d = register(h, "阀门-601")
    did, tok = d["device_id"], d["token"]
    r = make_command(h, clock, [did], cd=200, ea=200, ed=500)
    cid = r["command_id"]
    h.restart()  # 在确认前重启
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("未确认指令仍 PENDING_CONFIRM", cmd["status"] == "PENDING_CONFIRM")
    _, polled = hello_poll(h, (did, tok))
    check("未确认不下发", polled["delivery"] is None)

    # 第二角色在重启后确认，按新代号下发
    code, cf = confirm(h, cid, r["param_digest"])
    check("重启后确认成功", code == 200, str(cf))
    epoch_now = h.gw.epoch
    clock.advance(201)
    h.gw.sweeper_tick()
    _, p = req(f"{h.dev}/poll", "POST", device=(did, tok), body={})
    check(f"按新代号(epoch={epoch_now})下发 seq=1",
          p["delivery"] and p["delivery"]["epoch"] == epoch_now
          and p["delivery"]["seq"] == 1, str(p))
    code, a = ack(h, (did, tok), epoch_now, 1)
    check("新代号回执完成", code == 200 and a["command_status"] == "COMPLETED", str(a))

    # CONFIRMED_READY（已确认未到下发时刻）跨重启：窗口开启后按新代号下发
    clock.advance(1)
    d3 = register(h, "阀门-602")
    r2 = make_command(h, clock, [d3["device_id"]], cd=50, ea=300, ed=600,
                      action="SET_C")
    cid2 = r2["command_id"]
    confirm(h, cid2, r2["param_digest"])
    h.restart()
    _, polled = hello_poll(h, (d3["device_id"], d3["token"]))
    check("重启后、窗口前仍无下发", polled["delivery"] is None)
    clock.advance(301)
    h.gw.sweeper_tick()
    _, p3 = req(f"{h.dev}/poll", "POST", device=(d3["device_id"], d3["token"]), body={})
    check("布防指令窗口开启后按新代号 seq=1 下发",
          p3["delivery"] and p3["delivery"]["epoch"] == h.gw.epoch
          and p3["delivery"]["seq"] == 1, str(p3))


def test_offline_recovery(h: Harness, clock: Clock):
    print("\n[7] 设备离线：HELD 待命 → 窗口内恢复执行 / 窗口外过期")
    d = register(h, "阀门-701")
    did, tok = d["device_id"], d["token"]
    r = make_command(h, clock, [did], cd=10, ed=80)
    cid = r["command_id"]
    confirm(h, cid, r["param_digest"])
    clock.advance(20)
    h.gw.sweeper_tick()  # 设备从未 hello → 离线 → HELD
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("离线设备投递 HELD", cmd["deliveries"][0]["status"] == "HELD",
          str(cmd["deliveries"]))

    # 窗口内恢复：hello 触发重投
    clock.advance(10)
    code, hi = req(f"{h.dev}/hello", "POST", device=(did, tok), body={})
    check("hello 报告恢复投递", code == 200 and len(hi["redelivered"]) == 1, str(hi))
    _, p = req(f"{h.dev}/poll", "POST", device=(did, tok), body={})
    check("恢复后拿到下发 seq=1", p["delivery"] and p["delivery"]["seq"] == 1, str(p))
    code, a = ack(h, (did, tok), h.gw.epoch, 1)
    check("恢复后执行 COMPLETED", code == 200 and a["command_status"] == "COMPLETED", str(a))

    # 窗口外恢复：HELD 过期，不再执行
    d2 = register(h, "阀门-702")
    r2 = make_command(h, clock, [d2["device_id"]], cd=10, ed=60, action="SET_D")
    cid2 = r2["command_id"]
    confirm(h, cid2, r2["param_digest"])
    clock.advance(20)
    h.gw.sweeper_tick()  # HELD
    clock.advance(50)   # 超过 execute_deadline
    h.gw.sweeper_tick()
    _, cmd2 = req(f"{h.safe}/commands/{cid2}", token=h.safe_token)
    check("窗口结束 → EXPIRED", cmd2["status"] == "EXPIRED"
          and cmd2["deliveries"][0]["status"] == "EXPIRED", str(cmd2))
    _, hi2 = req(f"{h.dev}/hello", "POST", device=(d2["device_id"], d2["token"]), body={})
    check("过期后恢复不重投", hi2["redelivered"] == [])
    _, polled = req(f"{h.dev}/poll", "POST", device=(d2["device_id"], d2["token"]), body={})
    check("过期后轮询无下发", polled["delivery"] is None)


def test_queued_behind_busy(h: Harness, clock: Clock):
    print("\n[8] 设备忙时排队：前一条完成后按序下发，序号递增")
    d = register(h, "泵-801")
    did, tok = d["device_id"], d["token"]
    r1 = make_command(h, clock, [did], cd=10, ed=2000, action="A")
    confirm(h, r1["command_id"], r1["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p1 = hello_poll(h, (did, tok))
    check("第一条 seq=1 在途", p1["delivery"]["seq"] == 1)

    r2 = make_command(h, clock, [did], cd=10, ed=2000, action="B")
    confirm(h, r2["command_id"], r2["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, polled = req(f"{h.dev}/poll", "POST", device=(did, tok), body={})
    check("忙时轮询仍只返回第一条(seq=1)",
          polled["delivery"]["seq"] == 1, str(polled))
    _, cmd2 = req(f"{h.safe}/commands/{r2['command_id']}", token=h.safe_token)
    check("第二条保持 QUEUED", cmd2["deliveries"][0]["status"] == "QUEUED")

    ack(h, (did, tok), h.gw.epoch, 1)
    h.gw.sweeper_tick()
    _, p2 = req(f"{h.dev}/poll", "POST", device=(did, tok), body={})
    check("前条完成后第二条 seq=2 下发",
          p2["delivery"] and p2["delivery"]["seq"] == 2, str(p2))
    code, a = ack(h, (did, tok), h.gw.epoch, 2)
    check("第二条 COMPLETED", code == 200 and a["command_status"] == "COMPLETED", str(a))


def test_digest_and_nack(h: Harness, clock: Clock):
    print("\n[9] 参数摘要篡改拒绝；设备 NACK 记为失败终态")
    d = register(h, "阀门-901")
    did, tok = d["device_id"], d["token"]
    params = {"rpm": 3000}
    r = make_command(h, clock, [did], params=params, cd=10, ed=200)
    cid = r["command_id"]

    forged = digest_params({"rpm": 9999})
    code, bad = confirm(h, cid, forged)
    check("篡改摘要拒绝 DIGEST_MISMATCH",
          code == 400 and bad["error"] == "DIGEST_MISMATCH", str(bad))
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("拒绝后仍 PENDING_CONFIRM", cmd["status"] == "PENDING_CONFIRM")

    code, ok = confirm(h, cid, digest_params(params))
    check("正确摘要确认成功", code == 200)
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p = hello_poll(h, (did, tok))
    code, nack = ack(h, (did, tok), h.gw.epoch, 1,
                     status="INTERLOCK_OPEN", note="安全联锁未闭合")
    check("设备 NACK 被如实记录（未执行事实）", code == 200 and nack["executed"] is False,
          str(nack))
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("投递 FAILED、指令 FAILED", cmd["status"] == "FAILED"
          and cmd["deliveries"][0]["status"] == "FAILED", str(cmd))


def test_channel_isolation(h: Harness, clock: Clock):
    print("\n[10] 三通道凭证与职责隔离")
    d = register(h, "阀门-1001")
    did, tok = d["device_id"], d["token"]

    code, _ = req(f"{h.biz}/commands", "POST", token=h.safe_token, body={})
    check("安全令牌不能走业务通道", code == 401)
    code, _ = req(f"{h.safe}/pending", token=h.biz_token)
    check("业务令牌不能走安全通道", code == 401)
    code, _ = req(f"{h.biz}/devices", token=tok)
    check("设备令牌不能走业务通道", code == 401)
    code, _ = req(f"{h.dev}/poll", "POST", token=h.biz_token, body={})
    check("业务令牌不能走设备通道", code == 401)
    code, _ = req(f"{h.dev}/poll", "POST",
                  device=(did, "wrong-token"), body={})
    check("伪造设备令牌拒绝", code == 401)
    code, _ = req(f"{h.biz}/commands/x/confirm", "POST", token=h.biz_token,
                  body={"digest": "y"})
    check("业务通道不存在确认操作(404)", code == 404)
    code, _ = req(f"{h.safe}/commands/x/revoke", "POST", token=h.safe_token,
                  body={"by": "s"})
    check("安全通道不存在撤销操作(404)", code == 404)
    code, body = req(f"{h.safe}/ui")
    ui_ok = code == 200 and isinstance(body, str) and "安全通道" in body
    check("工作台无需令牌可打开登录页", ui_ok)


def test_validation_and_triggers(h: Harness, clock: Clock):
    print("\n[11] 输入校验 + 数据库冻结/只追加约束")
    d = register(h, "阀门-1101")
    did = d["device_id"]
    base = {"creator": "op", "action": "X", "params": {}, "device_ids": [did],
            "confirm_deadline": clock.t + 10, "execute_after": clock.t + 10,
            "execute_deadline": clock.t + 100}
    code, b = req(f"{h.biz}/commands", "POST", token=h.biz_token,
                  body={**base, "device_ids": ["D-NOPE"]})
    check("未知设备拒绝", code == 404 and b["error"] == "UNKNOWN_DEVICE", str(b))
    code, b = req(f"{h.biz}/commands", "POST", token=h.biz_token,
                  body={**base, "execute_deadline": clock.t + 5})
    check("非法时间窗口拒绝", code == 400 and b["error"] == "INVALID_WINDOW", str(b))

    r = make_command(h, clock, [did], cd=10, ed=200)
    raw = sqlite3.connect(h.db)
    try:
        froze = deleted = receipt_imm = False
        try:
            raw.execute("UPDATE commands SET param_digest='x' WHERE id=?",
                        (r["command_id"],))
        except sqlite3.IntegrityError:
            froze = True
        try:
            raw.execute("DELETE FROM commands WHERE id=?", (r["command_id"],))
        except sqlite3.IntegrityError:
            deleted = True
        try:
            raw.execute("UPDATE receipts_audit SET verdict='HACK' WHERE 1=1")
        except sqlite3.IntegrityError:
            receipt_imm = True
        check("冻结字段不可改写", froze)
        check("指令不可删除", deleted)
        check("回执审计只追加", receipt_imm)
    finally:
        raw.close()


def test_acked_after_window(h: Harness, clock: Clock):
    print("\n[12] 窗口结束后的迟到回执不能执行/改状态")
    d = register(h, "阀门-1201")
    did, tok = d["device_id"], d["token"]
    r = make_command(h, clock, [did], cd=10, ed=50)
    cid = r["command_id"]
    confirm(h, cid, r["param_digest"])
    clock.advance(11)
    h.gw.sweeper_tick()
    _, p = hello_poll(h, (did, tok))
    seq, epoch = p["delivery"]["seq"], h.gw.epoch
    clock.advance(45)  # 超过 execute_deadline，设备一直未回执
    h.gw.sweeper_tick()
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("投递过期、指令 EXPIRED", cmd["status"] == "EXPIRED"
          and cmd["deliveries"][0]["status"] == "EXPIRED")
    code, late = ack(h, (did, tok), epoch, seq)
    check("迟到回执 REJECTED_TERMINAL",
          code == 409 and late["error"] == "REJECTED_TERMINAL", str(late))
    _, cmd = req(f"{h.safe}/commands/{cid}", token=h.safe_token)
    check("状态保持 EXPIRED，未被执行覆盖", cmd["status"] == "EXPIRED")


def test_health_no_auth(h: Harness, clock: Clock):
    print("\n[13] 健康检查端点无需凭证")
    for name, url in (("business", h.biz), ("safety", h.safe), ("device", h.dev)):
        code, body = req(f"{url}/health")
        check(f"{name} /health 200", code == 200 and body.get("ok") is True
              and body.get("channel") == name, str(body))


def main() -> int:
    clock = Clock()
    h = Harness(clock)
    try:
        test_health_no_auth(h, clock)
        test_happy_path(h, clock)
        test_stale_epoch_order(h, clock)
        test_revoke_policy(h, clock)
        test_confirm_timeout(h, clock)
        test_restart_recovery(h, clock)
        test_unconfirmed_survives_restart(h, clock)
        test_offline_recovery(h, clock)
        test_queued_behind_busy(h, clock)
        test_digest_and_nack(h, clock)
        test_channel_isolation(h, clock)
        test_validation_and_triggers(h, clock)
        test_acked_after_window(h, clock)
    finally:
        h.close()

    print("\n" + "=" * 64)
    print(f"结果：{PASS} 通过，{FAIL} 失败")
    if FAILURES:
        print("失败项：")
        for f in FAILURES:
            print("  -", f)
    print("=" * 64)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
