"""网关核心领域逻辑（不依赖 HTTP 层）。

设计要点：
- 指令创建即冻结：设备集合 / 参数摘要 / 有效窗口存库，触发器禁止改写。
- 双通道职责分离：create/revoke 走业务通道，confirm 只走安全通道（HTTP 层强制）。
- 启动代号 epoch 每次网关进程启动 +1；设备在代号内使用严格递增 seq。
  旧代号、未知序号、乱序、终态后的回执一律拒绝，只写审计、不改变任何状态。
- 重启恢复：新代号下在途投递全部 INTERRUPTED，旧代号回执将被 STALE_EPOCH 拦截；
  DELIVERED 由数据库触发器保证不可回退，已执行事实不能被撤销/重启覆盖。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any, Callable, Optional

from . import store


class DomainError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_params(params: dict) -> str:
    return hashlib.sha256(canonical_json(params).encode("utf-8")).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


class Gateway:
    def __init__(
        self,
        db_path: str = "gateway.db",
        business_token: Optional[str] = None,
        safety_token: Optional[str] = None,
        offline_after: float = 8.0,
        now_fn: Optional[Callable[[], float]] = None,
    ):
        self.conn = store.connect(db_path)
        self.lock = threading.RLock()
        self.offline_after = offline_after
        self.now = now_fn or time.time
        self.business_token = business_token or secrets.token_urlsafe(24)
        self.safety_token = safety_token or secrets.token_urlsafe(24)
        self.epoch = 1
        self._sweeper_thread: Optional[threading.Thread] = None
        self._sweeper_stop = threading.Event()
        self._boot()

    # ---------------------------------------------------------------- 基础设施

    def _meta_get(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def _meta_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def event(self, actor: str, kind: str, detail: Any, target: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO events(at,actor,kind,target,detail) VALUES(?,?,?,?,?)",
            (self.now(), actor, kind, target,
             detail if isinstance(detail, str) else canonical_json(detail)),
        )

    def audit_receipt(
        self,
        device_id: Optional[str],
        raw: Any,
        verdict: str,
        detail: str,
        epoch: Any = None,
        seq: Any = None,
        status: Any = None,
        note: Any = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO receipts_audit(id,received_at,device_id,epoch,seq,status,note,"
            "verdict,detail,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (new_id("R"), self.now(), device_id, epoch, seq, status, note,
             verdict, detail, canonical_json(raw)),
        )

    # ---------------------------------------------------------------- 启动/恢复

    def _boot(self) -> None:
        """进程启动：推进启动代号；作废在途投递；未确认指令保留但不会被自动执行。"""
        with self.lock:
            now = self.now()
            persisted = self._meta_get("epoch")
            if persisted is None:
                self.epoch = 1
                self._meta_set("epoch", "1")
                self.event("GATEWAY", "GATEWAY_FIRST_BOOT", {"epoch": 1})
            else:
                self.epoch = int(persisted) + 1
                self._meta_set("epoch", str(self.epoch))
                self.event("GATEWAY", "GATEWAY_RESTART",
                           {"old_epoch": int(persisted), "new_epoch": self.epoch})

            # 设备一律视为离线，必须用新代号重新 hello 握手后才能接收投递。
            self.conn.execute("UPDATE devices SET online=0")

            # 在途（ACTIVE 指令的一切未终态投递）随旧代号作废：
            # QUEUED/PENDING 都不会在新代号下自动下发，满足“重启时未执行不得误执行”。
            open_rows = self.conn.execute(
                "SELECT d.id, d.command_id, d.device_id, d.seq, c.status AS cmd_status, "
                "c.execute_deadline FROM deliveries d JOIN commands c ON c.id=d.command_id "
                "WHERE d.status IN ('QUEUED','PENDING','HELD')"
            ).fetchall()
            affected_commands: dict[str, bool] = {}
            for r in open_rows:
                if r["cmd_status"] == store.CONFIRMED_READY:
                    # 确认通过但下发窗口尚未开始：保留，窗口开启后由 sweeper 在新代号下发。
                    continue
                if now > r["execute_deadline"]:
                    new_dstatus, reason, ekind = (
                        "EXPIRED", "execute_window_closed", "DELIVERY_EXPIRED")
                else:
                    new_dstatus, reason, ekind = (
                        "INTERRUPTED", "gateway_restart", "DELIVERY_INTERRUPTED")
                self.conn.execute(
                    "UPDATE deliveries SET status=? WHERE id=?", (new_dstatus, r["id"]))
                self.event("GATEWAY", ekind,
                           {"delivery_id": r["id"], "device_id": r["device_id"],
                            "seq": r["seq"], "reason": reason},
                           target=r["command_id"])
                affected_commands[r["command_id"]] = True
            for cid in affected_commands:
                self._finalize_command(cid)

    # ---------------------------------------------------------------- 设备注册/在线

    def register_device(self, name: str, device_id: Optional[str] = None) -> dict:
        with self.lock:
            if not name or not str(name).strip():
                raise DomainError("INVALID_NAME", "设备名称不能为空", 400)
            if device_id is not None:
                if self.conn.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                    raise DomainError("DEVICE_EXISTS", f"设备 {device_id} 已注册", 409)
                did = device_id
            else:
                did = new_id("D")
            token = secrets.token_urlsafe(24)
            self.conn.execute(
                "INSERT INTO devices(id,name,token,registered_at,last_seen,last_epoch,"
                "last_seq,online) VALUES(?,?,?,?,0,0,0,0)",
                (did, name.strip(), token, self.now()))
            self.event("BUSINESS", "DEVICE_REGISTERED",
                       {"device_id": did, "name": name}, target=did)
            return {"device_id": did, "name": name.strip(), "token": token,
                    "token_kind": "device_secret_returned_once"}

    def authenticate_device(self, device_id: str, token: str) -> dict:
        row = self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row or not hmac.compare_digest(str(token), row["token"]):
            raise DomainError("UNAUTHORIZED", "设备身份认证失败", 401)
        return row

    def _handshake(self, row: dict, now: float) -> bool:
        """设备 hello/poll 握手：识别新启动代号并重置该代号内序号。返回是否发生代号切换。"""
        switched = row["last_epoch"] != self.epoch
        self.conn.execute(
            "UPDATE devices SET last_seen=?, online=1, "
            "last_epoch=?, last_seq=CASE WHEN ? THEN 0 ELSE last_seq END",
            (now, self.epoch, 1 if switched else 0))
        if switched:
            self.event(row["id"], "DEVICE_EPOCH",
                       {"device_id": row["id"], "epoch": self.epoch}, target=row["id"])
        return switched

    def hello(self, device: dict) -> dict:
        with self.lock:
            now = self.now()
            switched = self._handshake(device, now)
            # 离线恢复：恢复该设备在窗口内的 HELD 待命投递。
            recovered = self._redrive_held(device["id"], now)
            return {"epoch": self.epoch, "server_time": now, "online": True,
                    "epoch_switched": switched, "redelivered": recovered}

    # ---------------------------------------------------------------- 指令创建（业务通道）

    def create_command(
        self,
        creator: str,
        action: str,
        params: dict,
        device_ids: list[str],
        confirm_deadline: float,
        execute_after: float,
        execute_deadline: float,
    ) -> dict:
        with self.lock:
            now = self.now()
            if not creator or not str(creator).strip():
                raise DomainError("INVALID_CREATOR", "creator 不能为空")
            if not action or not str(action).strip():
                raise DomainError("INVALID_ACTION", "action 不能为空")
            if not isinstance(params, dict):
                raise DomainError("INVALID_PARAMS", "params 必须是对象")
            if not isinstance(device_ids, list) or not device_ids:
                raise DomainError("INVALID_DEVICES", "device_ids 必须是非空数组")
            if len(set(device_ids)) != len(device_ids):
                raise DomainError("INVALID_DEVICES", "设备集合存在重复项")
            placeholders = ",".join("?" for _ in device_ids)
            found = {
                r["id"]
                for r in self.conn.execute(
                    f"SELECT id FROM devices WHERE id IN ({placeholders})", device_ids)
            }
            missing = [d for d in device_ids if d not in found]
            if missing:
                raise DomainError("UNKNOWN_DEVICE", f"设备未注册: {missing}", 404)
            try:
                cd, ea, ed = float(confirm_deadline), float(execute_after), float(execute_deadline)
            except (TypeError, ValueError):
                raise DomainError("INVALID_WINDOW", "窗口时间必须是数字时间戳")
            if not (now < cd <= ea < ed):
                raise DomainError(
                    "INVALID_WINDOW",
                    "窗口需满足 now < confirm_deadline <= execute_after < execute_deadline")

            cid = new_id("C")
            pj = canonical_json(params)
            pdgst = hashlib.sha256(pj.encode("utf-8")).hexdigest()
            self.conn.execute(
                "INSERT INTO commands(id,creator,action,params_json,param_digest,"
                "device_ids_json,created_at,confirm_deadline,execute_after,"
                "execute_deadline,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (cid, creator.strip(), action.strip(), pj, pdgst,
                 canonical_json(device_ids), now, cd, ea, ed, store.PENDING_CONFIRM))
            self.event(creator, "COMMAND_CREATED",
                       {"command_id": cid, "action": action, "device_ids": device_ids,
                        "param_digest": pdgst, "confirm_deadline": cd,
                        "execute_after": ea, "execute_deadline": ed},
                       target=cid)
            return {"command_id": cid, "status": store.PENDING_CONFIRM,
                    "param_digest": pdgst, "epoch_at_creation": self.epoch,
                    "frozen": {"device_ids": device_ids, "params": params,
                               "window": {"confirm_deadline": cd, "execute_after": ea,
                                          "execute_deadline": ed}}}

    # ---------------------------------------------------------------- 确认（安全通道）

    def confirm_command(self, command_id: str, role: str, digest: str) -> dict:
        with self.lock:
            now = self.now()
            cmd = self._get_command(command_id)
            if cmd["status"] != store.PENDING_CONFIRM:
                raise DomainError("COMMAND_NOT_PENDING",
                                  f"指令当前状态 {cmd['status']}，不可确认", 409)
            if now > cmd["confirm_deadline"]:
                raise DomainError("CONFIRM_WINDOW_CLOSED", "已超过确认截止时间", 409)
            if not digest or not hmac.compare_digest(str(digest), cmd["param_digest"]):
                self.event(role or "SAFETY", "COMMAND_CONFIRM_DIGEST_MISMATCH",
                           {"command_id": command_id, "provided": digest}, target=command_id)
                raise DomainError("DIGEST_MISMATCH",
                                  "参数摘要与冻结摘要不一致，拒绝确认", 400)
            role = (role or "SAFETY_OFFICER").strip()
            try:
                self.conn.execute(
                    "INSERT INTO confirmations(id,command_id,role,digest,at) VALUES(?,?,?,?,?)",
                    (new_id("A"), command_id, role, digest, now))
            except Exception:
                raise DomainError("ALREADY_CONFIRMED_BY_ROLE",
                                  f"角色 {role} 已确认过该指令", 409)

            active_now = now >= cmd["execute_after"]
            new_status = store.ACTIVE if active_now else store.CONFIRMED_READY
            self.conn.execute(
                "UPDATE commands SET status=?, confirmed_by=?, confirmed_at=? WHERE id=?",
                (new_status, role, now, command_id))

            device_ids = json.loads(cmd["device_ids_json"])
            for did in device_ids:
                self.conn.execute(
                    "INSERT INTO deliveries(id,command_id,device_id,epoch,seq,status,"
                    "attempts,dispatched_at,acked_at,receipt_note) "
                    "VALUES(?,?,?,?,?,'QUEUED',0,NULL,NULL,NULL)",
                    (new_id("DL"), command_id, did, self.epoch, None))
            self.event(role, "COMMAND_CONFIRMED",
                       {"command_id": command_id, "role": role,
                        "digest_verified": True, "mode": "IMMEDIATE" if active_now else "ARMED"},
                       target=command_id)

            if active_now:
                self._activate_command(command_id)
            return self.get_command(command_id)

    # ---------------------------------------------------------------- 撤销（业务通道，仅下发前）

    def revoke_command(self, command_id: str, reason: str, by: str) -> dict:
        with self.lock:
            cmd = self._get_command(command_id)
            if cmd["status"] != store.PENDING_CONFIRM:
                # 已确认/已下发/已执行的事实不得撤销覆盖
                raise DomainError("COMMAND_NOT_REVOCABLE",
                                  f"指令状态 {cmd['status']}：仅未确认指令可撤销，"
                                  "已执行事实不可撤销覆盖", 409)
            self.conn.execute("UPDATE commands SET status=? WHERE id=?",
                              (store.REVOKED, command_id))
            self.conn.execute(
                "INSERT INTO revocations(id,command_id,reason,by,at) VALUES(?,?,?,?,?)",
                (new_id("X"), command_id, reason or "", by or "BUSINESS", self.now()))
            self.event(by or "BUSINESS", "COMMAND_REVOKED",
                       {"command_id": command_id, "reason": reason}, target=command_id)
            return self.get_command(command_id)

    # ---------------------------------------------------------------- 下发推进

    def _device_busy(self, device_id: str) -> bool:
        """一台设备同一时刻只允许一个在途 PENDING，保证序号严格按回执推进。"""
        return self.conn.execute(
            "SELECT 1 FROM deliveries WHERE device_id=? AND status='PENDING' LIMIT 1",
            (device_id,)).fetchone() is not None

    def _dispatch(self, delivery_id: str, now: float) -> None:
        d = self.conn.execute(
            "SELECT dl.*, c.execute_deadline, c.action, c.params_json, c.id AS cid "
            "FROM deliveries dl JOIN commands c ON c.id=dl.command_id "
            "WHERE dl.id=?", (delivery_id,)).fetchone()
        dev = self.conn.execute("SELECT * FROM devices WHERE id=?",
                                (d["device_id"],)).fetchone()
        if not dev["online"] or dev["last_epoch"] != self.epoch:
            return
        if now > d["execute_deadline"]:
            return
        if d["status"] == store.PENDING:
            # 重试：保持同一 epoch/seq（幂等），设备可识别重复投递。
            self.conn.execute(
                "UPDATE deliveries SET attempts=attempts+1 WHERE id=?", (delivery_id,))
        else:
            seq = int(dev["last_seq"]) + 1
            self.conn.execute(
                "UPDATE deliveries SET status='PENDING', seq=?, dispatched_at=?, "
                "epoch=?, attempts=attempts+1 WHERE id=?",
                (seq, now, self.epoch, delivery_id))
            self.conn.execute("UPDATE devices SET last_seq=? WHERE id=?",
                              (seq, d["device_id"]))
            d = dict(d)
            d["seq"] = seq
        self.event("GATEWAY", "DISPATCH",
                   {"delivery_id": delivery_id, "command_id": d["cid"],
                    "device_id": d["device_id"], "epoch": self.epoch, "seq": d["seq"]},
                   target=d["cid"])

    def _activate_command(self, command_id: str) -> None:
        now = self.now()
        cmd = self._get_command(command_id)
        if cmd["status"] != store.CONFIRMED_READY:
            return
        if now < cmd["execute_after"]:
            return
        self.conn.execute("UPDATE commands SET status='ACTIVE' WHERE id=?", (command_id,))
        self.event("GATEWAY", "COMMAND_ACTIVATED",
                   {"command_id": command_id, "execute_after": cmd["execute_after"]},
                   target=command_id)
        self._promote_deliveries(command_id, now)

    def _promote_deliveries(self, command_id: str, now: float) -> None:
        cmd = self._get_command(command_id)
        # 只有已进入激活窗口的指令才能向现场推进；未到 execute_after 必须按兵不动。
        if cmd["status"] != store.ACTIVE or now < cmd["execute_after"]:
            return
        rows = self.conn.execute(
            "SELECT * FROM deliveries WHERE command_id=? AND status IN ('QUEUED','HELD','PENDING')",
            (command_id,)).fetchall()
        for d in rows:
            if now > cmd["execute_deadline"]:
                # 窗口结束：排队、待命与在途未回执一律不再有效
                self._expire_delivery(d["id"], "execute_window_closed")
                continue
            if d["status"] == store.PENDING:
                continue  # 在途等待回执，由设备轮询幂等重发
            dev = self.conn.execute("SELECT * FROM devices WHERE id=?",
                                    (d["device_id"],)).fetchone()
            online = bool(dev["online"]) and dev["last_epoch"] == self.epoch
            if not online:
                if d["status"] == store.QUEUED:
                    self.conn.execute("UPDATE deliveries SET status='HELD' WHERE id=?",
                                      (d["id"],))
                    self.event("GATEWAY", "DISPATCH_HELD",
                               {"delivery_id": d["id"], "device_id": d["device_id"],
                                "reason": "device_offline"}, target=command_id)
                continue
            if self._device_busy(d["device_id"]):
                continue  # 排在前一条指令之后，保持 QUEUED
            self._dispatch(d["id"], now)

    def _expire_delivery(self, delivery_id: str, reason: str) -> None:
        d = self.conn.execute("SELECT * FROM deliveries WHERE id=?",
                              (delivery_id,)).fetchone()
        if d["status"] not in store.DELIVERY_OPEN:
            return
        self.conn.execute("UPDATE deliveries SET status='EXPIRED' WHERE id=?", (delivery_id,))
        self.event("GATEWAY", "DELIVERY_EXPIRED",
                   {"delivery_id": delivery_id, "device_id": d["device_id"],
                    "seq": d["seq"], "reason": reason}, target=d["command_id"])

    def _redrive_held(self, device_id: str, now: float) -> list[str]:
        rows = self.conn.execute(
            "SELECT dl.id, c.execute_deadline FROM deliveries dl "
            "JOIN commands c ON c.id=dl.command_id "
            "WHERE dl.device_id=? AND dl.status='HELD' ORDER BY c.execute_after",
            (device_id,)).fetchall()
        recovered: list[str] = []
        for r in rows:
            if now > r["execute_deadline"]:
                self._expire_delivery(r["id"], "execute_window_closed")
            elif not self._device_busy(device_id):
                self._dispatch(r["id"], now)
                recovered.append(r["id"])
        return recovered

    def _finalize_command(self, command_id: str) -> None:
        cmd = self._get_command(command_id)
        if cmd["status"] in store.COMMAND_TERMINAL:
            return
        open_n = self.conn.execute(
            "SELECT COUNT(*) AS n FROM deliveries WHERE command_id=? AND status IN ('QUEUED','PENDING','HELD')",
            (command_id,)).fetchone()["n"]
        if open_n:
            return
        counts = {r["status"]: r["n"] for r in self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM deliveries WHERE command_id=? GROUP BY status",
            (command_id,))}
        delivered = counts.get(store.DELIVERED, 0)
        total = sum(counts.values())
        interrupted = counts.get(store.D_INTERRUPTED, 0)
        if delivered == total and total > 0:
            new_status, kind = store.COMPLETED, "COMMAND_COMPLETED"
        elif delivered > 0:
            new_status, kind = store.PARTIAL, "COMMAND_PARTIAL"
        elif interrupted > 0:
            new_status, kind = store.INTERRUPTED, "COMMAND_INTERRUPTED"
        elif counts.get(store.D_FAILED, 0) > 0:
            new_status, kind = store.FAILED, "COMMAND_FAILED"
        else:
            new_status, kind = store.EXPIRED, "COMMAND_EXPIRED"
        self.conn.execute("UPDATE commands SET status=? WHERE id=?",
                          (new_status, command_id))
        self.event("GATEWAY", kind,
                   {"command_id": command_id, "delivery_counts": counts}, target=command_id)

    # ---------------------------------------------------------------- 设备轮询/回执

    def poll(self, device: dict) -> dict:
        with self.lock:
            now = self.now()
            self._handshake(device, now)

            # 优先重发在途指令（同一 epoch/seq，幂等）。
            pend = self.conn.execute(
                "SELECT dl.*, c.action, c.params_json, c.execute_deadline "
                "FROM deliveries dl JOIN commands c ON c.id=dl.command_id "
                "WHERE dl.device_id=? AND dl.status='PENDING' "
                "AND c.execute_deadline>=? ORDER BY dl.dispatched_at LIMIT 1",
                (device["id"], now)).fetchone()
            if pend:
                self.conn.execute(
                    "UPDATE deliveries SET attempts=attempts+1 WHERE id=?", (pend["id"],))
                return {"delivery": self._delivery_payload(pend)}

            # 其次下发窗口内排队指令。
            q = self.conn.execute(
                "SELECT dl.*, c.action, c.params_json, c.execute_deadline "
                "FROM deliveries dl JOIN commands c ON c.id=dl.command_id "
                "WHERE dl.device_id=? AND dl.status IN ('QUEUED','HELD') "
                "AND c.status='ACTIVE' AND c.execute_after<=? AND c.execute_deadline>=? "
                "ORDER BY c.execute_after LIMIT 1",
                (device["id"], now, now)).fetchone()
            if q:
                self._dispatch(q["id"], now)
                row = self.conn.execute(
                    "SELECT dl.*, c.action, c.params_json, c.execute_deadline "
                    "FROM deliveries dl JOIN commands c ON c.id=dl.command_id "
                    "WHERE dl.id=?", (q["id"],)).fetchone()
                return {"delivery": self._delivery_payload(row)}
            return {"delivery": None, "epoch": self.epoch, "server_time": now}

    @staticmethod
    def _delivery_payload(row: dict) -> dict:
        return {"delivery_id": row["id"], "epoch": row["epoch"], "seq": row["seq"],
                "action": row["action"], "params": json.loads(row["params_json"]),
                "execute_deadline": row["execute_deadline"]}

    def process_receipt(self, device: dict, payload: Any) -> dict:
        """处理设备回执。任何拒收路径都只写 append-only 审计，不改变当前状态。"""
        with self.lock:
            now = self.now()
            did = device["id"]
            epoch = payload.get("epoch") if isinstance(payload, dict) else None
            seq = payload.get("seq") if isinstance(payload, dict) else None
            status = payload.get("status") if isinstance(payload, dict) else None
            note = payload.get("note") if isinstance(payload, dict) else None

            def reject(verdict: str, detail: str, http_status: int = 409):
                self.audit_receipt(did, payload, verdict, detail, epoch, seq, status, note)
                self.event(did, "DEVICE_RECEIPT_REJECTED",
                           {"verdict": verdict, "detail": detail, "epoch": epoch, "seq": seq})
                raise DomainError(verdict, detail, http_status)

            if not isinstance(payload, dict):
                self.audit_receipt(did, payload, "REJECTED_MALFORMED", "回执不是 JSON 对象",
                                   None, None, None, None)
                raise DomainError("REJECTED_MALFORMED", "回执必须是 JSON 对象", 400)
            if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
                reject("REJECTED_MALFORMED", "epoch 必须是非负整数", 400)
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
                reject("REJECTED_MALFORMED", "seq 必须是 >=1 的整数", 400)
            if not isinstance(status, str) or not status.strip():
                reject("REJECTED_MALFORMED", "status 必须是非空字符串", 400)

            dev = self.conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()

            # 旧启动代号：直接拒绝，设备必须先在新代号 hello/poll 握手。
            if epoch != self.epoch:
                reject("REJECTED_STALE_EPOCH",
                       f"启动代号 {epoch} 已失效，当前代号 {self.epoch}（可能发生过网关重启）")
            if dev["last_epoch"] != self.epoch:
                reject("REJECTED_EPOCH_NOT_SYNCHRONIZED",
                       "设备尚未在当前启动代号完成 hello 握手")

            d = self.conn.execute(
                "SELECT dl.*, c.execute_deadline FROM deliveries dl "
                "JOIN commands c ON c.id=dl.command_id "
                "WHERE dl.device_id=? AND dl.epoch=? AND dl.seq=?",
                (did, epoch, seq)).fetchone()
            if d is None:
                # 未知序号：不匹配任何已下发投递，绝不据此推进任何状态。
                reject("REJECTED_UNKNOWN_SEQ",
                       f"代号 {epoch} 内序号 {seq} 没有对应的已下发投递")

            # 乱序：必须是该设备当前期待的下一个序号。
            if seq != int(dev["last_seq"]):
                reject("REJECTED_OUT_OF_ORDER",
                       f"乱序回执：收到 seq={seq}，当前期待 seq={dev['last_seq']}")

            if d["status"] == store.DELIVERED:
                if status.strip().upper() == "OK":
                    reject("REJECTED_DUPLICATE",
                           f"seq={seq} 已成功执行并记录，重复回执不改变状态")
                reject("REJECTED_CONFLICT",
                       f"seq={seq} 已标记 DELIVERED，冲突回执被拒绝")
            if d["status"] in (store.D_EXPIRED, store.D_INTERRUPTED, store.D_FAILED):
                reject("REJECTED_TERMINAL",
                       f"投递已处于终态 {d['status']}，迟到回执不能改变状态")
            if now > d["execute_deadline"]:
                # 竞态兜底：窗口已关闭，回执再成功也不得执行（由 sweeper 置终态）。
                self._expire_delivery(d["id"], "execute_window_closed")
                reject("REJECTED_TERMINAL", "有效窗口已结束，回执迟到")
            if d["status"] != store.PENDING:
                reject("REJECTED_NOT_DISPATCHED",
                       f"投递状态 {d['status']}，尚无在途下发，拒绝回执")

            outcome = status.strip().upper()
            if outcome == "OK":
                self.conn.execute(
                    "UPDATE deliveries SET status='DELIVERED', acked_at=?, receipt_note=? "
                    "WHERE id=?", (now, note, d["id"]))
                self.audit_receipt(did, payload, "ACCEPTED",
                                   f"执行成功确认，epoch={epoch} seq={seq}",
                                   epoch, seq, status, note)
                self.event(did, "DEVICE_ACK",
                           {"delivery_id": d["id"], "command_id": d["command_id"],
                            "epoch": epoch, "seq": seq, "note": note},
                           target=d["command_id"])
                self._finalize_command(d["command_id"])
                cmd = self.get_command(d["command_id"])
                return {"accepted": True, "delivery_id": d["id"],
                        "command_id": d["command_id"], "command_status": cmd["status"]}

            # 设备报告执行失败：记录为终态事实（未执行），不做自动重试。
            self.conn.execute(
                "UPDATE deliveries SET status='FAILED', acked_at=?, receipt_note=? WHERE id=?",
                (now, f"DEVICE_REPORTED_FAILURE: {note or status}", d["id"]))
            self.audit_receipt(did, payload, "ACCEPTED_FAILURE_REPORT",
                               f"设备报告未执行成功，epoch={epoch} seq={seq}",
                               epoch, seq, status, note)
            self.event(did, "DEVICE_NACK",
                       {"delivery_id": d["id"], "command_id": d["command_id"],
                        "seq": seq, "status": status, "note": note},
                       target=d["command_id"])
            self._finalize_command(d["command_id"])
            return {"accepted": True, "executed": False, "delivery_id": d["id"],
                    "command_id": d["command_id"],
                    "command_status": self.get_command(d["command_id"])["status"]}

    # ---------------------------------------------------------------- 后台扫描

    def sweeper_tick(self) -> None:
        with self.lock:
            now = self.now()
            # 确认超时
            for r in self.conn.execute(
                "SELECT id FROM commands WHERE status='PENDING_CONFIRM' AND confirm_deadline<?",
                (now,)).fetchall():
                self.conn.execute("UPDATE commands SET status='EXPIRED' WHERE id=?", (r["id"],))
                self.event("GATEWAY", "COMMAND_EXPIRED",
                           {"command_id": r["id"], "reason": "confirm_timeout"},
                           target=r["id"])

            # 窗口推进 / 过期
            for r in self.conn.execute(
                "SELECT id, execute_after, execute_deadline, status FROM commands "
                "WHERE status IN ('CONFIRMED_READY','ACTIVE')").fetchall():
                if r["status"] == store.CONFIRMED_READY:
                    if now >= r["execute_after"]:
                        self.conn.execute("UPDATE commands SET status='ACTIVE' WHERE id=?",
                                          (r["id"],))
                        self.event("GATEWAY", "COMMAND_ACTIVATED",
                                   {"command_id": r["id"]}, target=r["id"])
                self._promote_deliveries(r["id"], now)
                self._finalize_command(r["id"])

            # 离线判定
            stale = self.conn.execute(
                "SELECT id FROM devices WHERE online=1 AND last_seen<?",
                (now - self.offline_after,)).fetchall()
            for r in stale:
                self.conn.execute("UPDATE devices SET online=0 WHERE id=?", (r["id"],))
                self.event("GATEWAY", "DEVICE_OFFLINE",
                           {"device_id": r["id"], "last_seen_threshold": self.offline_after},
                           target=r["id"])

    def start_sweeper(self, interval: float = 0.5) -> None:
        if self._sweeper_thread:
            return

        def loop():
            while not self._sweeper_stop.wait(interval):
                try:
                    self.sweeper_tick()
                except Exception as exc:  # 扫描线程永不致死
                    self.event("GATEWAY", "SWEEPER_ERROR", {"error": repr(exc)})

        self._sweeper_thread = threading.Thread(
            target=loop, name="gateway-sweeper", daemon=True)
        self._sweeper_thread.start()

    def stop_sweeper(self) -> None:
        self._sweeper_stop.set()

    # ---------------------------------------------------------------- 查询视图

    def _get_command(self, command_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM commands WHERE id=?",
                                (command_id,)).fetchone()
        if not row:
            raise DomainError("COMMAND_NOT_FOUND", f"指令 {command_id} 不存在", 404)
        return row

    def get_command(self, command_id: str) -> dict:
        with self.lock:
            cmd = self._get_command(command_id)
            return self._command_view(cmd)

    def _command_view(self, cmd: dict) -> dict:
        deliveries = []
        for d in self.conn.execute(
            "SELECT dl.*, dv.name AS device_name FROM deliveries dl "
            "JOIN devices dv ON dv.id=dl.device_id WHERE dl.command_id=? "
            "ORDER BY dl.dispatched_at", (cmd["id"],)).fetchall():
            deliveries.append({k: d[k] for k in d.keys()})
        rev = self.conn.execute(
            "SELECT reason, by, at FROM revocations WHERE command_id=?",
            (cmd["id"],)).fetchone()
        return {
            "id": cmd["id"], "creator": cmd["creator"], "action": cmd["action"],
            "params": json.loads(cmd["params_json"]),
            "param_digest": cmd["param_digest"],
            "device_ids": json.loads(cmd["device_ids_json"]),
            "created_at": cmd["created_at"],
            "confirm_deadline": cmd["confirm_deadline"],
            "execute_after": cmd["execute_after"],
            "execute_deadline": cmd["execute_deadline"],
            "status": cmd["status"],
            "confirmed_by": cmd["confirmed_by"], "confirmed_at": cmd["confirmed_at"],
            "deliveries": deliveries,
            "revocation": dict(rev) if rev else None,
        }

    def list_commands(self, status: Optional[str] = None) -> list[dict]:
        with self.lock:
            if status:
                rows = self.conn.execute(
                    "SELECT * FROM commands WHERE status=? ORDER BY created_at", (status,))
            else:
                rows = self.conn.execute(
                    "SELECT * FROM commands ORDER BY created_at DESC")
            return [self._command_view(r) for r in rows]

    def pending_confirmations(self) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE status='PENDING_CONFIRM' ORDER BY confirm_deadline")
            return [self._command_view(r) for r in rows]

    def list_devices(self) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM devices ORDER BY registered_at")
            return [{k: r[k] for k in r.keys() if k != "token"} for r in rows]

    def list_receipts(self, verdict: Optional[str] = None,
                      device_id: Optional[str] = None, limit: int = 200) -> list[dict]:
        with self.lock:
            sql = "SELECT * FROM receipts_audit WHERE 1=1"
            args: list[Any] = []
            if verdict:
                sql += " AND verdict=?"; args.append(verdict)
            if device_id:
                sql += " AND device_id=?"; args.append(device_id)
            sql += " ORDER BY received_at DESC, id DESC LIMIT ?"; args.append(int(limit))
            rows = self.conn.execute(sql, args).fetchall()
            out = []
            for r in rows:
                item = {k: r[k] for k in r.keys()}
                item["raw"] = json.loads(item.pop("raw_json"))
                out.append(item)
            return out

    def list_events(self, limit: int = 200) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id,at,actor,kind,target,detail FROM events "
                "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
            return [dict(r) for r in rows]
