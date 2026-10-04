"""存储层：SQLite 持久化 + 冻结/只追加/事实不可回退的数据库约束。

所有业务写操作都通过 Gateway 持有的全局锁串行化（见 gateway.py）。
本模块只负责表结构、连接与触发器，不包含业务规则。
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    token         TEXT NOT NULL,
    registered_at REAL NOT NULL,
    last_seen     REAL,
    last_epoch    INTEGER NOT NULL DEFAULT 0,
    last_seq      INTEGER NOT NULL DEFAULT 0,
    online        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id                 TEXT PRIMARY KEY,
    creator            TEXT NOT NULL,
    action             TEXT NOT NULL,
    params_json        TEXT NOT NULL,   -- 冻结的原始参数（规范化 JSON）
    param_digest       TEXT NOT NULL,   -- 冻结的参数摘要 sha256
    device_ids_json    TEXT NOT NULL,   -- 冻结的设备集合
    created_at         REAL NOT NULL,
    confirm_deadline   REAL NOT NULL,   -- 第二角色确认截止（有效窗口前段）
    execute_after      REAL NOT NULL,   -- 最早下发时刻
    execute_deadline   REAL NOT NULL,   -- 最晚下发/执行时刻
    status             TEXT NOT NULL,
    confirmed_by       TEXT,
    confirmed_at       REAL
);

CREATE TABLE IF NOT EXISTS confirmations (
    id          TEXT PRIMARY KEY,
    command_id  TEXT NOT NULL,
    role        TEXT NOT NULL,
    digest      TEXT NOT NULL,          -- 确认人复核的参数摘要
    at          REAL NOT NULL,
    UNIQUE(command_id, role)
);

CREATE TABLE IF NOT EXISTS deliveries (
    id             TEXT PRIMARY KEY,
    command_id     TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    epoch          INTEGER NOT NULL,    -- 下发时的网关启动代号
    seq            INTEGER,             -- 该设备在该代号内的递增序号
    status         TEXT NOT NULL,       -- QUEUED/PENDING/HELD/DELIVERED/EXPIRED/INTERRUPTED
    attempts       INTEGER NOT NULL DEFAULT 0,
    dispatched_at  REAL,
    acked_at       REAL,
    receipt_note   TEXT,
    UNIQUE(device_id, epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_command ON deliveries(command_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_device_status ON deliveries(device_id, status);

CREATE TABLE IF NOT EXISTS receipts_audit (
    id           TEXT PRIMARY KEY,
    received_at  REAL NOT NULL,
    device_id    TEXT,
    epoch        INTEGER,
    seq          INTEGER,
    status       TEXT,
    note         TEXT,
    verdict      TEXT NOT NULL,         -- ACCEPTED / REJECTED_*
    detail       TEXT NOT NULL,
    raw_json     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    actor      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    target     TEXT,
    detail     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    id          TEXT PRIMARY KEY,
    command_id  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    by          TEXT NOT NULL,
    at          REAL NOT NULL
);

-- 事件链只追加
CREATE TRIGGER IF NOT EXISTS trg_events_immutable
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_events_nodelete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

-- 回执审计只追加
CREATE TRIGGER IF NOT EXISTS trg_receipts_immutable
BEFORE UPDATE ON receipts_audit
BEGIN
    SELECT RAISE(ABORT, 'receipts_audit are append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_receipts_nodelete
BEFORE DELETE ON receipts_audit
BEGIN
    SELECT RAISE(ABORT, 'receipts_audit are append-only');
END;

-- 指令一旦创建，冻结字段（设备集合/参数摘要/参数体/窗口/创建人/动作）不可修改。
-- status、confirmed_* 是网关受控状态机字段，允许由网关自身推进。
CREATE TRIGGER IF NOT EXISTS trg_command_freeze
BEFORE UPDATE OF creator, action, params_json, param_digest,
                 device_ids_json, created_at, confirm_deadline,
                 execute_after, execute_deadline ON commands
BEGIN
    SELECT RAISE(ABORT, 'command is frozen after creation');
END;
CREATE TRIGGER IF NOT EXISTS trg_command_nodelete
BEFORE DELETE ON commands
BEGIN
    SELECT RAISE(ABORT, 'commands cannot be deleted');
END;

-- 已执行事实（DELIVERED）是终态，数据库层禁止回退/篡改。
CREATE TRIGGER IF NOT EXISTS trg_delivery_delivered_terminal
BEFORE UPDATE OF status ON deliveries
WHEN OLD.status = 'DELIVERED'
BEGIN
    SELECT RAISE(ABORT, 'DELIVERED is an irreversible fact');
END;
CREATE TRIGGER IF NOT EXISTS trg_delivery_nodelete
BEFORE DELETE ON deliveries
BEGIN
    SELECT RAISE(ABORT, 'deliveries cannot be deleted');
END;
"""

# 指令状态
PENDING_CONFIRM = "PENDING_CONFIRM"          # 已冻结，等待第二角色确认
CONFIRMED_READY = "CONFIRMED_READY"          # 已确认，未到最早下发时刻
ACTIVE = "ACTIVE"                            # 已确认且在下发窗口内，逐设备下发中
REVOKED = "REVOKED"                          # 下发前撤销
EXPIRED = "EXPIRED"                          # 确认超时 / 窗口结束仍全部未执行
INTERRUPTED = "INTERRUPTED"                  # 网关重启时在途且无成功执行
COMPLETED = "COMPLETED"                      # 全部设备回执成功
PARTIAL = "PARTIAL"                          # 部分设备执行成功，其余终态
FAILED = "FAILED"                           # 确认通过但无任何可下发设备（防御性）

COMMAND_TERMINAL = {REVOKED, EXPIRED, INTERRUPTED, COMPLETED, PARTIAL, FAILED}

# 投递状态
QUEUED = "QUEUED"          # 已确认但设备正忙（前面还有未完成指令）
PENDING = "PENDING"        # 已下发到设备，等待回执
HELD = "HELD"              # 该设备离线期间窗口已过前的待命态（离线恢复时再决策）
DELIVERED = "DELIVERED"    # 设备回执确认执行（不可变事实）
D_EXPIRED = "EXPIRED"      # 窗口结束未执行
D_INTERRUPTED = "INTERRUPTED"  # 重启时在途，本代号作废
D_FAILED = "FAILED"       # 设备明确回执执行失败（终态事实：未执行）

# 非终态（仍可推进）；DELIVERED/EXPIRED/INTERRUPTED/FAILED 为终态
DELIVERY_OPEN = {QUEUED, PENDING, HELD}
DELIVERY_TERMINAL = {DELIVERED, D_EXPIRED, D_INTERRUPTED, D_FAILED}


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    return conn
