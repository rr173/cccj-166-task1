# 工业控制指令双通道确认网关

高风险工业控制指令的**双通道职责分离**确认网关：业务系统只能创建/撤销指令；
指令必须由**独立安全通道上的第二角色**复核参数摘要后才能布防下发；现场设备以
**启动代号（epoch）+ 代号内递增序号（seq）**回执，旧代号、乱序、未知序号、重复
回执全部只进审计、不改变当前状态。撤销、确认超时、网关重启、设备离线恢复均保证：

> **未执行的指令不得误执行；已执行的事实不能被撤销或重启覆盖。**

仅依赖 Python 3.11 标准库，持久化使用 SQLite（含冻结/只追加/终态触发器）。

## 目录

```
gateway/
  store.py       表结构与数据库触发器（冻结、只追加、DELIVERED 不可回退）
  gateway.py     核心领域逻辑：状态机、冻结确认、epoch/seq 校验、重启恢复、扫描器
  channels.py    三个互相隔离的 HTTP 通道（端口 + 凭证互不相同）
  workbench.py   第二角色确认工作台（单页，托管于安全通道 /ui）
  app.py         启动入口
  device_sim.py  现场设备模拟器（正常 / 旧代号 / 乱序 / 重复 / NACK）
tests/
  test_gateway.py  79 项端到端断言（真实三端口 HTTP + 可控时钟 + 多次重启）
  smoke_live.py    真实子进程冒烟（含 SIGTERM 重启恢复）
```

## 启动

```bash
python -m gateway.app --db gateway.db
# 业务通道 http://127.0.0.1:18080  (Bearer <business_token>)
# 安全通道 http://127.0.0.1:18081  (Bearer <safety_token>；工作台 /ui)
# 设备通道 http://127.0.0.1:18082  (X-Device-Id / X-Device-Token)
```

首次启动自动生成两枚通道令牌并写入 `gateway.db.tokens.json`（权限 0600），
也可用 `--business-token` / `--safety-token` 指定。**每次进程启动 epoch 自动 +1**，
设备必须重新 `hello` 握手后才会在新代号接收投递。

## 指令生命周期

```
PENDING_CONFIRM ──第二角色摘要确认──► CONFIRMED_READY ──到 execute_after──► ACTIVE
     │ 撤销(仅此前)                       （重启保留，窗口到了在新代号下发）     │
     ▼                                                            全部 DELIVERED ▼ COMPLETED
   REVOKED                                                    部分成功 → PARTIAL
确认超时 / 执行窗口结束未执行 → EXPIRED                       全失败 → FAILED
重启时在途未回执 → INTERRUPTED（旧代号回执一律拒绝）
```

每台设备的每个目标生成一条 `deliveries`：
`QUEUED → PENDING(下发,分配 epoch/seq) → DELIVERED(设备OK回执，不可逆)`；
离线时 `HELD`（窗口内恢复重投）；窗口结束 `EXPIRED`；重启在途 `INTERRUPTED`。

## API

### 业务通道 18080（业务令牌；无确认操作）
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/devices` | `{name}` 注册设备，返回一机一令牌（仅展示一次） |
| GET | `/devices` | 设备列表 |
| POST | `/commands` | 创建高风险指令（冻结设备集/参数/窗口，见下） |
| GET | `/commands?status=` | 指令列表 |
| GET | `/commands/{id}` | 指令与每设备投递详情 |
| POST | `/commands/{id}/revoke` | **仅 PENDING_CONFIRM 可撤销** `{by,reason}` |

创建请求：
```json
{"creator":"scada-op-1","action":"REACTOR_FEED_OPEN",
 "params":{"valve":"feed","open_pct":100},
 "device_ids":["D-xxx","D-yyy"],
 "confirm_deadline":1700000030,"execute_after":1700000035,
 "execute_deadline":1700000090}
```
约束 `now < confirm_deadline ≤ execute_after < execute_deadline`。
响应返回冻结的 `param_digest = sha256(规范化JSON(params))`。

### 安全通道 18081（安全令牌；第二角色独占）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/pending` | 待确认工作台队列 |
| POST | `/commands/{id}/confirm` | `{role,digest}`，**digest 必须与冻结摘要逐字节一致** |
| GET | `/commands`、`/commands/{id}` | 只读核查 |
| GET | `/audit/receipts?verdict=&device_id=&limit=` | 回执审计（只追加，含全部拒收） |
| GET | `/audit/events?limit=` | 事件链（只追加） |
| GET | `/ui` | 确认工作台页面（令牌在页面内输入） |

### 设备通道 18082（一机一令）
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/hello` | 代号握手；离线恢复，窗口内 HELD 自动重投 |
| POST | `/poll` | 长轮询式取指令（在途指令幂等重发，保持同一 epoch/seq） |
| POST | `/receipt` | `{epoch,seq,status,note}`，status=`OK` 表示已执行 |

回执拒收码（均不改状态，均落审计）：
`REJECTED_STALE_EPOCH`（旧启动代号/未握手）、`REJECTED_OUT_OF_ORDER`（序号回退）、
`REJECTED_UNKNOWN_SEQ`（查无此投递）、`REJECTED_DUPLICATE`（重复成功）、
`REJECTED_CONFLICT`（与 DELIVERED 事实冲突）、`REJECTED_TERMINAL`（投递已过期/中断，
或迟到回执）、`REJECTED_MALFORMED`。设备报告非 OK 时记 `FAILED`（未执行事实）。

## 关键安全机制

1. **冻结**：创建后设备集、参数 JSON、摘要、三个窗口时刻由 SQLite 触发器禁止
   UPDATE/DELETE；确认人必须回传独立计算的摘要，篡改即 `DIGEST_MISMATCH`。
2. **双通道**：确认接口只存在于安全通道，撤销只存在于业务通道；令牌不通用，
   生产环境应把 18081 部署在物理/逻辑隔离网络。
3. **启动代号 + 递增序号**：每次重启 epoch+1，设备需重新握手；网关只接受
   `epoch==当前 && seq==该设备当前期待序号` 的回执；唯一约束
   `UNIQUE(device_id,epoch,seq)` 防止序号复用。
4. **重启恢复**：在途 QUEUED/PENDING/HELD 一律置 INTERRUPTED（窗口已过则 EXPIRED），
   绝不在新代号自动重放；DELIVERED 由触发器 `trg_delivery_delivered_terminal`
   在数据库层禁止回退；CONFIRMED_READY（窗口未到）保留，到点后按新代号下发；
   PENDING_CONFIRM 保留但仍需第二角色确认。
5. **离线恢复**：离线期间投递 HELD，hello 时若仍在执行窗口则重新下发，窗口已过
   则 EXPIRED；设备在线由最后心跳超时判定。
6. **只追加审计**：`receipts_audit`（含拒收原因与原始报文）、`events` 均由触发器
   禁止 UPDATE/DELETE。
7. **串行化**：所有领域写操作经网关全局锁 + 单后台扫描线程推进，避免并发状态竞争。

## 设备模拟器

```bash
python -m gateway.device_sim --device-id D-xxx --token TOKEN --mode normal
# mode: normal | stale-epoch | out-of-order | duplicate | nack
```

## 测试

```bash
python tests/test_gateway.py   # 79 项：正常流程、各类坏回执、撤销/超时、
                               #       多次重启、离线恢复、忙排队、通道隔离、触发器
python tests/smoke_live.py     # 真实进程：创建→确认→在途→SIGTERM 重启→旧代号拒收
```
