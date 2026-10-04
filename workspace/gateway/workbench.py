"""第二角色确认工作台（单页，托管在独立安全通道上）。"""

from __future__ import annotations

WORKBENCH_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>高风险指令 · 第二角色确认工作台</title>
<style>
  :root { --bg:#0f1420; --panel:#171e2e; --line:#28324a; --fg:#e6ebf5;
          --muted:#8b96ad; --ok:#2ecc71; --warn:#f39c12; --bad:#e74c3c; --accent:#4f8cff; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:14px 22px; border-bottom:1px solid var(--line); display:flex;
           align-items:center; gap:16px; background:#121827; }
  header h1 { font-size:16px; margin:0; }
  .badge { padding:2px 8px; border-radius:10px; font-size:12px; }
  .badge.safety { background:#23304d; color:#9db8ff; border:1px solid #344a7a; }
  .epoch { color:var(--muted); font-size:12px; }
  main { padding:18px 22px; max-width:1180px; margin:0 auto; }
  .tabs { display:flex; gap:6px; margin-bottom:14px; flex-wrap:wrap; }
  .tabs button { background:var(--panel); color:var(--muted); border:1px solid var(--line);
           padding:7px 14px; border-radius:8px; cursor:pointer; }
  .tabs button.active { color:#fff; border-color:var(--accent); background:#1b2740; }
  .login { background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:26px; max-width:460px; }
  .login input { width:100%; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px;
          margin-bottom:12px; overflow:hidden; }
  .card .hd { padding:12px 16px; display:flex; align-items:center; gap:10px; cursor:pointer;
          flex-wrap:wrap; }
  .card .bd { padding:0 16px 14px; border-top:1px solid var(--line); }
  .card.confirmable { border-color:#5a4a1e; }
  .grid { display:grid; grid-template-columns:130px 1fr; gap:4px 12px; margin:10px 0; }
  .grid .k { color:var(--muted); }
  code,pre { font-family:ui-monospace,Menlo,Consolas,monospace; }
  pre { background:#0c111d; border:1px solid var(--line); border-radius:6px;
        padding:10px; overflow:auto; font-size:12px; max-height:220px; }
  .digest { word-break:break-all; color:#8fd0ff; font-size:12px; }
  input[type=text],input[type=password] { background:#0c111d; border:1px solid var(--line);
        color:var(--fg); border-radius:6px; padding:8px 10px; }
  button.act { border:0; border-radius:7px; padding:8px 16px; cursor:pointer; font-weight:600; }
  button.confirm { background:var(--ok); color:#08210f; }
  button.deny { background:#3a2330; color:#e7a0a0; border:1px solid #5a2c38; }
  .st { font-size:12px; padding:1px 9px; border-radius:10px; border:1px solid var(--line); }
  .st-PENDING_CONFIRM { color:var(--warn); border-color:var(--warn); }
  .st-CONFIRMED_READY { color:#7ed6f0; border-color:#3a7f96; }
  .st-ACTIVE { color:#fff; background:#26407e; border-color:var(--accent); }
  .st-COMPLETED { color:var(--ok); border-color:var(--ok); }
  .st-PARTIAL { color:var(--warn); border-color:var(--warn); }
  .st-EXPIRED,.st-INTERRUPTED { color:var(--bad); border-color:var(--bad); }
  .st-REVOKED { color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 9px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--muted); font-weight:500; }
  .verdict-ACCEPTED { color:var(--ok); } .verdict-ACCEPTED_FAILURE_REPORT { color:var(--warn); }
  .verdict-REJECTED_STALE_EPOCH,.verdict-REJECTED_OUT_OF_ORDER,
  .verdict-REJECTED_UNKNOWN_SEQ,.verdict-REJECTED_DUPLICATE,
  .verdict-REJECTED_CONFLICT { color:var(--bad); }
  .muted { color:var(--muted); }
  .countdown { font-variant-numeric:tabular-nums; color:var(--warn); }
  .rowline { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:8px; }
  .okmsg { color:var(--ok); } .errmsg { color:var(--bad); }
  .hidden { display:none; }
  .dev-offline { color:var(--bad); } .dev-online { color:var(--ok); }
</style>
</head>
<body>
<header>
  <h1>🛡️ 高风险指令确认工作台</h1>
  <span class="badge safety">独立安全通道</span>
  <span class="epoch" id="epochInfo"></span>
  <span style="flex:1"></span>
  <label class="muted">安全令牌 <input type="password" id="token" placeholder="Bearer token"
         style="width:260px"/></label>
  <button class="act confirm" id="connectBtn">连接</button>
</header>
<main>
  <div id="loginHint" class="login hidden">
    <p>本工作台运行在<strong>独立安全通道</strong>上，与业务系统物理/凭证隔离。
       请输入第二角色（安全确认员）持有的安全通道令牌。</p>
    <p class="muted">令牌仅保存在本浏览器 localStorage。</p>
  </div>
  <div id="app" class="hidden">
    <div class="tabs">
      <button data-tab="pending" class="active">待确认 <span id="cntPending"></span></button>
      <button data-tab="commands">全部指令</button>
      <button data-tab="receipts">设备回执审计</button>
      <button data-tab="events">事件链</button>
      <button data-tab="devices">设备</button>
    </div>
    <div id="tab-pending"></div>
    <div id="tab-commands" class="hidden"></div>
    <div id="tab-receipts" class="hidden"></div>
    <div id="tab-events" class="hidden"></div>
    <div id="tab-devices" class="hidden"></div>
  </div>
</main>
<script>
const $ = s => document.querySelector(s);
const api = async (path, opts={}) => {
  const r = await fetch(path, Object.assign({
    headers: Object.assign({"Authorization":"Bearer "+localStorage.safetyToken},
      opts.body ? {"Content-Type":"application/json"} : {})
  }, opts));
  const j = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error((j.error||r.status)+": "+(j.message||""));
  return j;
};
const esc = s => String(s ?? "").replace(/[&<>]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const fmt = t => t ? new Date(t*1000).toLocaleString("zh-CN",{hour12:false}) : "—";
const st = s => `<span class="st st-${s}">${s}</span>`;

let currentTab = "pending";
document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  currentTab = b.dataset.tab;
  document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("active",x===b));
  ["pending","commands","receipts","events","devices"].forEach(t =>
    $("#tab-"+t).classList.toggle("hidden", t!==currentTab));
  refresh();
});

function countdown(deadline){
  const s = Math.max(0, Math.round(deadline - Date.now()/1000));
  return `<span class="countdown">${s}s</span>`;
}

function commandCard(c, confirmable){
  const frozen = {action:c.action, params:c.params, device_ids:c.device_ids};
  return `<div class="card ${confirmable?'confirmable':''}">
    <div class="hd" onclick="this.nextElementSibling.classList.toggle('hidden')">
      <strong>${esc(c.action)}</strong> ${st(c.status)}
      <span class="muted">${esc(c.id)}</span>
      <span style="flex:1"></span>
      ${confirmable ? `确认截止 ${countdown(c.confirm_deadline)}` : ""}
    </div>
    <div class="bd ${confirmable?'':'hidden'}">
      <div class="grid">
        <div class="k">创建人</div><div>${esc(c.creator)}</div>
        <div class="k">创建时间</div><div>${fmt(c.created_at)}</div>
        <div class="k">设备集合(冻结)</div><div>${c.device_ids.map(esc).join("，")}</div>
        <div class="k">确认截止</div><div>${fmt(c.confirm_deadline)}</div>
        <div class="k">最早下发</div><div>${fmt(c.execute_after)}</div>
        <div class="k">最晚执行</div><div>${fmt(c.execute_deadline)}</div>
        <div class="k">参数摘要</div><div class="digest">${esc(c.param_digest)}</div>
      </div>
      <div class="muted">冻结参数体：</div>
      <pre>${esc(JSON.stringify(c.params,null,2))}</pre>
      <div class="muted">各设备投递：</div>
      <table><tr><th>设备</th><th>状态</th><th>epoch</th><th>seq</th><th>回执时间</th><th>备注</th></tr>
      ${c.deliveries.map(d=>`<tr><td>${esc(d.device_id)}</td><td>${st(d.status)}</td>
        <td>${d.epoch ?? "—"}</td><td>${d.seq ?? "—"}</td><td>${fmt(d.acked_at)}</td>
        <td>${esc(d.receipt_note||"")}</td></tr>`).join("")}
      </table>
      ${confirmable ? `
      <div class="rowline">
        <input type="text" id="dg-${esc(c.id)}" style="width:480px"
          placeholder="粘贴你独立计算/核对得到的参数摘要 sha256"/>
        <input type="text" id="role-${esc(c.id)}" style="width:150px"
          value="SAFETY_OFFICER" placeholder="确认角色"/>
        <button class="act confirm" onclick="doConfirm('${esc(c.id)}')">第二角色确认并布防</button>
        <span id="msg-${esc(c.id)}"></span>
      </div>` : ""}
    </div>
  </div>`;
}

window.doConfirm = async id => {
  const digest = $("#dg-"+id).value.trim();
  const role = $("#role-"+id).value.trim() || "SAFETY_OFFICER";
  const msg = $("#msg-"+id);
  msg.className = ""; msg.textContent = "提交中…";
  try {
    const r = await api(`/commands/${encodeURIComponent(id)}/confirm`,
      {method:"POST", body:JSON.stringify({digest, role})});
    msg.className = "okmsg"; msg.textContent = "已确认 → "+r.status;
  } catch(e) {
    msg.className = "errmsg"; msg.textContent = "拒绝确认："+e.message;
  }
  refresh();
};

async function renderPending(){
  const list = (await api("/pending")).commands;
  $("#cntPending").textContent = list.length ? `(${list.length})` : "";
  $("#tab-pending").innerHTML = list.length
    ? list.map(c=>commandCard(c,true)).join("")
    : `<p class="muted">没有等待第二角色确认的高风险指令。</p>`;
}
async function renderCommands(){
  const list = (await api("/commands")).commands;
  $("#tab-commands").innerHTML = list.map(c=>commandCard(c,false)).join("")
    || `<p class="muted">暂无指令。</p>`;
}
async function renderReceipts(){
  const list = (await api("/audit/receipts?limit=300")).receipts;
  $("#tab-receipts").innerHTML = `<table>
    <tr><th>时间</th><th>设备</th><th>代号</th><th>序号</th><th>结论</th><th>说明</th><th>原始回执</th></tr>
    ${list.map(r=>`<tr><td>${fmt(r.received_at)}</td><td>${esc(r.device_id)}</td>
      <td>${r.epoch ?? ""}</td><td>${r.seq ?? ""}</td>
      <td class="verdict-${esc(r.verdict)}">${esc(r.verdict)}</td>
      <td>${esc(r.detail)}</td>
      <td><pre style="max-height:80px;margin:0">${esc(JSON.stringify(r.raw))}</pre></td></tr>`).join("")}
    </table>${list.length?"":'<p class="muted">暂无回执记录。</p>'}`;
}
async function renderEvents(){
  const list = (await api("/audit/events?limit=300")).events;
  $("#tab-events").innerHTML = `<table>
    <tr><th>#</th><th>时间</th><th>来源</th><th>事件</th><th>对象</th><th>详情</th></tr>
    ${list.map(e=>`<tr><td>${e.id}</td><td>${fmt(e.at)}</td><td>${esc(e.actor)}</td>
      <td>${esc(e.kind)}</td><td>${esc(e.target||"")}</td>
      <td><pre style="max-height:70px;margin:0">${esc(e.detail)}</pre></td></tr>`).join("")}
    </table>`;
}
async function renderDevices(){
  const list = (await api("/devices")).devices;
  $("#tab-devices").innerHTML = `<table>
    <tr><th>设备ID</th><th>名称</th><th>状态</th><th>当前代号</th><th>当前序号</th><th>最近在线</th></tr>
    ${list.map(d=>`<tr><td>${esc(d.id)}</td><td>${esc(d.name)}</td>
      <td class="${d.online?'dev-online':'dev-offline'}">${d.online?'在线':'离线'}</td>
      <td>${d.last_epoch}</td><td>${d.last_seq}</td><td>${fmt(d.last_seen)}</td></tr>`).join("")}
    </table>`;
}

async function refresh(){
  if (!localStorage.safetyToken) return;
  try {
    const h = await api("/health");
    $("#epochInfo").textContent = `网关启动代号 epoch=${h.epoch}`;
    ({pending:renderPending, commands:renderCommands, receipts:renderReceipts,
      events:renderEvents, devices:renderDevices})[currentTab]();
  } catch(e){ /* 定时刷新中的瞬时错误忽略 */ }
}

$("#connectBtn").onclick = () => {
  const v = $("#token").value.trim();
  if (v) localStorage.safetyToken = v;
  if (localStorage.safetyToken){
    $("#app").classList.remove("hidden"); $("#loginHint").classList.add("hidden");
    refresh();
  }
};
if (localStorage.safetyToken){
  $("#token").value = localStorage.safetyToken;
  $("#app").classList.remove("hidden");
  refresh();
} else {
  $("#loginHint").classList.remove("hidden");
}
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
