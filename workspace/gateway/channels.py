"""HTTP 通道层：三个互相独立的通道，端口与凭证彼此隔离。

- 业务通道 BUSINESS_PORT：创建/撤销指令、注册设备（业务系统令牌）
- 安全通道 SAFETY_PORT  ：第二角色确认、确认工作台、回执审计/事件链（安全通道令牌）
- 设备通道 DEVICE_PORT  ：设备 hello/poll/回执（一机一令牌）
通道之间不共用令牌，也不暴露彼此的操作；生产部署应将端口置于物理隔离网络。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from .gateway import DomainError, Gateway

BUSINESS_PORT = 18080
SAFETY_PORT = 18081
DEVICE_PORT = 18082


def _json_response(handler: BaseHTTPRequestHandler, code: int, body: Any) -> None:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


# 分发器已自行写出响应时返回该哨兵，框架不再重复写
ALREADY_WRITTEN = object()


def _constant_token_ok(provided: Optional[str], expected: str) -> bool:
    return bool(provided) and _ccd(provided, expected)


def _ccd(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(str(a), str(b))


def _read_json(handler: BaseHTTPRequestHandler) -> Any:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise DomainError("MALFORMED_JSON", "请求体不是合法 JSON", 400)


def _require_fields(body: dict, fields: list[str]) -> None:
    for f in fields:
        if f not in body:
            raise DomainError("MISSING_FIELD", f"缺少字段: {f}", 400)


def _bearer(handler: BaseHTTPRequestHandler) -> Optional[str]:
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


class _BaseHandler(BaseHTTPRequestHandler):
    gw: Gateway = None  # 由工厂注入
    log_traffic = True

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.log_traffic:
            super().log_message(fmt, *args)

    # 子类提供
    def _authenticate(self, method: str, path: str) -> None:
        raise NotImplementedError

    def _dispatch(self, method: str, path: str, qs: dict[str, list[str]],
                  body: Any) -> tuple[int, Any]:
        raise NotImplementedError

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        body: Any = None
        try:
            if self.command in ("POST", "PUT"):
                body = _read_json(self)
            self._authenticate(self.command, path)
            code, payload = self._dispatch(self.command, path, qs, body)
            if payload is ALREADY_WRITTEN:
                return
        except DomainError as exc:
            code, payload = exc.http_status, {"error": exc.code, "message": str(exc)}
        except Exception as exc:  # 单请求故障不拖垮通道
            code, payload = 500, {"error": "INTERNAL", "message": repr(exc)}
        _json_response(self, code, payload)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()


# ---------------------------------------------------------------------- 业务通道

class _BusinessHandler(_BaseHandler):
    def _authenticate(self, method: str, path: str) -> None:
        # 健康检查不要求令牌；其它一切操作必须使用业务令牌。
        if method == "GET" and path == "/health":
            return
        if not _constant_token_ok(_bearer(self), self.gw.business_token):
            raise DomainError("UNAUTHORIZED", "需要业务通道令牌 (Bearer)", 401)

    def _dispatch(self, method, path, qs, body):
        gw = self.gw
        if method == "GET" and path == "/health":
            return 200, {"channel": "business", "epoch": gw.epoch, "ok": True}

        if method == "POST" and path == "/devices":
            _require_fields(body, ["name"])
            return 201, gw.register_device(body["name"], body.get("device_id"))

        if method == "GET" and path == "/devices":
            return 200, {"devices": gw.list_devices()}

        if method == "POST" and path == "/commands":
            _require_fields(body, ["creator", "action", "params", "device_ids",
                                   "confirm_deadline", "execute_after",
                                   "execute_deadline"])
            return 201, gw.create_command(
                body["creator"], body["action"], body["params"], body["device_ids"],
                body["confirm_deadline"], body["execute_after"], body["execute_deadline"])

        if method == "GET" and path == "/commands":
            return 200, {"commands": gw.list_commands(qs.get("status", [None])[0])}

        if path.startswith("/commands/"):
            cid = path.split("/")[2]
            if method == "GET":
                return 200, gw.get_command(cid)
            if method == "POST" and path.endswith("/revoke"):
                _require_fields(body, ["by"])
                return 200, gw.revoke_command(cid, body.get("reason", ""), body["by"])

        raise DomainError("NOT_FOUND", f"业务通道不存在 {method} {path}", 404)


# ---------------------------------------------------------------------- 安全通道

WORKBENCH_HTML = None  # 延迟加载，见 workbench.py


class _SafetyHandler(_BaseHandler):
    def _authenticate(self, method: str, path: str) -> None:
        if method == "GET" and path in ("/health", "/ui", "/ui/"):
            return
        if not _constant_token_ok(_bearer(self), self.gw.safety_token):
            raise DomainError("UNAUTHORIZED", "需要独立安全通道令牌 (Bearer)", 401)

    def _dispatch(self, method, path, qs, body):
        gw = self.gw
        if method == "GET" and path == "/health":
            return 200, {"channel": "safety", "epoch": gw.epoch, "ok": True}

        if method == "GET" and path in ("/ui", "/ui/"):
            from .workbench import WORKBENCH_HTML
            data = WORKBENCH_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return 200, ALREADY_WRITTEN

        if method == "GET" and path == "/pending":
            return 200, {"commands": gw.pending_confirmations()}

        if path.startswith("/commands/"):
            cid = path.split("/")[2]
            if method == "GET":
                return 200, gw.get_command(cid)
            if method == "POST" and path.endswith("/confirm"):
                _require_fields(body, ["digest"])
                return 200, gw.confirm_command(cid, body.get("role", "SAFETY_OFFICER"),
                                               body["digest"])

        if method == "GET" and path == "/commands":
            return 200, {"commands": gw.list_commands(qs.get("status", [None])[0])}

        if method == "GET" and path == "/audit/receipts":
            return 200, {"receipts": gw.list_receipts(
                qs.get("verdict", [None])[0], qs.get("device_id", [None])[0],
                int(qs.get("limit", ["200"])[0]))}

        if method == "GET" and path == "/audit/events":
            return 200, {"events": gw.list_events(int(qs.get("limit", ["200"])[0]))}

        if method == "GET" and path == "/devices":
            return 200, {"devices": gw.list_devices()}

        raise DomainError("NOT_FOUND", f"安全通道不存在 {method} {path}", 404)


# ---------------------------------------------------------------------- 设备通道

class _DeviceHandler(_BaseHandler):
    def _authenticate(self, method: str, path: str) -> None:
        if method == "GET" and path == "/health":
            return
        # 设备通道使用 X-Device-Id + X-Device-Token（或 body 中的同名字段）。
        did = self.headers.get("X-Device-Id")
        token = self.headers.get("X-Device-Token")
        if did and token:
            self._device_row = self.gw.authenticate_device(did, token)
            return
        raise DomainError("UNAUTHORIZED",
                          "需要设备通道凭证 (X-Device-Id / X-Device-Token)", 401)

    def _dispatch(self, method, path, qs, body):
        gw = self.gw
        dev = getattr(self, "_device_row", None)
        if method == "GET" and path == "/health":
            return 200, {"channel": "device", "epoch": gw.epoch, "ok": True}
        if method == "POST" and path == "/hello":
            return 200, gw.hello(dev)
        if method == "POST" and path == "/poll":
            return 200, gw.poll(dev)
        if method == "POST" and path == "/receipt":
            return 200, gw.process_receipt(dev, body)
        raise DomainError("NOT_FOUND", f"设备通道不存在 {method} {path}", 404)


# ---------------------------------------------------------------------- 服务器装配

def _make_handler(handler_cls: type[BaseHTTPRequestHandler], gw: Gateway) -> type:
    return type(handler_cls.__name__, (handler_cls,), {"gw": gw})


def serve_all(gw: Gateway,
              business_port: int = BUSINESS_PORT,
              safety_port: int = SAFETY_PORT,
              device_port: int = DEVICE_PORT,
              bind: str = "127.0.0.1") -> dict[str, ThreadingHTTPServer]:
    """在独立端口上启动三个通道。返回 server 映射，便于测试中逐个关闭。"""
    servers: dict[str, ThreadingHTTPServer] = {}
    for name, port, cls in (
        ("business", business_port, _BusinessHandler),
        ("safety", safety_port, _SafetyHandler),
        ("device", device_port, _DeviceHandler),
    ):
        httpd = ThreadingHTTPServer((bind, port), _make_handler(cls, gw))
        t = threading.Thread(target=httpd.serve_forever, name=f"http-{name}",
                             daemon=True, kwargs={"poll_interval": 0.05})
        httpd._thread = t  # type: ignore[attr-defined]
        t.start()
        servers[name] = httpd
    return servers


def shutdown_all(servers: dict[str, ThreadingHTTPServer]) -> None:
    for httpd in servers.values():
        httpd.shutdown()
    for httpd in servers.values():
        t = getattr(httpd, "_thread", None)
        if t:
            t.join(timeout=2)
        httpd.server_close()
