"""转发服务：TCP 监听 + SNI 提取 + CONNECT 隧道到上游 HTTP 代理。"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from typing import Callable

from .events import EventBus
from .sni import extract_sni
from .util import set_bind_opts

CONNECT_TIMEOUT = 5.0
DIRECT_TIMEOUT = 10.0


@dataclass
class Endpoints:
    """运行时解析后的真实地址（配置里的 auto 已展开）。"""

    listen_host: str = ""
    listen_port: int = 0
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def listen_addr(self) -> str:
        return f"{self.listen_host}:{self.listen_port}"

    @property
    def upstream_addr(self) -> str:
        return f"{self.upstream_host}:{self.upstream_port}"


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            d = src.recv(32768)
            if not d:
                break
            dst.sendall(d)
    except Exception:
        pass


class ForwardServer:
    """把 DNAT 过来的 TLS 连接按 SNI 转成到上游代理的 CONNECT 隧道。"""

    def __init__(self, bus: EventBus, endpoints_fn: Callable[[], Endpoints],
                 skip_fn: Callable[[], set[str]]):
        self.bus = bus
        self.endpoints_fn = endpoints_fn
        self.skip_fn = skip_fn
        self.sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()
        self.host = ""
        self.port = 0
        self.conns = 0
        self.forwarded = 0
        self.passed = 0
        self.errors = 0

    # ---- 生命周期 ----

    def bind(self, host: str, port: int) -> tuple[bool, str]:
        s = socket.socket()
        set_bind_opts(s)
        try:
            s.bind((host, int(port)))
            s.listen(128)
        except OSError as e:
            try:
                s.close()
            except Exception:
                pass
            return False, f"{type(e).__name__}: {e}"
        self.sock = s
        self.host, self.port = host, int(port)
        return True, ""

    def start(self, host: str, port: int) -> tuple[bool, str]:
        """同步 bind 后再起线程：绑定失败必须在装 DNAT 之前暴露。"""
        self.stop()
        ok, err = self.bind(host, port)
        if not ok:
            return False, err
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True, name="fwd-accept")
        self._thread.start()
        self.bus.ok(f"[SRV] 监听 {host}:{port}", "srv")
        return True, ""

    def stop(self) -> None:
        self._running = False
        with self._lock:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
        if self._thread and self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        self._thread = None

    @property
    def running(self) -> bool:
        return self._running and self.sock is not None

    def _serve(self) -> None:
        while self._running:
            sock = self.sock
            if sock is None:
                break
            try:
                sock.settimeout(1.0)
                client, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.conns += 1
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    # ---- 连接处理 ----

    def _handle(self, client: socket.socket) -> None:
        ep = self.endpoints_fn()
        try:
            peer = client.getpeername()
            peer_s = f"{peer[0]}:{peer[1]}"
        except Exception:
            peer_s = "?"
        try:
            data = client.recv(16384)
        except Exception:
            self._close(client)
            return
        if not data or data[0] != 0x16:
            self._close(client)
            return
        host = extract_sni(data)
        if not host:
            self.bus.debug(f"[SKIP] {peer_s} 首包无 SNI", "fwd")
            self._close(client)
            return

        if host in self.skip_fn():
            self.bus.info(f"[PASS] {peer_s} -> {host}", "pass")
            self._direct(client, data, host, peer_s)
            return

        self.bus.info(f"[FWD] {peer_s} -> {host}", "fwd")
        self._tunnel(client, data, host, ep, peer_s)

    def _direct(self, client: socket.socket, data: bytes, host: str, peer_s: str) -> None:
        """Skip 域名：直连真实服务器，不走抓包代理。"""
        remote = None
        try:
            remote = socket.create_connection((host, 443), DIRECT_TIMEOUT)
            remote.sendall(data)
            threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
            pipe(remote, client)
            self.passed += 1
        except Exception as e:
            self.errors += 1
            self.bus.debug(f"[PASS] {host} 直连失败: {e}", "pass")
        finally:
            self._close(remote)
            self._close(client)

    def _tunnel(self, client: socket.socket, data: bytes, host: str,
                ep: Endpoints, peer_s: str) -> None:
        up = None
        try:
            up = socket.create_connection((ep.upstream_host, ep.upstream_port), CONNECT_TIMEOUT)
            up.send(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
            resp = up.recv(4096)
            if b"200" not in resp:
                self.errors += 1
                self.bus.warn(f"[FWD] {host} 隧道被拒: "
                              f"{resp.decode(errors='replace').strip()[:80]}", "fwd")
                return
            up.sendall(data)
            threading.Thread(target=pipe, args=(client, up), daemon=True).start()
            pipe(up, client)
            self.forwarded += 1
        except Exception as e:
            self.errors += 1
            self.bus.error(f"[FWD] {peer_s} -> {host} 失败: {e}"
                           f"（上游代理 {ep.upstream_addr}）", "fwd")
        finally:
            self._close(up)
            self._close(client)

    @staticmethod
    def _close(sock: socket.socket | None) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except Exception:
            pass

    def stats(self) -> dict:
        return {
            "host": self.host, "port": self.port, "running": self.running,
            "conns": self.conns, "forwarded": self.forwarded,
            "passed": self.passed, "errors": self.errors,
        }
