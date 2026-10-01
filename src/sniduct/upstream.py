"""上游代理探测：决定 CONNECT 隧道交给哪个 HTTP 代理。

本工具不绑定任何抓包软件，只认「能正常应答 HTTP CONNECT 的代理」。解析顺序：

  1. 配置里写死的 host / port（用户说了算：即使没人监听也照用，报错留给连通性检查）；
  2. `upstream.host` 为 auto 时，先采纳环境变量
     `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`（含小写写法）；
  3. 仍没结果，就在本机扫描候选端口（`upstream.probe_ports` 可自定义）。

第 3 步必须真的回一句 HTTP 应答才算命中：本机常同时开着多个代理
（Clash、mitmproxy、Charles、Burp 都可能占着坑），盲扫会把手机流量灌给不想要的
那个，所以每次命中都会连「来源」一起写进日志，方便一眼看出选错了。
"""
from __future__ import annotations

import os
import socket
from urllib.parse import urlsplit

from .util import is_auto, port_open

# 候选端口：常见抓包 / 代理工具的默认监听端口（顺序 = 探测顺序）
DEFAULT_PROBE_PORTS: tuple[int, ...] = (
    8080, 8888, 8081, 9090, 9000, 3128, 8118, 18080, 7890, 10809, 10808, 1080,
)
PROXY_ENV_VARS = (
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
)
HTTP_SCHEMES = ("http", "https")
CONNECT_PROBE_TIMEOUT = 1.2


# ---------------------------------------------------------------- 解析


def parse_proxy_url(value: str | None) -> tuple[str, int] | None:
    """`http://127.0.0.1:8080` / `127.0.0.1:8080` → (host, port)。

    只接受 HTTP(S) 代理写法：SOCKS 之类无法用 CONNECT 隧道，一律返回 None。
    """
    text = (value or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if (parts.scheme or "").lower() not in HTTP_SCHEMES:
        return None
    host = parts.hostname
    try:
        port = parts.port
    except ValueError:
        return None
    if not host or not port or not 0 < int(port) < 65536:
        return None
    return host, int(port)


def env_proxy(env: dict[str, str] | None = None) -> tuple[str, int, str] | None:
    """环境变量里的代理地址，返回 (host, port, 来源说明)。"""
    env = os.environ if env is None else env
    for name in PROXY_ENV_VARS:
        raw = (env.get(name) or "").strip()
        if not raw:
            continue
        parsed = parse_proxy_url(raw)
        if parsed:
            return parsed[0], parsed[1], f"环境变量 {name}"
    return None


def _as_port(value: object) -> int | None:
    try:
        port = int(str(value).strip())
    except Exception:
        return None
    return port if 0 < port < 65536 else None


# ---------------------------------------------------------------- 探测


def is_http_proxy(host: str, port: int, timeout: float = CONNECT_PROBE_TIMEOUT) -> bool:
    """发一条 CONNECT，看对方是否回 HTTP 应答：区分「HTTP 代理」与「随便一个端口」。"""
    try:
        with socket.create_connection((host, int(port)), timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n"
                      b"Host: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n")
            resp = s.recv(256)
    except Exception:
        return False
    return b"HTTP/" in resp[:16].upper()


def find_open_port(host: str = "127.0.0.1",
                   ports: tuple[int, ...] | list[int] = DEFAULT_PROBE_PORTS) -> int | None:
    """候选端口里第一个「像 HTTP 代理」的端口。"""
    for port in ports:
        port = int(port)
        if port_open(host, port, timeout=0.35) and is_http_proxy(host, port):
            return port
    return None


def probe(host: str, port: int) -> tuple[bool, str]:
    """确认某个上游代理地址是否可用，返回 (ok, 说明)。"""
    if not host or not port:
        return False, "未确定上游代理地址"
    if not port_open(host, int(port)):
        return False, f"{host}:{port} 不可连接（抓包代理是否已启动？）"
    if is_http_proxy(host, int(port)):
        return True, f"{host}:{port} 可连接（HTTP 代理应答正常）"
    return False, f"{host}:{port} 可连接，但不是 HTTP 代理（可能被别的程序占用）"


def resolve(cfg_host: str = "auto", cfg_port: str | int = "auto",
            probe_ports: list[int] | tuple[int, ...] | None = None,
            env: dict[str, str] | None = None) -> tuple[str, int, str]:
    """解析上游代理地址，返回 (host, port, 来源说明)；没找到时返回 ("", 0, 原因)。

    cfg_port 不是 auto 时严格采用配置：即便端口没人监听也原样返回，
    让连通性检查去报错，而不是偷偷换到别的端口。
    """
    auto_host = is_auto(str(cfg_host))
    host = "127.0.0.1" if auto_host else str(cfg_host).strip()

    if not is_auto(str(cfg_port)):
        port = _as_port(cfg_port)
        if port:
            return host, port, f"配置指定（{host}:{port}）"
        return "", 0, f"配置里的 upstream.port 无法识别：{cfg_port!r}"

    # 1) 环境变量（只在地址也是 auto 时才采纳，避免覆盖用户显式配置）
    from_env = env_proxy(env) if auto_host else None
    if from_env:
        ehost, eport, src = from_env
        if port_open(ehost, eport, timeout=0.5) and is_http_proxy(ehost, eport):
            return ehost, eport, f"{src}（{ehost}:{eport}）"

    # 2) 候选端口扫描（必须通过 HTTP 代理应答校验）
    ports = tuple(int(p) for p in (probe_ports or DEFAULT_PROBE_PORTS))
    for port in ports:
        if port_open(host, port, timeout=0.35) and is_http_proxy(host, port):
            return host, port, f"候选端口命中 {port}（自动探测，请确认是目标抓包代理）"

    if from_env:
        ehost, eport, src = from_env
        return ehost, eport, f"{src} 指向的 {ehost}:{eport} 当前无 HTTP 代理应答"
    return "", 0, (f"未探测到上游 HTTP 代理（{host} 上候选端口 {list(ports)} 均无应答）；"
                   f"用 `upstream <host:port>` 显式指定")


def doctor_lines(cfg_host: str, cfg_port: str | int,
                 probe_ports: list[int] | tuple[int, ...] | None = None
                 ) -> list[tuple[str, bool, str]]:
    """doctor 用的探测结论：[(项目, 是否通过, 说明)]。"""
    host, port, src = resolve(cfg_host, cfg_port, probe_ports)
    checks: list[tuple[str, bool, str]] = []
    checks.append(("上游代理地址", bool(port), f"{host}:{port}（{src}）" if port else src))
    if port:
        ok, msg = probe(host, port)
        checks.append(("上游代理可连接", ok, msg))
    return checks
