"""底层工具：子进程执行、本机地址/端口探测、地址解析。"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PROBE_HOSTS = ("1.1.1.1", "8.8.8.8", "223.5.5.5")


def run(cmd: list[str], timeout: float = 15.0) -> tuple[bool, str]:
    """同步执行命令，返回 (是否成功, 合并后的输出)。"""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except FileNotFoundError as e:
        return False, f"找不到可执行文件 {cmd[0]}: {e}"
    except subprocess.TimeoutExpired:
        return False, f"命令超时({timeout:g}s): {' '.join(cmd)}"
    except Exception as e:  # noqa: BLE001 - 诊断信息需要原样带出
        return False, f"{type(e).__name__}: {e}"
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if err:
        out = f"{out}\n{err}".strip()
    return r.returncode == 0, out


def which(exe: str) -> str | None:
    if not exe:
        return None
    if os.path.sep in exe or (os.path.altsep and os.path.altsep in exe):
        return exe if os.path.exists(exe) else None
    return shutil.which(exe)


# ===== 本机地址 =====

def local_addr_for(host: str, port: int = 9) -> str | None:
    """本机到 host 会使用的源 IPv4（不等于“能连通”，只表示路由选择）；拿不到返回 None。"""
    if not host:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, port))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return None
    return ip if ip and not ip.startswith("127.") else None


def all_local_ipv4() -> list[str]:
    """本机所有非回环 IPv4，优先“有默认路由”的那些。"""
    ips: list[str] = []
    for probe in PROBE_HOSTS:
        ip = local_addr_for(probe)
        if ip and ip not in ips:
            ips.append(ip)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def pick_listen_host(device_ip: str | None = None) -> tuple[str | None, str]:
    """选出本机应监听的地址：优先“通往设备的本机地址”，其次默认路由出口。

    返回 (ip, 说明)；ip 为 None 表示探测失败。
    """
    if device_ip:
        ip = local_addr_for(device_ip)
        if ip:
            return ip, f"通往设备 {device_ip} 的本机地址"
    for probe in PROBE_HOSTS:
        ip = local_addr_for(probe)
        if ip:
            return ip, "默认路由出口地址"
    ips = all_local_ipv4()
    if ips:
        return ips[0], "本机网卡地址"
    return None, "未探测到可用地址"


# ===== 端口 =====

def set_bind_opts(sock: socket.socket) -> None:
    """Windows 下 SO_REUSEADDR 会让两个进程绑同一端口而不报错，用 SO_EXCLUSIVEADDRUSE 暴露冲突。"""
    excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if os.name == "nt" and excl is not None:
        sock.setsockopt(socket.SOL_SOCKET, excl, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def can_bind(host: str, port: int) -> tuple[bool, str]:
    s = socket.socket()
    try:
        set_bind_opts(s)
        s.bind((host, int(port)))
        return True, ""
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def free_port(host: str = "0.0.0.0") -> int:
    s = socket.socket()
    try:
        s.bind((host, 0))
        return int(s.getsockname()[1])
    finally:
        try:
            s.close()
        except Exception:
            pass


def port_busy(err: str) -> bool:
    e = (err or "").lower()
    return "10048" in e or "eaddrinuse" in e or "address already in use" in e


def addr_invalid(err: str) -> bool:
    e = (err or "").lower()
    return ("10049" in e or "gaierror" in e or "cannot assign requested address" in e
            or "getaddrinfo" in e or "-2" in e and "name or service" in e)


def same_subnet(a: str, b: str, bits: int = 24) -> bool:
    try:
        pa = [int(x) for x in str(a).split(".")]
        pb = [int(x) for x in str(b).split(".")]
    except Exception:
        return True
    if len(pa) != 4 or len(pb) != 4:
        return True
    return pa[: bits // 8] == pb[: bits // 8]


def listen_port_free(host: str, port: int) -> bool:
    """能否监听；0.0.0.0 视为“任意本机地址均可”。"""
    if host in ("0.0.0.0", "", "*"):
        return can_bind("0.0.0.0", port)[0]
    return can_bind(host, port)[0]


# ===== 地址文本 =====

AUTO_TOKENS = ("auto", "AUTO", "*", "")


def is_auto(text: str | None) -> bool:
    return (text or "").strip() in AUTO_TOKENS


def parse_host_port(text: str, default_port: int | None = None) -> tuple[str | None, int | None]:
    """解析 "host:port" / "host" / ":port" / "port" / "auto"。"""
    t = (text or "").strip()
    if not t:
        return None, default_port
    if t.isdigit():
        return None, int(t)
    if ":" in t:
        host, _, port = t.rpartition(":")
        host = host.strip()
        port = port.strip()
        if port.isdigit():
            return (None if is_auto(host) else host), int(port)
        return (None if is_auto(host) else host), default_port
    return (None if is_auto(t) else t), default_port


def fmt_addr(host: str, port: int) -> str:
    return f"{host}:{port}"


def port_open(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout):
            return True
    except Exception:
        return False
