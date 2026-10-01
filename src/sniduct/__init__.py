"""sniduct —— SNI 隧道式抓包转发器（纯控制台实现）。

把 Android 应用的 TCP/443 流量经手机侧 iptables DNAT 引到本机，提取 TLS SNI 后
用 HTTP CONNECT 隧道交给任意抓包代理，App 无感知、无需 VPN 虚拟网卡。
"""
from __future__ import annotations

__version__ = "0.3.0"

__all__ = ["main", "__version__"]


def main(argv: list[str] | None = None) -> int:
    """包入口（console_script / python -m sniduct 共用）。"""
    from .cli import main as _main
    return _main(argv)
