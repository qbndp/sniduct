"""纯控制台输出层（rich）。所有界面文本集中在这里，核心逻辑不依赖 rich。"""
from __future__ import annotations

import os
import sys

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .events import Event, LEVEL_STYLE
from .util import port_open


def _enable_utf8() -> None:
    """Windows 控制台默认 GBK，直接把 UTF-8 写进去会乱码或抛 UnicodeEncodeError。

    先尝试把控制台代码页切到 65001，再让 Python 以 UTF-8 写；失败则退回 ASCII 符号。
    """
    global UNICODE_OK, MARK_OK, MARK_BAD, BULLET
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)  # type: ignore[attr-defined]
            ctypes.windll.kernel32.SetConsoleCP(65001)        # type: ignore[attr-defined]
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass
    enc = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
    try:
        "\u2713\u2717\u00b7\u23fa".encode(enc)
        UNICODE_OK = True
    except Exception:
        UNICODE_OK = False
    MARK_OK = "\u2713" if UNICODE_OK else "[ok]"
    MARK_BAD = "\u2717" if UNICODE_OK else "[!!]"
    BULLET = "\u00b7" if UNICODE_OK else "-"


UNICODE_OK = True
MARK_OK, MARK_BAD, BULLET = "\u2713", "\u2717", "\u00b7"

_enable_utf8()

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

KIND_LABEL = {
    "srv": "SRV", "fwd": "FWD", "pass": "PASS", "net": "NET",
    "adb": "ADB", "ipt": "IPT", "cfg": "CFG", "err": "ERR",
}
STATE_STYLE = {"running": "bold green", "stopped": "bold red", "degraded": "bold yellow"}


def rule(title: str = "") -> None:
    console.rule(f"[bold]{title}[/]" if title else "", style="grey37")


def info(msg: str) -> None:
    console.print(f"[cyan]·[/] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green]✓[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]![/] {msg}")


def error(msg: str) -> None:
    err_console.print(f"[bold red]✗[/] {msg}")


def print_event(ev: Event) -> None:
    """日志行渲染：时间 + 级别着色 + 原文。"""
    style = LEVEL_STYLE.get(ev.level, "white")
    console.print(f"[grey50]{ev.hhmmss}[/] [{style}]{ev.msg}[/]", soft_wrap=True)


def print_history(events: list[Event]) -> None:
    for ev in events:
        print_event(ev)


# ---------- 面板 ----------


def status_panel(st: dict, cfg, device_ip: str | None = None) -> Panel:
    state = st.get("state", "stopped")
    host = st.get("host") or "-"
    port = st.get("port") or "-"
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="grey50", no_wrap=True)
    grid.add_column(overflow="fold")

    grid.add_row("状态", Text(state.upper(), style=STATE_STYLE.get(state, "white")))
    grid.add_row("监听", f"{host}:{port}" if host != "-" else "-")
    upstream_addr = st.get("upstream_addr") or f"{cfg.upstream.host}:{cfg.upstream.port}"
    grid.add_row("上游代理", f"{upstream_addr}"
                 + (" [grey50](auto)[/]" if cfg.upstream_port_is_auto else ""))
    grid.add_row("设备", f"{st.get('device') or '(未指定)'}"
                 + (f"  [grey50]lan={device_ip}[/]" if device_ip else ""))
    scope = st.get("scope_apps") or []
    scope_txt = ("全部应用(所有 UID)"
                 if "*" in scope else (", ".join(scope) if scope else "[yellow]未选择[/]"))
    grid.add_row("抓包范围", scope_txt)
    grid.add_row("QUIC 拦截", "开" if cfg.block_quic else "关")
    grid.add_row("Skip 域名", str(len(cfg.skip_snis or [])))
    grid.add_row("连接数", f"{st.get('conns', 0)}  转发 {st.get('forwarded', 0)}  "
                          f"直通 {st.get('passed', 0)}  失败 {st.get('errors', 0)}")
    if "own_rules" in st:
        grid.add_row("DNAT 规则", f"{st['own_rules']} 条   QUIC: "
                                 f"{'在位' if st.get('quic') else '不在位'}")
    grid.add_row("配置", cfg.path or "-")
    return Panel(grid, title="[bold]sniduct status[/]", border_style="grey37", expand=False)


def apps_table(apps: list[dict], selected: list[str], limit: int | None = None,
               query: str = "") -> Table:
    is_all = "*" in (selected or [])
    q = (query or "").lower()
    rows = []
    for a in apps:
        label = a.get("label") or ""
        if q and q not in f"{label} {a['pkg']}".lower():
            continue
        rows.append(a)
    shown = rows[:limit] if limit else rows
    t = Table(title=f"应用（匹配 {len(rows)} 个{'，显示前 %d 个' % len(shown) if len(shown) != len(rows) else ''}）",
              box=None, pad_edge=False, header_style="bold")
    t.add_column("选", width=2)
    t.add_column("应用名", overflow="fold")
    t.add_column("包名", style="cyan", overflow="fold")
    t.add_column("UID", style="grey50", justify="right")
    for a in shown:
        mark = "[green]✓[/]" if is_all or a["pkg"] in (selected or []) else " "
        t.add_row(mark, a.get("label") or "-", a["pkg"], a.get("uid") or "?")
    return t


def doctor_table(checks: list[tuple[str, bool, str]]) -> Table:
    t = Table(box=None, pad_edge=False, show_header=False)
    t.add_column(width=3)
    t.add_column(style="bold", no_wrap=True)
    t.add_column(overflow="fold")
    for name, passed, detail in checks:
        t.add_row("[green]✓[/]" if passed else "[red]✗[/]", name,
                  detail if passed else f"[yellow]{detail}[/]")
    return t


def config_panel(cfg) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="grey50", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("listen.host", f"{cfg.listen.host}"
                 + ("  [grey50](auto：每次 START 重新探测)[/]" if cfg.listen_host_is_auto else
                    ("  [grey50](固定，失效时自动回落)[/]" if cfg.listen.fallback_auto else "")))
    grid.add_row("listen.port", str(cfg.listen.port)
                 + ("  [grey50](port_auto：占用时自动换）[/]" if cfg.listen.port_auto else ""))
    grid.add_row("upstream.host", f"{cfg.upstream.host}"
                 + ("  [grey50](auto：采纳环境变量 / 缺省 127.0.0.1)[/]"
                    if cfg.upstream_host_is_auto else ""))
    grid.add_row("upstream.port", str(cfg.upstream.port)
                 + ("  [grey50](auto：扫描候选端口找 HTTP 代理)[/]"
                    if cfg.upstream_port_is_auto else ""))
    grid.add_row("upstream.probe_ports",
                 ", ".join(str(p) for p in cfg.upstream.probe_ports) or "(内置候选列表)")
    grid.add_row("adb", cfg.adb)
    grid.add_row("device", cfg.device or "(首个在线设备)")
    grid.add_row("target_apps", ", ".join(cfg.target_apps) or "(空)")
    grid.add_row("skip_snis", ", ".join(cfg.skip_snis) or "(空)")
    grid.add_row("block_quic", str(cfg.block_quic))
    return Panel(grid, title="[bold]config[/]", border_style="grey37",
                 subtitle=cfg.path or "", expand=False)


def endpoints_panel(title: str, ep, notes: list[str] | None = None) -> Panel:
    reachable = port_open(ep.upstream_host, ep.upstream_port)
    body = [f"监听     [bold]{ep.listen_host}:{ep.listen_port}[/]",
            f"上游代理 [bold]{ep.upstream_host}:{ep.upstream_port}[/]",
            f"可达性   "
            f"{'[green]上游代理可连接[/]' if reachable else '[red]上游代理不可连接[/]'}"]
    for n in notes or []:
        body.append(f"[grey50]{n}[/]")
    return Panel(Group(*[Text.from_markup(b) for b in body]),
                 title=f"[bold]{title}[/]", border_style="grey37", expand=False)


def nat_panel(rules: list[str]) -> Panel:
    if not rules:
        return Panel("[grey50](nat OUTPUT 为空或无权限)[/]",
                     title="[bold]iptables nat OUTPUT[/]", border_style="grey37", expand=False)
    return Panel("\n".join(rules), title="[bold]iptables nat OUTPUT[/]",
                 border_style="grey37", expand=False)


def hint(msg: str) -> None:
    console.print(f"[grey50]{msg}[/]")


def print_help_shell() -> None:
    t = Table(title="命令", box=None, pad_edge=False, header_style="bold")
    t.add_column("命令", style="cyan", no_wrap=True)
    t.add_column("说明")
    rows = [
        ("start / s", "启动转发（自动解析地址/端口并装 DNAT）"),
        ("stop / x", "停止并清理 iptables"),
        ("restart / r", "重启"),
        ("status / st", "查看状态（含 iptables 现状）"),
        ("watch / w", "实时状态面板（q 退出）"),
        ("apps [关键字]", "列出目标应用，--refresh 重新读取"),
        ("use <序号|包名...>", "按上一份 apps 列表选择抓包应用"),
        ("scope all|none|<包名...>", "设置抓包范围（all = 所有 UID）"),
        ("skip list|add <域名>|rm <域名>", "管理不经过抓包代理的域名"),
        ("device [序列号]", "查看/切换 ADB 设备"),
        ("listen [host][:port]", "设置监听地址（auto 表示自动探测）"),
        ("upstream [host][:port]", "设置上游抓包代理（auto 表示自动探测端口）"),
        ("quic on|off", "QUIC(UDP/443) 拦截开关"),
        ("config", "查看当前配置"),
        ("doctor", "环境自检"),
        ("save", "写回配置文件"),
        ("help / ?", "本帮助"),
        ("exit / quit", "退出（运行中会先 STOP）"),
    ]
    for cmd_name, desc in rows:
        t.add_row(cmd_name, desc)
    console.print(t)
