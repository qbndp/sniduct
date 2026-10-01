"""命令行入口：子命令 + 交互式控制台（纯文本/rich）。"""
from __future__ import annotations

import argparse
import os
import shlex
import sys
import threading
import time

from . import render
from .config import Config
from .core import Session
from .events import Event, EventBus
from .rules import Rules
from .upstream import probe as upstream_probe
from .util import all_local_ipv4, can_bind, is_auto, parse_host_port, which

BANNER = "[bold]sniduct[/] [grey50]— iptables DNAT → SNI → CONNECT 隧道[/]"


# ---------------- 公共 ----------------


def build_session(args) -> Session:
    cfg = Config.load(args.config)
    if args.device:
        cfg.device = args.device
    bus = EventBus()
    bus.subscribe(render.print_event)
    return Session(cfg, bus)


def _rules_of(sess: Session) -> Rules:
    """取当前生效端口的规则视图（运行中用实绑端口，否则解析一次配置）。"""
    if sess.rules is not None and sess.state != "stopped":
        return sess.rules
    return sess.rules_view()


def _scope_desc(cfg: Config) -> str:
    apps = cfg.target_apps or []
    if cfg.is_all_scope(apps):
        return "全部应用(所有 UID)"
    return ", ".join(apps) if apps else "(未选择)"


# ---------------- 子命令 ----------------


def cmd_doctor(args) -> int:
    sess = build_session(args)
    render.rule("doctor")
    render.info(f"adb    {which(sess.cfg.adb) or sess.cfg.adb}")
    render.info(f"配置    {sess.cfg.path}")
    render.console.print(render.doctor_table(sess.doctor()))
    if args.verbose:
        ips = all_local_ipv4()
        render.rule("本机 IPv4")
        for ip in ips:
            okc, msg = can_bind(ip, sess.cfg.listen.port)
            render.info(f"{ip}  端口 {sess.cfg.listen.port}: {'可绑定' if okc else msg}")
    return 0


def cmd_config(args) -> int:
    sess = build_session(args)
    render.console.print(render.config_panel(sess.cfg))
    if args.verbose:
        render.console.print_json(data=sess.cfg.to_dict())
    return 0


def cmd_apps(args) -> int:
    sess = build_session(args)
    if not sess.pick_device():
        render.error("未发现在线 ADB 设备")
        return 1
    apps = sess.apps(refresh=True)
    render.console.print(render.apps_table(apps, sess.cfg.target_apps,
                                           limit=args.limit, query=args.keyword))
    if not args.limit:
        render.hint("用 `scope <包名...>` 或 `scope all` 设置抓包范围；"
                    "带关键字可过滤，-n 限制条数。")
    return 0


def cmd_scope(args) -> int:
    sess = build_session(args)
    _apply_scope(sess, args.targets)
    return 0


def _apply_scope(sess: Session, targets: list[str]) -> None:
    targets = [t for t in targets if t]
    if not targets or targets[0] in ("all", "*", "any", "ALL"):
        sess.set_scope(["*"])
        render.ok("抓包范围: 全部应用(所有 UID)")
    elif targets[0] in ("none", "clear", "empty"):
        sess.set_scope([])
        render.warn("抓包范围: 未选择（运行中将清空 DNAT）")
    else:
        sess.set_scope(targets)
        render.ok(f"抓包范围: {', '.join(targets)}")
    if sess.state == "running":
        sess.apply_scope()


def cmd_skip(args) -> int:
    sess = build_session(args)
    cfg = sess.cfg
    act = args.action or "list"
    if act == "list":
        for s in cfg.skip_snis or []:
            render.info(s)
        if not cfg.skip_snis:
            render.hint("(空)")
        return 0
    if act in ("add", "rm", "remove", "del"):
        host = (args.value or "").strip()
        if not host:
            render.error("用法: skip add|rm <域名>")
            return 2
        if act == "add":
            if host in cfg.skip_snis:
                render.warn(f"已存在: {host}")
            else:
                cfg.skip_snis.append(host)
                cfg.save()
                render.ok(f"已加入 Skip: {host}")
        else:
            if host in cfg.skip_snis:
                cfg.skip_snis.remove(host)
                cfg.save()
                render.ok(f"已移除 Skip: {host}")
            else:
                render.warn(f"不在列表: {host}")
        return 0
    render.error(f"未知动作: {act}")
    return 2


def cmd_device(args) -> int:
    sess = build_session(args)
    devs = sess.devices()
    if not devs:
        render.error("未发现在线 ADB 设备")
        return 1
    if args.serial:
        if args.serial not in devs:
            render.error(f"设备不在线: {args.serial}（在线: {', '.join(devs)}）")
            return 1
        sess.sync_device(args.serial)
        sess.cfg.save()
        render.ok(f"已切换设备: {args.serial}")
        return 0
    for d in devs:
        mark = "[green]✓[/]" if d == sess.cfg.device else " "
        render.console.print(f"{mark} {d}")
    state = sess.adb.device_state()
    render.info(f"当前状态: {state}   局域网 IP: {sess.adb.device_lan_ip() or '未知'}")
    return 0


def cmd_listen(args) -> int:
    sess = build_session(args)
    cfg = sess.cfg
    if not args.value:
        sess.resolve(persist=False)
        ep = sess.endpoints
        suffix = "（port_auto，占用时自动换）" if cfg.listen.port_auto else ""
        render.info(f"listen = {cfg.listen.host}:{cfg.listen.port}{suffix}")
        render.info(f"  → 实际监听 {ep.listen_addr}")
        return 0
    host, port = parse_host_port(args.value)
    if host is not None:
        cfg.listen.host = "auto" if is_auto(host) else host
    if port is not None:
        cfg.listen.port = int(port)
    cfg.save()
    render.ok(f"listen = {cfg.listen.host}:{cfg.listen.port}")
    return 0


def cmd_upstream(args) -> int:
    sess = build_session(args)
    cfg = sess.cfg
    if not args.value:
        sess.resolve(persist=False)
        ep = sess.endpoints
        render.info(f"upstream = {cfg.upstream.host}:{cfg.upstream.port}")
        render.info(f"  → 实际隧道 {ep.upstream_addr}")
        reachable, msg = upstream_probe(ep.upstream_host, ep.upstream_port)
        render.info(f"  → 连通性: {'可用' if reachable else msg}")
        return 0
    _set_upstream(cfg, args.value)
    cfg.save()
    render.ok(f"upstream = {cfg.upstream.host}:{cfg.upstream.port}")
    return 0


def _set_upstream(cfg: Config, value: str) -> None:
    """`upstream 8080` / `upstream 127.0.0.1:8080` / `upstream auto`。"""
    value = (value or "").strip()
    if value.lower() in ("auto", "*", ""):
        cfg.upstream.host = "auto"
        cfg.upstream.port = "auto"
        return
    host, port = parse_host_port(value, default_port=None)
    if host is None and port is not None:
        cfg.upstream.port = int(port)
        return
    if host:
        cfg.upstream.host = host
    if port is not None:
        cfg.upstream.port = int(port)


def cmd_quic(args) -> int:
    sess = build_session(args)
    sess.cfg.block_quic = args.state == "on"
    sess.cfg.save()
    render.ok(f"QUIC(UDP/443) 拦截: {'开' if sess.cfg.block_quic else '关'}"
              "（下次 START 生效）")
    return 0


def cmd_status(args) -> int:
    sess = build_session(args)
    _print_status(sess, deep=args.deep)
    return 0


def _print_status(sess: Session, deep: bool = False) -> None:
    st = sess.status()
    render.console.print(render.status_panel(st, sess.cfg, sess.device_ip))
    if deep:
        if not sess.pick_device():
            render.warn("设备不在线，跳过 iptables 现状读取")
            return
        rules = _rules_of(sess)
        render.console.print(render.nat_panel(rules.nat_output_pretty()))


def cmd_nat(args) -> int:
    sess = build_session(args)
    if not sess.pick_device():
        render.error("未发现在线 ADB 设备")
        return 1
    rules = _rules_of(sess)
    render.console.print(render.nat_panel(rules.nat_output_pretty()))
    own = rules.own_dnat_nums()
    render.info(f"本工具规则 {len(own)} 条    QUIC 拦截: {'在位' if rules.quic_present() else '不在位'}")
    return 0


def cmd_clean(args) -> int:
    """只清规则，不起转发：用于上次异常退出后的收尾。"""
    sess = build_session(args)
    if not sess.pick_device():
        render.error("未发现在线 ADB 设备")
        return 1
    rules = _rules_of(sess)
    ok = rules.clear_dnat()
    rules.clear_quic()
    if ok:
        render.ok("已清理本工具的 DNAT 与 QUIC 规则")
        return 0
    rules2 = _rules_of(sess)
    render.error("清理失败，请手动检查: iptables -t nat -L OUTPUT -n "
                 f"（当前 DNAT 规则 {len(rules2.own_dnat_nums())} 条）")
    render.console.print(render.nat_panel(rules2.nat_output_pretty()))
    return 1


def cmd_up(args) -> int:
    """前台启动：start → 打印事件 → Ctrl-C 停止。"""
    sess = build_session(args)
    render.console.print(BANNER)
    res = sess.start(args.device)
    if not res.ok:
        render.error(res.error)
        return 1
    render.console.print(render.endpoints_panel("已启动", sess.endpoints, res.notes))
    render.hint("Ctrl-C 停止并清理 iptables")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        render.rule("停止")
    finally:
        sess.stop()
        render.ok("已停止")
    return 0


def cmd_watch(args) -> int:
    sess = build_session(args)
    return _watch_loop(sess, interval=args.interval)


# ---------------- 交互控制台 ----------------


class Shell:
    def __init__(self, sess: Session, config_path: str | None = None):
        self.sess = sess
        self.config_path = config_path
        self.last_apps: list[dict] = []
        self._stop = False

    # -- 工具 --

    def _refresh_endpoints_preview(self) -> None:
        if self.sess.state != "running":
            try:
                self.sess.resolve(persist=False)
            except Exception:
                pass

    def print_status(self, deep: bool = True) -> None:
        st = self.sess.status()
        render.console.print(render.status_panel(st, self.sess.cfg, self.sess.device_ip))
        if deep and self.sess.pick_device():
            render.console.print(render.nat_panel(_rules_of(self.sess).nat_output_pretty()))

    # -- 单条命令执行 --

    def dispatch(self, line: str) -> None:  # noqa: C901 - 命令分发本身较长
        line = line.strip()
        if not line:
            return
        try:
            parts = shlex.split(line, posix=False)
        except ValueError as e:
            render.error(f"命令解析失败: {e}")
            return
        parts = [p.strip('"') for p in parts]
        cmd, rest = parts[0].lower(), parts[1:]

        if cmd in ("exit", "quit", "q"):
            self._stop = True
            return
        if cmd in ("help", "?", "h"):
            render.print_help_shell()
            return
        if cmd in ("start", "s"):
            self.do_start()
            return
        if cmd in ("stop", "x"):
            self.sess.stop()
            render.ok("已停止并清理规则")
            return
        if cmd in ("restart", "r"):
            self.sess.stop()
            self.do_start()
            return
        if cmd in ("status", "st"):
            self.print_status(deep=True)
            return
        if cmd in ("watch", "w"):
            _watch_loop(self.sess, interval=1.0)
            return
        if cmd in ("apps", "ls", "app"):
            self.do_apps(rest)
            return
        if cmd in ("use", "select", "sel"):
            self.do_use(rest)
            return
        if cmd in ("scope", "target"):
            _apply_scope(self.sess, rest)
            return
        if cmd == "skip":
            self.do_skip(rest)
            return
        if cmd in ("device", "dev"):
            self.do_device(rest)
            return
        if cmd in ("listen", "l"):
            render_hint_set(self.sess, "listen", rest)
            return
        if cmd in ("upstream", "us", "proxy"):
            render_hint_set(self.sess, "upstream", rest)
            return
        if cmd == "quic":
            self.do_quic(rest)
            return
        if cmd in ("config", "cfg"):
            render.console.print(render.config_panel(self.sess.cfg))
            return
        if cmd == "doctor":
            render.console.print(render.doctor_table(self.sess.doctor()))
            return
        if cmd in ("save", "write"):
            self.sess.cfg.save()
            render.ok(f"已写入 {self.sess.cfg.path}")
            return
        if cmd in ("logs", "log"):
            n = 60
            if rest and rest[0].isdigit():
                n = int(rest[0])
            render.print_history(self.sess.bus.history(n))
            return
        if cmd == "clear":
            self.sess.bus.clear()
            render.ok("日志缓冲已清空")
            return
        if cmd in ("nat", "iptables"):
            self.print_status(deep=True)
            return
        if cmd in ("clean", "purge"):
            if not self.sess.pick_device():
                render.error("设备不在线")
                return
            rules = _rules_of(self.sess)
            ok = rules.clear_dnat()
            rules.clear_quic()
            render.ok("规则已清理") if ok else render.error("清理失败，见 logs")
            return
        render.error(f"未知命令: {cmd}（help 查看全部）")

    # -- 具体动作 --

    def do_start(self) -> None:
        res = self.sess.start()
        if not res.ok:
            render.error(res.error)
            return
        render.console.print(render.endpoints_panel("RUNNING", self.sess.endpoints, res.notes))
        render.hint("stop 停止；apps/scope 可热更新抓包范围；status 看详情")

    def do_apps(self, rest: list[str]) -> None:
        refresh = "--refresh" in rest or "-r" in rest
        keyword = None
        limit = 40
        i = 0
        while i < len(rest):
            if rest[i] in ("--refresh", "-r"):
                i += 1
            elif rest[i] in ("-k", "--keyword") and i + 1 < len(rest):
                keyword = rest[i + 1]
                i += 2
            elif rest[i] in ("-n", "--limit") and i + 1 < len(rest):
                limit = int(rest[i + 1])
                i += 2
            elif rest[i] in ("-a", "--all"):
                limit = 0
                i += 1
            else:
                keyword = rest[i]
                i += 1
        if not self.sess.pick_device():
            render.error("未发现在线 ADB 设备")
            return
        apps = self.sess.apps(refresh=refresh)
        self.last_apps = apps
        render.console.print(render.apps_table(apps, self.sess.cfg.target_apps,
                                               limit=limit or None, query=keyword or ""))
        render.hint("用 `use <序号或包名...>` 选择，`use all` 抓全部应用")

    def do_use(self, rest: list[str]) -> None:
        if not rest:
            render.error("用法: use <序号|包名...>，或 use all")
            return
        if rest[0] in ("all", "*"):
            _apply_scope(self.sess, ["all"])
            return
        pkgs: list[str] = []
        for token in rest:
            if token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(self.last_apps):
                    pkgs.append(self.last_apps[idx]["pkg"])
                else:
                    render.warn(f"序号越界: {token}（先执行 apps）")
            else:
                pkgs.append(token)
        if pkgs:
            _apply_scope(self.sess, pkgs)

    def do_skip(self, rest: list[str]) -> None:
        cfg = self.sess.cfg
        if not rest or rest[0] == "list":
            for s in cfg.skip_snis or []:
                render.info(s)
            if not cfg.skip_snis:
                render.hint("(空)")
            return
        act = rest[0]
        val = rest[1] if len(rest) > 1 else ""
        if act in ("add", "+") and val:
            if val in cfg.skip_snis:
                render.warn(f"已存在: {val}")
            else:
                cfg.skip_snis.append(val)
                cfg.save()
                render.ok(f"已加入 Skip: {val}")
        elif act in ("rm", "remove", "del", "-") and val:
            if val in cfg.skip_snis:
                cfg.skip_snis.remove(val)
                cfg.save()
                render.ok(f"已移除 Skip: {val}")
            else:
                render.warn(f"不在列表: {val}")
        else:
            render.error("用法: skip list | skip add <域名> | skip rm <域名>")

    def do_quic(self, rest: list[str]) -> None:
        if not rest or rest[0] not in ("on", "off"):
            render.error("用法: quic on|off")
            return
        self.sess.cfg.block_quic = rest[0] == "on"
        self.sess.cfg.save()
        render.ok(f"QUIC 拦截: {'开' if self.sess.cfg.block_quic else '关'}"
                  + ("（运行中，下次 START 生效）" if self.sess.state == "running" else ""))

    def do_device(self, rest: list[str]) -> None:
        devs = self.sess.devices()
        if not devs:
            render.error("未发现在线 ADB 设备")
            return
        if not rest:
            for d in devs:
                mark = "[green]✓[/]" if d == self.sess.cfg.device else " "
                render.console.print(f"{mark} {d}")
            render.info(f"设备局域网 IP: {self.sess.adb.device_lan_ip() or '未知'}"
                        f"   root: {'可用' if self.sess.adb.is_rooted()[0] else '不可用'}")
            return
        if rest[0] not in devs:
            render.error(f"设备不在线: {rest[0]}")
            return
        self.sess.sync_device(rest[0])
        self.sess.cfg.save()
        render.ok(f"已切换设备: {rest[0]}")

    # -- 主循环 --

    def run(self) -> int:
        render.console.print(BANNER)
        render.hint(f"配置 {self.sess.cfg.path}  ·  help 查看命令  ·  exit 退出")
        if self.sess.pick_device():
            self._refresh_endpoints_preview()
        while not self._stop:
            try:
                line = render.console.input("[bold cyan]sniduct>[/] ")
            except (EOFError, KeyboardInterrupt):
                render.console.print()
                break
            try:
                self.dispatch(line)
            except Exception as e:  # noqa: BLE001 - 交互模式不因单条命令崩溃
                render.error(f"{type(e).__name__}: {e}")
        if self.sess.state == "running":
            self.sess.stop()
        render.hint("bye")
        return 0


def render_hint_set(sess: Session, which_cfg: str, rest: list[str]) -> None:
    """listen/upstream 设置：支持 `listen 192.168.1.2:8088`、`listen auto`、`upstream 8080`。"""
    cfg = sess.cfg
    if not rest:
        sess.resolve(persist=False)
        ep = sess.endpoints
        if which_cfg == "listen":
            render.info(f"listen = {cfg.listen.host}:{cfg.listen.port}")
            render.info(f"  → 实际监听 {ep.listen_addr}")
        else:
            render.info(f"upstream = {cfg.upstream.host}:{cfg.upstream.port}")
            render.info(f"  → 实际隧道 {ep.upstream_addr}")
        return
    value = rest[0].strip()
    if which_cfg == "listen":
        host, port = parse_host_port(value, default_port=None)
        if value.lower() in ("auto", "*"):
            cfg.listen.host = "auto"
        elif host is not None:
            cfg.listen.host = host
        if port is not None:
            cfg.listen.port = int(port)
        cfg.save()
        render.ok(f"listen = {cfg.listen.host}:{cfg.listen.port}"
                  + ("（下次 START / 运行中巡检生效）" if sess.state == "running" else ""))
    else:
        _set_upstream(cfg, value)
        cfg.save()
        render.ok(f"upstream = {cfg.upstream.host}:{cfg.upstream.port}"
                  + ("（下次 START / 运行中巡检生效）" if sess.state == "running" else ""))


def _watch_loop(sess: Session, interval: float = 1.0) -> int:
    """实时状态面板：q 退出（Windows 用 msvcrt，其它平台 Ctrl-C）。"""
    from rich.live import Live

    stop = threading.Event()

    def _key_listener() -> None:
        try:
            if os.name == "nt":
                import msvcrt
                while not stop.is_set():
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        if ch in (b"q", b"Q", b"\x1b"):
                            stop.set()
                            return
                    time.sleep(0.1)
            else:
                import select
                while not stop.is_set():
                    r, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if r and sys.stdin.read(1) in ("q", "Q", "\x1b"):
                        stop.set()
                        return
        except Exception:
            pass

    threading.Thread(target=_key_listener, daemon=True).start()

    def _build():
        from rich.console import Group
        st = sess.status()
        blocks = [render.status_panel(st, sess.cfg, sess.device_ip)]
        if sess.rules:
            blocks.append(render.nat_panel(sess.rules.nat_output_pretty()))
        log = sess.bus.history(12)
        from rich.panel import Panel
        body = "\n".join(
            f"[grey50]{e.hhmmss}[/] [{render.LEVEL_STYLE.get(e.level, 'white')}]{e.msg}[/]"
            for e in log) or "[grey50](暂无日志)[/]"
        blocks.append(Panel(body, title="[bold]日志[/]", border_style="grey37"))
        blocks.append(render.hint("按 q 退出 watch"))
        return Group(*blocks)

    render.hint("watch：按 q 退出")
    try:
        with Live(_build(), console=render.console, refresh_per_second=max(1, int(1 / interval)),
                  screen=False) as live:
            while not stop.is_set():
                time.sleep(interval)
                live.update(_build())
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


# ---------------- argparse ----------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sniduct",
        description="SNI 隧道式抓包转发器：iptables DNAT + SNI 提取 + HTTP CONNECT 隧道",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="不带子命令直接运行会进入交互式控制台。")
    p.add_argument("-c", "--config", help="配置文件路径（默认 sniduct.json）")
    p.add_argument("-d", "--device", help="ADB 设备序列号（覆盖配置）")
    p.add_argument("-v", "--verbose", action="store_true", help="输出更多细节")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("shell", help="交互式控制台（默认）")
    sub.add_parser("up", help="前台启动，Ctrl-C 停止")
    sub.add_parser("status", help="查看状态").add_argument(
        "--deep", action="store_true", help="附带读取手机 iptables 现状")
    sub.add_parser("doctor", help="环境自检")
    sub.add_parser("config", help="查看配置")

    ap = sub.add_parser("apps", help="列出应用")
    ap.add_argument("keyword", nargs="?", help="按应用名/包名过滤")
    ap.add_argument("-k", "--keyword", dest="keyword_opt", help="同上")
    ap.add_argument("-n", "--limit", type=int, default=40, help="显示条数（0 = 全部）")
    ap.add_argument("--refresh", "-r", action="store_true", help="忽略缓存重新读取")

    sc = sub.add_parser("scope", help="设置抓包范围")
    sc.add_argument("targets", nargs="*", help="包名列表 / all / none")

    sk = sub.add_parser("skip", help="管理 Skip 域名")
    sk.add_argument("action", nargs="?", choices=["list", "add", "rm"], default="list")
    sk.add_argument("value", nargs="?", default="")

    dv = sub.add_parser("device", help="查看/切换 ADB 设备")
    dv.add_argument("serial", nargs="?", help="设备序列号")
    sub.add_parser("nat", help="查看手机 iptables nat OUTPUT")
    sub.add_parser("clean", help="只清理本工具的 iptables 规则")

    ln = sub.add_parser("listen", help="设置监听地址")
    ln.add_argument("value", nargs="?", help="host:port / auto / :8090")
    us = sub.add_parser("upstream", help="设置上游抓包代理地址")
    us.add_argument("value", nargs="?", help="host:port / 端口 / auto")

    qc = sub.add_parser("quic", help="QUIC 拦截开关")
    qc.add_argument("state", choices=["on", "off"])

    wt = sub.add_parser("watch", help="实时状态面板（q 退出）")
    wt.add_argument("--interval", type=float, default=1.0)
    return p


DISPATCH = {
    "doctor": cmd_doctor, "config": cmd_config, "apps": cmd_apps, "scope": cmd_scope,
    "skip": cmd_skip, "device": cmd_device, "listen": cmd_listen, "upstream": cmd_upstream,
    "quic": cmd_quic, "status": cmd_status, "nat": cmd_nat, "clean": cmd_clean,
    "up": cmd_up, "watch": cmd_watch,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "keyword_opt", None) and not getattr(args, "keyword", None):
        args.keyword = args.keyword_opt
    if not args.cmd or args.cmd == "shell":
        sess = build_session(args)
        return Shell(sess).run()
    return DISPATCH[args.cmd](args)
