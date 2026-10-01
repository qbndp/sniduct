"""会话编排：把配置、ADB、上游代理探测、iptables、转发服务串起来。

地址 / 端口漂移的适配策略：
  1. 配置里的 `auto` 是「意图」，不是「值」——每次 START、每次巡检都重新解析，
     解析结果只放在 Session.endpoints，不写回配置，所以换网后不会被旧值卡住；
  2. 固定地址 / 固定端口也不会硬撞：地址失效默认自动回落（fallback_auto），
     端口被占用可开 port_auto 自动挑空闲端口，旧端口上的残留规则一并清理；
  3. 后台巡检线程周期比对「本机地址 / 上游代理地址 / DNAT 现状」，
     发现漂移就热重绑，手机侧规则同步重装（期间转发不中断到不可恢复）。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .adbkit import Adb
from .config import Config
from .events import EventBus
from .forwarder import Endpoints, ForwardServer
from .rules import Rules, dnat_spec
from .upstream import doctor_lines, probe as upstream_probe, resolve as resolve_upstream
from .util import (can_bind, free_port, is_auto, local_addr_for, pick_listen_host,
                   port_busy, same_subnet)

MONITOR_INTERVAL = 5.0
APP_CACHE_TTL = 120.0


@dataclass
class Resolution:
    """一次解析结果，含给用户看的说明。"""

    endpoints: Endpoints = field(default_factory=Endpoints)
    notes: list[str] = field(default_factory=list)
    ok: bool = True
    error: str = ""

    @property
    def listen_addr(self) -> str:
        return self.endpoints.listen_addr

    @property
    def upstream_addr(self) -> str:
        return self.endpoints.upstream_addr


class Session:
    def __init__(self, cfg: Config, bus: EventBus | None = None):
        self.cfg = cfg
        self.bus = bus or EventBus()
        self.adb = Adb(cfg.adb, cfg.device)
        self.endpoints = Endpoints()
        self.server = ForwardServer(self.bus, lambda: self.endpoints, self._skip_set)
        self.rules: Rules | None = None
        self.state = "stopped"          # stopped | running | degraded
        self.device_ip: str | None = None
        self._lock = threading.RLock()
        self._monitor: threading.Thread | None = None
        self._monitor_stop = threading.Event()
        self._apps: list[dict] = []
        self._apps_at = 0.0
        self._uid_cache: dict[str, str] = {}
        self._stale_ports: set[int] = set()
        self._last_upstream_port: int | None = None

    # ---------- 设备 / 应用 ----------

    def sync_device(self, device: str | None = None) -> None:
        if device is not None:
            self.cfg.device = device
        self.adb = Adb(self.cfg.adb, self.cfg.device)

    def devices(self) -> list[str]:
        return self.adb.devices()

    def pick_device(self) -> str:
        """配置里的设备不在线时，自动选第一个在线设备。"""
        devs = self.devices()
        if self.cfg.device in devs:
            return self.cfg.device
        if devs:
            self.bus.warn(f"[ADB] 设备 {self.cfg.device or '(未指定)'} 不在线，"
                          f"自动改用 {devs[0]}", "adb")
            self.sync_device(devs[0])
            self.cfg.save()
            return devs[0]
        return ""

    def apps(self, refresh: bool = False) -> list[dict]:
        if not refresh and self._apps and (time.time() - self._apps_at) < APP_CACHE_TTL:
            return self._apps
        self._apps = self.adb.list_apps()
        self._apps_at = time.time()
        self._uid_cache.update({a["pkg"]: str(a["uid"]) for a in self._apps if a.get("uid")})
        self.bus.info(f"[ADB] 读取到 {len(self._apps)} 个应用", "adb")
        return self._apps

    def uid_of(self, pkg: str) -> str | None:
        uid = self._uid_cache.get(pkg)
        if uid:
            return uid
        uid = self.adb.pkg_uid(pkg)
        if uid:
            self._uid_cache[pkg] = uid
        return uid

    def set_scope(self, apps: list[str]) -> None:
        self.cfg.set_scope(apps)
        self.cfg.save()

    def _skip_set(self) -> set[str]:
        return set(self.cfg.skip_snis or [])

    def scope_specs(self) -> tuple[list[str] | None, str]:
        """把配置里的目标应用解析成 DNAT spec 列表。"""
        if not self.endpoints.listen_host or not self.endpoints.listen_port:
            return None, "监听地址未就绪"
        apps = [a for a in (self.cfg.target_apps or []) if a]
        dst_host, dst_port = self.endpoints.listen_host, self.endpoints.listen_port
        if self.cfg.is_all_scope(apps):
            return [dnat_spec(dst_host, dst_port)], "全部应用(所有 UID)"
        if not apps:
            return None, "未选择应用"
        specs, descs, seen = [], [], set()
        for app in apps:
            uid = self.uid_of(app)
            if not uid:
                self.bus.warn(f"[!] 找不到应用: {app}", "adb")
                continue
            if uid in seen:
                continue
            seen.add(uid)
            specs.append(dnat_spec(dst_host, dst_port, uid))
            descs.append(f"UID={uid}({app})")
        if not specs:
            return None, "目标应用均无法解析 UID"
        return specs, ", ".join(descs)

    # ---------- 地址解析 ----------

    def resolve(self, persist: bool = False) -> Resolution:
        """解析监听地址 + 上游代理地址。可反复调用（START / 巡检 / 只读命令）。"""
        res = Resolution()
        with self._lock:
            self._probe_device_ip()

            # --- listen host ---
            host = self.cfg.listen.host
            if is_auto(host):
                picked, why = pick_listen_host(self.device_ip)
                if not picked:
                    res.ok, res.error = False, "无法探测本机可用地址（检查网卡/设备连接）"
                    return res
                host = picked
                res.notes.append(f"listen.host=auto → {picked}（{why}）")
            else:
                ok, err = can_bind(host, self.cfg.listen.port)
                if not ok and not port_busy(err) and self.cfg.listen.fallback_auto:
                    picked, why = pick_listen_host(self.device_ip)
                    if picked and picked != host:
                        res.notes.append(f"listen.host {host} 不可用（{err}）→ {picked}（{why}）")
                        host = picked

            # --- listen port ---
            port = int(self.cfg.listen.port)
            ok, err = can_bind(host, port)
            if not ok:
                if port_busy(err) and self.cfg.listen.port_auto:
                    newp = free_port(host)
                    res.notes.append(f"listen.port {port} 被占用 → 自动改用 {newp}")
                    self._stale_ports.add(port)
                    port = newp
                elif port_busy(err):
                    res.ok = False
                    res.error = (f"端口 {port} 已被占用（{err}）：多半是另一个转发器实例还在跑，"
                                 f"先退出它或执行 stop/clean；也可把 listen.port_auto 设为 true")
                    return res

            # --- 上游代理 ---
            rhost, rport, src = resolve_upstream(
                self.cfg.upstream.host, self.cfg.upstream.port, self.cfg.upstream.probe_ports)
            if not rport:
                res.ok, res.error = False, f"无法确定上游代理地址（{src}）"
                return res
            if self.cfg.upstream_host_is_auto:
                res.notes.append(f"upstream.host=auto → {rhost}")
            if rport != self._last_upstream_port:
                res.notes.append(f"上游代理 {rhost}:{rport}（{src}）")
                self._last_upstream_port = rport

            # 解析结果只落在 endpoints，不污染配置里的 auto 意图
            ep = Endpoints(host, port, rhost, rport, list(res.notes))
            self.endpoints = ep
            res.endpoints = ep
        return res

    def effective_listen_port(self) -> int:
        if self.endpoints.listen_port:
            return int(self.endpoints.listen_port)
        try:
            return int(self.cfg.listen.port)
        except Exception:
            return 8088

    def _probe_device_ip(self) -> None:
        try:
            self.device_ip = self.adb.device_lan_ip()
        except Exception:
            self.device_ip = None

    # ---------- 启停 ----------

    def start(self, device: str | None = None) -> Resolution:
        if device is not None:
            self.sync_device(device)
        if not self.pick_device():
            res = Resolution(ok=False, error="未发现在线 ADB 设备（检查 USB / 无线调试）")
            self.bus.error(f"[!] {res.error}")
            return res
        if self.state == "running":
            self.bus.info("[SRV] 已在运行，按新配置重启", "srv")
            self.stop()
        self.rules = None
        self._stale_ports.clear()

        res = self.resolve()
        if not res.ok:
            self.bus.error(f"[!] {res.error}")
            return res
        # 上游代理不可连是最常见的「装好了却抓不到」原因，先把话说在前面
        _ok, _msg = upstream_probe(self.endpoints.upstream_host, self.endpoints.upstream_port)
        if not _ok:
            self.bus.warn(f"[!] 上游代理不可用: {_msg}", "net")
        for n in res.notes:
            self.bus.info(f"[NET] {n}", "net")

        apps = [a for a in (self.cfg.target_apps or []) if a]
        if not apps:
            res.ok = False
            res.error = "未选择抓包应用（`scope all` 抓全部，或 `use <序号>` 指定应用）"
            self.bus.error(f"[!] {res.error}")
            return res

        ep = self.endpoints
        if self.device_ip and not same_subnet(self.device_ip, ep.listen_host):
            self.bus.warn(f"[!] 设备 {self.device_ip} 与监听地址 {ep.listen_host} 不同网段，"
                          f"DNAT 可能不可达", "net")

        ok, err = self.server.start(ep.listen_host, ep.listen_port)
        if not ok:
            res.ok, res.error = False, f"监听 {ep.listen_addr} 失败: {err}"
            self.bus.error(f"[!] {res.error}")
            return res

        self.rules = Rules(self.adb, ep.listen_port)
        specs, desc = self.scope_specs()
        if specs is None:
            res.ok, res.error = False, desc
            self.bus.error(f"[!] {desc}")
            self.server.stop()
            return res
        self.bus.info(f"[ADB] 目标 {desc}，写入 DNAT ...", "ipt")
        if not self.rules.set_dnat(specs, ep.listen_port):
            res.ok, res.error = False, "DNAT 安装失败（iptables 被系统占用，重试仍失败）"
            self.bus.error(f"[!] {res.error}")
            self.server.stop()
            return res
        self.bus.ok(f"[IPT] DNAT {desc} :443 -> {ep.listen_addr}", "ipt")

        if self.cfg.block_quic:
            if self.rules.set_quic():
                self.bus.ok("[IPT] QUIC UDP/443 -> REJECT（逼 App 回落 TCP）", "ipt")
            else:
                self.bus.warn("[!] QUIC 拦截安装失败（不影响 TCP 抓包）", "ipt")

        self.state = "running"
        self.cfg.save()
        self._start_monitor()
        return res

    def stop(self) -> None:
        self._stop_monitor()
        self.server.stop()
        if self.rules:
            self.bus.info("[ADB] 清理 iptables ...", "ipt")
            ok = self.rules.clear_dnat(tuple(self._stale_ports))
            self.rules.clear_quic()
            if ok:
                self.bus.ok("[IPT] 规则已清理，转发服务已停止", "ipt")
            else:
                self.bus.warn("[!] DNAT 清理失败，手动检查: iptables -t nat -L OUTPUT -n", "ipt")
        self.state = "stopped"
        self._stale_ports.clear()

    # ---------- 热更新 / 巡检 ----------

    def apply_scope(self) -> bool:
        """运行中按当前选择热更新 DNAT。"""
        if self.state != "running" or not self.rules:
            return False
        specs, desc = self.scope_specs()
        if specs is None:
            self.bus.warn(f"[!] {desc}，已清空 DNAT", "ipt")
            return self.rules.clear_dnat()
        if self.device_ip and not same_subnet(self.device_ip, self.endpoints.listen_host):
            self.bus.warn(f"[!] 设备 {self.device_ip} 与监听地址 "
                          f"{self.endpoints.listen_host} 不同网段", "net")
        ok = self.rules.set_dnat(specs, self.endpoints.listen_port, tuple(self._stale_ports))
        if ok:
            self._stale_ports.clear()
            self.bus.ok(f"[IPT] DNAT 已更新: {desc} -> {self.endpoints.listen_addr}", "ipt")
        else:
            self.bus.error("[!] DNAT 热更新失败（iptables 繁忙）", "ipt")
        return ok

    def _start_monitor(self) -> None:
        if self._monitor and self._monitor.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True, name="fwd-monitor")
        self._monitor.start()

    def _stop_monitor(self) -> None:
        self._monitor_stop.set()
        if self._monitor and self._monitor.is_alive():
            self._monitor.join(timeout=MONITOR_INTERVAL + 2)
        self._monitor = None

    def _monitor_loop(self) -> None:
        while not self._monitor_stop.wait(MONITOR_INTERVAL):
            try:
                if self.state == "running":
                    self._adapt()
            except Exception as e:  # noqa: BLE001 - 巡检不能因单次异常退出
                self.bus.debug(f"[NET] 巡检异常: {e}", "net")

    def _adapt(self) -> None:
        """检测地址 / 端口漂移并热重绑。"""
        ep = self.endpoints
        try:
            new_ip = self.adb.device_lan_ip()
        except Exception:
            new_ip = self.device_ip
        reason = ""
        if new_ip and new_ip != self.device_ip:
            reason = f"设备网段变化（{self.device_ip or '?'} → {new_ip}）"
            self.device_ip = new_ip

        want_host = ""
        if self.cfg.listen_host_is_auto:
            probe = local_addr_for(new_ip) if new_ip else None
            if probe and probe != ep.listen_host:
                want_host = probe
                reason = reason or f"本机监听地址变化（{ep.listen_host} → {probe}）"
        else:
            ok, _ = can_bind(ep.listen_host, ep.listen_port)
            if not ok and self.cfg.listen.fallback_auto:
                probe, why = pick_listen_host(new_ip)
                if probe and probe != ep.listen_host:
                    want_host = probe
                    reason = f"固定监听地址 {ep.listen_host} 失效 → {probe}（{why}）"

        if want_host:
            self._rebind(want_host, ep.listen_port, reason)
            return

        # 上游代理漂移：隧道目标换掉即可，listen 不受影响
        rhost, rport, _src = resolve_upstream(
            self.cfg.upstream.host, self.cfg.upstream.port, self.cfg.upstream.probe_ports)
        if rport and (rport != ep.upstream_port or rhost != ep.upstream_host):
            self.bus.warn(f"[NET] 上游代理变化（{ep.upstream_addr} → {rhost}:{rport}），"
                          f"隧道自动切换", "net")
            self.endpoints = Endpoints(ep.listen_host, ep.listen_port, rhost, rport, [])

    def _rebind(self, host: str, port: int, reason: str) -> None:
        self.bus.warn(f"[NET] {reason or '监听地址变化'} → 重新绑定 {host}:{port}", "net")
        self._stale_ports.add(self.endpoints.listen_port)
        self.server.stop()
        ok, err = self.server.start(host, port)
        if not ok:
            self.state = "degraded"
            self.bus.error(f"[!] 重新绑定 {host}:{port} 失败: {err}；"
                           f"DNAT 未跟随更新，请 STOP 后重新 START", "net")
            return
        self.endpoints = Endpoints(host, port, self.endpoints.upstream_host,
                                   self.endpoints.upstream_port, [])
        if self.rules:
            self.rules.listen_port = port
            specs, _desc = self.scope_specs()
            if specs and self.rules.set_dnat(specs, port, tuple(self._stale_ports)):
                self._stale_ports.clear()
                self.bus.ok(f"[IPT] DNAT 已跟随更新 -> {self.endpoints.listen_addr}", "ipt")
            else:
                self.state = "degraded"
                self.bus.error("[!] DNAT 跟随更新失败，请 STOP 后重新 START", "ipt")

    # ---------- 状态 / 自检 ----------

    def status(self) -> dict:
        if not self.endpoints.listen_port:
            self.resolve(persist=False)
        st = self.server.stats()
        st.update({
            "state": self.state,
            "device": self.cfg.device,
            "device_ip": self.device_ip,
            "upstream_addr": self.endpoints.upstream_addr,
            "scope": self.cfg.scope_token() or "(空)",
            "scope_apps": list(self.cfg.target_apps),
            "skip": list(self.cfg.skip_snis),
            "block_quic": self.cfg.block_quic,
            "adb": self.cfg.adb,
        })
        return st

    def rules_view(self) -> Rules:
        self.resolve(persist=False)
        return Rules(self.adb, self.effective_listen_port())

    def doctor(self) -> list[tuple[str, bool, str]]:
        """环境自检：[(项目, 是否通过, 说明)]。"""
        checks: list[tuple[str, bool, str]] = []
        from .util import which

        adb_path = which(self.cfg.adb)
        checks.append(("adb 可执行文件", bool(adb_path), adb_path or f"未找到 {self.cfg.adb}"))

        devs = self.devices()
        checks.append(("ADB 设备", bool(devs),
                       f"在线: {', '.join(devs)}" if devs else
                       "未发现在线设备（检查 USB / 无线调试 / adb kill-server）"))

        checks.extend(doctor_lines(self.cfg.upstream.host, self.cfg.upstream.port,
                                   self.cfg.upstream.probe_ports))

        if not devs:
            return checks

        rooted, info = self.adb.is_rooted()
        checks.append(("root 权限", rooted, "su 可用" if rooted else f"su 不可用: {info[:60]}"))

        dip = self.adb.device_lan_ip()
        checks.append(("设备局域网 IP", bool(dip), dip or "未探测到（设备先连上 Wi-Fi/热点）"))

        picked, why = pick_listen_host(dip)
        checks.append(("本机监听地址", bool(picked), f"{picked}（{why}）" if picked else "探测失败"))

        if picked:
            port = int(self.cfg.listen.port)
            ok, err = can_bind(picked, port)
            detail = "可绑定" if ok else (
                f"{err}（port_auto 已开启，将自动换端口）" if self.cfg.listen.port_auto else err)
            checks.append((f"监听端口 {port}", ok or self.cfg.listen.port_auto, detail))

        if dip and picked:
            same = same_subnet(dip, picked)
            checks.append(("设备与本机同网段", same,
                           f"{dip} / {picked}" if same else
                           f"{dip} 与 {picked} 不同网段，DNAT 可能不可达"))
        return checks
