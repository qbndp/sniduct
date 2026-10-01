"""ADB 封装：设备发现、root shell、应用列表（包名/UID/中文名）、设备网段探测。"""
from __future__ import annotations

import re

from .util import run

_PKG_LINE = re.compile(r"^package:(\S+?)(?:\s+uid:(\d+))?(?:\s|$)")
_PKG_HEAD = re.compile(r"Package \[([^\]\s]+)\]")
_SRC_IP = re.compile(r"\bsrc (\d+\.\d+\.\d+\.\d+)")
_DEV_LINE = re.compile(r"^(\S+)\s+device\b")


class AdbError(RuntimeError):
    pass


class Adb:
    """一次调用 = 一条 adb 命令；无状态，配置改动即时生效。"""

    def __init__(self, exe: str = "adb", device: str = "", timeout: float = 15.0):
        self.exe = exe or "adb"
        self.device = device or ""
        self.timeout = timeout

    # ---- 基础 ----

    def raw(self, *args: str, timeout: float | None = None) -> tuple[bool, str]:
        cmd = [self.exe]
        if self.device:
            cmd += ["-s", self.device]
        cmd += [str(a) for a in args]
        return run(cmd, timeout or self.timeout)

    def shell(self, cmd: str, root: bool = True, timeout: float | None = None) -> tuple[bool, str]:
        if root:
            return self.raw("shell", "su", "-c", cmd, timeout=timeout)
        return self.raw("shell", cmd, timeout=timeout)

    def sh(self, cmd: str, root: bool = True, timeout: float | None = None) -> str:
        """只要输出文本（失败时返回空串，不抛异常）。"""
        ok, out = self.shell(cmd, root=root, timeout=timeout)
        return out if out else ""

    def sh_any(self, cmd: str, timeout: float | None = None) -> str:
        """先试 root，失败或空则退回非 root。"""
        out = self.sh(cmd, root=True, timeout=timeout)
        if out.strip():
            return out
        return self.sh(cmd, root=False, timeout=timeout)

    def is_rooted(self) -> tuple[bool, str]:
        ok, out = self.shell("id", root=True)
        if ok and "uid=0" in out:
            return True, out.strip()
        return False, out.strip() or "su -c 不可用"

    # ---- 设备 ----

    def devices(self) -> list[str]:
        ok, out = self.raw("devices")
        devs: list[str] = []
        for line in (out or "").splitlines():
            m = _DEV_LINE.match(line.strip())
            if m:
                devs.append(m.group(1))
        return devs

    def device_lan_ip(self) -> str | None:
        """设备在 Wi-Fi/局域网侧的地址，用反推本机该监听哪个 IP。"""
        for cmd in ("ip -4 route get 1.1.1.1", "ip route", "ip -4 addr show wlan0"):
            out = self.sh(cmd, root=False) or self.sh(cmd, root=True)
            m = _SRC_IP.search(out or "")
            if m:
                return m.group(1)
        return None

    def device_state(self) -> str:
        ok, out = self.raw("get-state")
        return out.strip() if ok else "offline"

    # ---- 应用 ----

    def list_apps(self, third_party_only: bool = True) -> list[dict]:
        """[{'pkg','uid','label'}]，按名称排序。"""
        apps = self._list_packages(third_party_only)
        if not apps:
            return []
        # pm list packages -U 已带 uid 时无需 dumpsys（大机型上要几十秒）
        if not any(not a["uid"] for a in apps):
            apps.sort(key=lambda a: a["pkg"].lower())
            return apps
        want = {a["pkg"] for a in apps}
        dump = self.sh("dumpsys package", root=False, timeout=60)
        if len(dump) < 200:
            dump = self.sh("dumpsys package", root=True, timeout=60)
        for pkg, info in _parse_dumpsys(dump, want).items():
            for a in apps:
                if a["pkg"] != pkg:
                    continue
                if info.get("uid") and not a["uid"]:
                    a["uid"] = info["uid"]
                if info.get("label"):
                    a["label"] = info["label"]
                break
        apps.sort(key=lambda a: ((a.get("label") or a["pkg"]).lower(), a["pkg"]))
        return apps

    def _list_packages(self, third_party_only: bool) -> list[dict]:
        flag = " -3" if third_party_only else ""
        attempts = (
            (f"pm list packages{flag} -U", False),
            (f"pm list packages{flag} -U", True),
            (f"pm list packages{flag}", False),
            (f"pm list packages{flag}", True),
        )
        for cmd, root in attempts:
            out = self.sh(cmd, root=root, timeout=20)
            if "package:" in out:
                return _parse_pm(out)
        return []

    def pkg_uid(self, pkg: str) -> str | None:
        out = self.sh(f"stat -c %u /data/data/{pkg}").strip()
        return out if out.isdigit() else None


def _parse_pm(out: str) -> list[dict]:
    apps: list[dict] = []
    for line in (out or "").splitlines():
        s = line.strip()
        if not s.startswith("package:"):
            continue
        m = _PKG_LINE.match(s)
        if m:
            apps.append({"pkg": m.group(1), "uid": m.group(2) or "", "label": ""})
            continue
        rest = s[len("package:"):].strip()
        pkg, uid = rest, ""
        if " uid:" in rest:
            pkg, uid = rest.split(" uid:", 1)
            uid = uid.strip().split()[0]
        if pkg.strip():
            apps.append({"pkg": pkg.strip(), "uid": uid, "label": ""})
    return apps


def _parse_dumpsys(dump: str, want: set[str] | None = None) -> dict[str, dict]:
    info: dict[str, dict] = {}
    current: str | None = None
    for line in (dump or "").splitlines():
        m = _PKG_HEAD.search(line)
        if m:
            current = m.group(1)
            if want is not None and current not in want:
                current = None
                continue
            info.setdefault(current, {"uid": "", "label": ""})
            continue
        if not current:
            continue
        s = line.strip()
        if s.startswith("userId="):
            uid = s.split("=", 1)[1].split()[0].strip()
            if uid.isdigit():
                info[current]["uid"] = uid
        elif s.startswith("appId=") and not info[current]["uid"]:
            uid = s.split("=", 1)[1].split()[0].strip()
            if uid.isdigit():
                info[current]["uid"] = uid
        else:
            for key, prefer in (("applicationLabel=", True), ("nonLocalizedLabel=", False)):
                if key not in s:
                    continue
                val = s.split(key, 1)[1].strip().strip("\"'")
                if not val or val.lower() in ("null", "none"):
                    continue
                if prefer or not info[current]["label"]:
                    info[current]["label"] = val
                break
    return info
