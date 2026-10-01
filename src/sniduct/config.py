"""配置：加载 / 保存 sniduct.json。

设计目标：地址与端口都会变，所以允许写 "auto"：
  - listen.host   = "auto" → 每次 START 都探测「通往设备的本机地址」
  - listen.host   = 固定 IP → 该地址失效时自动回落（fallback_auto）
  - upstream.host = "auto" → 允许采纳 HTTPS_PROXY / HTTP_PROXY 等环境变量，缺省 127.0.0.1
  - upstream.port = "auto" → 扫描候选端口，找一个真正的 HTTP 代理
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from typing import Any

from .util import is_auto

CONFIG_NAME = "sniduct.json"
CONFIG_ENV = "SNIDUCT_CONFIG"
CONFIG_VERSION = 3
ALL_TARGET_TOKENS = ("", "*", "all", "ALL", "any")


def user_config_dir() -> str:
    """非源码安装时的配置目录：Windows 走 %APPDATA%，其它平台走 XDG。"""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = (os.environ.get("XDG_CONFIG_HOME")
                or os.path.join(os.path.expanduser("~"), ".config"))
    return os.path.join(base, "sniduct")


def default_config_path() -> str:
    """配置位置：$SNIDUCT_CONFIG > 仓库根 sniduct.json（源码模式）> 用户配置目录。"""
    env = (os.environ.get(CONFIG_ENV) or "").strip()
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))       # .../src/sniduct
    src = os.path.dirname(here)                             # .../src
    if os.path.basename(src) == "src":
        return os.path.join(os.path.dirname(src), CONFIG_NAME)
    return os.path.join(user_config_dir(), CONFIG_NAME)


@dataclass
class ListenCfg:
    host: str = "auto"          # "auto" 或固定 IP
    port: int = 8088
    port_auto: bool = False     # True: 端口被占用时自动挑一个空闲端口
    fallback_auto: bool = True  # 固定 IP 失效时自动改用探测到的地址


@dataclass
class UpstreamCfg:
    host: str = "auto"          # "auto" 或固定 IP
    port: str | int = "auto"    # "auto" 或固定端口
    probe_ports: list[int] = field(default_factory=list)  # 空 = 用内置候选端口


@dataclass
class Config:
    listen: ListenCfg = field(default_factory=ListenCfg)
    upstream: UpstreamCfg = field(default_factory=UpstreamCfg)
    adb: str = "adb"
    device: str = ""
    target_apps: list[str] = field(default_factory=lambda: ["*"])
    skip_snis: list[str] = field(default_factory=list)
    block_quic: bool = True
    version: int = CONFIG_VERSION
    path: str = ""

    # ---- 读写 ----

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        path = path or default_config_path()
        raw: dict[str, Any] = {}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    raw = data
            except Exception:
                raw = {}
        cfg = cls.from_dict(raw)
        cfg.path = path
        return cfg

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Config":
        cfg = cls()
        listen = d.get("listen") if isinstance(d.get("listen"), dict) else {}
        upstream = d.get("upstream") if isinstance(d.get("upstream"), dict) else {}
        cfg.listen = ListenCfg(
            host=str(listen.get("host") or "auto").strip() or "auto",
            port=_int(listen.get("port"), 8088),
            port_auto=bool(listen.get("port_auto", False)),
            fallback_auto=bool(listen.get("fallback_auto", True)),
        )
        cfg.upstream = UpstreamCfg(
            host=str(upstream.get("host") or "auto").strip() or "auto",
            port=_port_or_auto(upstream.get("port")),
            probe_ports=_norm_ports(upstream.get("probe_ports")),
        )
        cfg.adb = str(d.get("adb") or "adb").strip() or "adb"
        cfg.device = str(d.get("device") or "").strip()
        cfg.target_apps = _norm_apps(d)
        cfg.skip_snis = _norm_list(d.get("skip_snis"))
        cfg.block_quic = bool(d.get("block_quic", True))
        cfg.version = _int(d.get("version"), CONFIG_VERSION)
        return cfg

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d.pop("path", None)
        d["version"] = CONFIG_VERSION
        return d

    def save(self, path: str | None = None) -> None:
        target = path or self.path or default_config_path()
        self.path = target
        tmp = f"{target}.tmp"
        try:
            parent = os.path.dirname(os.path.abspath(target))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            os.replace(tmp, target)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    # ---- 语义 ----

    def is_all_scope(self, apps: list[str] | None = None) -> bool:
        apps = self.target_apps if apps is None else apps
        return any((a or "").strip() in ALL_TARGET_TOKENS[1:] for a in apps or [])

    def scope_token(self) -> str:
        apps = self.target_apps
        if self.is_all_scope(apps):
            return "*"
        if not apps:
            return ""
        return apps[0]

    def set_scope(self, apps: list[str]) -> None:
        apps = [str(a).strip() for a in apps if str(a).strip()]
        self.target_apps = apps or []

    @property
    def listen_host_is_auto(self) -> bool:
        return is_auto(self.listen.host)

    @property
    def upstream_port_is_auto(self) -> bool:
        return is_auto(str(self.upstream.port))

    @property
    def upstream_host_is_auto(self) -> bool:
        return is_auto(self.upstream.host)


def _int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _port_or_auto(v: Any) -> str | int:
    if is_auto(str(v)) or v is None:
        return "auto"
    n = _int(v, -1)
    return n if 0 < n < 65536 else "auto"


def _norm_list(v: Any) -> list[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        s = str(x).strip()
        if s and s not in out:
            out.append(s)
    return out


def _norm_ports(v: Any) -> list[int]:
    out: list[int] = []
    for x in v if isinstance(v, list) else []:
        n = _int(x, -1)
        if 0 < n < 65536 and n not in out:
            out.append(n)
    return out


def _norm_apps(d: dict[str, Any]) -> list[str]:
    if "target_apps" in d:
        apps = _norm_list(d.get("target_apps"))
    else:
        ta = d.get("target_app", "*")
        if isinstance(ta, list):
            apps = _norm_list(ta)
        else:
            ta = str(ta or "*").strip()
            apps = ["*"] if ta in ALL_TARGET_TOKENS else ([ta] if ta else ["*"])
    if any(a in ALL_TARGET_TOKENS[1:] for a in apps):
        return ["*"]
    return apps
