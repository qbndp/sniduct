"""iptables 规则管理（手机侧 nat OUTPUT DNAT + QUIC 拦截）。

归属判定（本工具增删哪些规则的依据）：
  1. 首选 comment 标记：本工具写的规则都带 `-m comment --comment SNIDUCT`，
     旧端口残留也能被认出来（换端口后清理旧规则靠它）；
  2. 对无标记的历史规则，要求同时满足 `--dport 443` 且
     `--to-destination` 端口 == 本工具监听端口；
  3. 其余规则一律不碰——手机 nat OUTPUT 里常有系统/其它工具的规则
     （实测有 `dport 6279 -> 127.0.0.1:16279`、`dport 80 -> 12121`），
     绝不能 `-F OUTPUT`。
"""
from __future__ import annotations

import re
import time

from .adbkit import Adb

IPT = "iptables -w 5"
MARK = "SNIDUCT"                       # 本工具规则标记
QUIC_MARK = f"{MARK}-QUIC"
LEGACY_MARKS = ("RFWD", "RFWD-QUIC")   # 旧名字留下的标记，仅用于清扫

_DNAT_DST = re.compile(r"--to-destination\s+(\S+)")
_UID = re.compile(r"--uid-owner\s+(\d+)")


def dnat_spec(dst_host: str, dst_port: int, uid: str | None = None) -> str:
    """生成一条带归属标记的 DNAT 规则。"""
    mark = f"-m comment --comment {MARK}"
    if uid is None:
        return f"-p tcp --dport 443 {mark} -j DNAT --to-destination {dst_host}:{dst_port}"
    return (f"-p tcp -m owner --uid-owner {uid} --dport 443 {mark} "
            f"-j DNAT --to-destination {dst_host}:{dst_port}")


def _target_port(spec: str) -> str | None:
    m = _DNAT_DST.search(spec)
    if not m:
        return None
    return m.group(1).rsplit(":", 1)[-1]


class Rules:
    def __init__(self, adb: Adb, listen_port: int):
        self.adb = adb
        self.listen_port = int(listen_port)

    # ---- 读 ----

    def rules(self, table: str = "nat") -> list[tuple[int, str]]:
        """指定表 OUTPUT 链现存规则 [(序号, spec)]，`iptables -S` 风格。"""
        tbl = f"-t {table}" if table else ""
        out = self.adb.sh_any(f"{IPT} {tbl} -S OUTPUT")
        rules: list[tuple[int, str]] = []
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("-A OUTPUT"):
                rules.append((len(rules) + 1, line[len("-A OUTPUT"):].strip()))
        return rules

    def nat_output_pretty(self) -> list[str]:
        out = self.adb.sh_any(f"{IPT} -t nat -L OUTPUT -n")
        return [l.strip() for l in (out or "").splitlines() if "DNAT" in l or "Chain" in l]

    def _is_marked(self, spec: str, mark: str = MARK) -> bool:
        return f"--comment {mark}" in spec or f'--comment "{mark}"' in spec

    def _is_ours_marked(self, spec: str) -> bool:
        """当前标记或旧标记（旧标记只用于把它清掉，不再新写）。"""
        return any(self._is_marked(spec, m) for m in (MARK, *LEGACY_MARKS))

    def own_dnat_nums(self, port: int | None = None) -> list[int]:
        """本工具的 DNAT 规则序号（1-based）。

        port=None  -> 只认带标记的（含任意目标端口，用于全量清理）；
        port= 数字 -> 带标记且目标端口匹配的 + 无标记但形态吻合的历史规则。
        """
        nums: list[int] = []
        want = str(port) if port is not None else None
        for num, spec in self.rules():
            marked = self._is_ours_marked(spec)
            if "--to-destination" not in spec:
                continue
            if marked:
                if want is None or _target_port(spec) == want:
                    nums.append(num)
            elif want is not None:
                # 历史规则兜底：必须明确是 443 的 DNAT 且落在本工具端口上
                if "--dport 443" in spec and _target_port(spec) == want:
                    nums.append(num)
        return nums

    def quic_present(self) -> bool:
        return bool(self.quic_nums())

    def quic_nums(self) -> list[int]:
        """本工具的 QUIC 拦截规则（filter 表 OUTPUT 链）：带标记的 + 旧版无标记规则。"""
        nums = []
        for num, spec in self.rules(table=""):  # filter 表（REJECT 目标所在）
            if not ("-p udp" in spec and "--dport 443" in spec and "-j REJECT" in spec):
                continue
            if self._is_ours_marked(spec):
                nums.append(num)
            elif "--reject-with icmp-port-unreachable" in spec and "--comment" not in spec:
                nums.append(num)      # 旧版脚本写的无标记规则
        return nums

    def dnat_count(self) -> int:
        """当前带标记的 DNAT 规则条数（(uid,dst) 去重前）。"""
        return len([1 for _n, s in self.rules()
                    if self._is_ours_marked(s) and "--to-destination" in s])

    # ---- 写 ----

    def _delete(self, nums: list[int], table: str = "nat") -> None:
        tbl = f"-t {table}" if table else ""
        for num in sorted(set(nums), reverse=True):
            self.adb.sh(f"{IPT} {tbl} -D OUTPUT {num}")

    def _retry(self, apply_fn, check_fn, tries: int = 6, delay: float = 1.0) -> bool:
        for _ in range(tries):
            apply_fn()
            try:
                if check_fn():
                    return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    @staticmethod
    def _expected(specs: list[str]) -> set[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for s in specs:
            m = _DNAT_DST.search(s)
            dst = m.group(1) if m else ""
            u = _UID.search(s)
            out.add((u.group(1) if u else "", dst))
        return out

    def _actual(self) -> set[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for _num, spec in self.rules():
            if not self._is_marked(spec) or "--to-destination" not in spec:
                continue
            m = _DNAT_DST.search(spec)
            u = _UID.search(spec)
            out.add((u.group(1) if u else "", m.group(1) if m else ""))
        return out

    def set_dnat(self, specs: list[str], dst_port: int | None = None,
                 stale_ports: tuple[int, ...] = ()) -> bool:
        """重装 DNAT：先清自己的（含换端口前的残留），再写入新规则，最后按 (uid,dst) 校验。"""
        port = int(dst_port or self.listen_port)
        ports = (port,) + tuple(p for p in stale_ports if p and p != port)
        expected = self._expected(specs)

        def apply():
            self._delete(self.own_dnat_nums())
            for p in ports:
                self._delete([n for n in self.own_dnat_nums(p) if n])
            for spec in specs:
                self.adb.sh(f"{IPT} -t nat -A OUTPUT {spec}")

        return self._retry(apply, lambda: self._actual() == expected)

    def clear_dnat(self, stale_ports: tuple[int, ...] = ()) -> bool:
        ports = (int(self.listen_port),) + tuple(p for p in stale_ports if p)

        def apply():
            self._delete(self.own_dnat_nums())
            for p in ports:
                self._delete(self.own_dnat_nums(p))

        return self._retry(apply, lambda: not self.own_dnat_nums())

    def set_quic(self) -> bool:
        if self.quic_present():
            return True
        rule = (f"-p udp --dport 443 -m comment --comment {QUIC_MARK} "
                f"-j REJECT --reject-with icmp-port-unreachable")

        def ensure():
            # 重试过程中只在没有时才添加，避免装出重复规则
            if not self.quic_present():
                self.adb.sh(f"{IPT} -A OUTPUT {rule}")

        return self._retry(ensure, self.quic_present)

    def clear_quic(self) -> bool:
        def apply():
            self._delete(self.quic_nums(), table="")

        return self._retry(apply, lambda: not self.quic_nums(), tries=12, delay=0.5)
