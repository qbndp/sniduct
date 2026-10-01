"""事件与日志：核心逻辑只发事件，显示层订阅，互不依赖。"""
from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

LEVELS = ("debug", "info", "ok", "warn", "error")
LEVEL_STYLE = {
    "debug": "dim",
    "info": "cyan",
    "ok": "green",
    "warn": "yellow",
    "error": "bold red",
}
KINDS = ("srv", "fwd", "pass", "net", "adb", "ipt", "cfg", "err")


@dataclass
class Event:
    msg: str
    level: str = "info"
    kind: str = "srv"
    ts: float = field(default_factory=time.time)

    @property
    def hhmmss(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


class EventBus:
    """线程安全的事件总线 + 环形日志缓冲。"""

    def __init__(self, capacity: int = 500, echo: Callable[[Event], None] | None = None):
        self._lock = threading.Lock()
        self._subs: list[Callable[[Event], None]] = []
        self._buf: collections.deque[Event] = collections.deque(maxlen=capacity)
        self._echo = echo
        self._counts: collections.Counter[str] = collections.Counter()

    def subscribe(self, fn: Callable[[Event], None]) -> Callable[[], None]:
        with self._lock:
            self._subs.append(fn)
        return lambda: self.unsubscribe(fn)

    def unsubscribe(self, fn: Callable[[Event], None]) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def emit(self, msg: str, level: str = "info", kind: str = "srv") -> Event:
        ev = Event(msg=msg, level=level, kind=kind)
        with self._lock:
            self._buf.append(ev)
            self._counts[kind] += 1
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(ev)
            except Exception:
                pass
        if self._echo is not None:
            try:
                self._echo(ev)
            except Exception:
                pass
        return ev

    def history(self, limit: int = 200, kinds: tuple[str, ...] | None = None) -> list[Event]:
        with self._lock:
            items = list(self._buf)
        if kinds:
            items = [e for e in items if e.kind in kinds]
        return items[-limit:]

    def counters(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    # 便捷方法
    def info(self, msg: str, kind: str = "srv") -> Event:
        return self.emit(msg, "info", kind)

    def ok(self, msg: str, kind: str = "srv") -> Event:
        return self.emit(msg, "ok", kind)

    def warn(self, msg: str, kind: str = "srv") -> Event:
        return self.emit(msg, "warn", kind)

    def error(self, msg: str, kind: str = "err") -> Event:
        return self.emit(msg, "error", kind)

    def debug(self, msg: str, kind: str = "srv") -> Event:
        return self.emit(msg, "debug", kind)
