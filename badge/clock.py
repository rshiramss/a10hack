"""Injectable clock. Every time-based decision reads the clock through this module so
tests can control time without sleeping."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Current time as epoch seconds."""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class FrozenClock:
    """A clock that only moves when told to. Thread-safe enough for tests (float writes)."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def to_ms(epoch_seconds: float) -> int:
    return int(round(epoch_seconds * 1000))
