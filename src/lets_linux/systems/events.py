"""Scheduled events: work that happens at a future simulated time.

The simulation has no background threads. Instead, subsystems schedule
events (a service restart after ``RestartSec=``, a timer elapsing, a cron
job) and the machine runs every due event whenever simulated time is
observed to have advanced — after each command line in an interactive
session, for example. Events are plain data so they survive snapshots.
"""

from __future__ import annotations

import heapq
import itertools
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Handler = Callable[["Event"], None]


@dataclass(order=True)
class Event:
    due: float
    seq: int
    kind: str = field(compare=False)
    data: dict[str, Any] = field(compare=False, default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"due": self.due, "seq": self.seq, "kind": self.kind, "data": dict(self.data)}


class EventQueue:
    #: protects against an event that keeps rescheduling itself at the same instant
    MAX_PER_RUN = 1000

    def __init__(self) -> None:
        self._heap: list[Event] = []
        self._seq = itertools.count()
        self.handlers: dict[str, Handler] = {}

    def schedule(self, due: float, kind: str, **data: Any) -> Event:
        ev = Event(due, next(self._seq), kind, dict(data))
        heapq.heappush(self._heap, ev)
        return ev

    def cancel(self, kind: str, **match: Any) -> int:
        before = len(self._heap)
        self._heap = [
            e for e in self._heap
            if not (e.kind == kind and all(e.data.get(k) == v for k, v in match.items()))
        ]  # fmt: skip
        heapq.heapify(self._heap)
        return before - len(self._heap)

    def next_due(self) -> float | None:
        return self._heap[0].due if self._heap else None

    def clear(self) -> None:
        """Forget all scheduled work (the machine shut down)."""
        self._heap = []

    def pending(self, kind: str | None = None) -> list[Event]:
        return sorted(e for e in self._heap if kind is None or e.kind == kind)

    def run_due(self, now: float) -> int:
        """Run every event due at or before ``now``, in order. Returns the number run."""
        count = 0
        while self._heap and self._heap[0].due <= now and count < self.MAX_PER_RUN:
            ev = heapq.heappop(self._heap)
            handler = self.handlers.get(ev.kind)
            if handler is not None:
                handler(ev)
            count += 1
        return count

    def to_dict(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in sorted(self._heap)]

    def load(self, data: list[dict[str, Any]]) -> None:
        self._heap = []
        top = -1
        for d in data:
            ev = Event(float(d["due"]), int(d["seq"]), str(d["kind"]), dict(d.get("data", {})))
            heapq.heappush(self._heap, ev)
            top = max(top, ev.seq)
        self._seq = itertools.count(top + 1)
