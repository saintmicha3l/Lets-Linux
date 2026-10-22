"""Declarative achievements driven by named counters."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class Achievement:
    id: str
    title: str
    description: str
    counter: str
    threshold: int


@lru_cache(maxsize=1)
def load_achievements() -> tuple[Achievement, ...]:
    text = (
        resources.files("lets_linux.content")
        .joinpath("achievements.toml")
        .read_text(encoding="utf-8")
    )
    data = tomllib.loads(text)
    items = []
    seen = set()
    for a in data.get("achievement", []):
        if a["id"] in seen:
            raise ValueError(f"duplicate achievement {a['id']}")
        seen.add(a["id"])
        items.append(
            Achievement(a["id"], a["title"], a["description"], a["counter"], int(a["threshold"]))
        )
    return tuple(items)


def newly_unlocked(counters: Mapping[str, int], unlocked: Iterable[str]) -> list[Achievement]:
    have = set(unlocked)
    return [
        a
        for a in load_achievements()
        if a.id not in have and counters.get(a.counter, 0) >= a.threshold
    ]
