"""Loads the default simulated network world from ``content/world``."""

from __future__ import annotations

import tomllib
from importlib import resources
from typing import Any

from lets_linux.systems.world import DnsServer, Peer, Record, World


def _records(data: dict[str, Any]) -> dict[str, list[Record]]:
    return {name.lower(): [Record(**r) for r in rs] for name, rs in data.items()}


def load_world(name: str = "default") -> World:
    text = (
        resources.files("lets_linux.content")
        .joinpath("world", f"{name}.toml")
        .read_text(encoding="utf-8")
    )
    data = tomllib.loads(text)
    world = World()
    for p in data.get("peer", []):
        world.peers.append(Peer.from_dict(p))
    for d in data.get("dns", []):
        world.dns.append(DnsServer(address=d["address"], records=_records(d.get("records", {})),
                                   zones=list(d.get("zones", [])), recursive=bool(d.get("recursive", True))))  # fmt: skip
    world.public = _records(data.get("public", {}))
    return world
