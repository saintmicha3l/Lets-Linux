"""Mission template variables: ``{{name}}`` substitution with seeded randomness."""

from __future__ import annotations

import random
import re
from typing import Any

_VAR = re.compile(r"(?<!\\)\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
#: \{{ … }} is a literal "{{ … }}" (for content that has its own templates, such as Ansible's)
_ESCAPED = re.compile(r"\\(\{\{)")

WORDS = ["amber", "basalt", "cobalt", "delta", "ember", "falcon", "garnet", "harbor", "indigo",
         "juniper", "krypton", "lumen", "magnet", "nectar", "onyx", "pixel", "quartz", "raven",
         "saffron", "tundra", "umber", "vortex", "willow", "xenon", "yonder", "zephyr"]  # fmt: skip


def resolve_vars(
    spec: dict[str, Any], rng: random.Random, base: dict[str, str] | None = None
) -> dict[str, str]:
    """Turn a ``[environment.vars]`` table into concrete strings.

    ``name = "fixed"``; ``name = { choices = [...] }``; ``name = { range = [lo, hi] }``;
    ``name = { word = true }`` (random code word); ``name = { template = "x-{{other}}" }``.
    Variables are resolved in definition order, so later ones may reference earlier ones.
    """
    values: dict[str, str] = dict(base or {})
    for name, value in spec.items():
        if isinstance(value, dict):
            if "choices" in value:
                values[name] = str(rng.choice(list(value["choices"])))
            elif "range" in value:
                lo, hi = value["range"]
                values[name] = str(rng.randint(int(lo), int(hi)))
            elif value.get("word"):
                values[name] = rng.choice(WORDS) + str(rng.randint(10, 99))
            elif "template" in value:
                values[name] = render(str(value["template"]), values)
            else:
                raise ValueError(f"variable {name!r}: unknown specification {value!r}")
        else:
            values[name] = render(str(value), values)
    return values


def render(value: Any, values: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _ESCAPED.sub(r"\1", _VAR.sub(lambda m: values.get(m.group(1), m.group(0)), value))
    if isinstance(value, list):
        return [render(v, values) for v in value]
    if isinstance(value, dict):
        return {k: render(v, values) for k, v in value.items()}
    return value


def referenced(value: Any) -> set[str]:
    """Variable names referenced anywhere in ``value``."""
    found: set[str] = set()
    if isinstance(value, str):
        found.update(m.group(1) for m in _VAR.finditer(value))
    elif isinstance(value, list):
        for v in value:
            found |= referenced(v)
    elif isinstance(value, dict):
        for v in value.values():
            found |= referenced(v)
    return found
