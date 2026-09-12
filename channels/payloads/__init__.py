"""Loader for the starter payload library.

The library is JSON so it is editable at the booth without touching code, and so
the front-end can offer players a menu of starting points (DEV.md §B3). Every
entry marked `verified` is checked by tests/test_payloads.py against the scripted
harness, so the menu never offers a payload that silently doesn't work.
"""

from __future__ import annotations

import json
from pathlib import Path

_LIB = Path(__file__).resolve().parent / "library.json"


def load_payloads() -> list[dict]:
    data = json.loads(_LIB.read_text(encoding="utf-8"))
    return data["payloads"]


def verified_payloads() -> list[dict]:
    return [p for p in load_payloads() if p.get("verified")]


def payloads_for(level: int | None = None, vector: str | None = None) -> list[dict]:
    out = load_payloads()
    if level is not None:
        out = [p for p in out if p["level"] == level]
    if vector is not None:
        out = [p for p in out if p["vector"] == vector]
    return out
