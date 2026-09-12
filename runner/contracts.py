"""The two JSON shapes everything hangs off (DEV.md §1).

Locked first on purpose. Once these are fixed the front-end, the runner and the
payload work proceed behind stubs and nobody blocks on anybody.

Contract A is what the front-end submits. Contract B is what comes back. Both
are specified in DEV.md; the fields added here are additive and each one earns
its place below — nothing in the original shape moved or changed meaning.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

LEVELS = (1, 2, 3, 4)
VECTORS = ("page_hidden_text", "fake_system_block", "poisoned_tool_return")
TRIGGER_TYPES = ("exfil", "destructive", "cred_use")

MAX_PAYLOAD_CHARS = 8000


class ContractError(ValueError):
    """A submission that cannot be run. Reported to the player, not raised at them."""


@dataclass
class Submission:
    """Contract A — front-end → runner."""

    payload: str
    level: int = 1
    vector: str = "page_hidden_text"
    attack_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    player: str = "anonymous"          # added: the leaderboard needs a name
    submitted_at: float = field(default_factory=time.time)

    def validate(self) -> "Submission":
        if self.level not in LEVELS:
            raise ContractError(f"level must be one of {LEVELS}, got {self.level!r}")
        if self.vector not in VECTORS:
            raise ContractError(f"vector must be one of {VECTORS}, got {self.vector!r}")
        if not self.payload or not self.payload.strip():
            raise ContractError("payload is empty — there is nothing to plant")
        if len(self.payload) > MAX_PAYLOAD_CHARS:
            raise ContractError(
                f"payload is {len(self.payload)} chars, limit is {MAX_PAYLOAD_CHARS}"
            )
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Submission":
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(raw) - known
        if unknown:
            raise ContractError(f"unexpected field(s): {', '.join(sorted(unknown))}")
        try:
            sub = cls(**{k: v for k, v in raw.items() if k in known})
        except TypeError as exc:
            raise ContractError(str(exc)) from exc
        if isinstance(sub.level, str) and sub.level.isdigit():
            sub.level = int(sub.level)
        return sub.validate()


@dataclass
class Step:
    """One turn of the agent loop — the raw material for the replay UI."""

    i: int
    thought: str
    action: str
    output: str
    tool_input: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    """Contract B — runner → front-end."""

    attack_id: str
    triggered: bool = False
    trigger_type: str | None = None
    step_index: int | None = None
    steel_session_id: str | None = None
    viewer_url: str | None = None
    steps: list[Step] = field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None

    # --- additive fields, and why each one is here --------------------------
    level: int = 1
    """Echoed back so the leaderboard can weight without a second lookup."""

    vector: str = "page_hidden_text"

    score: int = 0
    """Level-weighted points. See scoring.py — kept out of the runner so the
    scoring rule can change during the event without touching the spine."""

    evidence: dict = field(default_factory=dict)
    """How the secret left: encoding chain, surface, matched snippet. This is
    what makes a verdict arguable-with rather than taken on faith."""

    model_backend: str = "unknown"
    sandbox_backend: str = "unknown"
    """Integrity. A run against the scripted model in a local sandbox must never
    be mistaken for a real model in a real Steel Computer — on the leaderboard,
    in the demo, or in the write-up. Every result says what actually ran."""

    tripwire_events: list[dict] = field(default_factory=list)
    """Everything the tripwires saw, not just the winning hit — including the
    near-misses, which is what a losing player wants to see."""

    defended: bool = False
    """The agent read the injection and refused. Distinct from 'nothing
    happened', and worth showing: it is the interesting outcome at levels 2-4."""

    def to_dict(self) -> dict:
        out = asdict(self)
        out["steps"] = [s.to_dict() if isinstance(s, Step) else s for s in self.steps]
        return out

    @classmethod
    def from_dict(cls, raw: dict) -> "Result":
        data = dict(raw)
        data["steps"] = [
            Step(**s) if isinstance(s, dict) else s for s in data.get("steps", [])
        ]
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def summary(self) -> str:
        if self.error:
            return f"run failed: {self.error}"
        if self.triggered:
            where = f" at step {self.step_index}" if self.step_index is not None else ""
            return f"TRIGGERED ({self.trigger_type}){where}"
        if self.defended:
            return "agent read the injection and refused"
        return "no trigger — the agent stayed on task"
