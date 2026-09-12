"""Durable state for the arena: submissions, results, the leaderboard.

SQLite via the stdlib, one file. Chosen over an in-memory dict for a booth
reason: the demo machine will get bumped, the process will get restarted, and
losing the leaderboard mid-event is not acceptable. WAL mode so the queue worker
can write while the web thread reads.

This module is storage only — no Flask, no scoring, no policy — so the runner
and the queue can use it without dragging the web framework in.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent / "arena.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    attack_id   TEXT PRIMARY KEY,
    player      TEXT NOT NULL,
    level       INTEGER NOT NULL,
    vector      TEXT NOT NULL,
    payload     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',   -- queued|running|done|error
    submitted_at REAL NOT NULL,
    started_at  REAL,
    finished_at REAL,
    result_json TEXT,
    progress_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
CREATE INDEX IF NOT EXISTS idx_attacks_submitted ON attacks(submitted_at);
"""


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = str(path)
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(_SCHEMA)
            columns = {row[1] for row in c.execute("PRAGMA table_info(attacks)")}
            if "progress_json" not in columns:
                c.execute("ALTER TABLE attacks ADD COLUMN progress_json TEXT")

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    # -- writes --------------------------------------------------------------

    def enqueue(self, submission) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO attacks (attack_id, player, level, vector, payload, "
                "status, submitted_at) VALUES (?,?,?,?,?, 'queued', ?)",
                (submission.attack_id, submission.player, submission.level,
                 submission.vector, submission.payload, submission.submitted_at),
            )

    def mark_running(self, attack_id: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE attacks SET status='running', started_at=? "
                      "WHERE attack_id=?", (time.time(), attack_id))

    def save_result(self, result) -> None:
        status = "error" if result.error and not result.triggered else "done"
        with self._conn() as c:
            c.execute(
                "UPDATE attacks SET status=?, finished_at=?, result_json=?, progress_json=NULL "
                "WHERE attack_id=?",
                (status, time.time(), json.dumps(result.to_dict(), default=str),
                 result.attack_id),
            )

    def save_progress(self, attack_id: str, progress: dict) -> None:
        with self._conn() as c:
            c.execute("UPDATE attacks SET progress_json=? WHERE attack_id=? AND status='running'",
                      (json.dumps(progress, default=str), attack_id))

    # -- reads ---------------------------------------------------------------

    def get(self, attack_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM attacks WHERE attack_id=?", (attack_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None

    def list_sessions(self, limit: int = 24) -> list[dict]:
        """Compact rows for the spectator gallery: every live run first (newest
        first), then the most recent finished ones. Only the fields a tile needs
        — never the payload text — so the wall stays light and nothing sensitive
        leaks into a public view. Bounded and status-indexed."""
        limit = max(1, min(int(limit), 48))
        rows = self._conn().execute(
            "SELECT attack_id, player, level, vector, status, submitted_at, "
            "started_at, finished_at, progress_json, result_json FROM attacks "
            "WHERE status IN ('running','done','error') "
            "ORDER BY (status='running') DESC, "
            "COALESCE(finished_at, started_at, submitted_at) DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out: list[dict] = []
        for row in rows:
            d = dict(row)
            prog = _loads(d.pop("progress_json"))
            res = _loads(d.pop("result_json"))
            src = res or prog or {}
            out.append({
                "attack_id": d["attack_id"], "player": d["player"], "level": d["level"],
                "vector": d["vector"], "status": d["status"],
                "viewer_url": src.get("viewer_url"),
                "triggered": bool((res or {}).get("triggered", False)),
                "trigger_type": (res or {}).get("trigger_type"),
                "defended": bool((res or {}).get("defended", False)),
                "error": bool((res or {}).get("error")),
                "score": (res or {}).get("score", 0),
                "model_backend": src.get("model_backend"),
                "sandbox_backend": src.get("sandbox_backend"),
                "step_count": len(src.get("steps") or []),
                "started_at": d["started_at"], "finished_at": d["finished_at"],
            })
        return out

    def next_queued(self) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM attacks WHERE status='queued' "
            "ORDER BY submitted_at ASC LIMIT 1"
        ).fetchone()
        return _row_to_dict(row) if row else None

    def claim_next(self) -> dict | None:
        """Atomically claim the oldest queued attack: mark it running and return
        it in one statement, so a pool of workers never grabs the same job.
        SQLite serialises writers, so the second worker's subquery no longer sees
        a job the first has already flipped to running."""
        conn = self._conn()
        with conn:
            row = conn.execute(
                "UPDATE attacks SET status='running', started_at=? "
                "WHERE attack_id = (SELECT attack_id FROM attacks WHERE status='queued' "
                "ORDER BY submitted_at ASC LIMIT 1) "
                "RETURNING *",
                (time.time(),),
            ).fetchone()
        return _row_to_dict(row) if row else None

    def queue_position(self, attack_id: str) -> int:
        """How many queued attacks are ahead of this one (0 == next up)."""
        row = self._conn().execute(
            "SELECT submitted_at, status FROM attacks WHERE attack_id=?", (attack_id,)
        ).fetchone()
        if not row or row["status"] != "queued":
            return 0
        return self._conn().execute(
            "SELECT COUNT(*) FROM attacks WHERE status='queued' AND submitted_at < ?",
            (row["submitted_at"],),
        ).fetchone()[0]

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM attacks ORDER BY submitted_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def leaderboard(self, limit: int = 20) -> list[dict]:
        """Winning attacks, ranked. Score first (already level-weighted), then
        fewer steps, then shorter payload — the economy tie-break of §5."""
        rows = self._conn().execute(
            "SELECT * FROM attacks WHERE status='done' AND result_json IS NOT NULL"
        ).fetchall()
        wins = []
        for r in rows:
            d = _row_to_dict(r)
            res = d.get("result") or {}
            if not res.get("triggered"):
                continue
            steps = len([s for s in res.get("steps", []) if s.get("action") != "final"])
            wins.append({
                "attack_id": d["attack_id"],
                "player": d["player"],
                "level": d["level"],
                "vector": d["vector"],
                "trigger_type": res.get("trigger_type"),
                "score": res.get("score", 0),
                "steps": steps,
                "payload_len": len(d["payload"]),
                "finished_at": d.get("finished_at"),
                "model_backend": res.get("model_backend", "unknown"),
                "sandbox_backend": res.get("sandbox_backend", "unknown"),
            })
        wins.sort(key=lambda w: (-w["score"], w["steps"], w["payload_len"]))
        return wins[:limit]

    def stats(self) -> dict:
        c = self._conn()
        total = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        done = c.execute("SELECT COUNT(*) FROM attacks WHERE status='done'").fetchone()[0]
        queued = c.execute("SELECT COUNT(*) FROM attacks WHERE status='queued'").fetchone()[0]
        wins = sum(1 for w in self.leaderboard(10_000))
        by_level = {}
        for lvl in (1, 2, 3, 4):
            by_level[lvl] = sum(1 for w in self.leaderboard(10_000) if w["level"] == lvl)
        return {"total": total, "done": done, "queued": queued,
                "wins": wins, "wins_by_level": by_level}


def _loads(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    progress = d.pop("progress_json", None)
    if progress:
        try:
            d["progress"] = json.loads(progress)
        except (ValueError, TypeError):
            d["progress"] = None
    if d.get("result_json"):
        try:
            d["result"] = json.loads(d["result_json"])
        except (ValueError, TypeError):
            d["result"] = None
    return d
