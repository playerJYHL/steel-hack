"""The attack queue: a small pool of workers draining a FIFO queue.

Each attack runs in its own Steel browser session, fully independent of the
others (its own canary, monitor and session), so the browser path is safe to run
several at once — a fleet, not one machine (PROJECT_CONTEXT §3). Concurrency is
capped (ARENA_CONCURRENCY, default 5) so a busy booth serves several players at
once without an unbounded number of live sessions billing in parallel.

Jobs are claimed atomically in the store (one UPDATE ... RETURNING under
SQLite's writer lock), so two workers never pick up the same submission. Each
worker owns its run and therefore the release guarantee: a run that throws still
gets written back as an error result and the queue keeps draining. A booth that
stops draining is worse than one that occasionally reports a failed run.
"""

from __future__ import annotations

import os
import threading
import time
import traceback

from runner.contracts import Result, Submission
from runner.runner import RunConfig, run_attack

from .store import Store

POLL_INTERVAL_S = 0.5
DEFAULT_CONCURRENCY = int(os.environ.get("ARENA_CONCURRENCY", "5"))


class QueueWorker:
    def __init__(self, store: Store, config: RunConfig | None = None,
                 concurrency: int | None = None):
        self.store: Store = store
        self.config: RunConfig = config or RunConfig()
        self.concurrency: int = max(1, concurrency or DEFAULT_CONCURRENCY)
        self._threads: list[threading.Thread] = []
        self._stop: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()
        self._current: list[str] = []   # running attack ids, most-recent last

    @property
    def current_attack_id(self) -> str | None:
        with self._lock:
            return self._current[-1] if self._current else None

    def is_running(self, attack_id: str) -> bool:
        with self._lock:
            return attack_id in self._current

    def start(self) -> "QueueWorker":
        if any(t.is_alive() for t in self._threads):
            return self
        self._stop.clear()
        self._threads = []
        for i in range(self.concurrency):
            t = threading.Thread(target=self._loop, daemon=True, name=f"arena-queue-{i}")
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.store.claim_next()
            except Exception:
                traceback.print_exc()
                self._stop.wait(POLL_INTERVAL_S)
                continue
            if job is None:
                self._stop.wait(POLL_INTERVAL_S)
                continue
            self._run_one(job)

    def _run_one(self, job: dict) -> None:
        attack_id = job["attack_id"]
        with self._lock:
            self._current.append(attack_id)
        try:
            submission = Submission(
                payload=job["payload"], level=job["level"], vector=job["vector"],
                attack_id=attack_id, player=job["player"],
                submitted_at=job["submitted_at"],
            )
            result = run_attack(
                submission, self.config,
                on_progress=lambda progress: self.store.save_progress(attack_id, progress),
            )
        except Exception as exc:  # the runner already guards itself, but belt-and-braces
            traceback.print_exc()
            result = Result(attack_id=attack_id, level=job["level"],
                            vector=job["vector"], error=f"{type(exc).__name__}: {exc}",
                            model_backend=self.config.model_backend,
                            sandbox_backend=self.config.sandbox_backend)
        try:
            self.store.save_result(result)
        finally:
            with self._lock:
                if attack_id in self._current:
                    self._current.remove(attack_id)
