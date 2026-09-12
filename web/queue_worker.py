"""The async queue: attacks run one at a time, in a background thread.

PROJECT_CONTEXT §9 is explicit that this is a cost constraint, not a feature —
ten people at the booth must not each spin up a live Steel Computer. So this is a
single worker draining a FIFO queue, not a pool and not real concurrency. One
machine is alive at a time; the rest of the booth watches their position tick
down.

The worker owns the runner call and therefore the release guarantee. It catches
everything: a run that throws still gets written back as an error result and the
queue keeps moving. A booth that stops draining is worse than a booth that
occasionally reports a failed run.
"""

from __future__ import annotations

import threading
import time
import traceback

from runner.contracts import Result, Submission
from runner.runner import RunConfig, run_attack

from .store import Store

POLL_INTERVAL_S = 0.5


class QueueWorker:
    def __init__(self, store: Store, config: RunConfig | None = None):
        self.store = store
        self.config = config or RunConfig()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.current_attack_id: str | None = None

    def start(self) -> "QueueWorker":
        if self._thread and self._thread.is_alive():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="arena-queue")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self.store.next_queued()
            if job is None:
                self._stop.wait(POLL_INTERVAL_S)
                continue
            self._run_one(job)

    def _run_one(self, job: dict) -> None:
        attack_id = job["attack_id"]
        self.current_attack_id = attack_id
        self.store.mark_running(attack_id)
        try:
            submission = Submission(
                payload=job["payload"], level=job["level"], vector=job["vector"],
                attack_id=attack_id, player=job["player"],
                submitted_at=job["submitted_at"],
            )
            result = run_attack(submission, self.config)
        except Exception as exc:  # the runner already guards itself, but belt-and-braces
            traceback.print_exc()
            result = Result(attack_id=attack_id, level=job["level"],
                            vector=job["vector"], error=f"{type(exc).__name__}: {exc}",
                            model_backend=self.config.model_backend,
                            sandbox_backend=self.config.sandbox_backend)
        finally:
            self.current_attack_id = None
        self.store.save_result(result)
