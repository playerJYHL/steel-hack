"""The atomic claim is the race-safety core of the concurrent pool.

If two pool workers could ever claim the same submission, one player's attack
would run twice (double Steel spend) and the other's could be skipped. This
hammers claim_next from many threads and asserts every job is handed out exactly
once — deterministic, no timing luck involved.
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner.contracts import Submission
from web.store import Store


def test_claim_next_hands_each_job_to_exactly_one_thread(tmp_path):
    store = Store(tmp_path / "arena.db")
    n = 200
    ids = []
    for i in range(n):
        sub = Submission(payload=f"p{i}", level=1, vector="page_hidden_text", player="x")
        store.enqueue(sub)
        ids.append(sub.attack_id)

    claimed: list[str] = []
    claimed_lock = threading.Lock()

    def drain():
        while True:
            job = store.claim_next()
            if job is None:
                # could be genuinely empty, or a transient miss while others hold
                # the writer lock — re-check the queue count to decide.
                if store.stats()["queued"] == 0:
                    return
                continue
            with claimed_lock:
                claimed.append(job["attack_id"])

    threads = [threading.Thread(target=drain) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(claimed) == n, f"claimed {len(claimed)} of {n}"
    assert len(set(claimed)) == n, "a submission was claimed by more than one worker"
    assert set(claimed) == set(ids)


def test_claim_next_returns_none_on_empty_queue(tmp_path):
    assert Store(tmp_path / "a.db").claim_next() is None
