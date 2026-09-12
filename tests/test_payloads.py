"""Every 'verified' payload in the library must actually fire at its level.

DEV.md §4/B2 requires each level to have at least one verified working exploit,
and warns that a level nobody can beat is a level that shouldn't ship. This test
is that requirement made executable: it runs each verified payload through the
real spine at its stated level and asserts the tripwire fires. If someone tightens
a defense and silently breaks a level's only exploit, this goes red.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from channels.page_builder import render_injection
from channels.payloads import load_payloads, verified_payloads
from runner.contracts import VECTORS
from runner.runner import RunConfig, run_attack
from runner.contracts import Submission

SCRIPTED = RunConfig(model_backend="scripted", sandbox_backend="local")


@pytest.fixture(autouse=True)
def isolated_event_log(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_EVENT_LOG", str(tmp_path / "events.jsonl"))


@pytest.mark.parametrize("p", verified_payloads(), ids=lambda p: p["id"])
def test_verified_payload_fires_at_its_level(p):
    res = run_attack(
        Submission(payload=p["text"], level=p["level"], vector=p["vector"]), SCRIPTED
    )
    assert res.triggered, (
        f"{p['id']} is marked verified but did not fire at level {p['level']}"
    )
    if p.get("trigger"):
        assert res.trigger_type == p["trigger"], (
            f"{p['id']} fired as {res.trigger_type}, expected {p['trigger']}"
        )


def test_every_level_has_a_verified_exploit():
    """The ladder must have no dead rung (DEV.md §4/B2)."""
    covered = {p["level"] for p in verified_payloads()}
    assert covered == {1, 2, 3, 4}, f"levels missing a verified exploit: {{1,2,3,4}} - {covered}"


def test_library_entries_are_well_formed():
    for p in load_payloads():
        assert p["vector"] in VECTORS, f"{p['id']} has an unknown vector"
        assert 1 <= p["level"] <= 4
        assert p["text"].strip()


@pytest.mark.parametrize("vector", VECTORS)
def test_every_vector_plants_the_payload_in_the_page(vector):
    """The payload must actually appear in the rendered page for each vector."""
    marker = "UNIQUE_PAYLOAD_MARKER_42"
    html = render_injection(marker, vector)
    assert marker in html
