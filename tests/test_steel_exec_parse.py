"""Parsing the Steel Computer exec response.

The exec endpoint streams output as a sequence of JSON events (we hit
`Extra data: line 2 column 1` on first contact — a single json.loads can't read
NDJSON). These lock the stream-aware parser against the shapes it must survive,
including the single-object form the local backend and older code assume.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from runner.backends.steel_computer import ExecResult, decode_json_stream


@pytest.mark.parametrize("text,out,code", [
    ('{"stdout":"arena-ready\\n","exitCode":0}', "arena-ready", 0),
    ('{"output":"x","code":"2"}', "x", 2),
    ('{"type":"stdout","data":"arena-ready\\n"}\n{"type":"exit","exitCode":0}', "arena-ready", 0),
    ('{"stream":"stdout","data":"hel"}\n{"stream":"stdout","data":"lo\\n"}\n'
     '{"stream":"stderr","data":"warn"}\n{"type":"end","exit_code":3}', "hello", 3),
    ('{"type":"stdout","line":"a"}{"type":"stdout","line":"b"}{"type":"exit","code":0}', "ab", 0),
    ('{"result":{"stdout":"nested","exitCode":5}}', "nested", 5),
    ("", "", 0),
])
def test_parses_stream_shapes(text, out, code):
    r = ExecResult.from_response_text(text)
    assert r.stdout.strip() == out
    assert r.exit_code == code


def test_stderr_is_separated_and_surfaced():
    r = ExecResult.from_response_text(
        '{"stream":"stdout","data":"o"}\n{"stream":"stderr","data":"e"}\n'
        '{"type":"exit","exitCode":1}')
    assert r.stdout == "o" and r.stderr == "e"
    assert r.exit_code == 1
    assert not r.ok and "e" in r.output


def test_decoder_skips_a_garbage_line_without_aborting():
    r = ExecResult.from_response_text(
        '{"type":"stdout","data":"good\\n"}\n<<not json>>\n{"type":"exit","exitCode":0}')
    assert "good" in r.stdout and r.exit_code == 0


def test_decoder_handles_a_plain_json_array():
    assert len(decode_json_stream('[{"a":1},{"b":2}]')) == 2
