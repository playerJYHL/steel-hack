#!/usr/bin/env python3
"""Dump the RAW shape of a Steel Computer exec response — schema-locking probe.

The exec endpoint streams JSON events and the exact field names aren't documented
for Python. Run this once on a box that can reach api.steel.dev to see the wire
format verbatim, so the parser can be made exact if the inferred one is off:

    STEEL_API_KEY=sk-... python3 scripts/probe_steel_exec.py

It creates a computer, runs `echo arena-probe && id`, prints the status,
content-type and raw body, shows how the current parser interprets it, and
deletes the computer. Deliberately uses raw httpx (not our parser) for the dump
so nothing hides the true format. Set KEEP_MACHINE=1 to skip deletion.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from runner.backends.steel_computer import STEEL_API_BASE, ExecResult

CMD = "echo arena-probe && id && pwd"


def main() -> int:
    key = os.environ.get("STEEL_API_KEY")
    if not key:
        print("ERROR: set STEEL_API_KEY", file=sys.stderr)
        return 2
    verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or True
    http = httpx.Client(base_url=STEEL_API_BASE,
                        headers={"steel-api-key": key, "content-type": "application/json"},
                        timeout=120, verify=verify)

    print(f"POST {STEEL_API_BASE}/v1/computers")
    body = {}
    if os.environ.get("STEEL_TEMPLATE"):
        body["template"] = os.environ["STEEL_TEMPLATE"]
    if os.environ.get("STEEL_REGION"):
        body["region"] = os.environ["STEEL_REGION"]
    r = http.post("/v1/computers", json=body)
    print(f"  -> {r.status_code}")
    print(f"  raw create body: {r.text[:800]}")
    r.raise_for_status()
    data = r.json()
    cid = data.get("id") or data.get("computerId") or data.get("computer_id")
    print(f"  computer id: {cid}")

    try:
        # exec can 4xx while the machine boots; retry a handful of times.
        for attempt in range(20):
            print(f"\nPOST /v1/computers/{cid}/exec  (attempt {attempt+1})  cmd={CMD!r}")
            er = http.post(f"/v1/computers/{cid}/exec",
                           json={"command": CMD, "timeout": 60}, timeout=90)
            print(f"  -> HTTP {er.status_code}   content-type={er.headers.get('content-type')}")
            print("  ---- RAW BODY START ----")
            print(er.text[:4000])
            print("  ---- RAW BODY END ----")
            if er.status_code == 200 and er.text.strip():
                parsed = ExecResult.from_response_text(er.text)
                print(f"\n  parser sees: stdout={parsed.stdout!r} "
                      f"stderr={parsed.stderr!r} exit={parsed.exit_code}")
                if "arena-probe" in parsed.stdout:
                    print("  ✅ parser extracted stdout correctly")
                else:
                    print("  ⚠️  parser did NOT find 'arena-probe' — paste the RAW BODY back")
                break
            time.sleep(3)
    finally:
        if not os.environ.get("KEEP_MACHINE"):
            print(f"\nDELETE /v1/computers/{cid}")
            try:
                d = http.delete(f"/v1/computers/{cid}")
                print(f"  -> {d.status_code}")
            except Exception as exc:
                print(f"  delete failed: {exc}")
        http.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
