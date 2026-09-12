"""Talking to a Steel Computer — the empty Linux machine the agent runs inside.

The Steel Computer exec API is real but not wrapped by the Python `steel-sdk`
0.19.0 we pin (that SDK is browser-only: sessions + computer-use GUI actions).
The endpoints exist though, as the Node SDK and CLI show:

    POST   /v1/computers            create a machine        -> {id, ...}
    POST   /v1/computers/{id}/exec  run /bin/sh -c <cmd>     -> {stdout, stderr, exitCode}
    DELETE /v1/computers/{id}       destroy it
    GET    /v1/computers/{id}/ssh   websocket shell (unused here)

So we call the REST endpoints directly with the `steel-api-key` header. The exact
response field names aren't documented for Python, so `ExecResult` parsing is
deliberately forgiving (stdout/output, exitCode/exit_code/code, …) and adjusts on
first contact with a real machine.

Two client implementations behind one interface, mirroring the sandbox design:

  * SteelComputerClient — the real thing, hits api.steel.dev.
  * LocalComputerClient — runs the same commands via subprocess against a temp
    directory standing in for the machine's filesystem. It exists so the whole
    SteelSandbox orchestration (seed → in-machine proxy → exec → read events back
    → release) can be exercised on any Linux box without a Steel key or network —
    the only untested surface then being the three REST calls themselves.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

STEEL_API_BASE = os.environ.get("STEEL_API_BASE", "https://api.steel.dev")
DEFAULT_EXEC_TIMEOUT = 300


@dataclass
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False

    @property
    def output(self) -> str:
        out = (self.stdout or "")
        if self.stderr:
            out += ("\n" if out else "") + self.stderr
        return out.strip()

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @classmethod
    def from_api(cls, data: dict) -> "ExecResult":
        """Parse a single exec response object (or one stream event)."""
        return cls._aggregate([data])

    @classmethod
    def from_response_text(cls, text: str) -> "ExecResult":
        """Parse an exec HTTP body that may be a single JSON object, NDJSON, or
        concatenated JSON stream events. Steel streams exec output as a sequence
        of JSON events (the `Extra data: line 2` we hit on first contact), so we
        decode every value in the body and fold them into one result."""
        return cls._aggregate(decode_json_stream(text))

    @staticmethod
    def _aggregate(events: list) -> "ExecResult":
        stdout: list[str] = []
        stderr: list[str] = []
        code = 0
        code_seen = False
        timed_out = False

        def as_int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        for ev in events:
            if isinstance(ev, str):
                stdout.append(ev)
                continue
            if not isinstance(ev, dict):
                continue
            # Some APIs nest the real result under "result"/"data" as an object.
            if isinstance(ev.get("result"), dict):
                ev = {**ev, **ev["result"]}

            # explicit stream fields on a whole-result object
            if isinstance(ev.get("stdout"), str):
                stdout.append(ev["stdout"])
            if isinstance(ev.get("stderr"), str):
                stderr.append(ev["stderr"])

            # exit code under any of the usual spellings
            for k in ("exitCode", "exit_code", "returnCode", "return_code", "code", "status"):
                if k in ev and as_int(ev[k]) is not None:
                    code, code_seen = as_int(ev[k]), True

            if ev.get("timedOut") or ev.get("timed_out"):
                timed_out = True

            # a streamed chunk: a kind + a payload
            # (confirmed Steel shape: {"event":"output","data":"..."} and a
            #  terminal {"event":"exit","exitCode":N,"timedOut":false})
            kind = str(ev.get("type") or ev.get("event") or ev.get("stream")
                       or ev.get("channel") or ev.get("name") or "").lower()
            payload = None
            for k in ("data", "text", "line", "chunk", "message", "log", "content", "output", "out"):
                if isinstance(ev.get(k), str):
                    payload = ev[k]
                    break
            if payload is not None and not (isinstance(ev.get("stdout"), str) and payload == ev.get("stdout")):
                if "err" in kind:
                    stderr.append(payload)
                elif any(t in kind for t in ("out", "stdout", "log", "print", "data")):
                    stdout.append(payload)
                elif kind in ("exit", "end", "done", "close", "result", "complete", "finish"):
                    pass  # terminal marker, code handled above
                else:
                    stdout.append(payload)  # default unknown data to stdout

        return ExecResult(stdout="".join(stdout), stderr="".join(stderr),
                          exit_code=code if code_seen else 0, timed_out=timed_out)


class ComputerClient:
    """Interface: create/exec/write_file/release on one machine."""

    computer_id: Optional[str] = None
    viewer_url: Optional[str] = None

    def exec(self, cmd: str, *, cwd: str | None = None, env: dict | None = None,
             timeout: int = DEFAULT_EXEC_TIMEOUT) -> ExecResult:
        raise NotImplementedError

    def write_file(self, path: str, content: bytes, *, mode: int | None = None) -> None:
        """Write bytes to a path on the machine, base64 so no quoting can bite."""
        b64 = base64.b64encode(content).decode("ascii")
        parent = os.path.dirname(path) or "/"
        # printf keeps the whole blob on one arg; base64 -d is coreutils, present
        # on a bare Debian even before any apt install.
        script = (
            f"mkdir -p {shell_quote(parent)} && "
            f"printf '%s' {shell_quote(b64)} | base64 -d > {shell_quote(path)}"
        )
        if mode is not None:
            script += f" && chmod {mode:o} {shell_quote(path)}"
        res = self.exec(script, timeout=60)
        if not res.ok:
            raise RuntimeError(f"write_file({path}) failed: {res.output[:400]}")

    def read_file(self, path: str) -> str:
        res = self.exec(f"cat {shell_quote(path)} 2>/dev/null || true", timeout=60)
        return res.stdout

    def release(self) -> None:
        raise NotImplementedError


def shell_quote(s: str) -> str:
    """POSIX single-quote a string for /bin/sh."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def decode_json_stream(text: str) -> list:
    """Decode a body that is one JSON value, NDJSON, or concatenated JSON values.

    Uses raw_decode in a loop so it handles both newline-delimited and
    whitespace-separated concatenations; unparseable lines are skipped rather
    than aborting the whole parse.
    """
    text = (text or "").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, list) else [obj]
    except json.JSONDecodeError:
        pass
    out: list = []
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(text, i)
            out.append(obj)
            i = end
        except json.JSONDecodeError:
            nl = text.find("\n", i)
            if nl == -1:
                break
            i = nl + 1
    return out


# --- real Steel Computer -----------------------------------------------------


class SteelComputerClient(ComputerClient):
    def __init__(self, *, api_key: str | None = None, template: str | None = None,
                 region: str | None = None, timeout_s: int = 1800):
        import httpx  # bundled with the steel sdk

        self._key = api_key or os.environ["STEEL_API_KEY"]
        self._template = template or os.environ.get("STEEL_TEMPLATE")
        self._region = region or os.environ.get("STEEL_REGION")
        # Trust the agent-proxy CA if present (harmless off-sandbox).
        verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or True
        self._http = httpx.Client(
            base_url=STEEL_API_BASE,
            headers={"steel-api-key": self._key, "content-type": "application/json"},
            timeout=httpx.Timeout(DEFAULT_EXEC_TIMEOUT + 30),
            verify=verify,
        )
        self._create(timeout_s)

    def _create(self, timeout_s: int) -> None:
        body: dict = {}
        if self._template:
            body["template"] = self._template
        if self._region:
            body["region"] = self._region
        if timeout_s:
            # Confirmed against a live create response: the field is
            # `timeoutSeconds` (seconds), and it is the machine\'s auto-delete
            # horizon — a safety net behind our explicit release() so a crashed
            # run can\'t leave a machine billing forever.
            body["timeoutSeconds"] = timeout_s
        r = self._http.post("/v1/computers", json=body)
        r.raise_for_status()
        data = r.json()
        self.computer_id = data.get("id") or data.get("computerId") or data.get("computer_id")
        if not self.computer_id:
            raise RuntimeError(f"no computer id in create response: {str(data)[:400]}")
        self.viewer_url = (data.get("viewerUrl") or data.get("sessionViewerUrl")
                           or data.get("debugUrl") or data.get("viewer_url"))
        # Wait until the machine can run a command (it may boot asynchronously).
        self._await_ready(timeout_s=90)

    def _await_ready(self, timeout_s: int = 90) -> None:
        deadline = time.time() + timeout_s
        last = ""
        while time.time() < deadline:
            try:
                res = self.exec("echo arena-ready", timeout=30)
                if "arena-ready" in res.stdout:
                    return
                last = res.output
            except Exception as exc:  # noqa: BLE001 - keep polling through boot errors
                last = str(exc)
            time.sleep(3)
        raise RuntimeError(f"computer {self.computer_id} never became ready: {last[:300]}")

    def exec(self, cmd, *, cwd=None, env=None, timeout=DEFAULT_EXEC_TIMEOUT) -> ExecResult:
        body: dict = {"command": cmd, "timeout": timeout}
        if cwd:
            body["cwd"] = cwd
        if env:
            body["env"] = env
        r = self._http.post(f"/v1/computers/{self.computer_id}/exec", json=body,
                            timeout=timeout + 30)
        r.raise_for_status()
        self.last_exec_raw = r.text
        if os.environ.get("ARENA_STEEL_DEBUG"):
            ct = r.headers.get("content-type", "?")
            print(f"[steel exec raw] status={r.status_code} content-type={ct}\n"
                  f"{r.text[:2000]}", flush=True)
        return ExecResult.from_response_text(r.text)

    def release(self) -> None:
        if not self.computer_id:
            return
        cid, self.computer_id = self.computer_id, None
        try:
            self._http.delete(f"/v1/computers/{cid}")
        finally:
            self._http.close()


# --- local stand-in ----------------------------------------------------------


class LocalComputerClient(ComputerClient):
    """Runs the same commands on this box, under a temp 'machine root'.

    Lets the full SteelSandbox flow be tested with no Steel key: absolute paths
    the orchestration uses (/root, /workspace, /opt/arena, /etc/resolv.conf) are
    remapped under one temp dir. Install commands (apt/pip) are no-ops because
    this box already has python3/curl — the point is to test orchestration, not
    the install. Background processes (the in-machine proxy) really start, so an
    exfil attempt is really caught.
    """

    _INSTALL_RE = re.compile(r"^\s*(sudo\s+)?(apt-get|apt|pip3?|update-ca-certificates)\b")
    _PATH_RE = re.compile(r"(?<![\w/])(/root|/workspace|/opt/arena|/etc/resolv\.conf|/tmp/arena)")

    def __init__(self):
        self.computer_id = "local-" + os.urandom(4).hex()
        self.viewer_url = None
        self._root = Path(tempfile.mkdtemp(prefix="arena-computer-"))
        (self._root / "root").mkdir(parents=True, exist_ok=True)
        (self._root / "workspace").mkdir(parents=True, exist_ok=True)
        (self._root / "etc").mkdir(parents=True, exist_ok=True)
        self._pids: list[int] = []

    def _translate(self, text: str) -> str:
        mapping = {
            "/root": str(self._root / "root"),
            "/workspace": str(self._root / "workspace"),
            "/opt/arena": str(self._root / "opt-arena"),
            "/etc/resolv.conf": str(self._root / "etc" / "resolv.conf"),
            "/tmp/arena": str(self._root / "tmp-arena"),
        }
        return self._PATH_RE.sub(lambda m: mapping[m.group(1)], text)

    def exec(self, cmd, *, cwd=None, env=None, timeout=DEFAULT_EXEC_TIMEOUT) -> ExecResult:
        if self._INSTALL_RE.match(cmd):
            return ExecResult(stdout="(local stand-in: install skipped)\n", exit_code=0)
        real_cmd = self._translate(cmd)
        run_env = dict(os.environ)
        if env:
            run_env.update({k: self._translate(str(v)) for k, v in env.items()})
        run_cwd = self._translate(cwd) if cwd else str(self._root / "workspace")
        Path(run_cwd).mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(["/bin/sh", "-c", real_cmd], cwd=run_cwd, env=run_env,
                                  capture_output=True, text=True, timeout=timeout)
            return ExecResult(stdout=proc.stdout, stderr=proc.stderr, exit_code=proc.returncode)
        except subprocess.TimeoutExpired:
            return ExecResult(stderr="timeout", exit_code=124)

    def release(self) -> None:
        # Best-effort kill of any in-machine proxies we started, then wipe.
        self.exec("pkill -f 'tripwire.localproxy' 2>/dev/null; "
                  "pkill -f 'tripwire.dnsguard' 2>/dev/null; true", timeout=15)
        shutil.rmtree(self._root, ignore_errors=True)
