"""A stdlib intercepting forward proxy — the egress tripwire for local runs.

Inside a Steel Computer we use mitmproxy (see proxy.py). This is its counterpart
for everywhere else: laptops, CI, and the booth when the network is hostile. It
speaks enough HTTP to be a real proxy, hands every request to the same
`EgressMonitor`, and needs nothing installed.

It runs **sealed** by default: anything not explicitly allowlisted is refused.
Local runs then have no real egress at all, which makes them free, deterministic
and safe to run a thousand times while tuning payloads.

It cannot see inside TLS — there is no CA to mint certificates from here. It
inspects the CONNECT target and, when it does tunnel, says so in the event log
rather than pretending it inspected the bytes. Full HTTPS bodies are mitmproxy's
job in the sandbox.
"""

from __future__ import annotations

import argparse
import http.client
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .canary import Canary
from .events import EventLog
from .inspect import EgressMonitor, RequestFacts

BLOCK_BODY = (
    b"arena: request blocked by the egress tripwire.\n"
    b"nothing left the sandbox.\n"
)
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}
MAX_BODY = 8 * 1024 * 1024
TUNNEL_IDLE_S = 30


def _ascii(text: str) -> str:
    """Header-safe rendering of arbitrary text."""
    return text.encode("ascii", "replace").decode("ascii")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "arena-tripwire/1.0"

    # -- plumbing ------------------------------------------------------------

    @property
    def monitor(self) -> EgressMonitor:
        return self.server.monitor  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # noqa: A003 - silence stderr spam
        pass

    def _headers(self) -> dict[str, str]:
        return {k: v for k, v in self.headers.items()}

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if length:
            try:
                return self.rfile.read(min(int(length), MAX_BODY))
            except (ValueError, OSError):
                return b""
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            return self._read_chunked()
        return b""

    def _read_chunked(self) -> bytes:
        out = bytearray()
        while len(out) < MAX_BODY:
            line = self.rfile.readline(64)
            if not line:
                break
            try:
                size = int(line.strip().split(b";")[0] or b"0", 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline()
                break
            out += self.rfile.read(size)
            self.rfile.read(2)
        return bytes(out)

    def _refuse(self, status: int, reason: str) -> None:
        body = BLOCK_BODY + f"reason: {reason}\n".encode()
        self.send_response(status, "Blocked")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Header values are latin-1 only, and reasons are assembled from
        # detection text that can contain anything. Sanitise rather than let an
        # unencodable character take down the response the attacker is waiting on.
        self.send_header("X-Arena-Tripwire", _ascii(reason)[:120])
        self.end_headers()
        self.wfile.write(body)

    # -- absolute-form requests (plain HTTP) ---------------------------------

    def _handle(self) -> None:
        url = self.path
        if not url.startswith("http://") and not url.startswith("https://"):
            # Origin-form: someone pointed a client straight at us rather than
            # using us as a proxy. Reconstruct the URL from the Host header.
            host = self.headers.get("Host", "")
            url = f"http://{host}{self.path}"

        body = self._read_body()
        facts = RequestFacts.from_url(self.command, url, self._headers(), body)
        verdict = self.monitor.inspect(facts)
        if not verdict.allow:
            self._refuse(403, verdict.reason)
            return
        self._forward(facts, body)

    def _forward(self, facts: RequestFacts, body: bytes) -> None:
        parts = urlsplit(facts.url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query

        headers = {
            k: v for k, v in facts.headers.items() if k.lower() not in HOP_BY_HOP
        }
        try:
            cls = (
                http.client.HTTPSConnection
                if parts.scheme == "https"
                else http.client.HTTPConnection
            )
            conn = cls(parts.hostname, port, timeout=20)
            conn.request(facts.method, target, body=body or None, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        except Exception as exc:
            self._refuse(502, f"upstream error: {type(exc).__name__}")
            return

        self.send_response(resp.status, resp.reason)
        for name, value in resp.getheaders():
            if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

    # -- CONNECT (TLS) -------------------------------------------------------

    def do_CONNECT(self) -> None:
        host, _, port_s = self.path.partition(":")
        port = int(port_s or 443)
        facts = RequestFacts.from_url("CONNECT", f"https://{host}:{port}/", self._headers())
        verdict = self.monitor.inspect(facts)
        if not verdict.allow:
            self._refuse(403, verdict.reason)
            return

        # We are about to relay bytes we cannot read. Say so in the log rather
        # than letting the record imply this traffic was inspected.
        self.monitor.events.record(
            "tls_opaque",
            f"tunnelled to {host}:{port} without inspecting contents",
            triggered=False,
            host=host,
        )
        try:
            upstream = socket.create_connection((host, port), timeout=20)
        except OSError as exc:
            self._refuse(502, f"tunnel failed: {type(exc).__name__}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self._pump(self.connection, upstream)

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        socks = [a, b]
        try:
            while True:
                readable, _, errored = select.select(socks, [], socks, TUNNEL_IDLE_S)
                if errored or not readable:
                    break
                for src in readable:
                    dst = b if src is a else a
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, monitor: EgressMonitor):
        self.monitor = monitor
        super().__init__(addr, _Handler)


class InterceptProxy:
    """Start/stop wrapper. Always stop it in a `finally:` — see runner.py."""

    def __init__(self, monitor: EgressMonitor, host: str = "127.0.0.1", port: int = 0):
        self.monitor = monitor
        self._server = _Server((host, port), monitor)
        self.host, self.port = self._server.server_address[:2]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "InterceptProxy":
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.2},
            daemon=True,
            name="arena-proxy",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "InterceptProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def main() -> int:
    ap = argparse.ArgumentParser(description="arena egress tripwire (stdlib proxy)")
    ap.add_argument("--canary", required=True, help="full canary token to watch for")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--log", default=None, help="event log path")
    ap.add_argument("--allow", action="append", default=[], help="allowlisted host")
    ap.add_argument("--open", action="store_true", help="forward instead of sealing")
    args = ap.parse_args()

    monitor = EgressMonitor(
        Canary.from_token(args.canary),
        EventLog(args.log),
        allow_hosts=args.allow,
        sealed=not args.open,
    )
    proxy = InterceptProxy(monitor, port=args.port).start()
    print(f"arena tripwire proxy on {proxy.url} (sealed={monitor.sealed})", flush=True)
    try:
        while True:
            threading.Event().wait(60)
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
