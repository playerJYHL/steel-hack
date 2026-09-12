#!/usr/bin/env bash
# Steel Environment template bootstrap — bakes the arena into a Steel Computer
# image so a machine boots ready in ~1s instead of paying ~36s of apt per attack
# (DEV.md §0). Run this once when building the Environment template, NOT per run.
#
# It installs the toolchain, stands up the mitmproxy CA in the system trust store
# (so the agent's HTTPS is inspectable), and places the command shims ahead of the
# real binaries on PATH. What it deliberately does NOT do is start the proxy or
# seed a canary — those are per-run and belong to the runner, because the canary
# must be unique per attack.
set -euo pipefail

echo "[arena] installing toolchain…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv git curl ca-certificates build-essential

echo "[arena] installing python deps…"
pip3 install --quiet --break-system-packages mitmproxy anthropic steel-sdk playwright

echo "[arena] priming the mitmproxy CA…"
# Running mitmdump once generates ~/.mitmproxy/mitmproxy-ca-cert.pem. We trust it
# system-wide so the agent's curl/requests/browser accept the intercept.
timeout 8 mitmdump --set confdir=/root/.mitmproxy >/dev/null 2>&1 || true
if [ -f /root/.mitmproxy/mitmproxy-ca-cert.pem ]; then
    cp /root/.mitmproxy/mitmproxy-ca-cert.pem \
       /usr/local/share/ca-certificates/mitmproxy.crt
    update-ca-certificates >/dev/null 2>&1 || true
    # Python's requests/certifi and Node don't read the system store by default.
    echo 'export REQUESTS_CA_BUNDLE=/root/.mitmproxy/mitmproxy-ca-cert.pem' >> /etc/profile.d/arena.sh
    echo 'export SSL_CERT_FILE=/root/.mitmproxy/mitmproxy-ca-cert.pem' >> /etc/profile.d/arena.sh
    echo 'export NODE_EXTRA_CA_CERTS=/root/.mitmproxy/mitmproxy-ca-cert.pem' >> /etc/profile.d/arena.sh
    echo "[arena] mitmproxy CA trusted system-wide"
else
    echo "[arena] WARNING: mitmproxy CA not generated — HTTPS inspection will fail" >&2
fi

echo "[arena] installing command shims…"
# The shims live in the repo; copy this directory's sibling tripwire/shims into
# the template. When baking, run this script from a checkout so the path resolves.
SHIM_SRC="$(cd "$(dirname "$0")/../tripwire/shims" 2>/dev/null && pwd || echo /opt/arena/tripwire/shims)"
if [ -d "$SHIM_SRC" ]; then
    sh "$SHIM_SRC/install.sh" /usr/local/bin
else
    echo "[arena] NOTE: shim source not found at build time; the runner installs them at seed time as a fallback" >&2
fi

echo "[arena] done. A machine from this template has python3 + mitmproxy + the"
echo "        CA + shims already present, so per-attack setup is near-zero."
