#!/usr/bin/env bash
# Loopback 4-way benchmark: direct floor vs wormhole vs (optional) rathole
# vs (optional) frp.
#
# Usage:  bench/run4way.sh [wormhole-bin] [rathole-bin] [frp-dir]
#   wormhole-bin : default ./target/release/wormhole (relative to repo root)
#   rathole-bin  : optional; if given and present, rathole is benchmarked too
#   frp-dir      : optional; a directory containing the frps + frpc binaries
#
# Everything runs on 127.0.0.1. A fresh random secret and private ports are
# generated each run. bwtool.py measures latency, one-way bandwidth, and 96
# concurrent round-trips (median of 5 runs per tunnel).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WH="${1:-$ROOT/target/release/wormhole}"
RTH="${2:-}"
BW="$ROOT/bench/bwtool.py"

# private loopback ports (avoid 0-1024 and the common dev ports)
SVC=19201       # wormhole public service port
CTRL=19100      # wormhole control (data port = 19101, the default)
RSVC=14201      # rathole public service port
RBIND=14101     # rathole bind base (1 channel: 14101)
BE=19990        # local echo backend

secret="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
tmp="$(mktemp -d)"; SRV="" CLI="" RS="" RC="" FS="" FC=""
trap 'kill 2>/dev/null $SRV $CLI $RS $RC $FS $FC 2>/dev/null || true; rm -rf "$tmp"' EXIT

echo "### DIRECT (floor) — 5 runs ###"
for _ in 1 2 3 4 5; do python3 "$BW" 127.0.0.1:$BE $BE; done

echo
echo "### WORMHOLE — 5 runs ###"
cat > "$tmp/wh_s.toml" <<EOF
[server]
bind = "127.0.0.1:$CTRL"
secret = "$secret"
EOF
cat > "$tmp/wh_c.toml" <<EOF
[client]
server = "127.0.0.1:$CTRL"
secret = "$secret"
channels = 8

[services.echo]
remote = $SVC
local = "127.0.0.1:$BE"
EOF
"$WH" serve "$tmp/wh_s.toml" >/dev/null 2>&1 & SRV=$!
sleep 0.4
"$WH" client -c "$tmp/wh_c.toml" >/dev/null 2>&1 & CLI=$!
sleep 1.5
for _ in 1 2 3 4 5; do python3 "$BW" 127.0.0.1:$SVC $BE; done
kill $SRV $CLI 2>/dev/null || true
wait 2>/dev/null || true

if [ -n "$RTH" ] && [ -x "$RTH" ]; then
  echo
  echo "### RATHOLE — 5 runs ###"
  cat > "$tmp/rth_srv.toml" <<EOF
[server]
bind_addr = "127.0.0.1:$RBIND"
default_token = "$secret"

[server.services.echo]
type = "tcp"
bind_addr = "127.0.0.1:$RSVC"
EOF
  cat > "$tmp/rth_cli.toml" <<EOF
[client]
remote_addr = "127.0.0.1:$RBIND"
default_token = "$secret"

[client.services.echo]
type = "tcp"
local_addr = "127.0.0.1:$BE"
EOF
  "$RTH" -s "$tmp/rth_srv.toml" >/dev/null 2>&1 & RS=$!
  sleep 0.5
  "$RTH" -c "$tmp/rth_cli.toml" >/dev/null 2>&1 & RC=$!
  sleep 1.5
  for _ in 1 2 3 4 5; do python3 "$BW" 127.0.0.1:$RSVC $BE; done
  kill $RS $RC 2>/dev/null || true
fi

FRPDIR="${3:-}"
if [ -n "$FRPDIR" ] && [ -x "$FRPDIR/frps" ] && [ -x "$FRPDIR/frpc" ]; then
  echo
  echo "### FRP — 5 runs ###"
  FRP_BIND=19110      # frps management/transport bind
  FRP_SVC=14301       # frp public service port
  cat > "$tmp/frp_s.toml" <<EOF
bindPort = $FRP_BIND
EOF
  cat > "$tmp/frp_c.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $FRP_BIND

[[proxies]]
name = "echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = $BE
remotePort = $FRP_SVC
EOF
  "$FRPDIR/frps" -c "$tmp/frp_s.toml" >/dev/null 2>&1 & FS=$!
  sleep 0.5
  "$FRPDIR/frpc" -c "$tmp/frp_c.toml" >/dev/null 2>&1 & FC=$!
  sleep 1.5
  for _ in 1 2 3 4 5; do python3 "$BW" 127.0.0.1:$FRP_SVC $BE; done
  kill $FS $FC 2>/dev/null || true
fi

echo
echo "done"
