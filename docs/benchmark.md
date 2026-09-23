# Benchmark

Methodology and raw data for the README charts.

## Setup

All four rows run the same probe (`bench/bwtool.py`) against a local echo backend on loopback; only the tunnel software in the middle differs.

| row | path |
|---|---|
| direct | `127.0.0.1:port` → echo (the machine's floor) |
| wormhole | `127.0.0.1:tunnel` → wormhole (same box) → echo |
| rathole | `127.0.0.1:tunnel` → rathole (same box) → echo |
| frp | `127.0.0.1:tunnel` → frp (same box) → echo |

Metrics:

1. **Latency** — 64 B ping-pong on one connection, p50/p99 over 2000 round-trips.
2. **Bulk bandwidth** — one-way 256 MB, drain+ACK (the backend drains and returns one ACK byte; deadlock-free).
3. **Concurrency** — 96 parallel connections, one 64 B ping-pong each.

5 runs per tunnel (bandwidth: median of 4 transfers per run); charts show medians with the 5-run spread as whiskers. All tools in stock/default configuration — wormhole 8 data channels (its default), rathole and frp multiplexed over one connection (theirs).

## Raw data

Loopback, x86_64 Linux (kernel 6.17), 2026-09-22. wormhole v0.3.0 (protocol v4, zero-copy data path), rathole 0.5.0, frp 0.71.0.

```
### DIRECT (floor) — 5 runs
lat p50= 0.00ms p99= 0.01ms | bw_med= 105305Mbps (105.3 Gbps) | conc96 ok=96/96 in   11ms
lat p50= 0.00ms p99= 0.01ms | bw_med=  98339Mbps ( 98.3 Gbps) | conc96 ok=96/96 in   12ms
lat p50= 0.00ms p99= 0.01ms | bw_med= 103033Mbps (103.0 Gbps) | conc96 ok=96/96 in   12ms
lat p50= 0.00ms p99= 0.01ms | bw_med= 105065Mbps (105.1 Gbps) | conc96 ok=96/96 in   12ms
lat p50= 0.00ms p99= 0.01ms | bw_med= 103489Mbps (103.5 Gbps) | conc96 ok=96/96 in   12ms

### WORMHOLE — 5 runs
lat p50= 0.01ms p99= 0.03ms | bw_med=  51471Mbps ( 51.5 Gbps) | conc96 ok=96/96 in   14ms
lat p50= 0.02ms p99= 0.03ms | bw_med=  45662Mbps ( 45.7 Gbps) | conc96 ok=96/96 in   13ms
lat p50= 0.02ms p99= 0.03ms | bw_med=  45683Mbps ( 45.7 Gbps) | conc96 ok=96/96 in   13ms
lat p50= 0.02ms p99= 0.04ms | bw_med=  44247Mbps ( 44.2 Gbps) | conc96 ok=96/96 in   12ms
lat p50= 0.02ms p99= 0.03ms | bw_med=  40983Mbps ( 41.0 Gbps) | conc96 ok=96/96 in   12ms

### RATHOLE — 5 runs
lat p50= 0.02ms p99= 0.03ms | bw_med=  23346Mbps ( 23.3 Gbps) | conc96 ok=96/96 in   15ms
lat p50= 0.01ms p99= 0.02ms | bw_med=  19660Mbps ( 19.7 Gbps) | conc96 ok=96/96 in   14ms
lat p50= 0.01ms p99= 0.03ms | bw_med=  23961Mbps ( 24.0 Gbps) | conc96 ok=96/96 in   14ms
lat p50= 0.02ms p99= 0.03ms | bw_med=  23400Mbps ( 23.4 Gbps) | conc96 ok=96/96 in   13ms
lat p50= 0.01ms p99= 0.02ms | bw_med=  28889Mbps ( 28.9 Gbps) | conc96 ok=96/96 in   13ms

### FRP — 5 runs
lat p50= 0.03ms p99= 0.05ms | bw_med=  14343Mbps ( 14.3 Gbps) | conc96 ok=96/96 in   17ms
lat p50= 0.03ms p99= 0.05ms | bw_med=  14215Mbps ( 14.2 Gbps) | conc96 ok=96/96 in   17ms
lat p50= 0.03ms p99= 0.05ms | bw_med=  14286Mbps ( 14.3 Gbps) | conc96 ok=96/96 in   17ms
lat p50= 0.03ms p99= 0.04ms | bw_med=  14606Mbps ( 14.6 Gbps) | conc96 ok=96/96 in   18ms
lat p50= 0.03ms p99= 0.04ms | bw_med=  13916Mbps ( 13.9 Gbps) | conc96 ok=96/96 in   16ms
```

## Reproduce

```sh
cargo build --release
bash bench/run4way.sh ./target/release/wormhole /path/to/rathole /path/to/frp-dir
python3 bench/make_charts.py   # regenerate docs/img/*.svg from the data
```

## Results

Median bulk bandwidth: **wormhole 45.7 Gbps** (≈44% of the ~103.5 Gbps direct floor), rathole 23.4, frp 14.3. Latency is at the machine floor for all four; for concurrency, wormhole's 96-conn round-trip time is within 1 ms of direct.

Why wormhole leads on loopback: one data channel = one task with a bounded per-connection buffer (no cross-connection head-of-line); a lone frame flushes immediately; the hot path is zero-copy (a `DATA` payload is a refcounted slice of the socket read buffer from kernel to write). Part of the gap is also architectural: wormhole's default is 8 data channels, rathole/frp's is one.

Loopback is the CPU-bound case; on a bandwidth-limited link every tunnel ties at the link ceiling.
