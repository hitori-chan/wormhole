#!/usr/bin/env python3
"""Clean tunnel benchmark.

Backend protocol (one server handles all test types by connection):
  - first 4 bytes == MAGIC  -> one-way drain+ACK bandwidth:
        [MAGIC:4][size:4][data:size]  -> server drains, replies 1 ACK byte.
      (deadlock-free: only 1 byte flows back)
  - otherwise               -> pure echo (for latency ping-pong + concurrent)

Measures, all against --target (a tunnel service port, or the local backend
itself for the direct floor):
  lat   : 2000x 64B ping-pong on one conn    -> p50/p99 ms
  bw    : 4x one-way 256MB drain+ACK         -> median Mbps
  conc  : 96x concurrent 64B round-trips     -> ok/96 + time (noise-dominated)
"""
import socket, threading, time, sys, statistics

MAGIC = b"\xde\xad\xbe\xef"

def _drain_ack(c):
    sb = c.recv(4)
    if len(sb) < 4:
        return
    size = int.from_bytes(sb, "big")
    rem = size
    while rem > 0:
        b = c.recv(65536)
        if not b:
            break
        rem -= len(b)
    c.sendall(b"\x01")

def _echo(c, first):
    c.sendall(first)
    while True:
        b = c.recv(65536)
        if not b:
            break
        c.sendall(b)

def _handle(c):
    try:
        hdr = c.recv(4)
        if len(hdr) < 4:
            return
        if hdr == MAGIC:
            _drain_ack(c)
        else:
            _echo(c, hdr)
    finally:
        try:
            c.close()
        except Exception:
            pass

def backend(port, stop):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(256); s.settimeout(0.4)
    while not stop.is_set():
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle, args=(c,), daemon=True).start()

def main():
    target = sys.argv[1]            # host:port (tunnel service or the backend itself)
    backend_port = int(sys.argv[2]) # local port for the backend
    host, port = target.rsplit(":", 1)
    addr = (host, int(port))
    stop = threading.Event()
    threading.Thread(target=backend, args=(backend_port, stop), daemon=True).start()
    time.sleep(0.2)

    up = False
    for _ in range(40):
        try:
            c = socket.create_connection(addr, timeout=3); c.sendall(b"\xab" * 64)
            c.settimeout(3); got = 0
            while got < 64:
                b = c.recv(64 - got)
                if not b: break
                got += len(b)
            c.close(); up = (got == 64); break
        except Exception:
            time.sleep(0.2)
    if not up:
        print(f"{target}: PATH DOWN"); return

    # --- latency: 2000x 64B ping-pong on one persistent conn ---
    c = socket.create_connection(addr, timeout=10); c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    lats = []
    for _ in range(2000):
        t0 = time.perf_counter(); c.sendall(b"\xab" * 64); got = 0
        while got < 64:
            b = c.recv(64 - got)
            if not b: break
            got += len(b)
        lats.append((time.perf_counter() - t0) * 1000)
    c.close()
    lats.sort()
    lat_p50 = lats[len(lats) // 2]; lat_p99 = lats[int(len(lats) * 0.99)]

    # --- bandwidth: 4x one-way 256MB drain+ACK ---
    MB = 256_000_000
    data = bytes(range(256)) * (MB // 256)
    data = data[:MB]
    bws = []
    for _ in range(4):
        c = socket.create_connection(addr, timeout=8)
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t0 = time.perf_counter()
        try:
            c.sendall(MAGIC); c.sendall(MB.to_bytes(4, "big")); c.sendall(data)
            ack = c.recv(1)
            if ack:
                bws.append(MB * 8 / (time.perf_counter() - t0) / 1e6)  # Mbps
        except Exception:
            pass
        finally:
            c.close()  # ALWAYS close: a leaked conn holds a channel and wedges the tunnel

    # --- concurrent: 96x 64B round-trips ---
    errs = 0
    lock = threading.Lock()
    def worker():
        nonlocal errs
        c = None
        ok = False
        try:
            c = socket.create_connection(addr, timeout=5)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.sendall(b"\xab" * 64); got = 0
            while got < 64:
                b = c.recv(64 - got)
                if not b: break
                got += len(b)
            ok = (got == 64)
        except Exception:
            ok = False
        finally:
            if c is not None:
                try: c.close()
                except Exception: pass
        if not ok:
            with lock: errs += 1
    t0 = time.perf_counter()
    th = [threading.Thread(target=worker) for _ in range(96)]
    for t in th: t.start()
    for t in th: t.join()
    conc_dt = time.perf_counter() - t0

    bw_med = statistics.median(bws) if bws else 0
    print(f"lat p50={lat_p50:6.2f}ms p99={lat_p99:6.2f}ms | "
          f"bw_med={bw_med:8.0f}Mbps ({bw_med/1000:5.1f} Gbps) | "
          f"conc96 ok={96-errs}/96 in {conc_dt*1000:5.0f}ms")

if __name__ == "__main__":
    main()
