//! Tunnel core: a control channel plus N parallel data channels.
//!
//! - The **control channel** carries AUTH/OK/FAIL, DCOUNT, PROXIES/PROXYACK,
//!   NEW, CLOSE, PING/PONG.
//! - **Data channels** (N TCP connections, all to the server's one shared
//!   data port, each identified by a CHIDX) carry DATA. Connection `id` rides
//!   data channel `id % N`, so data bandwidth scales with N and a slow consumer
//!   on one channel never stalls the others.
//! - Each connection has a **bounded** in-flight buffer (`BUFFER_FRAMES` frames),
//!   giving backpressure + bounded memory (a slow consumer blocks its own
//!   producer instead of growing memory without bound).
//!
//! Every spawned task takes its tunnel handle as an owned `Arc<Tunnel>` (a cheap
//! refcount clone), so futures are `'static` and the per-connection table is
//! shared across the control + data channels.

use std::collections::HashMap;
use std::io::IoSlice;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, watch};


use crate::protocol::{self, Frame};

/// In-flight frames buffered per connection before backpressure kicks in.
/// 64 frames x 64KB ~= 4MB per connection worst case.
pub const BUFFER_FRAMES: usize = 64;
/// Upper bound on live connections per session: a connection flood is dropped
/// at capacity instead of spawning unbounded tasks.
pub const MAX_CONNS: usize = 16384;

/// TCP keepalive for every wormhole channel: idle 30 s, then 10 s probes × 3.
/// A half-open (no-RST) dead peer is reaped by the OS in ~60 s instead of
/// holding its socket/slot until the kernel default (hours).
fn keepalive_opts(sock: &socket2::Socket) {
    let _ = sock.set_keepalive(true);
    let _ = sock.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(3),
    );
}

fn domain(addr: &SocketAddr) -> socket2::Domain {
    if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    }
}

/// Bind a listener with keepalive pre-set. Accepted sockets inherit the
/// options (on Linux the full timer set; elsewhere at least SO_KEEPALIVE).
pub fn listen(addr: &SocketAddr) -> std::io::Result<TcpListener> {
    let sock = socket2::Socket::new(
        domain(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_reuse_address(true)?;
    sock.bind(&socket2::SockAddr::from(*addr))?;
    sock.listen(1024)?;
    keepalive_opts(&sock);
    sock.set_nonblocking(true)?;
    TcpListener::from_std(sock.into())
}

/// Connect to a concrete address with keepalive + nodelay pre-set.
pub async fn connect_addr(addr: &SocketAddr) -> std::io::Result<TcpStream> {
    let sock = socket2::Socket::new(
        domain(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    keepalive_opts(&sock);
    sock.set_tcp_nodelay(true)?;
    sock.set_nonblocking(true)?;
    TcpSocket::from_std_stream(sock.into()).connect(*addr).await
}

/// Resolve `host` (hostname or IP literal) and connect to the first address
/// that accepts, with keepalive + nodelay pre-set. Re-resolving on every
/// attach also picks up IP changes for hostname targets.
pub async fn connect_host(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match connect_addr(&addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no addresses for {host}:{port}"),
        )
    }))
}
/// How often the control-channel liveness deadline is evaluated.
pub const LIVENESS_CHECK: Duration = Duration::from_secs(5);
/// No control-channel activity for this long -> drop the session (3 heartbeat
/// intervals; the heartbeat is 15s). Bounds how long a half-open (no-RST) dead
/// peer holds our resources and public ports.
pub const LIVENESS_DEADLINE: Duration = Duration::from_secs(45);

/// A fixed reference point so `now_ms()` can report a monotonic elapsed-ms
/// counter (tokio's `Instant` exposes no absolute ms value).
static T0: OnceLock<tokio::time::Instant> = OnceLock::new();
/// Current monotonic elapsed time in milliseconds (for liveness deadlines).
pub fn now_ms() -> u64 {
    let t0 = *T0.get_or_init(tokio::time::Instant::now);
    tokio::time::Instant::now().duration_since(t0).as_millis() as u64
}
/// Writer batch high-water mark: a burst of frames already queued in the mpsc
/// is gathered (via `try_recv`) up to this size and shared across one
/// write/segment; a lone frame flushes immediately instead of waiting on a
/// timer (a fixed wait added ~3ms loopback RTT).
const HIGH_WATER: usize = 256 * 1024;

/// A NEW connection to hand to the local side: `(id, local_host, local_port,
/// per-connection inbound buffer)`.
pub type NewConn = (u16, String, u16, mpsc::Receiver<Bytes>);

/// Per-connection table, guarded by a single lock so that the data readers and
/// the control reader can't race on id registration.
///
/// `conns`: id -> per-connection in-flight sender (bounded mpsc). The data
/// readers push DATA payloads here; the pipe drains it.
#[derive(Default)]
pub struct ConnTable {
    /// id -> the bounded per-connection buffer the pipe drains into the local
    /// socket. A connection's NEW, DATA, and CLOSE all ride the same data
    /// channel (pinned by `id % n`), so the NEW is always processed before the
    /// first DATA — there is no NEW-vs-DATA race and no parking buffer.
    pub conns: HashMap<u16, mpsc::Sender<Bytes>>,
}

/// Shared tunnel state, held as `Arc<Tunnel>` by every task that touches it.
#[derive(Clone)]
pub struct Tunnel {
    /// connection table (conns + pending), one lock for both.
    pub table: Arc<Mutex<ConnTable>>,
    /// one writer input per data channel (DATA frames for that channel).
    pub chan_out: Vec<mpsc::Sender<Frame>>,
    /// control-channel writer input (NEW/CLOSE/...).
    pub control_out: mpsc::Sender<Frame>,
    /// connection-id allocator (server side).
    pub next_id: Arc<AtomicU16>,
    /// number of data channels (id % n picks the channel).
    pub n: u8,
}

impl Tunnel {
    pub fn new(n: u8) -> (Self, mpsc::Receiver<Frame>, Vec<mpsc::Receiver<Frame>>) {
        let table = Arc::new(Mutex::new(ConnTable::default()));
        let (control_tx, control_rx) = mpsc::channel(1024);
        let mut chan_tx = Vec::with_capacity(n as usize);
        let mut chan_rx = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(2048);
            chan_tx.push(tx);
            chan_rx.push(rx);
        }
        (
            Self {
                table,
                chan_out: chan_tx,
                control_out: control_tx,
                next_id: Arc::new(AtomicU16::new(1)),
                n,
            },
            control_rx,
            chan_rx,
        )
    }

    /// Sender for DATA frames destined to connection `id` (routed by id % n).
    pub fn data_sender(&self, id: u16) -> mpsc::Sender<Frame> {
        let c = (id % self.n as u16) as usize;
        self.chan_out[c].clone()
    }
}

/// Generic frame writer: drains `rx`, batches, writes.
///
/// A **lone** frame is written immediately (no fixed wait), which keeps single
/// small packets at the sub-millisecond floor. A **burst** already queued in
/// `rx` is gathered up to `HIGH_WATER` and shared across one write, so bulk
/// traffic still batches. We gather with `try_recv` (never block on the timer
/// for a lone frame): a previous timed-window form that always waited out a
/// flush window added ~3ms loopback RTT, so the fast path never sleeps on a
/// timer at all.
///
/// **Flap safety**: `dead` is raised by the peer direction of the channel
/// dying. A writer that sees it mid-write still *completes* the in-flight
/// batch first (a half-written frame would desync the peer), then stops.
/// Frames still queued in `rx` are never touched, so a re-attached channel
/// delivers them — a flap costs latency, not data.
///
/// `rx` is borrowed, not consumed: the caller keeps the receiver alive after
/// the writer ends, so a channel's queued frames survive a re-attach.
pub async fn writer<W: AsyncWrite + Unpin + Send>(
    stream: &mut W,
    rx: &mut mpsc::Receiver<Frame>,
    dead: &mut watch::Receiver<bool>,
) {
    let mut buf = BytesMut::with_capacity(HIGH_WATER);
    loop {
        if *dead.borrow() {
            break;
        }
        // Block for the first frame (or the death signal), then gather
        // everything already ready without blocking.
        let first = tokio::select! {
            _ = dead.changed() => break,
            f = rx.recv() => match f {
                Some(f) => f,
                // Disconnected (all senders gone): done.
                None => break,
            },
        };
        protocol::encode(&mut buf, &first);
        while buf.len() < HIGH_WATER {
            match rx.try_recv() {
                Ok(m) => protocol::encode(&mut buf, &m),
                // Empty (nothing more queued): flush what we have.
                Err(_) => break,
            }
        }
        // If the death signal fires mid-write, finish the write first.
        let w = stream.write_all_buf(&mut buf);
        tokio::pin!(w);
        let res = tokio::select! {
            r = &mut w => r,
            _ = dead.changed() => w.await,
        };
        if res.is_err() {
            break;
        }
        buf.clear();
    }
}

/// Write every iovec, advancing `consumed` offsets on partial writes. The
/// iovecs (and the buffers they borrow) are not mutated: partial progress is
/// tracked in the parallel `consumed` array, and each syscall sees a fresh
/// view of the unconsumed remainder.
async fn write_vectored_all<W: AsyncWrite + Unpin + Send>(
    stream: &mut W,
    iovecs: &[IoSlice<'_>],
    consumed: &mut [usize],
) -> std::io::Result<()> {
    loop {
        let mut view: Vec<IoSlice<'_>> = Vec::with_capacity(iovecs.len());
        let mut pending = 0usize;
        for (i, io) in iovecs.iter().enumerate() {
            let o = consumed[i];
            if o < io.len() {
                view.push(IoSlice::new(&io[o..]));
                pending += io.len() - o;
            }
        }
        if pending == 0 {
            return Ok(());
        }
        let n = stream.write_vectored(&view).await?;
        if n == 0 {
            continue; // no bytes taken (would-block); re-await readiness
        }
        let mut rem = n;
        for (i, io) in iovecs.iter().enumerate() {
            if rem == 0 {
                break;
            }
            let o = consumed[i];
            let avail = io.len() - o;
            if avail == 0 {
                continue;
            }
            if rem < avail {
                consumed[i] = o + rem;
                rem = 0;
            } else {
                consumed[i] = io.len();
                rem -= avail;
            }
        }
    }
}

/// Data-channel READER: demuxes DATA frames by id into per-connection bounded
/// buffers, and (on the client) registers NEW connections. A connection's NEW
/// and its DATA/CLOSE all ride this same channel (pinned by `id % n`), so the
/// NEW is always processed before the first DATA — no parking buffer needed.
/// Returns when the channel closes.
pub async fn data_reader<R: AsyncRead + Unpin + Send>(
    mut stream: R,
    tun: Arc<Tunnel>,
    new_tx: Option<mpsc::Sender<NewConn>>,
) {
    let mut buf = BytesMut::with_capacity(256 * 1024);
    // Read until EOF, then drain `buf`: on a graceful close, whole frames can
    // still sit in the buffer and must be delivered before the channel is
    // declared dead (otherwise up to 256 KiB were lost on every flap).
    let mut eof = false;
    while !eof {
        if stream.read_buf(&mut buf).await.unwrap_or(0) == 0 {
            eof = true;
        }
        while let Some(frame) = protocol::parse(&mut buf) {
            match frame {
                Frame::New {
                    id,
                    local_host,
                    local_port,
                } => {
                    // client only: register the per-connection buffer, then hand
                    // the dial to the NEW handler (connect the local address +
                    // pipe). The id is registered before any of its DATA arrives.
                    if let Some(tx) = &new_tx {
                        let (from_tx, from_rx) = mpsc::channel::<Bytes>(BUFFER_FRAMES);
                        tun.table.lock().unwrap().conns.insert(id, from_tx);
                        let _ = tx.send((id, local_host, local_port, from_rx)).await;
                    }
                }
                Frame::Data(id, data) => {
                    // The id is always registered by now (its NEW preceded this
                    // frame on the same channel). `data` is a refcounted slice
                    // of the read buffer: zero copies from socket to conn buffer.
                    let sender = tun.table.lock().unwrap().conns.get(&id).cloned();
                    if let Some(s) = sender {
                        // bounded: a slow consumer blocks here (backpressure), not OOM
                        let _ = s.send(data).await;
                    } else {
                        // desync: DATA for an id that was never registered here
                        tracing::warn!("data_reader: dropping DATA for unregistered id {id}");
                    }
                }
                // CLOSE rides the data channel: ordered after all of this id's
                // DATA, so dropping the buffer now loses no in-flight byte.
                Frame::Close(id) => {
                    tun.table.lock().unwrap().conns.remove(&id);
                }
                _ => {} // control-only frames on a data channel are ignored
            }
        }
    }
}

/// Drive one data channel: a writer (frames -> channel) + a reader (channel ->
/// per-connection buffers). Returns when EITHER half ends (the other is
/// dropped with it) — `select!`, not `join!`, so a dead read side ends the
/// attach promptly instead of parking on the writer's recv.
pub async fn data_channel(
    mut dw: impl AsyncWrite + Unpin + Send,
    dr: impl AsyncRead + Unpin + Send + 'static,
    rx: &mut mpsc::Receiver<Frame>,
    tun: Arc<Tunnel>,
    new_tx: Option<mpsc::Sender<NewConn>>,
) {
    let (dead_tx, mut dead_rx) = watch::channel(false);
    let reader_task = tokio::spawn(async move {
        data_reader(dr, tun, new_tx).await;
        let _ = dead_tx.send(true);
    });
    writer(&mut dw, rx, &mut dead_rx).await;
    if *dead_rx.borrow() {
        // Flap: wait for the reader to finish draining the socket.
        let _ = reader_task.await;
    } else {
        // Writer died (write error or session end): the reader is done for.
        reader_task.abort();
    }
    let _ = dw.shutdown().await;
}

/// Control-channel READER: replies PING->PONG and tears the connection table
/// down when the channel closes. NEW/DATA/CLOSE ride the data channels (pinned
/// by `id % n`), not the control channel. Returns when the control channel
/// closes.
pub async fn control_reader<R: AsyncRead + Unpin + Send>(
    mut stream: R,
    tun: Arc<Tunnel>,
    last_seen: Option<Arc<AtomicU64>>,
) {
    let mut buf = BytesMut::with_capacity(64 * 1024);
    loop {
        if stream.read_buf(&mut buf).await.unwrap_or(0) == 0 {
            break;
        }
        if let Some(ls) = &last_seen {
            ls.store(now_ms(), Ordering::Relaxed);
        }
        while let Some(frame) = protocol::parse(&mut buf) {
            match frame {
                // Per-connection CLOSE rides the data channel; a CLOSE seen here
                // is a defensive teardown of a single connection.
                Frame::Close(id) => {
                    let _ = tun.table.lock().unwrap().conns.remove(&id);
                }
                Frame::Ping(nonce) => {
                    let _ = tun.control_out.send(Frame::Pong(nonce)).await;
                }
                _ => {}
            }
        }
    }
    // control gone: drop every live connection (their buffers close -> pipes end).
    tun.table.lock().unwrap().conns.clear();
}

/// A liveness deadline: resolves once the control channel has had no activity
/// for `deadline` (polled every `check`). Use with `tokio::select!` to drop a
/// session whose peer has gone half-open (no RST) — without it a dead link
/// would hold the session (and its public ports) until the OS TCP timeout.
pub async fn liveness(last_seen: Arc<AtomicU64>, check: Duration, deadline: Duration) {
    let mut iv = tokio::time::interval(check);
    loop {
        iv.tick().await; // first tick is immediate; idle ~= 0 so it won't fire
        let idle = now_ms().saturating_sub(last_seen.load(Ordering::Relaxed));
        if idle > deadline.as_millis() as u64 {
            tracing::warn!(
                "liveness: no control-channel activity for {idle} ms (> {deadline:?}); dropping session"
            );
            return;
        }
    }
}

/// Pipe a bidirectional byte stream (a socket) <-> the tunnel. TWO tasks handle
/// the two directions independently (so a slow write never blocks the read and
/// vice versa - no write/read deadlock for large payloads). A close-signal
/// (one mpsc per direction) ensures that when EITHER direction ends, the other
/// is torn down and the whole socket is closed (no connection leaks). CLOSE is
/// sent once both directions are done.
pub async fn pipe(
    stream: TcpStream,
    id: u16,
    tun: Arc<Tunnel>,
    mut from_rx: mpsc::Receiver<Bytes>,
) {
    let (mut read_half, mut write_half) = stream.into_split();
    let out = tun.data_sender(id);
    // The CLOSE is sent on the DATA channel (same per-id ordering as this id's
    // DATA), so the receiver drops the per-connection buffer only after every
    // byte has been delivered. A separate `out_close` clone is kept because `out`
    // itself is moved into task2 below.
    let out_close = out.clone();

    // Task 1: tunnel -> socket (drain the per-connection buffer into the socket).
    // Ends ONLY when the tunnel CLOSEs this id (from_rx -> None) or the local
    // write fails. It must NOT stop when the local *read* side EOFs (the peer
    // half-closed): the peer can still owe us a reply in the other direction,
    // and tearing this side down early would hand the peer a premature EOF and
    // lose the in-flight response.
    // A burst of payloads is shared across one writev: one syscall, no concat
    // copy. A lone payload writes immediately (single-iov writev == write).
    let h1 = tokio::spawn(async move {
        let mut batch: Vec<Bytes> = Vec::with_capacity(8);
        // from_rx -> None means the tunnel CLOSEd this id (the peer is done).
        while let Some(first) = from_rx.recv().await {
            batch.clear();
            let mut size = first.len();
            batch.push(first);
            while size < protocol::PIPE_BATCH {
                match from_rx.try_recv() {
                    Ok(m) => {
                        size += m.len();
                        batch.push(m);
                    }
                    Err(_) => break,
                }
            }
            let bufs: Vec<IoSlice<'_>> = batch.iter().map(|b| IoSlice::new(b)).collect();
            let mut consumed = vec![0usize; bufs.len()];
            // write_vectored_all loops on partial writes: a single
            // write_vectored under a full sndbuf would silently drop the
            // un-written tail of the batch.
            if write_vectored_all(&mut write_half, &bufs, &mut consumed).await.is_err() {
                break;
            }
        }
        // Everything the tunnel sent is delivered; half-close our write side.
        let _ = write_half.shutdown().await;
    });

    // Task 2: socket -> tunnel (read the socket, send DATA over the data channel).
    let h2 = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(64 * 1024);
        loop {
            match read_half.read_buf(&mut buf).await {
                Ok(0) => break, // local read EOF: the peer closed its send side
                Ok(_) => {
                    let data = buf.split().freeze();
                    let mut off = 0;
                    let mut ok = true;
                    while off < data.len() && ok {
                        let end = std::cmp::min(off + protocol::MAX_PAYLOAD, data.len());
                        // `slice` is a refcounted range: chunking copies nothing,
                        // and the id rides the frame instead of the bytes.
                        ok = out
                            .send(Frame::Data(id, data.slice(off..end)))
                            .await
                            .is_ok();
                        off = end;
                    }
                    if !ok {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        drop(read_half);
    });

    // The local->tunnel direction is exhausted (or failed). Send CLOSE now,
    // ordered after this id's DATA on the data channel: it tells the peer "no
    // more bytes are coming from my local side" while task1 keeps draining the
    // tunnel->local direction until the PEER's CLOSE arrives (from_rx -> None).
    // A request-then-half-close client therefore still receives its full reply
    // before the connection tears down.
    let _ = h2.await;
    let _ = out_close.send(Frame::Close(id)).await;
    let _ = h1.await;
    tracing::debug!("pipe id={id} ending");
}

/// SERVER: a connection arrived on a bound public port. Allocate an id, register
/// it, announce NEW (carrying the local address to reach), then pipe both ways
/// over the right data channel.
pub async fn server_on_accept(
    stream: TcpStream,
    svc_name: String,
    local_host: String,
    local_port: u16,
    tun: Arc<Tunnel>,
) {
    let id = tun.next_id.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        return; // wrapped (2^16 conns) - drop
    }
    // Bound live connections (a connection flood is dropped at capacity rather
    // than spawning unbounded tasks).
    if tun.table.lock().unwrap().conns.len() >= MAX_CONNS {
        tracing::warn!("server_on_accept: at capacity ({MAX_CONNS} conns); dropping");
        return;
    }
    let (from_tx, from_rx) = mpsc::channel::<Bytes>(BUFFER_FRAMES);
    tun.table.lock().unwrap().conns.insert(id, from_tx);
    tracing::debug!("server NEW id={id} svc={svc_name} -> {local_host}:{local_port}");
    // Announce NEW on the SAME data channel this id's DATA/CLOSE ride (id % n),
    // so the client's data reader sees NEW strictly before the first DATA — the
    // connection is registered before any byte arrives (no pending buffer, no
    // data-loss race). A control-channel NEW (a separate TCP connection) could
    // arrive out of order with the data channel and lose the tail of a stream.
    if tun
        .data_sender(id)
        .send(Frame::New {
            id,
            local_host,
            local_port,
        })
        .await
        .is_err()
    {
        tun.table.lock().unwrap().conns.remove(&id);
        return;
    }
    tokio::spawn(pipe(stream, id, tun, from_rx));
}

/// CLIENT: a NEW arrived. Connect the given local address, pipe both ways.
pub async fn client_on_new(
    id: u16,
    local_host: String,
    local_port: u16,
    from_rx: mpsc::Receiver<Bytes>,
    tun: Arc<Tunnel>,
) {
    let addr = format!("{local_host}:{local_port}");
    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("client: connect {addr} failed: {e}");
            tun.table.lock().unwrap().conns.remove(&id);
            let _ = tun.control_out.send(Frame::Close(id)).await;
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    tokio::spawn(pipe(stream, id, tun, from_rx));
}
