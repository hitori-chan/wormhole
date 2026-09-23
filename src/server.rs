//! Server: a control listener + one shared data port. The server is a
//! **stateless generic forwarder** — it does not know the service list from
//! its own config. When a client authenticates and declares its proxies
//! (PROXIES), the server binds the requested public ports (subject to
//! `allow_ports` / `forbid_ports`) and forwards each accepted connection to
//! the client, which dials the local address. On disconnect the server tears
//! the public-port listeners back down. Only one client at a time.
//!
//! All N data channels share ONE port (the client learns it from PROXYACK);
//! each data connection names its channel with a CHIDX frame after AUTH. A
//! channel slot is `Some(receiver)` when free, `None` while attached — and
//! the receiver is held across re-attaches, so frames queued while a channel
//! is down survive the flap.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{self, ServerConfig};
use crate::protocol::{self, Frame, ProxyAckEntry};
use crate::tunnel::{self, Tunnel};

/// A live tunnel session (the current authenticated client) and the on-demand
/// public-port listeners it owns (aborted when the session ends, freeing the
/// ports for the next client).
struct Session {
    tun: Arc<Tunnel>,
    /// one slot per data channel: `Some(rx)` = free, `None` = attached. The
    /// receiver is held across re-attaches so a channel's queued frames
    /// survive a flap (a stalled pipe backpressures; it does not die).
    chan_rx: Mutex<Vec<Option<mpsc::Receiver<Frame>>>>,
    /// accept-loop tasks for the on-demand public ports (abort to free ports).
    service_tasks: Vec<JoinHandle<()>>,
}

pub async fn run(cfg: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let (ctrl_addr, data_port) = cfg.resolve()?;
    let expected = protocol::secret_hash(&cfg.secret);
    let current: Arc<Mutex<Option<Arc<Session>>>> = Arc::new(Mutex::new(None));
    let data_host = ctrl_addr.ip();

    // --- control listener ---
    let control_listener = tunnel::listen(&ctrl_addr)?;
    tracing::info!(
        "wormhole server: control on {ctrl_addr}, data on {data_host}:{data_port} (shared port), stateless",
    );
    if let Some(ports) = &cfg.allow_ports {
        let set = ports.resolve()?;
        tracing::info!("wormhole server: allow_ports {set:?}");
    }
    if let Some(ports) = &cfg.forbid_ports {
        let set = ports.resolve()?;
        tracing::info!("wormhole server: forbid_ports {set:?}");
    }

    // --- shared data-port listener (N channel connections attach by CHIDX) ---
    {
        let data_addr = SocketAddr::new(data_host, data_port);
        let dl = tunnel::listen(&data_addr)
            .map_err(|e| format!("bind data port {data_addr}: {e}"))?;
        let current = current.clone();
        let exp = expected;
        tokio::spawn(async move {
            loop {
                match dl.accept().await {
                    Ok((stream, _addr)) => {
                        // keepalive is inherited from the listener; nodelay is not
                        let _ = stream.set_nodelay(true);
                        let current = current.clone();
                        let exp = exp;
                        tokio::spawn(handle_data_conn(stream, exp, current));
                    }
                    Err(e) => tracing::warn!("data port accept: {e}"),
                }
            }
        });
    }

    // --- control accept loop ---
    loop {
        let (stream, addr) = control_listener.accept().await?;
        // keepalive is inherited from the listener; nodelay is not
        let _ = stream.set_nodelay(true);
        let current = current.clone();
        tokio::spawn(handle_control(
            stream,
            addr,
            expected,
            cfg.clone(),
            current,
            data_host,
            data_port,
        ));
    }
}

/// Control channel: authenticate, learn N + the proxies, bind the public ports,
/// run control I/O, then tear the public ports back down.
async fn handle_control(
    mut stream: TcpStream,
    addr: SocketAddr,
    expected: [u8; 32],
    cfg: ServerConfig,
    current: Arc<Mutex<Option<Arc<Session>>>>,
    bind_host: std::net::IpAddr,
    data_port: u16,
) {
    tracing::debug!("server: handle_control {addr}");
    let mut buf = BytesMut::with_capacity(1024);

    // --- AUTH ---
    match read_frame(&mut stream, &mut buf).await {
        Some(Frame::Auth(h)) if h == expected => {}
        Some(Frame::Auth(_)) => {
            tracing::warn!("server: {addr} auth FAILED");
            let _ = reply(&mut stream, &mut buf, &Frame::Fail).await;
            return;
        }
        _ => return,
    }
    let _ = reply(&mut stream, &mut buf, &Frame::Ok).await;
    tracing::info!("server: {addr} authenticated");

    // --- DCOUNT (how many data channels the client will open; sizes the session) ---
    let n = match read_frame(&mut stream, &mut buf).await {
        Some(Frame::DCount(cn)) if (1..=config::MAX_DATA_CHANNELS).contains(&cn) => cn,
        Some(Frame::DCount(cn)) => {
            tracing::warn!(
                "server: {addr} wants {cn} data channels (valid 1..={}); closed",
                config::MAX_DATA_CHANNELS
            );
            return;
        }
        _ => return,
    };

    // --- PROXIES (the public->local mappings to expose) ---
    let regs = match read_frame(&mut stream, &mut buf).await {
        Some(Frame::Proxies(regs)) => regs,
        _ => return,
    };

    // --- build the tunnel + session ---
    let (t0, mut control_rx, chan_rx) = Tunnel::new(n);
    let tun = Arc::new(t0);

    // --- bind the requested public ports (policy-checked) ---
    let mut service_tasks = Vec::new();
    let mut ack: Vec<ProxyAckEntry> = Vec::new();
    let mut seen: HashSet<u16> = HashSet::new();
    for reg in &regs {
        if !seen.insert(reg.remote) {
            tracing::warn!(
                "server: proxy {} duplicate remote port {}, skipped",
                reg.name,
                reg.remote
            );
            ack.push(ProxyAckEntry {
                name: reg.name.clone(),
                status: 2,
            });
            continue;
        }
        if !cfg.port_allowed(reg.remote) {
            tracing::warn!(
                "server: proxy {} wants public port {} but policy forbids it; skipped",
                reg.name,
                reg.remote
            );
            ack.push(ProxyAckEntry {
                name: reg.name.clone(),
                status: 1,
            });
            continue;
        }
        let bind_addr = SocketAddr::new(bind_host, reg.remote);
        let listener = match tunnel::listen(&bind_addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    "server: bind {bind_addr} for proxy {} failed: {e}; skipped",
                    reg.name
                );
                ack.push(ProxyAckEntry {
                    name: reg.name.clone(),
                    status: 2,
                });
                continue;
            }
        };
        tracing::info!(
            "server: proxy {} -> public {bind_addr} => local {}:{}",
            reg.name,
            reg.local_host,
            reg.local_port
        );
        let name = reg.name.clone();
        let lh = reg.local_host.clone();
        let lp = reg.local_port;
        service_tasks.push(tokio::spawn(service_accept_loop(
            listener,
            name,
            lh,
            lp,
            tun.clone(),
        )));
        ack.push(ProxyAckEntry {
            name: reg.name.clone(),
            status: 0,
        });
    }

    let n_bound = ack.iter().filter(|e| e.status == 0).count();
    tracing::info!("server: {n_bound}/{} proxie(s) bound for {addr}", ack.len());

    let session = Arc::new(Session {
        tun: tun.clone(),
        chan_rx: Mutex::new(chan_rx.into_iter().map(Some).collect()),
        service_tasks,
    });

    // replace any prior session cleanly (tear down its public ports first)
    {
        let prev = current.lock().unwrap().take();
        if let Some(old) = prev {
            tracing::warn!("server: {addr} replacing an existing session");
            for h in old.service_tasks.iter() {
                h.abort();
            }
        }
        *current.lock().unwrap() = Some(session.clone());
    }

    // tell the client the per-proxy results + the data port (also = "ready,
    // open the data channels")
    let _ = reply(
        &mut stream,
        &mut buf,
        &Frame::ProxyAck {
            entries: ack,
            data_port,
        },
    )
    .await;

    // heartbeat + control I/O. A liveness deadline drops the session if the
    // client goes silent, so a half-open link can't hold the public ports
    // until the OS TCP timeout.
    let last_seen = Arc::new(std::sync::atomic::AtomicU64::new(tunnel::now_ms()));
    let (read_half, write_half) = stream.into_split();
    let hb_task = spawn_heartbeat(session.tun.control_out.clone());
    let writer_task = tokio::spawn(async move {
        // Control channels don't flap; `dead` is never raised.
        let (_dead_tx, mut dead_rx) = tokio::sync::watch::channel(false);
        let mut wh = write_half;
        tunnel::writer(&mut wh, &mut control_rx, &mut dead_rx).await;
        let _ = wh.shutdown().await;
    });
    let mut reader_task = tokio::spawn(tunnel::control_reader(
        read_half,
        session.tun.clone(),
        Some(last_seen.clone()),
    ));
    tokio::select! {
        _ = &mut reader_task => {}
        _ = tunnel::liveness(last_seen, tunnel::LIVENESS_CHECK, tunnel::LIVENESS_DEADLINE) => {
            reader_task.abort();
        }
    }
    writer_task.abort();
    hb_task.abort();

    // teardown: free the on-demand public ports + drop the session (its held
    // channel receivers drop with it, ending every data channel)
    for h in session.service_tasks.iter() {
        h.abort();
    }
    *current.lock().unwrap() = None;
    tracing::info!(
        "server: control channel closed (was {addr}); {} public port(s) released",
        session.service_tasks.len()
    );
}

/// Accept loop for one on-demand public port. Each accepted connection is handed
/// to the client via NEW (carrying the local address to reach). The task runs
/// for the life of the session; it is aborted (freeing the port) on teardown.
async fn service_accept_loop(
    listener: TcpListener,
    name: String,
    local_host: String,
    local_port: u16,
    tun: Arc<Tunnel>,
) {
    while let Ok((stream, _addr)) = listener.accept().await {
        // keepalive is inherited from the listener; nodelay is not
        let _ = stream.set_nodelay(true);
        let lh = local_host.clone();
        let lp = local_port;
        tokio::spawn(tunnel::server_on_accept(
            stream,
            name.clone(),
            lh,
            lp,
            tun.clone(),
        ));
    }
}

/// A data-channel connection on the shared data port: authenticate, learn the
/// channel index (CHIDX), take the slot, run the channel, and release the slot
/// (receiver held back) when either half ends — so the client can re-attach
/// the same index on a flap and queued frames survive.
async fn handle_data_conn(
    mut stream: TcpStream,
    expected: [u8; 32],
    current: Arc<Mutex<Option<Arc<Session>>>>,
) {
    let mut buf = BytesMut::with_capacity(64);
    // --- authenticate the data channel ---
    match read_frame(&mut stream, &mut buf).await {
        Some(Frame::Auth(h)) if h == expected => {}
        Some(Frame::Auth(_)) => {
            tracing::warn!("data conn: auth FAILED");
            return;
        }
        _ => return,
    }
    // --- channel index ---
    let Some(Frame::ChIdx(i)) = read_frame(&mut stream, &mut buf).await else {
        tracing::warn!("data conn: no CHIDX after AUTH; closed");
        return;
    };
    let session = current.lock().unwrap().clone();
    let Some(session) = session else {
        tracing::trace!("data conn: no active session, closed");
        return;
    };
    let n = session.tun.n as usize;
    if i as usize >= n {
        tracing::warn!("data conn: channel {i} out of range (n={n}), closed");
        let _ = reply(&mut stream, &mut buf, &Frame::Fail).await;
        return;
    }
    let rx = session.chan_rx.lock().unwrap()[i as usize].take();
    let Some(rx) = rx else {
        tracing::warn!("data conn: channel {i} already attached, closed");
        let _ = reply(&mut stream, &mut buf, &Frame::Fail).await;
        return;
    };
    // the slot is taken from here on; a failed OK hands it straight back
    if !reply(&mut stream, &mut buf, &Frame::Ok).await {
        session.chan_rx.lock().unwrap()[i as usize] = Some(rx);
        return;
    }
    tracing::trace!("data channel {i} attached");

    let (dr, dw) = stream.into_split();
    let mut rx = rx;
    let tun = session.tun.clone();
    // The server never receives NEW (it emits them); pass `new_tx = None`.
    tunnel::data_channel(dw, dr, &mut rx, tun, None).await;
    // release the slot, keeping the receiver (and its queued frames) alive
    session.chan_rx.lock().unwrap()[i as usize] = Some(rx);
    tracing::trace!("data channel {i} closed; slot released for re-attach");
}

/// Read exactly one frame from the stream (accumulating across reads).
async fn read_frame(stream: &mut TcpStream, buf: &mut BytesMut) -> Option<Frame> {
    loop {
        if let Some(f) = protocol::parse(buf) {
            return Some(f);
        }
        if stream.read_buf(buf).await.unwrap_or(0) == 0 {
            return None;
        }
    }
}

/// Write one frame. Returns false if the write failed.
async fn reply(stream: &mut TcpStream, buf: &mut BytesMut, frame: &Frame) -> bool {
    protocol::encode(buf, frame);
    let ok = stream.write_all_buf(buf).await.is_ok();
    buf.clear();
    ok
}

/// Send PING on the control channel every 15s; the peer replies PONG.
/// (Both ends enforce the control-channel liveness deadline; data channels
/// ride TCP keepalive.)
fn spawn_heartbeat(out: mpsc::Sender<Frame>) -> JoinHandle<()> {
    let interval = std::time::Duration::from_secs(15);
    tokio::spawn(async move {
        let mut nonce = 0u32;
        loop {
            tokio::time::sleep(interval).await;
            nonce += 1;
            if out.send(Frame::Ping(nonce)).await.is_err() {
                break;
            }
        }
    })
}
