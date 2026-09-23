//! Client: connects to the server's control port, declares the proxies it
//! wants exposed (PROXIES), learns the data port from PROXYACK, then opens N
//! data channels on that one shared port (each AUTH + CHIDX) and runs the
//! tunnel. On each NEW it dials the local address the server named and pipes
//! it through the tunnel.
//!
//! A dropped data channel is re-opened automatically (backoff + jitter). The
//! per-channel frame queue is held open across the flap, so bytes queued while
//! the channel is down are delivered when it comes back — a flap costs
//! latency, never data.

use std::collections::HashMap;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::config::{ClientConfig, ProxySpec};
use crate::protocol::{self, Frame, ProxyReg};
use crate::tunnel::{self, NewConn, Tunnel};

/// Max reconnect/reattach backoff (the client retries forever by default; this
/// bounds the exponential growth).
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub async fn run(cfg: &ClientConfig, services: &HashMap<String, ProxySpec>) {
    let (host, ctrl_port, n) = cfg.resolve().expect("client config validated at load");
    let proxies = build_proxies(services);
    tracing::info!(
        "wormhole client: {host}:{ctrl_port} control + {n} data channel(s), {} proxie(s) declared",
        proxies.len()
    );

    let mut backoff = Duration::from_millis(250);
    loop {
        match connect_and_tunnel(cfg, n, &proxies).await {
            Ok(()) => tracing::warn!("client: tunnel closed; reconnecting"),
            Err(e) => tracing::warn!("client: tunnel error: {e}; reconnecting"),
        }
        // exponential backoff + jitter (avoids a fixed retry cadence)
        let jitter = Duration::from_millis(rand::random::<u64>() % 256);
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Expand the service specs into the flat proxy list sent to the server.
fn build_proxies(services: &HashMap<String, ProxySpec>) -> Vec<ProxyReg> {
    let mut proxies = Vec::new();
    let mut names: Vec<&String> = services.keys().collect();
    names.sort();
    for name in names {
        let spec = &services[name];
        for m in spec.expand().unwrap_or_default() {
            proxies.push(ProxyReg {
                name: name.clone(),
                remote: m.remote,
                local_host: m.local_host,
                local_port: m.local_port,
            });
        }
    }
    proxies
}

/// One tunnel session: authenticate, declare proxies, learn the data port,
/// open the data channels, run.
async fn connect_and_tunnel(
    cfg: &ClientConfig,
    n: u8,
    proxies: &[ProxyReg],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (host, ctrl_port, _) = cfg.resolve()?;

    // --- control channel ---
    let ctrl_addr = format!("{host}:{ctrl_port}");
    let mut stream = tunnel::connect_host(&host, ctrl_port).await?;
    let hash = protocol::secret_hash(&cfg.secret);
    let mut buf = BytesMut::with_capacity(4096);

    // AUTH
    protocol::encode(&mut buf, &Frame::Auth(hash));
    stream.write_all_buf(&mut buf).await?;
    buf.clear();

    // OK?
    let mut got_ok = false;
    while !got_ok {
        if stream.read_buf(&mut buf).await? == 0 {
            return Err("control channel closed during auth".into());
        }
        if let Some(f) = protocol::parse(&mut buf) {
            match f {
                Frame::Ok => got_ok = true,
                Frame::Fail => return Err("server rejected the shared secret".into()),
                _ => {}
            }
        }
    }
    tracing::info!("client: authenticated to {ctrl_addr}");

    // DCOUNT (how many data channels we'll open)
    protocol::encode(&mut buf, &Frame::DCount(n));
    stream.write_all_buf(&mut buf).await?;
    buf.clear();

    // PROXIES (the public->local mappings to expose)
    protocol::encode(&mut buf, &Frame::Proxies(proxies.to_vec()));
    stream.write_all_buf(&mut buf).await?;
    buf.clear();

    // PROXYACK (per-proxy registration results + the data port; also = ready)
    let mut ack: Option<(Vec<protocol::ProxyAckEntry>, u16)> = None;
    while ack.is_none() {
        if stream.read_buf(&mut buf).await? == 0 {
            return Err("control channel closed before proxy ack".into());
        }
        if let Some(f) = protocol::parse(&mut buf) {
            match f {
                Frame::ProxyAck {
                    entries,
                    data_port,
                } => ack = Some((entries, data_port)),
                Frame::Fail => return Err("server rejected the proxy list".into()),
                _ => {}
            }
        }
    }
    let (entries, data_port) = ack.unwrap();
    let mut n_bound = 0;
    for e in entries {
        match e.status {
            0 => {
                n_bound += 1;
                tracing::info!("client: proxy '{}' bound on the server", e.name);
            }
            1 => tracing::warn!(
                "client: proxy '{}' DENIED by the server's allow/forbid policy",
                e.name
            ),
            _ => tracing::warn!(
                "client: proxy '{}' not bound (duplicate port or server bind failure)",
                e.name
            ),
        }
    }
    if n_bound < proxies.len() {
        tracing::warn!(
            "client: server bound only {n_bound}/{} proxie(s)",
            proxies.len()
        );
    }

    // --- data channels (all on the server-advertised data port) ---
    let (t0, mut control_rx, chan_rx) = Tunnel::new(n);
    let tun = std::sync::Arc::new(t0);
    let data_addr = format!("{host}:{data_port}");
    tracing::info!("client: {n} data channel(s) on {data_addr}");

    // NEW handler: dial the local address the server named, pipe both ways.
    let (new_tx, mut new_rx) = mpsc::channel::<NewConn>(256);
    let new_rx_handle = tokio::spawn({
        let tun = tun.clone();
        async move {
            while let Some((id, local_host, local_port, from_rx)) = new_rx.recv().await {
                let t = tun.clone();
                tokio::spawn(tunnel::client_on_new(
                    id, local_host, local_port, from_rx, t,
                ));
            }
        }
    });

    // writer (control), reader (control)
    let (read_half, write_half) = stream.into_split();
    let writer_task = tokio::spawn(async move {
        // Control channels don't flap; `dead` is never raised.
        let (_dead_tx, mut dead_rx) = tokio::sync::watch::channel(false);
        let mut wh = write_half;
        tunnel::writer(&mut wh, &mut control_rx, &mut dead_rx).await;
        let _ = wh.shutdown().await;
    });
    // Liveness: stamp last_seen on every control frame; the select! below
    // drops the session if the link goes half-open (no RST) past the deadline.
    let last_seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(tunnel::now_ms()));
    let mut reader_task = tokio::spawn(tunnel::control_reader(
        read_half,
        tun.clone(),
        Some(last_seen.clone()),
    ));

    // one re-attach loop per data channel. The watch sender is the session's
    // liveness token: it is owned by THIS task, so when the session ends (or
    // this task is aborted) the sender drops and every channel loop exits.
    let (_live_tx, _live_init) = watch::channel(());
    let mut data_tasks = Vec::with_capacity(n as usize);
    for (i, rx) in chan_rx.into_iter().enumerate() {
        let live_rx = _live_tx.subscribe();
        let ch = Channel {
            host: host.clone(),
            port: data_port,
            hash,
            idx: i as u8,
        };
        data_tasks.push(tokio::spawn(channel_loop(
            ch, rx, tun.clone(), new_tx.clone(), live_rx,
        )));
    }

    // heartbeat (liveness; the server also pings)
    let hb_task = {
        let out = tun.control_out.clone();
        tokio::spawn(async move {
            let mut nonce = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                nonce += 1;
                if out.send(Frame::Ping(nonce)).await.is_err() {
                    break;
                }
            }
        })
    };

    // run until the control channel ends (EOF/error) OR the liveness deadline
    // fires (peer went half-open). Either way, tear the session down cleanly so
    // no data/writer task leaks and run() reconnects.
    tokio::select! {
        r = &mut reader_task => { let _ = r; }
        _ = tunnel::liveness(last_seen, tunnel::LIVENESS_CHECK, tunnel::LIVENESS_DEADLINE) => {
            reader_task.abort();
        }
    }
    writer_task.abort();
    hb_task.abort();
    new_rx_handle.abort();
    for t in data_tasks {
        t.abort();
    }
    Ok(())
}

/// The invariant part of one data channel (same across re-attaches).
struct Channel {
    host: String,
    port: u16,
    hash: [u8; 32],
    idx: u8,
}

/// Drive one data channel for the life of the session: attach, run, and on any
/// death re-attach with backoff + jitter. The per-channel receiver `rx`
/// outlives each attach, so frames queued while the channel is down are
/// delivered on re-attach — a flap costs latency, never bytes. Exits when the
/// session token (`live`) is dropped.
async fn channel_loop(
    ch: Channel,
    mut rx: mpsc::Receiver<Frame>,
    tun: std::sync::Arc<Tunnel>,
    new_tx: mpsc::Sender<NewConn>,
    mut live: watch::Receiver<()>,
) {
    let i = ch.idx;
    let mut backoff = Duration::from_millis(250);
    loop {
        let r = tokio::select! {
            _ = live.changed() => return, // session token dropped
            r = attach_data_channel(&ch, &mut rx, &tun, &new_tx) => r,
        };
        let jitter = Duration::from_millis(rand::random::<u64>() % 256);
        let sleep = backoff + jitter;
        match r {
            // attached and ran until the channel died: reset, retry promptly
            Ok(()) => {
                tracing::warn!("client: data channel {i} closed; re-attaching");
                backoff = Duration::from_millis(250);
            }
            // attach itself failed (connect refused, rejected, no session):
            Err(e) => {
                tracing::warn!("client: data channel {i}: {e}; retrying");
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
        tokio::select! {
            _ = live.changed() => return,
            _ = tokio::time::sleep(sleep) => {}
        }
    }
}

/// One attach: TCP connect, AUTH + CHIDX(i), await the server's OK, then run
/// the channel (writer + reader) until either half ends. `rx` is borrowed, not
/// consumed, so the receiver (and its queued frames) survives into the next
/// attach.
async fn attach_data_channel(
    ch: &Channel,
    rx: &mut mpsc::Receiver<Frame>,
    tun: &std::sync::Arc<Tunnel>,
    new_tx: &mpsc::Sender<NewConn>,
) -> Result<(), String> {
    let i = ch.idx;
    let mut ds = tunnel::connect_host(&ch.host, ch.port).await.map_err(|e| e.to_string())?;
    let mut dbuf = BytesMut::with_capacity(64);
    protocol::encode(&mut dbuf, &Frame::Auth(ch.hash));
    protocol::encode(&mut dbuf, &Frame::ChIdx(i));
    ds.write_all_buf(&mut dbuf).await.map_err(|e| e.to_string())?;
    dbuf.clear();
    // await the server's OK (slot taken) or FAIL (busy / out of range / none)
    loop {
        if ds.read_buf(&mut dbuf).await.map_err(|e| e.to_string())? == 0 {
            return Err("server closed the data connection before OK".into());
        }
        if let Some(f) = protocol::parse(&mut dbuf) {
            match f {
                Frame::Ok => break,
                Frame::Fail => {
                    return Err("server rejected the data channel (busy or unknown index?)"
                        .into())
                }
                _ => {}
            }
        }
    }
    let (dr, dw) = ds.into_split();
    tunnel::data_channel(dw, dr, rx, tun.clone(), Some(new_tx.clone())).await;
    Ok(())
}
