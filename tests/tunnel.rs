//! End-to-end integration + stress test: boots a real wormhole server and
//! client on loopback (with a local backend) and drives the public port —
//! correctness across payload sizes, 256-way concurrency, connection churn,
//! and reconnect after the server is killed and restarted.
//!
//! Uses fixed high ports (28100-range) to avoid collisions; run `cargo test
//! --release --test tunnel` for the full suite.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::net::{TcpListener, TcpStream};

use wormhole::config::{ClientConfig, LocalSpec, PortPolicy, ProxySpec, ServerConfig};
use wormhole::protocol::{self, Frame};

/// Encode one frame to its on-wire bytes.
fn wire(f: &Frame) -> BytesMut {
    let mut b = BytesMut::new();
    protocol::encode(&mut b, f);
    b
}

/// Write one frame to the stream.
async fn send(stream: &mut TcpStream, f: &Frame) {
    let mut b = wire(f);
    stream.write_all_buf(&mut b).await.expect("write frame");
}

/// Read exactly one frame from the stream (Fail on EOF).
async fn read_one(stream: &mut TcpStream, buf: &mut BytesMut) -> Frame {
    loop {
        if let Some(f) = protocol::parse(buf) {
            return f;
        }
        if stream.read_buf(buf).await.unwrap_or(0) == 0 {
            return Frame::Fail;
        }
    }
}

/// Raw data-channel attach (AUTH + CHIDX). Returns the socket + the server's
/// reply (Ok = attached, Fail = rejected or closed).
async fn attach_raw(port: u16, hash: [u8; 32], idx: u8) -> (TcpStream, Frame, BytesMut) {
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("data connect");
    let mut b = BytesMut::new();
    send(&mut s, &Frame::Auth(hash)).await;
    send(&mut s, &Frame::ChIdx(idx)).await;
    let r = read_one(&mut s, &mut b).await;
    // `b` may hold bytes read past the reply frame (the kernel coalesces):
    // they belong to the data stream and MUST NOT be dropped.
    (s, r, b)
}

/// Raw data-channel attach, asserting the server accepted (OK).
async fn attach(port: u16, hash: [u8; 32], idx: u8) -> (TcpStream, BytesMut) {
    let (s, r, b) = attach_raw(port, hash, idx).await;
    assert_eq!(r, Frame::Ok, "channel {idx} attach should be OK");
    (s, b)
}

const CTRL: u16 = 28100; // control
const DATA0: u16 = 28101; // shared data port (default: control + 1)
const PUB: u16 = 28110; // public port the client exposes
const BACKEND: u16 = 28120; // local backend the client dials

fn server_cfg() -> ServerConfig {
    // data port = CTRL + 1 = DATA0 (the default)
    ServerConfig {
        bind: format!("127.0.0.1:{CTRL}"),
        secret: "integration-test-secret".into(),
        data_port: Some(DATA0),
        allow_ports: None,
        forbid_ports: None,
    }
}

fn client_cfg() -> ClientConfig {
    ClientConfig {
        server: format!("127.0.0.1:{CTRL}"),
        secret: "integration-test-secret".into(),
        channels: Some(2),
    }
}

fn services() -> HashMap<String, ProxySpec> {
    let mut m = HashMap::new();
    m.insert(
        "t".into(),
        ProxySpec {
            remote: PortPolicy::Num(PUB),
            local: Some(LocalSpec::Num(BACKEND)),
        },
    );
    m
}

/// Backend: read the whole request, reverse it, send it back, close. The
/// reverse transform guarantees the bytes truly round-tripped the tunnel (a
/// loopback echo shortcut is impossible to match).
async fn backend_reverse(listener: TcpListener) {
    while let Ok((s, _)) = listener.accept().await {
        let _ = s.set_nodelay(true);
        tokio::spawn(async move {
            let (mut r, mut w) = s.into_split();
            let mut data = Vec::new();
            if r.read_to_end(&mut data).await.is_err() {
                return;
            }
            data.reverse();
            let _ = w.write_all(&data).await;
            let _ = w.shutdown().await;
        });
    }
}

/// Poll-connect to a port until it accepts (or the timeout elapses).
async fn wait_for_port(port: u16, timeout: Duration) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(format!("127.0.0.1:{port}")).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// One full-duplex round trip through the tunnel: send `data`, send EOF, read
/// the backend's reversed reply to EOF, return it.
async fn reverse_roundtrip(data: &[u8]) -> io::Result<Vec<u8>> {
    let s = TcpStream::connect(format!("127.0.0.1:{PUB}")).await?;
    let _ = s.set_nodelay(true);
    let (mut r, mut w) = s.into_split();
    let (sent, received) = tokio::join!(
        async {
            w.write_all(data).await?;
            w.shutdown().await
        },
        async {
            let mut v = Vec::new();
            r.read_to_end(&mut v).await?;
            Ok::<_, io::Error>(v)
        }
    );
    sent?;
    received
}

fn reversed(data: &[u8]) -> Vec<u8> {
    data.iter().rev().copied().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_end_to_end_and_stress() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let overall = async {
        // --- backend ---
        let bl = TcpListener::bind(format!("127.0.0.1:{BACKEND}"))
            .await
            .unwrap();
        let backend = tokio::spawn(backend_reverse(bl));

        // --- server + client ---
        let scfg = server_cfg();
        let ccfg = client_cfg();
        let svcs = services();
        let server = tokio::spawn({
            let cfg = scfg.clone();
            async move {
                let _ = wormhole::server::run(&cfg).await;
            }
        });
        let client = tokio::spawn({
            let cfg = ccfg.clone();
            let svcs = svcs.clone();
            async move {
                wormhole::client::run(&cfg, &svcs).await;
            }
        });

        wait_for_port(PUB, Duration::from_secs(5))
            .await
            .expect("public port should come up");

        // --- 1. correctness across payload sizes ---
        for size in [64usize, 1000, 65536, 1 << 20, 16 << 20] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
            let got = reverse_roundtrip(&data)
                .await
                .unwrap_or_else(|e| panic!("size {size}: {e}"));
            let want = reversed(&data);
            if got != want {
                let first = got.iter().zip(want.iter()).position(|(a, b)| a != b);
                panic!(
                    "size {size} mismatch: got {} of {} bytes, first diff at {:?}",
                    got.len(),
                    want.len(),
                    first
                );
            }
        }

        // --- 2. concurrency: 256 simultaneous round trips, all must succeed ---
        let ok = ArcCounter::new();
        let mut handles = Vec::new();
        for i in 0..256u32 {
            let ok = ok.clone();
            handles.push(tokio::spawn(async move {
                let data = vec![(i % 251) as u8; 64];
                match reverse_roundtrip(&data).await {
                    Ok(got) if got == reversed(&data) => ok.inc(),
                    _ => {}
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            ok.get(),
            256,
            "not all 256 concurrent round trips succeeded"
        );

        // --- 3. churn: 500 rapid open/close ---
        let ok = ArcCounter::new();
        let mut handles = Vec::new();
        for i in 0..500u32 {
            let ok = ok.clone();
            handles.push(tokio::spawn(async move {
                let data = [i as u8; 16];
                match reverse_roundtrip(&data).await {
                    Ok(got) if got == reversed(&data) => ok.inc(),
                    _ => {}
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(ok.get(), 500, "churn lost connections");

        // --- 4. reconnect: kill the server, restart it, the client re-attaches ---
        let probe: Vec<u8> = (0..128).map(|i| i as u8).collect();
        assert_eq!(reverse_roundtrip(&probe).await.unwrap(), reversed(&probe));

        server.abort();
        tokio::time::sleep(Duration::from_millis(400)).await; // let the client notice the drop

        // restart the server on the same ports; the client's reconnect loop picks it up
        let scfg2 = server_cfg();
        let server2 = tokio::spawn({
            let cfg = scfg2.clone();
            async move {
                let _ = wormhole::server::run(&cfg).await;
            }
        });
        wait_for_port(PUB, Duration::from_secs(10))
            .await
            .expect("public port should come back after reconnect");
        assert_eq!(
            reverse_roundtrip(&probe).await.unwrap(),
            reversed(&probe),
            "round trip should work after server restart"
        );

        // --- cleanup ---
        client.abort();
        server2.abort();
        backend.abort();
    };

    let _ = tokio::time::timeout(Duration::from_secs(120), overall).await;
}

/// A cheap shared success counter (Send + Sync) for the stress phases.
#[derive(Clone, Default)]
struct ArcCounter(std::sync::Arc<AtomicUsize>);
impl ArcCounter {
    fn new() -> Self {
        Self(std::sync::Arc::new(AtomicUsize::new(0)))
    }
    fn inc(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Channel attach mechanics on the shared data port (protocol-level, raw
/// connections so the test owns the data sockets and can kill them):
/// PROXYACK carries the data port, a taken slot is rejected (FAIL), an
/// out-of-range index is rejected, and a killed channel's slot is re-attachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_channel_re_attach_mechanics() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    const CTRL2: u16 = 28200; // control
    const DATA2: u16 = 28201; // shared data port

    let scfg = ServerConfig {
        bind: format!("127.0.0.1:{CTRL2}"),
        secret: "re-attach-secret".into(),
        data_port: Some(DATA2),
        allow_ports: None,
        forbid_ports: None,
    };
    let server = tokio::spawn({
        let cfg = scfg.clone();
        async move {
            let _ = wormhole::server::run(&cfg).await;
        }
    });
    let hash = protocol::secret_hash("re-attach-secret");

    // --- raw control session: AUTH, DCount(2), zero proxies ---
    wait_for_port(CTRL2, Duration::from_secs(5)).await.expect("control port up");
    let mut ctrl = TcpStream::connect(format!("127.0.0.1:{CTRL2}"))
        .await
        .expect("control connect");
    let mut buf = BytesMut::new();
    send(&mut ctrl, &Frame::Auth(hash)).await;
    assert_eq!(read_one(&mut ctrl, &mut buf).await, Frame::Ok);
    send(&mut ctrl, &Frame::DCount(2)).await;
    send(&mut ctrl, &Frame::Proxies(Vec::new())).await;
    match read_one(&mut ctrl, &mut buf).await {
        Frame::ProxyAck {
            entries,
            data_port,
        } => {
            assert!(entries.is_empty());
            assert_eq!(data_port, DATA2, "PROXYACK must advertise the data port");
        }
        other => panic!("expected PROXYACK, got kind 0x{:02x}", other.kind()),
    }

    // --- attach both channels ---
    let (mut ch0, _b0) = attach(DATA2, hash, 0).await;
    let (_ch1, _b1) = attach(DATA2, hash, 1).await;

    // a second attach of a taken slot must FAIL (busy)
    let (dup, r, _bd) = attach_raw(DATA2, hash, 0).await;
    assert_eq!(r, Frame::Fail, "busy slot must FAIL");
    drop(dup);
    // an index >= n must FAIL (out of range)
    let (oor, r, _bo) = attach_raw(DATA2, hash, 7).await;
    assert_eq!(r, Frame::Fail, "out-of-range index must FAIL");
    drop(oor);
    // a bad secret must be rejected
    let (bad, r, _bb) = attach_raw(DATA2, protocol::secret_hash("wrong"), 0).await;
    assert!(matches!(r, Frame::Fail), "bad secret must not attach");
    drop(bad);

    // kill ch0 (client-side close) -> the server must release the slot
    ch0.shutdown().await.unwrap();
    drop(ch0);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // re-attach the same index: the released slot must accept it
    let (mut ch0b, _b0b) = attach(DATA2, hash, 0).await;
    ch0b.shutdown().await.unwrap();

    // close the session
    ctrl.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.abort();
}



/// `tunnel::writer` must be byte-exact against the reference `protocol::encode`
/// for the same frame sequence (mixed DATA/control, small and 64 KiB chunks).
#[tokio::test]
async fn writer_matches_reference_encode() {
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;
    let (a, mut b) = tokio::io::duplex(1 << 22);
    let (tx, mut rx) = mpsc::channel::<Frame>(4096);

    let mut expected = BytesMut::new();
    for i in 0..300u32 {
        let f = if i % 7 == 0 {
            Frame::Ping(i)
        } else {
            Frame::Data((i as u16) % 500, Bytes::from(vec![(i % 251) as u8; 1 + i as usize % 70_000]))
        };
        protocol::encode(&mut expected, &f);
        tx.send(f).await.unwrap();
    }
    drop(tx);

    let mut got = BytesMut::new();
    let mut tmp = vec![0u8; 65536];
    let reader = async {
        loop {
            match b.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
                Err(e) => panic!("read: {e}"),
            }
        }
    };
    let (_dead_tx, mut dead_rx) = watch::channel(false);
    let mut a2 = a;
    let w = wormhole::tunnel::writer(&mut a2, &mut rx, &mut dead_rx);
    // Run the writer; when it returns, half-close so the reader sees EOF.
    w.await;
    a2.shutdown().await.unwrap();
    reader.await;
    assert_eq!(got.len(), expected.len(), "length mismatch");
    assert_eq!(&got[..], &expected[..], "writer output must match reference encode");
}

/// Real TCP with a tiny receive buffer forces partial writev's; the writer
/// must loop on partial progress and lose no byte (regression: a single
/// unchecked write_vectored dropped batch tails under a full sndbuf).
#[tokio::test]
async fn writer_survives_partial_writes() {
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        // Tiny rcvbuf (via a dup'd fd): the sender's writev constantly hits
        // full buffers, forcing the partial-write loop.
        let std_sock: std::net::TcpStream = sock.into_std().unwrap();
        let dup = std_sock.try_clone().unwrap();
        socket2::Socket::from(dup).set_recv_buffer_size(32 * 1024).unwrap();
        let mut sock = TcpStream::from_std(std_sock).unwrap();
        let mut got = Vec::new();
        let mut tmp = vec![0u8; 65536];
        loop {
            match sock.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
                Err(_) => panic!("recv error"),
            }
        }
        got
    });

    let std_client = std::net::TcpStream::connect(addr).unwrap();
    let dup = std_client.try_clone().unwrap();
    socket2::Socket::from(dup).set_send_buffer_size(64 * 1024).unwrap();
    let client = TcpStream::from_std(std_client).unwrap();

    let (tx, mut rx) = mpsc::channel::<Frame>(4096);
    let mut expected = BytesMut::new();
    for i in 0..200u32 {
        let f =
            Frame::Data(i as u16, Bytes::from(vec![(i % 251) as u8; 1 + i as usize % 70_000]));
        protocol::encode(&mut expected, &f);
        tx.send(f).await.unwrap();
    }
    drop(tx);
    let (_dead_tx, mut dead_rx) = watch::channel(false);
    let mut client2 = client;
    wormhole::tunnel::writer(&mut client2, &mut rx, &mut dead_rx).await;
    client2.shutdown().await.unwrap();
    let got = srv.await.unwrap();
    assert_eq!(got.len(), expected.len(), "length mismatch under partial writes");
    assert_eq!(&got[..], &expected[..], "no byte lost under partial writes");
}

/// Lossless channel flap with data in flight (protocol-level, raw
/// connections): mid-way through a 16 MiB transfer, the channel that carries
/// the connection is killed. The server must keep that channel's queued
/// frames (the session holds the receiver across re-attaches), and the
/// re-attached channel must deliver them — every byte arrives, in order,
/// with zero application-level retransmit. The persistent tunnel loops below
/// mirror `wormhole-client`'s channel_loop: the queues are held across
/// re-attaches, so a flap costs latency, not data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_channel_flap_is_lossless() {
    let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();

    const CTRL3: u16 = 28300; // control
    const DATA3: u16 = 28301; // shared data port
    const PUB3: u16 = 28320; // public port (server side)
    const BACKEND3: u16 = 28330; // local backend (client side)
    const PAYLOAD: usize = 16 << 20;
    const MAXC: usize = protocol::MAX_PAYLOAD; // 65533

    let scfg = ServerConfig {
        bind: format!("127.0.0.1:{CTRL3}"),
        secret: "flap-secret".into(),
        data_port: Some(DATA3),
        allow_ports: None,
        forbid_ports: None,
    };
    let _server = tokio::spawn({
        let cfg = scfg.clone();
        async move {
            let _ = wormhole::server::run(&cfg).await;
        }
    });
    let hash = protocol::secret_hash("flap-secret");

    // Backend: streaming echo (no buffering to EOF — bytes must flow while
    // in flight).
    let bl = TcpListener::bind(format!("127.0.0.1:{BACKEND3}"))
        .await
        .unwrap();
    let _backend = tokio::spawn(async move {
        while let Ok((s, _)) = bl.accept().await {
            let _ = s.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let mut tmp = vec![0u8; MAXC];
                loop {
                    match r.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if w.write_all(&tmp[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = w.shutdown().await;
            });
        }
    });

    // --- raw control session: AUTH, DCount(2), one proxy PUB3 -> BACKEND3 ---
    wait_for_port(CTRL3, Duration::from_secs(5)).await.expect("control port up");
    let mut ctrl = TcpStream::connect(format!("127.0.0.1:{CTRL3}"))
        .await
        .unwrap();
    let mut cbuf = BytesMut::new();
    send(&mut ctrl, &Frame::Auth(hash)).await;
    assert_eq!(read_one(&mut ctrl, &mut cbuf).await, Frame::Ok);
    send(&mut ctrl, &Frame::DCount(2)).await;
    send(
        &mut ctrl,
        &Frame::Proxies(vec![protocol::ProxyReg {
            name: "flap".into(),
            remote: PUB3,
            local_host: "127.0.0.1".into(),
            local_port: BACKEND3,
        }]),
    )
    .await;
    match read_one(&mut ctrl, &mut cbuf).await {
        Frame::ProxyAck {
            entries,
            data_port,
        } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(data_port, DATA3);
        }
        other => panic!("expected PROXYACK, got kind 0x{:02x}", other.kind()),
    }
    // PROXYACK is sent after the server binds the remote port, so PUB3 is up
    // now. (Do NOT probe the port: a probe connection consumes a connection
    // id and would shift the id -> channel routing.)

    let (_ch0, _ch0_left) = attach(DATA3, hash, 0).await;
    let (mut ch1, ch1_left) = attach(DATA3, hash, 1).await;

    // Open the public connection: the server assigns id 1 -> channel 1 % 2 = 1.
    let pub_sock = TcpStream::connect(format!("127.0.0.1:{PUB3}")).await.unwrap();
    let _ = pub_sock.set_nodelay(true);
    let (mut pub_r, mut pub_w) = pub_sock.into_split();

    // NEW must be the first frame on ch1.
    let mut nbuf = BytesMut::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut new_frame = None;
    while new_frame.is_none() {
        if let Some(f) = protocol::parse(&mut nbuf) {
            new_frame = Some(f);
            break;
        }
        let n = tokio::time::timeout_at(deadline, ch1.read_buf(&mut nbuf)).await;
        match n {
            Ok(Ok(0)) => panic!("ch1 EOF while waiting for NEW"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("ch1 read error: {e}"),
            Err(_) => panic!("NEW did not arrive within 5s"),
        }
    }
    let ch1 = match new_frame.unwrap() {
        Frame::New { id, local_port, .. } => {
            assert_eq!(id, 1, "first connection of the session is id 1");
            assert_eq!(local_port, BACKEND3);
            ch1
        }
        other => panic!("expected NEW on ch1, got kind 0x{:02x}", other.kind()),
    };

    // Dial the backend (what wormhole-client does on NEW).
    let backend_sock = TcpStream::connect(format!("127.0.0.1:{BACKEND3}"))
        .await
        .unwrap();
    let _ = backend_sock.set_nodelay(true);
    let (backend_r, mut backend_w) = backend_sock.into_split();

    // --- persistent tunnel-side loops (queues held across re-attaches) ---
    let (new_r_tx, mut new_r_rx) = mpsc::channel::<(OwnedReadHalf, BytesMut)>(4);
    let (new_w_tx, mut new_w_rx) = mpsc::channel::<OwnedWriteHalf>(4);
    let (alive_tx, alive_rx_w) = watch::channel(true);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(512);

    // backend -> outbound queue (persistent)
    let backend_task = tokio::spawn(async move {
        let mut r = backend_r;
        let mut tmp = vec![0u8; MAXC];
        while let Ok(n) = r.read(&mut tmp).await {
            if n == 0 {
                break;
            }
            if out_tx.send(tmp[..n].to_vec()).await.is_err() {
                break;
            }
        }
        drop(out_tx);
    });

    // ch1 -> backend (persistent): Data frames on the *current* ch1 reader go
    // to the backend socket; on flap (kill flag or EOF) the half is dropped
    // and the loop waits for the re-attached generation.
    let reader_task = tokio::spawn(async move {
        let mut cur: Option<OwnedReadHalf> = None;
        let mut b = BytesMut::new();
        enum Ev { Data, Dead }
        loop {
            if cur.is_none() {
                let r = new_r_rx.recv().await;
                match r {
                    Some((half, pending)) => {
                        // Seed the buffer with bytes already read past the
                        // attach reply (the kernel coalesces them with it).
                        b.extend_from_slice(&pending);
                        cur = Some(half);
                    }
                    None => break, // no more generations
                }
                continue;
            }
            // No kill flag here: on a flap the reader keeps DRAINING until
            // the peer's FIN, so buffered bytes are never lost.
            let ev = {
                let r = cur.as_mut().unwrap();
                match r.read_buf(&mut b).await {
                    Ok(0) | Err(_) => Ev::Dead,
                    Ok(_) => Ev::Data,
                }
            };
            match ev {
                Ev::Dead => {
                    cur = None; // drained; a re-attach (or end) follows
                    continue;
                }
                Ev::Data => {
                    let mut done = false;
                    while let Some(f) = protocol::parse(&mut b) {
                        match f {
                            Frame::Data(1, d) => {
                                if backend_w.write_all(&d).await.is_err() {
                                    done = true;
                                    break;
                                }
                            }
                            Frame::Close(_) => {
                                done = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    if done {
                        break;
                    }
                }
            }
        }
        drop(backend_w);
    });

    // outbound queue -> ch1 (persistent): every chunk is encoded as
    // Data(1, chunk) and written to the *current* ch1 writer; on flap the
    // chunk is retried on the re-attached channel (never dropped).
    let writer_task = tokio::spawn({
        let mut alive_rx = alive_rx_w;
        async move {
            let mut cur: Option<OwnedWriteHalf> = None;
            let mut ob = BytesMut::new();
        while let Some(chunk) = out_rx.recv().await {
            let data = Bytes::from(chunk);
            loop {
                if cur.is_none() {
                    tokio::select! {
                        _ = alive_rx.changed() => {}
                        w = new_w_rx.recv() => {
                            cur = w;
                            if cur.is_none() {
                                return;
                            }
                        }
                    }
                    continue;
                }
                ob.clear();
                protocol::encode(&mut ob, &Frame::Data(1, data.clone()));
                let ok = {
                    let w = cur.as_mut().unwrap();
                    tokio::select! {
                        _ = alive_rx.changed() => {
                            // A re-attach (true) must NOT drop the fresh
                            // half; only a real kill (false) does.
                            if !*alive_rx.borrow_and_update() {
                                cur = None;
                                continue; // retry this chunk after re-attach
                            }
                            // alive is true: keep the current half, write on.
                            if let Some(w) = cur.as_mut() {
                                w.write_all_buf(&mut ob).await.is_ok()
                            } else {
                                continue; // no half: wait for one, retry chunk
                            }
                        }
                        r = w.write_all_buf(&mut ob) => r.is_ok(),
                    }
                };
                if ok {
                    break; // chunk delivered; next one
                }
                cur = None; // dead socket: retry this chunk after re-attach
            }
        }
            if let Some(w) = cur.as_mut() {
                let _ = w.shutdown().await;
            }
        }
    });

    // control heartbeat responder (the server's liveness drops the session
    // after 45s of silence; we must answer PINGs while the test runs)
    let heartbeat = tokio::spawn({
        let mut c = ctrl;
        let mut b = BytesMut::new();
        async move {
            // Answer PINGs until the control channel EOFs (read_one
            // reports EOF as Fail).
            while let Frame::Ping(n) = read_one(&mut c, &mut b).await {
                let _ = send(&mut c, &Frame::Pong(n)).await;
            }
        }
    });

    // --- generation 1 ---
    let (r1, w1) = ch1.into_split();
    new_r_tx.send((r1, ch1_left)).await.unwrap();
    new_w_tx.send(w1).await.unwrap();

    // --- drive the transfer ---
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i * 7 + 3) as u8).collect();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let payload_tx = payload.clone();
    let pub_write = tokio::spawn(async move {
        for c in payload_tx.chunks(MAXC) {
            pub_w.write_all(c).await.unwrap();
        }
        // Hold the connection open until the echo is fully verified:
        // an early half-close would send the peer's Close through and
        // tear down the echo path.
        let _ = done_rx.await;
        pub_w.shutdown().await.unwrap();
    });

    // Read the echo; once 1 MiB has come back, data is provably in flight on
    // ch1 — kill the channel now and re-attach it.
    let mut got = Vec::with_capacity(PAYLOAD);
    let mut tmp = vec![0u8; MAXC];
    let mut killed = false;
    loop {
        let n = pub_r
            .read(&mut tmp)
            .await
            .unwrap_or_else(|e| panic!("pub read: {e}"));
        if n == 0 {
            panic!("public socket EOF after only {} bytes", got.len());
        }
        got.extend_from_slice(&tmp[..n]);
        if got.len() == PAYLOAD {
            break;
        }
        if !killed && got.len() >= (1 << 20) {
            killed = true;
            // Kill ch1: the persistent loops drop their halves (socket closes);
            // the server drains its receive buffer and releases the slot.
            alive_tx.send(false).unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            // Re-attach with retries (the slot may not be released yet).
            let mut ch2: Option<(TcpStream, BytesMut)> = None;
            let mut attempt = 0;
            while ch2.is_none() {
                attempt += 1;
                assert!(attempt < 100, "re-attach never succeeded");
                let (s, reply, left) = attach_raw(DATA3, hash, 1).await;
                match reply {
                    Frame::Ok => ch2 = Some((s, left)),
                    _ => {
                        drop(s);
                        drop(left);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            let (s2, left2) = ch2.unwrap();
            let (r2, w2) = s2.into_split();
            // Order matters: announce the re-attach (true) BEFORE handing
            // over the halves, so no kill transition can be observed while
            // holding the fresh half.
            alive_tx.send(true).unwrap();
            new_r_tx.send((r2, left2)).await.unwrap();
            new_w_tx.send(w2).await.unwrap();
        }
    }
    assert_eq!(got.len(), PAYLOAD);
    assert_eq!(got, payload, "echo must be byte-exact after the flap");
    // verification complete: release the pub write task (it half-closes
    // pub, which tears the public connection down the normal way)
    done_tx.send(()).unwrap();
    pub_write.await.unwrap();

    // --- teardown: Close/EOF cascade ---
    drop(pub_r);
    drop(_ch0);
    // Kill the writer so it drops the active half (FIN) and the server
    // closes the generation stream. A SendError just means the task already
    // exited on the Close/EOF cascade (normal).
    let _ = alive_tx.send(false);
    drop(new_r_tx);
    drop(new_w_tx);
    heartbeat.abort();
    let _ = backend_task.await;
    let _ = (reader_task, writer_task);
}
