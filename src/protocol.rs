//! Wire protocol for wormhole.
//!
//! A connection between server and client is either a **control channel** or a
//! **data channel**. Both speak the same frame language:
//!
//!   [type:u8][len:u16 BE][payload:len]
//!
//! Control channel (1):
//!   AUTH/OK/FAIL  -> shared-secret handshake (sha256 of the secret)
//!   DCOUNT        -> client tells the server how many data channels it will open
//!   PROXIES       -> client declares the public->local port mappings it wants exposed
//!   PROXYACK      -> server reports per-proxy bind results (policy-checked) + the
//!                    data port; also = "ready"
//!   NEW           -> a connection arrived on a bound public port; carry its local addr
//!   CLOSE         -> a connection is closing (rides the data channel, in id order)
//!   PING/PONG     -> heartbeat (liveness)
//!
//! Data channels (N): DATA both ways. All N attach to ONE shared port; a channel
//! connection authenticates (AUTH) then names itself (CHIDX). Connection `id`
//! rides data channel `id % N`, so total data bandwidth scales with the number
//! of data channels and a slow consumer on one channel never stalls the others.
//!
//! The server is a **stateless generic forwarder**: it never learns the service
//! list from its own config. The client declares the proxies at connect time
//! (PROXIES); the server binds them on demand (subject to `allow_ports` /
//! `forbid_ports`) and tears them down when the client disconnects.
//!
//! Framing is currently cleartext. End-to-end encryption is on the roadmap; the
//! 5-byte header is left in the clear for framing and would wrap the payload.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};

// frame types
pub const AUTH: u8 = 0x01;
pub const OK: u8 = 0x02;
pub const FAIL: u8 = 0x03;
pub const DCOUNT: u8 = 0x04; // client -> server: number of data channels
pub const NEW: u8 = 0x05; // server -> client: a connection arrived; carry its local addr
pub const CLOSE: u8 = 0x06; // either: a connection is closing (data channel, in id order)
pub const DATA: u8 = 0x07; // either: payload for a connection (data channel)
pub const PROXIES: u8 = 0x08; // client -> server: the public->local mappings to expose
pub const PING: u8 = 0x09; // either: heartbeat, payload = nonce(u32)
pub const PONG: u8 = 0x0a; // either: heartbeat reply, payload = nonce(u32)
pub const CHIDX: u8 = 0x0b; // client -> server: which data channel this connection is (after AUTH)
pub const PROXYACK: u8 = 0x0c; // server -> client: per-proxy bind results + data port (= ready)

/// max DATA *chunk* (the bytes after the 2-byte id prefix). A Data frame's
/// on-wire payload is `id(2) + chunk`, which must fit the u16 length field:
/// `2 + MAX_PAYLOAD <= u16::MAX`. Capping the chunk at `u16::MAX - 2` keeps the
/// frame well-formed; a larger chunk would wrap the length field and desync the
/// whole data channel.
pub const MAX_PAYLOAD: usize = u16::MAX as usize - 2; // 65533

/// Max bytes gathered into one socket write by the per-connection pipe
/// (a burst of payloads is shared across one writev; a lone payload
/// writes immediately).
pub const PIPE_BATCH: usize = 256 * 1024;

/// Header size: type + len.
pub const HDR: usize = 3;

/// One public->local mapping the client wants exposed (a unit of `PROXIES`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyReg {
    /// human label (for logs); routing does not depend on it
    pub name: String,
    /// the public port the server binds
    pub remote: u16,
    /// the local host the client connects to
    pub local_host: String,
    /// the local port the client connects to
    pub local_port: u16,
}

/// Per-proxy registration result (a unit of `PROXYACK`), echoing the order
/// of the client's `PROXIES`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyAckEntry {
    /// the proxy name, as declared by the client
    pub name: String,
    /// 0 = bound, 1 = denied by the server's port policy, 2 = not bound
    /// (duplicate public port or bind failure)
    pub status: u8,
}

#[derive(Debug, PartialEq)]
pub enum Frame {
    /// AUTH: 32-byte sha256(secret).
    Auth([u8; 32]),
    /// OK / FAIL: auth result (empty payload).
    Ok,
    Fail,
    /// DCOUNT: number of data channels the client will open.
    DCount(u8),
    /// PROXIES: the mappings the client wants exposed.
    Proxies(Vec<ProxyReg>),
    /// PROXYACK: per-proxy registration results + the data port the client
    /// dials for all its channels (also signals "ready: open the data channels").
    ProxyAck {
        entries: Vec<ProxyAckEntry>,
        data_port: u16,
    },
    /// CHIDX: this data connection is channel `i` of the session (sent right
    /// after AUTH on a data-channel connection).
    ChIdx(u8),
    /// NEW: connection `id` wants local_host:local_port.
    New {
        id: u16,
        local_host: String,
        local_port: u16,
    },
    /// CLOSE: connection `id` is closing.
    Close(u16),
    /// DATA: `payload` for connection `id`. The id rides the frame (on the
    /// wire it is prefixed inside the payload); keeping it out of the bytes
    /// means the hot path never copies a data chunk to prepend it.
    Data(u16, Bytes),
    /// PING / PONG: heartbeat with `nonce`.
    Ping(u32),
    Pong(u32),
}

impl Frame {
    /// type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Frame::Auth(_) => AUTH,
            Frame::Ok => OK,
            Frame::Fail => FAIL,
            Frame::DCount(_) => DCOUNT,
            Frame::Proxies(_) => PROXIES,
            Frame::ProxyAck { .. } => PROXYACK,
            Frame::ChIdx(_) => CHIDX,
            Frame::New { .. } => NEW,
            Frame::Close(_) => CLOSE,
            Frame::Data(..) => DATA,
            Frame::Ping(_) => PING,
            Frame::Pong(_) => PONG,
        }
    }
}

/// Encode `frame` into `payload` (just the payload bytes, no header).
pub fn encode_payload(buf: &mut BytesMut, frame: &Frame) {
    match frame {
        Frame::Auth(h) => buf.put_slice(h),
        Frame::Ok | Frame::Fail => {}
        Frame::DCount(n) => buf.put_u8(*n),
        Frame::Proxies(regs) => {
            buf.put_u16(regs.len() as u16);
            for r in regs {
                let n = r.name.as_bytes();
                buf.put_u8(n.len() as u8);
                buf.put_slice(n);
                buf.put_u16(r.remote);
                let lh = r.local_host.as_bytes();
                buf.put_u8(lh.len() as u8);
                buf.put_slice(lh);
                buf.put_u16(r.local_port);
            }
        }
        Frame::ProxyAck {
            entries,
            data_port,
        } => {
            for e in entries {
                let n = e.name.as_bytes();
                buf.put_u8(n.len() as u8);
                buf.put_slice(n);
                buf.put_u8(e.status);
            }
            buf.put_u16(*data_port);
        }
        Frame::ChIdx(i) => buf.put_u8(*i),
        Frame::New {
            id,
            local_host,
            local_port,
        } => {
            let lh = local_host.as_bytes();
            buf.put_u16(*id);
            buf.put_u8(lh.len() as u8);
            buf.put_slice(lh);
            buf.put_u16(*local_port);
        }
        Frame::Close(id) => buf.put_u16(*id),
        Frame::Data(id, p) => {
            buf.put_u16(*id);
            buf.put_slice(p);
        },
        Frame::Ping(n) | Frame::Pong(n) => buf.put_u32(*n),
    }
}

/// Append the full frame (header + payload) to `buf`.
pub fn encode(buf: &mut BytesMut, frame: &Frame) {
    let mut payload = BytesMut::new();
    encode_payload(&mut payload, frame);
    // The length field is u16; an oversized payload would silently wrap and
    // desync the peer. Fail loud (debug) instead of emitting a corrupt frame.
    debug_assert!(
        payload.len() <= u16::MAX as usize,
        "frame payload {}B exceeds u16 length field",
        payload.len()
    );
    buf.put_u8(frame.kind());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(&payload);
}

/// Parse one frame from the front of `buf`, consuming it. Returns None until a
/// full frame is present.
///
/// DATA is a zero-copy fast path: `split_to` gives a buffer with
/// len == capacity, so `freeze()` + `slice(2..)` share the allocation instead
/// of copying every data byte.
pub fn parse(buf: &mut BytesMut) -> Option<Frame> {
    if buf.len() < HDR {
        return None;
    }
    let t = buf[0];
    let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if buf.len() < HDR + len {
        return None;
    }
    buf.advance(HDR);
    let payload = buf.split_to(len);
    if t == DATA && len >= 2 {
        let id = u16::from_be_bytes([payload[0], payload[1]]);
        return Some(Frame::Data(id, payload.freeze().slice(2..)));
    }
    Some(decode(t, &payload))
}

/// Decode a payload into a Frame. Malformed payloads (wrong type or wrong
/// length) yield `Frame::Fail` rather than panicking, so a desynced stream
/// degrades gracefully instead of crashing the process.
fn decode(t: u8, p: &[u8]) -> Frame {
    match t {
        AUTH if p.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(p);
            Frame::Auth(h)
        }
        OK => Frame::Ok,
        FAIL => Frame::Fail,
        DCOUNT if p.len() == 1 => Frame::DCount(p[0]),
        PROXYACK => match decode_proxyack(p) {
            Some((entries, data_port)) => Frame::ProxyAck {
                entries,
                data_port,
            },
            None => {
                core::hint::cold_path();
                Frame::Fail
            }
        },
        CHIDX if p.len() == 1 => Frame::ChIdx(p[0]),
        CLOSE if p.len() == 2 => Frame::Close(u16::from_be_bytes([p[0], p[1]])),
        PING if p.len() == 4 => Frame::Ping(u32::from_be_bytes([p[0], p[1], p[2], p[3]])),
        PONG if p.len() == 4 => Frame::Pong(u32::from_be_bytes([p[0], p[1], p[2], p[3]])),
        NEW => decode_new(p),
        PROXIES => decode_proxies(p),
        _ => {
            // unknown type or malformed -> treat as terminal. Hot path: this
            // arm is expected to be cold, tell the branch predictor so.
            core::hint::cold_path();
            Frame::Fail
        }
    }
}

/// PROXYACK payload: repeated [name_len:u8][name][status:u8], then a trailing
/// [data_port:u16] (the port the client dials for all data channels). Zero
/// proxies is valid (the payload is just the 2-byte data port). Returns None
/// if an entry is truncated (the caller degrades to `Fail`).
fn decode_proxyack(p: &[u8]) -> Option<(Vec<ProxyAckEntry>, u16)> {
    if p.len() < 2 {
        return None;
    }
    let data_port = u16::from_be_bytes([p[p.len() - 2], p[p.len() - 1]]);
    let body = &p[..p.len() - 2];
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let nlen = *body.get(i)? as usize;
        let start = i + 1;
        let end = start + nlen;
        let name = body.get(start..end)?;
        let status = *body.get(end)?;
        out.push(ProxyAckEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            status,
        });
        i = end + 1;
    }
    Some((out, data_port))
}

/// NEW payload: [id:u16][lh_len:u8][local_host][local_port:u16].
fn decode_new(p: &[u8]) -> Frame {
    if p.len() < 3 {
        return Frame::Fail;
    }
    let id = u16::from_be_bytes([p[0], p[1]]);
    let lh_len = p[2] as usize;
    let end = 3 + lh_len + 2;
    if p.len() < end {
        return Frame::Fail;
    }
    let local_host = String::from_utf8_lossy(&p[3..3 + lh_len]).to_string();
    let local_port = u16::from_be_bytes([p[3 + lh_len], p[4 + lh_len]]);
    Frame::New {
        id,
        local_host,
        local_port,
    }
}

/// PROXIES payload: [count:u16] (count × [name][remote:u16][local_host][local_port:u16]).
fn decode_proxies(p: &[u8]) -> Frame {
    if p.len() < 2 {
        return Frame::Fail;
    }
    let count = u16::from_be_bytes([p[0], p[1]]) as usize;
    let mut regs = Vec::with_capacity(count);
    let mut i = 2;
    for _ in 0..count {
        if i >= p.len() {
            return Frame::Fail;
        }
        let nlen = p[i] as usize;
        i += 1;
        if i + nlen + 2 > p.len() {
            return Frame::Fail;
        }
        let name = String::from_utf8_lossy(&p[i..i + nlen]).to_string();
        i += nlen;
        let remote = u16::from_be_bytes([p[i], p[i + 1]]);
        i += 2;
        if i >= p.len() {
            return Frame::Fail;
        }
        let lhlen = p[i] as usize;
        i += 1;
        if i + lhlen + 2 > p.len() {
            return Frame::Fail;
        }
        let local_host = String::from_utf8_lossy(&p[i..i + lhlen]).to_string();
        i += lhlen;
        let local_port = u16::from_be_bytes([p[i], p[i + 1]]);
        i += 2;
        regs.push(ProxyReg {
            name,
            remote,
            local_host,
            local_port,
        });
    }
    Frame::Proxies(regs)
}

/// sha256 of the shared secret (the base secret material).
pub fn secret_hash(secret: &str) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(secret.as_bytes());
    let out = d.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    h
}
