//! Unit tests for the wire protocol: encode/parse roundtrips, malformed-frame
//! safety (must degrade to `Fail`, never panic), and the MAX_PAYLOAD boundary.

use bytes::{BufMut, Bytes, BytesMut};
use std::assert_matches;
use wormhole::protocol::{self, Frame, HDR, MAX_PAYLOAD, ProxyAckEntry, ProxyReg};

fn roundtrip(f: &Frame) {
    let mut buf = BytesMut::new();
    protocol::encode(&mut buf, f);
    let mut b2 = buf.clone();
    let parsed = protocol::parse(&mut b2).expect("encoded frame should parse");
    assert_eq!(&parsed, f, "roundtrip mismatch");
    assert!(b2.is_empty(), "frame should fully consume the buffer");
}

#[test]
fn roundtrip_all_frame_types() {
    roundtrip(&Frame::Auth([7u8; 32]));
    roundtrip(&Frame::Ok);
    roundtrip(&Frame::Fail);
    roundtrip(&Frame::DCount(3));
    roundtrip(&Frame::ChIdx(0));
    roundtrip(&Frame::ChIdx(63));
    roundtrip(&Frame::ProxyAck {
        entries: vec![
            ProxyAckEntry {
                name: "rs".into(),
                status: 0,
            },
            ProxyAckEntry {
                name: "scan".into(),
                status: 1,
            },
            ProxyAckEntry {
                name: "x".into(),
                status: 2,
            },
        ],
        data_port: 1405,
    });
    roundtrip(&Frame::ProxyAck {
        entries: vec![],
        data_port: 1,
    });
    roundtrip(&Frame::New {
        id: 1,
        local_host: "127.0.0.1".into(),
        local_port: 8080,
    });
    roundtrip(&Frame::New {
        id: 65535,
        local_host: "10.0.0.5".into(),
        local_port: 1,
    });
    roundtrip(&Frame::Close(9));
    roundtrip(&Frame::Data(0x1234, Bytes::from_static(&[1, 2, 3, 4, 5])));
    roundtrip(&Frame::Data(7, Bytes::new())); // empty DATA (id only) is valid
    roundtrip(&Frame::Ping(0xdead_beef));
    roundtrip(&Frame::Pong(0x1234_5678));
    roundtrip(&Frame::Proxies(vec![
        ProxyReg {
            name: "rs".into(),
            remote: 1401,
            local_host: "127.0.0.1".into(),
            local_port: 1401,
        },
        ProxyReg {
            name: "scan".into(),
            remote: 1402,
            local_host: "10.0.0.5".into(),
            local_port: 5432,
        },
    ]));
    roundtrip(&Frame::Proxies(vec![]));
}

/// DATA payload bounds: a 2-byte payload (id + zero data bytes) is a valid
/// empty DATA frame; a 1-byte payload (no id prefix) is malformed -> `Fail`.
#[test]
fn data_frame_payload_bounds() {
    let f = Frame::Data(7, Bytes::new());
    let mut buf = BytesMut::new();
    protocol::encode(&mut buf, &f);
    let parsed = protocol::parse(&mut buf).expect("header present");
    assert_eq!(parsed, f, "2-byte DATA (id only) is a valid empty DATA frame");

    let mut buf = BytesMut::new();
    buf.put_u8(protocol::DATA);
    buf.put_u16(1);
    buf.put_slice(&[1]);
    assert_eq!(
        protocol::parse(&mut buf),
        Some(Frame::Fail),
        "1-byte DATA must be malformed"
    );
}

/// A DATA frame at the exact MAX_PAYLOAD boundary (payload == u16::MAX) must
/// encode and parse without wrapping the u16 length field.
#[test]
fn data_frame_at_max_payload() {
    let chunk: Vec<u8> = (0..MAX_PAYLOAD).map(|i| (i % 251) as u8).collect();
    let f = Frame::Data(0x1234, Bytes::from(chunk.clone()));

    let mut buf = BytesMut::new();
    protocol::encode(&mut buf, &f);
    assert_eq!(buf.len(), HDR + MAX_PAYLOAD + 2); // on-wire payload == u16::MAX

    let parsed = protocol::parse(&mut buf).expect("max DATA should parse");
    match parsed {
        Frame::Data(id, d) => {
            assert_eq!(id, 0x1234);
            assert_eq!(d.len(), MAX_PAYLOAD);
            assert_eq!(&d[..], &chunk[..]);
        }
        other => panic!("expected Data, got kind 0x{:02x}", other.kind()),
    }
}

#[test]
fn proxyack_entries_roundtrip_and_malformed() {
    roundtrip(&Frame::ProxyAck {
        entries: Vec::new(),
        data_port: 1401,
    }); // zero proxies is valid (payload = just the data port)

    // truncated entry (name_len overruns the entries body) must degrade to Fail
    let mut buf = BytesMut::new();
    buf.put_u8(0x0C); // PROXYACK
    buf.put_u16(3);
    buf.put_slice(&[0x03, b'a', b'b']);
    assert_matches!(protocol::parse(&mut buf), Some(Frame::Fail));
}

/// `parse` must return None (need more bytes) for a partial frame and must not
/// consume it.
#[test]
fn parse_returns_none_on_partial_frame() {
    let mut buf = BytesMut::new();
    buf.put_slice(&[protocol::DATA, 0x00, 0x05, 1, 2, 3]); // 3 of 5 payload bytes
    assert!(protocol::parse(&mut buf).is_none());
    assert_eq!(buf.len(), 6, "partial frame must not be consumed");
    // complete it
    buf.put_slice(&[4, 5]);
    assert!(protocol::parse(&mut buf).is_some());
}

/// A frame can be split across arbitrary read boundaries; the decoder must
/// reassemble it.
#[test]
fn parse_reassembles_across_reads() {
    let f = Frame::New {
        id: 7,
        local_host: "192.168.1.20".into(),
        local_port: 443,
    };
    let mut full = BytesMut::new();
    protocol::encode(&mut full, &f);
    // feed one byte at a time; `parse` consumes the frame once complete
    let mut buf = BytesMut::new();
    let mut parsed = None;
    for b in full.iter() {
        buf.put_u8(*b);
        if let Some(p) = protocol::parse(&mut buf) {
            parsed = Some(p);
            break;
        }
    }
    let parsed = parsed.expect("frame should parse once fully fed");
    assert_eq!(&parsed, &f);
    assert!(buf.is_empty());
}

/// Malformed payloads must decode to `Fail` (never panic): wrong lengths,
/// truncated sub-fields, and unknown frame types.
#[test]
fn malformed_frames_never_panic() {
    cases::run();
}

mod cases {
    use super::*;

    /// build a raw frame `[type][len][payload]` and assert it parses to Fail.
    fn expect_fail(t: u8, payload: &[u8]) {
        let mut buf = BytesMut::new();
        buf.put_u8(t);
        buf.put_u16(payload.len() as u16);
        buf.put_slice(payload);
        let parsed = protocol::parse(&mut buf).expect("header is well-formed");
        assert_eq!(
            parsed,
            Frame::Fail,
            "type 0x{t:02x} len {} must be Fail",
            payload.len()
        );
    }

    pub fn run() {
        expect_fail(protocol::AUTH, &[0u8; 5]); // AUTH needs 32
        expect_fail(protocol::AUTH, &[0u8; 33]); // AUTH needs exactly 32
        expect_fail(protocol::DCOUNT, &[]); // DCOUNT needs 1
        expect_fail(protocol::DCOUNT, &[1, 2]); // DCOUNT needs 1
        expect_fail(protocol::CLOSE, &[1]); // CLOSE needs 2
        // PROXYACK is entries + a trailing 2-byte data port
        expect_fail(protocol::PROXYACK, &[]); // needs the 2-byte data port
        expect_fail(protocol::PROXYACK, &[1]); // needs the 2-byte data port
        expect_fail(protocol::PROXYACK, &[3, 1, 2, 0, 0]); // name_len=3, truncated
        // ...but a well-formed 1-entry ack parses (regression guard)
        let mut buf = BytesMut::new();
        buf.put_u8(protocol::PROXYACK);
        buf.put_u16(5);
        buf.put_slice(&[1, b'x', 3, 0x12, 0x34]);
        let parsed = protocol::parse(&mut buf).expect("well-formed PROXYACK");
        assert_eq!(
            parsed,
            Frame::ProxyAck {
                entries: vec![ProxyAckEntry {
                    name: "x".into(),
                    status: 3
                }],
                data_port: 0x1234
            }
        );
        // CHIDX needs exactly 1 byte
        expect_fail(protocol::CHIDX, &[]);
        expect_fail(protocol::CHIDX, &[1, 2]);
        expect_fail(protocol::PING, &[1, 2, 3]); // PING needs 4
        expect_fail(protocol::DATA, &[1]); // DATA needs >=2
        // NEW truncated in various ways
        expect_fail(protocol::NEW, &[1, 2, 5]); // lh_len=5 but only 2 bytes left
        expect_fail(protocol::NEW, &[1, 2]); // too short
        // PROXIES with a count but not enough data
        expect_fail(protocol::PROXIES, &[0, 1, 0]); // count=1, one empty reg (missing fields)
        expect_fail(protocol::PROXIES, &[0, 1, 3, b'a', b'b', b'c', 0, 1, 2]); // truncated local host
        // unknown type
        expect_fail(0xff, &[0, 0, 0]);
    }
}

/// secret_hash is deterministic and 32 bytes.
#[test]
fn secret_hash_deterministic() {
    let a = protocol::secret_hash("hunter2");
    let b = protocol::secret_hash("hunter2");
    assert_eq!(a, b);
    assert_ne!(a, protocol::secret_hash("hunter3"));
}
