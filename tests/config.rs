//! Unit tests for config parsing, proxy expansion, port policy, and the
//! server/client cross-validation.

use std::collections::HashMap;

use serde::Deserialize;
use wormhole::config::{
    ClientConfig, PortMapping, PortPolicy, ProxySpec, ServerConfig, validate_pair,
};

fn spec(remote: PortPolicy) -> ProxySpec {
    ProxySpec {
        remote,
        local: None,
    }
}

fn srv(data_port: Option<u16>) -> ServerConfig {
    ServerConfig {
        bind: "0.0.0.0:1400".into(),
        secret: "s".into(),
        data_port,
        allow_ports: None,
        forbid_ports: None,
    }
}

#[test]
fn expand_single_defaults_to_localhost_remote() {
    let m = spec(PortPolicy::Num(1401)).expand().unwrap();
    assert_eq!(
        m,
        vec![PortMapping {
            remote: 1401,
            local_host: "127.0.0.1".into(),
            local_port: 1401,
        }]
    );
}

#[test]
fn expand_range_maps_positionally() {
    let m = spec(PortPolicy::Str("1402-1404".into())).expand().unwrap();
    assert_eq!(
        m,
        vec![
            PortMapping {
                remote: 1402,
                local_host: "127.0.0.1".into(),
                local_port: 1402
            },
            PortMapping {
                remote: 1403,
                local_host: "127.0.0.1".into(),
                local_port: 1403
            },
            PortMapping {
                remote: 1404,
                local_host: "127.0.0.1".into(),
                local_port: 1404
            }
        ]
    );
}

#[test]
fn expand_explicit_local_override() {
    let sp = ProxySpec {
        remote: PortPolicy::Num(1500),
        local: Some(wormhole::config::LocalSpec::Str("10.0.0.5:5432".into())),
    };
    let m = sp.expand().unwrap();
    assert_eq!(
        m,
        vec![PortMapping {
            remote: 1500,
            local_host: "10.0.0.5".into(),
            local_port: 5432
        }]
    );
}

#[test]
fn expand_bare_local_port_defaults_to_localhost() {
    let sp = ProxySpec {
        remote: PortPolicy::Num(1500),
        local: Some(wormhole::config::LocalSpec::Num(5432)),
    };
    let m = sp.expand().unwrap();
    assert_eq!(m[0].local_host, "127.0.0.1");
    assert_eq!(m[0].local_port, 5432);
}

#[test]
fn expand_mismatched_lengths_is_error() {
    let sp = ProxySpec {
        remote: PortPolicy::Str("1402-1403".into()), // 2 remotes
        local: Some(wormhole::config::LocalSpec::Num(5432)), // 1 local
    };
    let e = sp.expand().unwrap_err();
    assert!(e.contains("must map positionally"), "got: {e}");
}

/// F6: overlong hosts/names are rejected (protocol stores them in a u8 length).
#[test]
fn expand_rejects_overlong_host() {
    let sp = ProxySpec {
        remote: PortPolicy::Num(1401),
        local: Some(wormhole::config::LocalSpec::Str(format!(
            "{}:1401",
            "b".repeat(300)
        ))),
    };
    let e = sp.expand().unwrap_err();
    assert!(e.contains("protocol limit is 255"), "got: {e}");
}

#[test]
fn port_policy_forbid() {
    let mut s = srv(None);
    s.forbid_ports = Some(PortPolicy::Vec(vec![wormhole::config::PortItem::Num(22), wormhole::config::PortItem::Num(3306)]));
    assert!(!s.port_allowed(22));
    assert!(!s.port_allowed(3306));
    assert!(s.port_allowed(2222));
}

#[test]
fn port_policy_allow() {
    let mut s = srv(None);
    s.allow_ports = Some(PortPolicy::Str("1401-1402".into()));
    assert!(s.port_allowed(1401));
    assert!(s.port_allowed(1402));
    assert!(!s.port_allowed(1500));
}

#[test]
fn port_policy_forbid_beats_allow() {
    let mut s = srv(None);
    s.allow_ports = Some(PortPolicy::Vec(vec![wormhole::config::PortItem::Num(1401), wormhole::config::PortItem::Num(1402)]));
    s.forbid_ports = Some(PortPolicy::Num(1401));
    assert!(!s.port_allowed(1401)); // forbidden
    assert!(s.port_allowed(1402)); // allowed
    assert!(!s.port_allowed(1500)); // not in allow
}

#[test]
fn port_policy_mixed_list_parses_frp_style() {
    // frp-style allow_ports: a list mixing bare ports and "a-b" ranges.
    #[derive(Deserialize)]
    struct W {
        t: PortPolicy,
    }
    let W { t } = toml::from_str::<W>(r#"t = [2222, "1500-1503"]"#).unwrap();
    assert_eq!(
        t.resolve().unwrap(),
        vec![2222, 1500, 1501, 1502, 1503]
    );
}

#[test]
fn data_port_default_and_explicit() {
    // default: control port + 1
    let (_, p) = srv(None).resolve().unwrap();
    assert_eq!(p, 1401);
    // explicit
    let (_, p) = srv(Some(1500)).resolve().unwrap();
    assert_eq!(p, 1500);
    // must differ from the control port
    assert!(srv(Some(1400)).resolve().is_err());
    // zero is invalid
    assert!(srv(Some(0)).resolve().is_err());
}

#[test]
fn client_channels_validation() {
    let ok = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: Some(16),
    };
    assert_eq!(ok.resolve().unwrap().2, 16);
    let def = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: None,
    };
    assert_eq!(def.resolve().unwrap().2, 8); // default
    let zero = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: Some(0),
    };
    assert!(zero.resolve().is_err());
    let too_many = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: Some(65),
    };
    assert!(too_many.resolve().is_err());
}

#[test]
fn validate_pair_agrees() {
    let s = srv(Some(1500));
    let c = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: Some(2),
    };
    let mut svcs = HashMap::new();
    svcs.insert("rs".into(), spec(PortPolicy::Num(1401)));
    assert!(validate_pair(&s, &c, &svcs).is_empty());
}

#[test]
fn validate_pair_detects_secret_mismatch() {
    let s = srv(None);
    let c = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "OTHER".into(),
        channels: None,
    };
    let mut svcs = HashMap::new();
    svcs.insert("rs".into(), spec(PortPolicy::Num(1500)));
    let problems = validate_pair(&s, &c, &svcs);
    assert!(
        problems.iter().any(|p| p.contains("secret")),
        "got: {problems:?}"
    );
}

#[test]
fn validate_pair_detects_policy_denied_port() {
    let mut s = srv(None);
    s.allow_ports = Some(PortPolicy::Vec(vec![wormhole::config::PortItem::Num(1500)]));
    let c = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: None,
    };
    let mut svcs = HashMap::new();
    svcs.insert("bad".into(), spec(PortPolicy::Num(9999))); // not in allow
    let problems = validate_pair(&s, &c, &svcs);
    assert!(
        problems.iter().any(|p| p.contains("9999")),
        "got: {problems:?}"
    );
}

#[test]
fn validate_pair_flags_data_port_collision_and_duplicates() {
    let s = srv(Some(1500)); // data port 1500
    let c = ClientConfig {
        server: "127.0.0.1:1400".into(),
        secret: "s".into(),
        channels: None,
    };
    let mut svcs = HashMap::new();
    svcs.insert("bad".into(), spec(PortPolicy::Num(1500))); // collides with data
    svcs.insert("a".into(), spec(PortPolicy::Num(1401)));
    svcs.insert("b".into(), spec(PortPolicy::Num(1401))); // duplicate of a
    let problems = validate_pair(&s, &c, &svcs);
    assert!(
        problems.iter().any(|p| p.contains("collides")),
        "should flag the data-port collision; got: {problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("1401")),
        "should flag the duplicate public port; got: {problems:?}"
    );
}

/// Full `Config::load` from a file: a valid client config parses, and an
/// overlong service name (F6) is rejected.
#[test]
fn load_client_config_and_reject_long_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.toml");
    std::fs::write(
        &path,
        r##"[client]
server = "127.0.0.1:1400"
secret = "s"
channels = 2

[services.rs]
remote = 1401
"##,
    )
    .unwrap();
    let cfg = wormhole::config::Config::load(&path).expect("valid client config should load");
    assert!(cfg.client.is_some());
    assert_eq!(cfg.services.len(), 1);

    // overlong service name (F6)
    let long = "a".repeat(300);
    let path2 = dir.path().join("client2.toml");
    std::fs::write(
        &path2,
        format!(
            r##"[client]
server = "127.0.0.1:1400"
secret = "s"
[services.{long}]
remote = 1401
"##
        ),
    )
    .unwrap();
    let e = wormhole::config::Config::load(&path2).unwrap_err();
    assert!(e.contains("protocol limit is 255"), "got: {e}");
}

/// The removed v3 geometry keys (data_bind/data_channels) must be rejected
/// loudly, not silently ignored.
#[test]
fn load_rejects_removed_geometry_keys() {
    let dir = tempfile::tempdir().unwrap();
    for (side, table) in [("client", "[client]\nserver = \"127.0.0.1:1400\""), ("server", "[server]\nbind = \"0.0.0.0:1400\"")] {
        let path = dir.path().join(format!("{side}.toml"));
        std::fs::write(&path, format!("{table}\nsecret = \"s\"\ndata_bind = 1500\n")).unwrap();
        let e = wormhole::config::Config::load(&path).unwrap_err();
        assert!(e.contains("data_bind"), "got: {e}");
        let path2 = dir.path().join(format!("{side}_ch.toml"));
        std::fs::write(&path2, format!("{table}\nsecret = \"s\"\ndata_channels = 8\n")).unwrap();
        let e = wormhole::config::Config::load(&path2).unwrap_err();
        assert!(e.contains("data_channels"), "got: {e}");
    }
}
