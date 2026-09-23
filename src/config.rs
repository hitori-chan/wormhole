//! Config parsing + validation.
//!
//! A config file has a `[server]` OR `[client]` section.
//!
//! **frp-style model (stateless server):** the server is a generic forwarder —
//! it binds its control + data-channel ports at startup and otherwise knows
//! nothing about the services. The *client* declares the proxies it wants
//! exposed via top-level `[services.NAME]` entries; each maps a **public**
//! port (`remote`, the one the server binds on demand) to a **local** address
//! (`local`, the one the client connects to). At connect time the client sends
//! this list to the server (`PROXIES`); the server binds the public ports
//! subject to its `allow_ports` / `forbid_ports` policy and tears them down
//! when the client disconnects.
//!
//! ```toml
//! # server.toml
//! [server]
//! bind = "0.0.0.0:1400"
//! secret = "..."
//! # data_port = 1405               # the ONE port all data channels attach to
//!                                   # (default: control port + 1; advertised to
//!                                   # the client at connect time)
//! # allow_ports = [1401, "1402-1404"]   # only these public ports may be exposed
//! # forbid_ports = [22, 3306]           # never these
//!
//! # client.toml
//! [client]
//! server = "public.example.com:1400"
//! secret = "..."
//! # channels = 8                   # parallel data channels (default 8, 1..64)
//!
//! [services.rs]
//! remote = 1401                # public port to expose (required)
//! local  = 1401                # local addr to connect (default: remote on 127.0.0.1)
//!
//! [services.scan]
//! remote = "1402-1404"         # a range -> 3 public ports
//! # local defaults to "1402-1404" on 127.0.0.1 (positionally)
//! ```
//!
//! Ports: the control channel uses the main `bind` (server) / `server` (client)
//! address. All N data channels share ONE port (`data_port`, default control
//! port + 1); the server advertises it in PROXYACK, so the client config never
//! states it. The two configs share nothing to agree on besides the secret.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

/// Default number of parallel data channels when not specified.
pub const DEFAULT_DATA_CHANNELS: u8 = 8;
/// Max data channels (the CHIDX payload is one byte; one `id % n` slot each).
pub const MAX_DATA_CHANNELS: u8 = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
    /// client-declared proxies. Ignored by the server (stateless); the client
    /// sends these to the server at connect time.
    #[serde(default)]
    pub services: HashMap<String, ProxySpec>,
}

/// SERVER side: control listener + secret + shared data port + public-port policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// control listener the client dials, e.g. "0.0.0.0:1400"
    pub bind: String,
    /// shared secret (its sha256 is exchanged; the raw secret never crosses the wire)
    pub secret: String,
    /// the single port all data channels attach to (default: control port + 1).
    /// Advertised to the client in PROXYACK — the client never has to set it.
    #[serde(default)]
    pub data_port: Option<u16>,
    /// if set, ONLY these public ports may be exposed by a client.
    #[serde(default)]
    pub allow_ports: Option<PortPolicy>,
    /// if set, these public ports may never be exposed by a client.
    #[serde(default)]
    pub forbid_ports: Option<PortPolicy>,
}

/// CLIENT side: server address + secret + channel count.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// server control address, e.g. "public.example.com:1400"
    pub server: String,
    /// shared secret (must match the server)
    pub secret: String,
    /// how many parallel data channels to open (default 8; 1..64).
    /// The data PORT is learned from the server at connect time, so there is
    /// nothing to agree on in config besides the secret.
    #[serde(default)]
    pub channels: Option<u8>,
}

/// A single public->local mapping, after range expansion. The unit the client
/// registers with the server and the unit `NEW` carries back.
#[derive(Debug, Clone, PartialEq)]
pub struct PortMapping {
    pub remote: u16,
    pub local_host: String,
    pub local_port: u16,
}

impl ServerConfig {
    /// Resolve the control address + the shared data port.
    pub fn resolve(&self) -> Result<(SocketAddr, u16), String> {
        let ctrl: SocketAddr = self
            .bind
            .parse()
            .map_err(|e| format!("bad server.bind {:?}: {e}", self.bind))?;
        let data = match self.data_port {
            Some(0) => return Err("server.data_port must be >= 1".into()),
            Some(p) if p == ctrl.port() => {
                return Err(format!(
                    "server.data_port {p} must differ from the control port"
                ))
            }
            Some(p) => p,
            None => {
                if ctrl.port() == u16::MAX {
                    return Err(
                        "control port is 65535; set server.data_port explicitly".into(),
                    );
                }
                ctrl.port() + 1
            }
        };
        Ok((ctrl, data))
    }

    /// Does the public-port policy permit `port` to be exposed?
    pub fn port_allowed(&self, port: u16) -> bool {
        if let Some(f) = &self.forbid_ports
            && let Ok(set) = f.resolve()
            && set.contains(&port)
        {
            return false;
        }
        if let Some(a) = &self.allow_ports
            && let Ok(set) = a.resolve()
        {
            return set.contains(&port);
        }
        true
    }
}

impl ClientConfig {
    /// Resolve the control (host, port) + the channel count. The host may be a
    /// hostname (resolved by the OS on connect).
    pub fn resolve(&self) -> Result<(String, u16, u8), String> {
        let (host, port) = parse_host_port(&self.server)
            .map_err(|e| format!("bad client.server {:?}: {e}", self.server))?;
        let n = match self.channels {
            None => DEFAULT_DATA_CHANNELS,
            Some(0) => return Err("client.channels must be >= 1".into()),
            Some(c) if c > MAX_DATA_CHANNELS => {
                return Err(format!(
                    "client.channels {c} exceeds the maximum {MAX_DATA_CHANNELS}"
                ))
            }
            Some(c) => c,
        };
        Ok((host, port, n))
    }
}

/// Split "host:port" into (host, port). Host may be a hostname or an IP.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("expected host:port, got {s:?}"))?;
    let port: u16 = port
        .trim()
        .parse()
        .map_err(|e| format!("bad port {port:?}: {e}"))?;
    if host.trim().is_empty() {
        return Err("empty host".into());
    }
    Ok((host.trim().to_string(), port))
}

/// A set of ports: a single number, a "a-b" range, or a list mixing both
/// (frp-style `allow_ports` / `forbid_ports`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortPolicy {
    Num(u16),
    Str(String),
    Vec(Vec<PortItem>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortItem {
    Num(u16),
    Str(String),
}

impl PortPolicy {
    /// Expand to the concrete, ordered port list (ranges expanded).
    pub fn resolve(&self) -> Result<Vec<u16>, String> {
        match self {
            PortPolicy::Num(p) => Ok(vec![*p]),
            PortPolicy::Str(s) => parse_port_range(s),
            PortPolicy::Vec(v) if !v.is_empty() => v
                .iter()
                .map(|i| match i {
                    PortItem::Num(p) => Ok(vec![*p]),
                    PortItem::Str(s) => parse_port_range(s),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|parts| parts.concat()),
            PortPolicy::Vec(_) => Err("empty port list".into()),
        }
    }
}

/// Parse "a", "a-b" (inclusive), into a port list.
fn parse_port_range(s: &str) -> Result<Vec<u16>, String> {
    let t = s.trim();
    if let Some((a, b)) = t.split_once('-') {
        let a: u16 = a
            .trim()
            .parse()
            .map_err(|e| format!("bad port {a:?}: {e}"))?;
        let b: u16 = b
            .trim()
            .parse()
            .map_err(|e| format!("bad port {b:?}: {e}"))?;
        if a > b {
            return Err(format!("range {a}-{b} is inverted"));
        }
        Ok((a..=b).collect())
    } else {
        let p: u16 = t.parse().map_err(|e| format!("bad port {t:?}: {e}"))?;
        Ok(vec![p])
    }
}

/// A local address: a port, a "host:port", or a list of either.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LocalSpec {
    Num(u16),
    Str(String),
    Vec(Vec<LocalItem>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LocalItem {
    Num(u16),
    Str(String),
}

impl LocalSpec {
    /// Expand to (host, port) pairs. Bare ports use `default_host`.
    fn resolve(&self, default_host: &str) -> Result<Vec<(String, u16)>, String> {
        match self {
            LocalSpec::Num(p) => Ok(vec![(default_host.to_string(), *p)]),
            LocalSpec::Str(s) => parse_local_str(s, default_host),
            LocalSpec::Vec(v) if !v.is_empty() => v
                .iter()
                .map(|i| match i {
                    LocalItem::Num(p) => Ok((default_host.to_string(), *p)),
                    LocalItem::Str(s) => parse_local_item(s, default_host),
                })
                .collect(),
            LocalSpec::Vec(_) => Err("empty local list".into()),
        }
    }
}

/// "a-b" (range, default host) | "host:port" | "port" -> (host, port) pairs.
fn parse_local_str(s: &str, default_host: &str) -> Result<Vec<(String, u16)>, String> {
    let t = s.trim();
    if t.contains('-') {
        return parse_port_range(t).map(|ports| {
            ports
                .into_iter()
                .map(|p| (default_host.to_string(), p))
                .collect()
        });
    }
    Ok(vec![parse_local_item(t, default_host)?])
}

/// "host:port" | "port" -> (host, port).
fn parse_local_item(s: &str, default_host: &str) -> Result<(String, u16), String> {
    let t = s.trim();
    match t.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .trim()
                .parse()
                .map_err(|e| format!("bad port {port:?}: {e}"))?;
            if host.trim().is_empty() {
                return Err("empty host in local addr".into());
            }
            Ok((host.trim().to_string(), port))
        }
        None => {
            let port: u16 = t
                .parse()
                .map_err(|e| format!("bad local port {t:?}: {e}"))?;
            Ok((default_host.to_string(), port))
        }
    }
}

/// One `[services.NAME]` entry: the public port(s) to expose + the local
/// address(es) to connect (positionally).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySpec {
    /// public port(s) the SERVER binds. Required. Single or "a-b" or [..].
    pub remote: PortPolicy,
    /// local address(es) the CLIENT connects to. A bare port means
    /// 127.0.0.1; "host:port" carries its own host. Default: `remote` on
    /// 127.0.0.1.
    #[serde(default)]
    pub local: Option<LocalSpec>,
}

impl ProxySpec {
    /// Expand to concrete (remote, local_host, local_port) tuples.
    pub fn expand(&self) -> Result<Vec<PortMapping>, String> {
        let remotes = self.remote.resolve()?;
        let default_host = "127.0.0.1";
        let locals: Vec<(String, u16)> = match &self.local {
            None => remotes
                .iter()
                .map(|r| (default_host.to_string(), *r))
                .collect(),
            Some(l) => l.resolve(default_host)?,
        };
        for (host, _) in &locals {
            if host.len() > 255 {
                return Err(format!(
                    "local host {host:?} is {} bytes; the protocol limit is 255",
                    host.len()
                ));
            }
        }
        if remotes.len() != locals.len() {
            return Err(format!(
                "`remote` has {} port(s) but `local` has {} — they must map positionally (or omit `local`)",
                remotes.len(),
                locals.len()
            ));
        }
        Ok(remotes
            .into_iter()
            .zip(locals)
            .map(|(remote, (local_host, local_port))| PortMapping {
                remote,
                local_host,
                local_port,
            })
            .collect())
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let side = if cfg.server.is_some() {
            "server"
        } else {
            "client"
        };
        for (name, sp) in &cfg.services {
            // Protocol limit: name and host lengths are single u8 bytes on the
            // wire; reject overlong values at load with a clear error rather
            // than emitting a corrupt frame at runtime.
            if name.len() > 255 {
                return Err(format!(
                    "service {name:?}: name is {} bytes; the protocol limit is 255",
                    name.len()
                ));
            }
            sp.expand()
                .map_err(|e| format!("{side} service {name}: {e}"))?;
        }
        if let Some(s) = &cfg.server {
            s.resolve().map_err(|e| format!("server: {e}"))?;
        }
        if let Some(c) = &cfg.client {
            c.resolve().map_err(|e| format!("client: {e}"))?;
        }
        Ok(cfg)
    }
}

/// Cross-validate a server + client config pair. With the shared data port the
/// two files no longer share any geometry (the data port is server-advertised,
/// the channel count is client-chosen), so this checks the remaining
/// cross-file facts: shared secret, the server's port policy, a service port
/// colliding with the data port, and duplicate public ports. Returns a list of
/// problems (empty = consistent).
pub fn validate_pair(
    server: &ServerConfig,
    client: &ClientConfig,
    services: &HashMap<String, ProxySpec>,
) -> Vec<String> {
    let mut problems = Vec::new();

    if server.secret != client.secret {
        problems.push("secrets differ between the two configs".into());
    }

    let data_port = server.resolve().map(|(_, p)| p).unwrap_or(0);
    for (name, sp) in services {
        for m in sp.expand().unwrap_or_default() {
            if !server.port_allowed(m.remote) {
                problems.push(format!(
                    "service {name}: public port {} not permitted by the server's allow/forbid policy",
                    m.remote
                ));
            }
            if data_port != 0 && m.remote == data_port {
                problems.push(format!(
                    "service {name}: public port {} collides with the server's data port",
                    m.remote
                ));
            }
        }
    }

    // duplicate public ports across (or within) services
    let mut remotes: HashMap<u16, String> = HashMap::new();
    for (name, sp) in services {
        for m in sp.expand().unwrap_or_default() {
            if let Some(prev) = remotes.insert(m.remote, name.clone())
                && prev != *name
            {
                problems.push(format!(
                    "services {prev} and {name} both use public port {}",
                    m.remote
                ));
            }
        }
    }

    problems
}
