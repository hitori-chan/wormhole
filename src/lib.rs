//! wormhole — a fast, minimal, multiplexed TCP tunnel.
//!
//! See the README for the model: a stateless generic server, client-declared
//! proxies, shared-secret auth, and N parallel data channels.

pub mod client;
pub mod config;
pub mod protocol;
pub mod server;
pub mod tunnel;
