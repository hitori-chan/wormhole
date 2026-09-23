use std::path::{Path, PathBuf};

use clap::builder::styling::{Style, Styles};
use clap::{Parser, Subcommand};

use wormhole::config::Config;

#[derive(Parser)]
#[command(
    name = "wormhole",
    version,
    about = "a fast, minimal, stateless TCP tunnel for NAT traversal",
    styles = Styles::plain()
        .header(Style::new().bold())
        .usage(Style::new().bold())
        .literal(Style::new().bold())
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate a config file; with two files, check the complete setup
    Check {
        /// config file (defaults: ./wormhole.toml, ./client.toml, ./server.toml)
        file: Option<PathBuf>,
        /// a second config (one [server] + one [client], either order)
        other: Option<PathBuf>,
    },
    /// Run the server
    Serve {
        /// server config file (default: ./server.toml)
        file: Option<PathBuf>,
    },
    /// Run the client
    Client {
        /// client config file (default: ./client.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Print version
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match cli.cmd {
        Cmd::Version => println!("wormhole {}", env!("CARGO_PKG_VERSION")),
        Cmd::Check { file, other } => {
            if let Err(e) = check(file, other) {
                eprintln!("wormhole: {e}");
                std::process::exit(1);
            }
        }
        Cmd::Serve { file } => {
            let path = file.unwrap_or_else(|| PathBuf::from("server.toml"));
            if let Err(e) = run_serve(&path).await {
                eprintln!("wormhole: {e}");
                std::process::exit(1);
            }
        }
        Cmd::Client { config } => {
            let path = config.unwrap_or_else(|| PathBuf::from("client.toml"));
            if let Err(e) = run_client(&path).await {
                eprintln!("wormhole: {e}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_serve(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = wormhole::config::Config::load(path)?;
    let server = cfg
        .server
        .as_ref()
        .ok_or("config has no [server] section")?;
    if !cfg.services.is_empty() {
        tracing::warn!(
            "server: ignoring {} [services] entrie(s) — the server is stateless; declare them in the client config",
            cfg.services.len()
        );
    }
    wormhole::server::run(server).await?;
    Ok(())
}

async fn run_client(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = wormhole::config::Config::load(path)?;
    let client = cfg
        .client
        .as_ref()
        .ok_or("config has no [client] section")?;
    if cfg.services.is_empty() {
        return Err(format!(
            "no [services] declared in {path:?} — the client would connect with nothing to tunnel.\n\n\
             Declare at least one public->local mapping, e.g.:\n\n\
             [services.web]\n\
             remote = 1401\n\
             local = \"127.0.0.1:8080\"\n\n\
             (port ranges are allowed: local = \"127.0.0.1:8080-8090\")"
        ).into());
    }
    wormhole::client::run(client, &cfg.services).await;
    Ok(())
}

fn check(file: Option<PathBuf>, other: Option<PathBuf>) -> Result<(), String> {
    let a_path = resolve_config(file)?;
    let a = wormhole::config::Config::load(&a_path)?;

    // single-file mode: show this config's resolved layout
    let Some(b_path_in) = other else {
        print_side(&a_path, &a)?;
        return Ok(());
    };

    // pair mode: the complete server + client setup (either file order)
    let b_path = b_path_in
        .exists()
        .then_some(b_path_in.clone())
        .ok_or_else(|| format!("config not found: {}", b_path_in.display()))?;
    let b = wormhole::config::Config::load(&b_path)?;

    let (s_path, s, c_path, c): (&Path, &Config, &Path, &Config) =
        match (a.server.is_some(), b.server.is_some()) {
            (true, false) => (a_path.as_path(), &a, b_path.as_path(), &b),
            (false, true) => (b_path.as_path(), &b, a_path.as_path(), &a),
            (true, true) => {
                return Err(format!(
                    "pair check needs one [server] and one [client] config (both {} and {} have [server])",
                    a_path.display(),
                    b_path.display()
                ))
            }
            (false, false) => {
                return Err(format!(
                    "pair check needs one [server] and one [client] config (neither {} nor {} has [server])",
                    a_path.display(),
                    b_path.display()
                ))
            }
        };
    if c.client.is_none() {
        return Err(format!(
            "pair check needs one [server] and one [client] config ({} has no [client])",
            c_path.display()
        ));
    }
    if s.client.is_some() {
        println!(
            "warning: {} also has [client] — ignored for the server side",
            s_path.display()
        );
    }

    print_side(s_path, s)?;
    println!();
    print_side(c_path, c)?;
    report_pair(
        s_path,
        c_path,
        wormhole::config::validate_pair(
            s.server.as_ref().unwrap(),
            c.client.as_ref().unwrap(),
            &c.services,
        ),
    );
    Ok(())
}

/// Print one config's resolved layout, tagged with its file and role.
fn print_side(path: &Path, cfg: &Config) -> Result<(), String> {
    let role = match (cfg.server.is_some(), cfg.client.is_some()) {
        (true, true) => "server+client",
        (true, false) => "server",
        (false, true) => "client",
        (false, false) => "empty",
    };
    println!("{} ({role}):", path.display());

    if let Some(server) = &cfg.server {
        let (ctrl, data) = server.resolve()?;
        println!("server   control = {ctrl}");
        println!("server   data    = {data} (one shared port; the client learns it at connect time)");
        if let Some(a) = &server.allow_ports {
            println!("server   allow   = {:?}", a.resolve()?);
        }
        if let Some(f) = &server.forbid_ports {
            println!("server   forbid  = {:?}", f.resolve()?);
        }
        if !cfg.services.is_empty() {
            println!("warning: server config has [services] — ignored (server is stateless)");
        }
    }
    if let Some(client) = &cfg.client {
        let (host, port, n) = client.resolve()?;
        println!("client   server  = {host}:{port}");
        println!("client   data    = {n} channel(s) on the server's data port");
        if cfg.services.is_empty() {
            println!("warning: client config has no [services.*] — nothing to expose");
        } else {
            println!("client   proxies:");
            for (name, spec) in &cfg.services {
                for m in spec.expand()? {
                    println!(
                        "               [{name}] remote {} -> local {}:{}",
                        m.remote, m.local_host, m.local_port
                    );
                }
            }
        }
    }
    Ok(())
}

/// Verdict on the complete setup. Fails loudly (exit 1) on any mismatch.
fn report_pair(server: &Path, client: &Path, problems: Vec<String>) {
    println!();
    if problems.is_empty() {
        println!(
            "setup OK: {} (server) + {} (client) agree — secrets match, port policy permits every service, no data-port collision, no duplicate public ports",
            server.display(),
            client.display()
        );
    } else {
        println!(
            "setup MISMATCH between {} (server) and {} (client):",
            server.display(),
            client.display()
        );
        for p in &problems {
            println!("  - {p}");
        }
        std::process::exit(1);
    }
}

/// Resolve the config path: explicit, or the first of the conventional names.
fn resolve_config(file: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(f) = file {
        if f.exists() {
            return Ok(f);
        }
        return Err(format!("config not found: {}", f.display()));
    }
    for name in ["wormhole.toml", "client.toml", "server.toml"] {
        let p = PathBuf::from(name);
        if p.exists() {
            return Ok(p);
        }
    }
    Err("no config found (pass a path to a server.toml or client.toml)".into())
}
