//! waydesk-web: browser access to Waydesk. It serves the web client over HTTPS and bridges its WebSocket to the RDP daemon (see `bridge.rs`).
//!
//! Safe as shipped: it listens on this machine only (`127.0.0.1:8443`), so an SSH tunnel reaches it, and it starts sessions only for addresses on
//! its list, within rate limits (`limits.rs`). It has no second factor yet: the login is the account's password, checked by the daemon, as with RDP.

mod bridge;
#[cfg(test)]
mod e2e;
mod limits;
mod portal;
mod stream;
mod tlsconf;
mod totp;
mod web;
#[path = "../../src/allow.rs"]
mod allow;
// The line the daemon reads when a gateway connects: written here, read there, by the same file.
#[path = "../../src/gateway.rs"]
#[allow(dead_code)] // the daemon reads the line, this crate only writes it
mod daemon_gateway;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use tokio::net::TcpListener;
use tracing::{info, warn};

use web::{App, ClientAddr, Config};

const USAGE: &str = "usage: waydesk-web [--bind ADDR:PORT] [--cert FILE] [--key FILE] [--target HOST:PORT] [--root DIR] [--allow-from LIST]
                   [--rate-per-minute N] [--max-per-ip N] [--max-total N]
                   [--plain-http] [--trusted-proxy LIST] [--public-origin https://HOST]
                   [--totp off|optional|required] [--totp-dir DIR] [--gateway-key FILE]
                   [--helper-socket FILE] [--idle-minutes N]
set up codes: waydesk-web totp add ACCOUNT | recovery ACCOUNT | remove ACCOUNT | list
behind a reverse proxy: --plain-http --trusted-proxy 127.0.0.1 --public-origin https://waydesk.example.com (docs: web/README.md)
defaults: --helper-socket /run/waydesk/helper.sock (only the daemon's account can open it: run as that account) --idle-minutes 30 --bind 127.0.0.1:8443 --cert /etc/waydesk/cert.pem --key /etc/waydesk/key.pem --target 127.0.0.1:3389 --root /usr/share/waydesk/web
          --rate-per-minute 10 --max-per-ip 3 --max-total 64";

fn parse_args(args: impl Iterator<Item = String>) -> Result<Config> {
    let mut cfg = Config {
        bind: "127.0.0.1:8443".parse().expect("a valid address"),
        cert: "/etc/waydesk/cert.pem".into(),
        key: "/etc/waydesk/key.pem".into(),
        target: "127.0.0.1:3389".into(),
        root: "/usr/share/waydesk/web".into(),
        allow_from: None,
        rate_per_minute: 10,
        max_per_ip: 3,
        max_total: 64,
        plain_http: false,
        trusted_proxies: None,
        public_origin: None,
        totp: web::TotpMode::Off,
        totp_dir: "/etc/waydesk/totp".into(),
        gateway_key: None,
        fail_delay: Duration::from_secs(4),
        idle: Duration::from_secs(30 * 60),
        absolute: Duration::from_secs(8 * 3600),
        helper_socket: "/run/waydesk/helper.sock".into(),
    };
    let mut args = args;
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().with_context(|| format!("{name} needs a value"));
        match a.as_str() {
            "--bind" => cfg.bind = value("--bind")?.parse().context("bad --bind address")?,
            "--cert" => cfg.cert = PathBuf::from(value("--cert")?),
            "--key" => cfg.key = PathBuf::from(value("--key")?),
            "--target" => cfg.target = value("--target")?,
            "--root" => cfg.root = PathBuf::from(value("--root")?),
            "--allow-from" => {
                let v = value("--allow-from")?;
                cfg.allow_from = (!v.trim().is_empty()).then_some(v);
            }
            "--totp" => {
                cfg.totp = match value("--totp")?.as_str() {
                    "off" => web::TotpMode::Off,
                    "optional" => web::TotpMode::Optional,
                    "required" => web::TotpMode::Required,
                    other => bail!("--totp is off, optional or required, not {other:?}"),
                }
            }
            "--helper-socket" => cfg.helper_socket = PathBuf::from(value("--helper-socket")?),
            "--idle-minutes" => cfg.idle = Duration::from_secs(60 * value("--idle-minutes")?.parse::<u64>().context("bad --idle-minutes")?.max(1)),
            "--totp-dir" => cfg.totp_dir = PathBuf::from(value("--totp-dir")?),
            "--gateway-key" => {
                let path = value("--gateway-key")?;
                let key = std::fs::read_to_string(&path).with_context(|| format!("cannot read {path}"))?.trim().to_owned();
                if key.len() < 16 || key.contains(char::is_whitespace) {
                    bail!("{path}: the key must be one word of at least 16 characters");
                }
                cfg.gateway_key = Some(key);
            }
            "--plain-http" => cfg.plain_http = true,
            "--trusted-proxy" => cfg.trusted_proxies = Some(value("--trusted-proxy")?),
            "--public-origin" => {
                let v = value("--public-origin")?;
                let v = v.trim_end_matches('/').to_owned();
                if !v.starts_with("https://") || v[8..].contains('/') || v.len() == 8 {
                    bail!("--public-origin must look like https://waydesk.example.com (no path)");
                }
                cfg.public_origin = Some(v);
            }
            "--rate-per-minute" => cfg.rate_per_minute = value("--rate-per-minute")?.parse().context("bad --rate-per-minute")?,
            "--max-per-ip" => cfg.max_per_ip = value("--max-per-ip")?.parse().context("bad --max-per-ip")?,
            "--max-total" => cfg.max_total = value("--max-total")?.parse().context("bad --max-total")?,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }
    if cfg.rate_per_minute == 0 || cfg.max_per_ip == 0 || cfg.max_total == 0 {
        bail!("the limits must be at least 1");
    }
    if cfg.totp != web::TotpMode::Off && cfg.gateway_key.is_none() {
        // The gateway checks the code for the account the visitor names, but only the daemon sees which account the visitor then logs in to. Without
        // the key the daemon cannot be told, and a code of one account would open the login of every other.
        bail!("--totp {} needs --gateway-key FILE: the daemon has to be told which account the code was for, or a code of one account would open any other", if cfg.totp == web::TotpMode::Required { "required" } else { "optional" });
    }
    if cfg.plain_http && cfg.trusted_proxies.is_none() {
        bail!("--plain-http needs --trusted-proxy: without a proxy in front, plain HTTP would send the passwords in the clear");
    }
    Ok(cfg)
}

/// Most connections open at once, sessions and plain requests together.
const MAX_CONNECTIONS: usize = 512;

pub async fn serve(listener: TcpListener, app: Arc<App>, tls: Arc<rustls::ServerConfig>, allow: Arc<allow::Allow>) {
    let router = web::router(app.clone());
    let trusted: Option<Arc<allow::Allow>> = app.cfg.trusted_proxies.as_deref().map(|l| Arc::new(allow::Allow::parse(l).expect("checked at start")));
    let plain = app.cfg.plain_http;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let refusals = Arc::new(allow::RefusalLog::new());
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // A reverse proxy is let in whatever the list says: the list is about its clients, and is checked for each request, against the address
        // the proxy forwarded. Any other address that is not allowed gets nothing: no TLS, no page.
        let from_proxy = trusted.as_ref().is_some_and(|t| t.permits(peer.ip()));
        if !from_proxy && !allow.permits(peer.ip()) {
            if let Some(more) = refusals.note() {
                warn!(%peer, also_refused = more, "connection refused: the address is not in the allowed list (--allow-from)");
            }
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "too many connections, refused");
            continue;
        };
        let (router, acceptor, allow, trusted, refusals) = (router.clone(), acceptor.clone(), allow.clone(), trusted.clone(), refusals.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let _ = stream.set_nodelay(true);
            keepalive(&stream);
            let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
                let (ip, host) = match &trusted {
                    Some(t) if from_proxy => {
                        let ip = web::client_ip(peer.ip(), header("x-forwarded-for").as_deref(), t);
                        let host = header("x-forwarded-host").map(|h| h.split(',').next().unwrap_or("").trim().to_owned()).or_else(|| header("host"));
                        (ip, host)
                    }
                    _ => (peer.ip(), header("host")),
                };
                let permitted = allow.permits(ip);
                if !permitted {
                    if let Some(more) = refusals.note() {
                        warn!(%ip, also_refused = more, "request refused: the address is not in the allowed list (--allow-from)");
                    }
                }
                req.extensions_mut().insert(ClientAddr(std::net::SocketAddr::new(ip, peer.port())));
                req.extensions_mut().insert(web::PublicHost(host.unwrap_or_default()));
                let router = router.clone();
                async move {
                    if !permitted {
                        return Ok(axum::response::IntoResponse::into_response((axum::http::StatusCode::FORBIDDEN, "forbidden\n")));
                    }
                    tower::ServiceExt::oneshot(router, req.map(axum::body::Body::new)).await
                }
            });
            let builder = || {
                let mut b = hyper::server::conn::http1::Builder::new();
                b.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                b
            };
            let result = if plain {
                builder().serve_connection(hyper_util::rt::TokioIo::new(stream), service).with_upgrades().await
            } else {
                let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await else { return };
                builder().serve_connection(hyper_util::rt::TokioIo::new(tls), service).with_upgrades().await
            };
            if let Err(e) = result {
                tracing::debug!(%peer, "connection ended: {e}");
            }
        });
    }
}

/// TCP keepalive, so that a browser that vanished (a closed laptop) is noticed by the kernel even on an idle connection.
fn keepalive(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(15));
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        tracing::debug!("cannot set TCP keepalive: {e}");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("totp") {
        return totp::cli(&args[1..]);
    }
    let cfg = parse_args(args.into_iter())?;
    let files = tlsconf::CertFiles::open(&cfg.cert, &cfg.key)?;
    let server_tls = tlsconf::server_config(files.clone())?;
    let daemon_tls = tlsconf::daemon_client_config(files)?;
    let allow = Arc::new(allow::Allow::from_config(cfg.allow_from.as_deref(), &cfg.bind).map_err(|e| anyhow::anyhow!("--allow-from: {e}"))?);
    if !cfg.bind.ip().is_loopback() && allow.is_any() {
        warn!(bind = %cfg.bind, "listening for any source address: there is no second factor, keep this off the open internet (--allow-from limits who may connect)");
    }
    if let Some(list) = &cfg.trusted_proxies {
        let t = allow::Allow::parse(list).map_err(|e| anyhow::anyhow!("--trusted-proxy: {e}"))?;
        if t.is_any() {
            bail!("--trusted-proxy any would believe every client's X-Forwarded-For: name the proxy's address (for example 127.0.0.1)");
        }
        if !cfg.bind.ip().is_loopback() {
            warn!(bind = %cfg.bind, "behind a proxy but not on loopback: only the proxy should be able to reach this port (a firewall rule), or its clients bypass it");
        }
    }
    if cfg.totp == web::TotpMode::Off && cfg.bind.ip().is_loopback() == false {
        warn!("--totp off on an address other machines can reach: the account password is all a visitor needs");
    }
    if !cfg.root.join("index.html").is_file() {
        warn!(root = %cfg.root.display(), "no index.html in the web root: the page will not load (the client is built and installed separately)");
    }
    let listener = TcpListener::bind(cfg.bind).await.with_context(|| format!("cannot listen on {}", cfg.bind))?;
    info!(totp = ?cfg.totp, gateway_key = cfg.gateway_key.is_some(), bind = %cfg.bind, target = %cfg.target, root = %cfg.root.display(), allowed = %cfg.allow_from.as_deref().unwrap_or(if cfg.bind.ip().is_loopback() { "any (loopback)" } else { "private" }), "waydesk-web listening");
    let auth = Arc::new(portal::HelperAuth { socket: cfg.helper_socket.clone() });
    let app = App::new(cfg, daemon_tls, auth);
    tokio::select! {
        () = serve(listener, app, server_tls, allow) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}
