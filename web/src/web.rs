//! The HTTP side: the web client's files, a token for starting a session, and the WebSocket that the bridge runs on.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tracing::{info, warn};

use crate::limits::{RateLimiter, Refusal, Sessions, Tokens};
use crate::totp::{CodeCheck, Guesses, Store};

/// Whether a one-time code from an authenticator app is asked for before a session may start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpMode {
    /// Never.
    Off,
    /// For the accounts that have an authenticator set up; the others sign in with the password alone.
    Optional,
    /// For every account: one without an authenticator cannot start a session here.
    Required,
}

pub struct Config {
    pub bind: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// The RDP daemon: `host:port`.
    pub target: String,
    /// The directory of the web client's files.
    pub root: PathBuf,
    pub allow_from: Option<String>,
    /// Tokens (login attempts) per address per minute.
    pub rate_per_minute: usize,
    pub max_per_ip: usize,
    pub max_total: usize,
    /// Serve plain HTTP: a reverse proxy in front terminates TLS.
    pub plain_http: bool,
    /// Addresses of the reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Host` are believed.
    pub trusted_proxies: Option<String>,
    /// The address users open, `https://waydesk.example.com`; when set, it is the only origin accepted.
    pub public_origin: Option<String>,
    pub totp: TotpMode,
    /// Where the accounts' authenticators are kept.
    pub totp_dir: PathBuf,
    /// The key that tells the daemon a connection comes from this gateway, so that it can believe the account and the client address that the
    /// gateway names (see `bridge.rs`). Without it the gateway connects as any client would.
    pub gateway_key: Option<String>,
}

pub struct App {
    pub cfg: Config,
    pub tokens: Tokens,
    pub token_rate: RateLimiter,
    pub ws_rate: RateLimiter,
    pub sessions: Arc<Sessions>,
    pub daemon_tls: Arc<rustls::ClientConfig>,
    pub store: Store,
    pub guesses: Guesses,
}

impl App {
    pub fn new(cfg: Config, daemon_tls: Arc<rustls::ClientConfig>) -> Arc<Self> {
        Arc::new(Self {
            tokens: Tokens::new(Duration::from_secs(30)),
            token_rate: RateLimiter::new(cfg.rate_per_minute, Duration::from_secs(60)),
            ws_rate: RateLimiter::new(cfg.rate_per_minute.saturating_mul(3), Duration::from_secs(60)),
            sessions: Sessions::new(cfg.max_per_ip, cfg.max_total),
            daemon_tls,
            store: Store::new(&cfg.totp_dir),
            // 5 wrong codes from one address for one account, 20 for one account from anywhere, within ten minutes.
            guesses: Guesses::new(20, 5, Duration::from_secs(600)),
            cfg,
        })
    }
}

/// The client a request is from, put in by the accept loop: the peer of the connection, or, when that is a trusted reverse proxy, the address it
/// forwarded the request for.
#[derive(Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

/// The host the browser used, which an `Origin` must match: the `Host` header, or what a trusted reverse proxy forwarded.
#[derive(Clone)]
pub struct PublicHost(pub String);

/// The address of the client behind a reverse proxy. `X-Forwarded-For` is a list that every proxy on the way adds the address it got the request
/// from to; only the entries added by proxies we trust can be believed, so the list is read from the right, skipping trusted proxies, and the first
/// address that is not one is the client (whatever a client put before that is its own claim, and ignored). Without such a header the peer is
/// the answer.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &crate::allow::Allow) -> IpAddr {
    if !trusted.permits(peer) {
        return peer;
    }
    let Some(list) = forwarded_for else { return peer };
    for entry in list.rsplit(',') {
        let entry = entry.trim();
        let addr = entry
            .parse::<IpAddr>()
            .ok()
            .or_else(|| entry.parse::<SocketAddr>().ok().map(|s| s.ip()))
            .or_else(|| entry.trim_start_matches('[').split(']').next().and_then(|e| e.parse::<IpAddr>().ok()));
        match addr {
            Some(ip) if trusted.permits(ip) => continue,
            Some(ip) => return ip,
            None => return peer, // a list that does not parse is not believed
        }
    }
    peer
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/session", post(session_token).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/ws", get(ws_handler))
        .fallback(get(static_file))
        .layer(middleware::map_response(security_headers))
        .with_state(app)
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    for (k, v) in [
        // Scripts only from this origin (and WebAssembly), no framing, nothing sent in the Referer. `data:` in connect-src because the client bundle holds the
        // WebAssembly module as a data URL and fetches it (a data URL is local content: it cannot send anything anywhere).
        ("content-security-policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' data:; worker-src 'self' blob:; media-src blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("x-frame-options", "DENY"),
    ] {
        h.insert(header::HeaderName::from_static(k), HeaderValue::from_static(v));
    }
    res
}

/// A request that changes anything (a token, a session) must come from a page of this gateway: the browser sends an `Origin` with such requests,
/// and it has to be this host. Without this, any page the user visits could start a session from their browser, or ask for tokens in their name.
/// `host` is what the browser used (see [`PublicHost`]); with `public_origin` set, that exact origin is the only one accepted.
pub fn origin_ok(headers: &HeaderMap, host: &str, public_origin: Option<&str>) -> bool {
    let Some(Ok(origin)) = headers.get(header::ORIGIN).map(|o| o.to_str()) else { return false };
    match public_origin {
        Some(expected) => origin == expected,
        None => !host.is_empty() && origin == format!("https://{host}"),
    }
}

fn text(status: StatusCode, body: &'static str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
}

#[derive(serde::Deserialize)]
struct SessionRequest {
    username: String,
    #[serde(default)]
    code: String,
}

fn json(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], body).into_response()
}

/// The same answer whatever was wrong (the account, the code, a limit), so that it does not say which accounts exist or have an authenticator.
fn refused() -> Response {
    json(StatusCode::UNAUTHORIZED, "{\"error\":\"Sign-in refused. Check the account and the code.\"}\n".into())
}

async fn session_token(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if !origin_ok(&headers, &host, app.cfg.public_origin.as_deref()) {
        return text(StatusCode::FORBIDDEN, "wrong origin\n");
    }
    let ip = peer.ip();
    let now = Instant::now();
    if !app.token_rate.hit(ip, now) {
        warn!(%ip, "too many session requests from this address");
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<SessionRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    let account = req.username.trim();
    if !crate::totp::valid_account(account) {
        warn!(%ip, "session request for an account name that is not valid");
        return refused();
    }
    if app.cfg.totp != TotpMode::Off {
        let enrolled = app.store.exists(account);
        if !enrolled {
            if app.cfg.totp == TotpMode::Required {
                warn!(%ip, account, "no session: this account has no authenticator and one is required");
                return refused();
            }
        } else {
            if app.guesses.blocked(ip, account, now) {
                warn!(%ip, account, "no session: too many wrong codes");
                return refused();
            }
            let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            match app.store.check_and_use(account, &req.code, unix) {
                CodeCheck::Good => app.guesses.succeeded(ip, account),
                CodeCheck::GoodRecovery(left) => {
                    app.guesses.succeeded(ip, account);
                    warn!(%ip, account, left, "a recovery code was used");
                }
                CodeCheck::Wrong | CodeCheck::NoAuthenticator => {
                    app.guesses.failed(ip, account, now);
                    warn!(%ip, account, "wrong code");
                    return refused();
                }
            }
        }
    }
    match app.tokens.issue(ip, account, now) {
        Some(t) => json(StatusCode::OK, format!("{{\"token\":\"{t}\",\"expires_in\":{}}}\n", app.tokens.ttl().as_secs())),
        None => text(StatusCode::SERVICE_UNAVAILABLE, "busy\n"),
    }
}

async fn ws_handler(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if !origin_ok(&headers, &host, app.cfg.public_origin.as_deref()) {
        return text(StatusCode::FORBIDDEN, "wrong origin\n");
    }
    let ip: IpAddr = peer.ip();
    if !app.ws_rate.hit(ip, Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let guard = match app.sessions.start(ip) {
        Ok(g) => g,
        Err(Refusal::PerAddress) => return text(StatusCode::TOO_MANY_REQUESTS, "too many sessions from this address\n"),
        Err(Refusal::Total) => return text(StatusCode::SERVICE_UNAVAILABLE, "the server is full\n"),
    };
    info!(%ip, active = app.sessions.active(), "session requested");
    // The first message is the RDCleanPath request, which a few hundred bytes hold; later ones are RDP packets, which the client keeps small.
    ws.max_message_size(1 << 20).max_frame_size(1 << 20).on_upgrade(move |socket| crate::bridge::run(socket, ip, app, guard))
}

/// `root` joined with a path from a URL, only if it stays inside `root` and names no hidden file.
pub fn safe_join(root: &Path, url_path: &str) -> Option<PathBuf> {
    let mut out = root.to_owned();
    for part in url_path.split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." || part.starts_with('.') || part.contains(['\\', '\0']) {
            return None;
        }
        out.push(part);
    }
    Some(out)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

const MAX_FILE: u64 = 64 << 20;

async fn static_file(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let path = if uri.path() == "/" { "/index.html" } else { uri.path() };
    let Some(wanted) = safe_join(&app.cfg.root, path) else { return text(StatusCode::NOT_FOUND, "not found\n") };
    // A file next to it with .gz is sent instead to browsers that take it (the build gzips the big files, the WebAssembly above all).
    let gzip_ok = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("gzip"));
    let mut candidates = Vec::new();
    if gzip_ok {
        let mut gz = wanted.clone().into_os_string();
        gz.push(".gz");
        candidates.push((PathBuf::from(gz), true));
    }
    candidates.push((wanted.clone(), false));
    let Ok(root) = tokio::fs::canonicalize(&app.cfg.root).await else { return text(StatusCode::NOT_FOUND, "not found\n") };
    for (file, gzipped) in candidates {
        let Ok(real) = tokio::fs::canonicalize(&file).await else { continue };
        if !real.starts_with(&root) {
            continue; // a link that leads out of the directory
        }
        let Ok(meta) = tokio::fs::metadata(&real).await else { continue };
        if !meta.is_file() || meta.len() > MAX_FILE {
            continue;
        }
        let Ok(body) = tokio::fs::read(&real).await else { continue };
        let cache = if wanted.extension().is_some_and(|e| e == "html") || path == "/index.html" { "no-cache" } else { "public, max-age=3600" };
        let mut res = ([(header::CONTENT_TYPE, content_type(&wanted)), (header::CACHE_CONTROL, cache)], body).into_response();
        if gzipped {
            res.headers_mut().insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        }
        res.headers_mut().insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        return res;
    }
    info!(path = uri.path(), "not found");
    text(StatusCode::NOT_FOUND, "not found\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_cannot_leave_the_directory_or_name_hidden_files() {
        let root = Path::new("/srv/web");
        assert_eq!(safe_join(root, "/a/b.js"), Some(PathBuf::from("/srv/web/a/b.js")));
        assert_eq!(safe_join(root, "/a//b.js"), Some(PathBuf::from("/srv/web/a/b.js")));
        for bad in ["/../etc/passwd", "/a/../../x", "/.env", "/a/.git/config", "/a\\b", "/a/b/..", "/../x", "/.hidden"] {
            assert!(safe_join(root, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn origin_must_be_this_host_over_https() {
        let mut h = HeaderMap::new();
        let host = "waydesk.example:8443";
        assert!(!origin_ok(&h, host, None), "no origin");
        h.insert(header::ORIGIN, "https://waydesk.example:8443".parse().unwrap());
        assert!(origin_ok(&h, host, None));
        assert!(!origin_ok(&h, "", None), "no host");
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!origin_ok(&h, host, None));
        h.insert(header::ORIGIN, "http://waydesk.example:8443".parse().unwrap());
        assert!(!origin_ok(&h, host, None), "plain http is not this origin");
        h.insert(header::ORIGIN, "null".parse().unwrap());
        assert!(!origin_ok(&h, host, None));
    }

    #[test]
    fn a_public_origin_is_the_only_one_accepted() {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, "https://waydesk.example.com".parse().unwrap());
        assert!(origin_ok(&h, "127.0.0.1:8443", Some("https://waydesk.example.com")), "whatever the proxy made of Host");
        assert!(!origin_ok(&h, "waydesk.example.com", Some("https://other.example.com")));
    }

    fn trusted(list: &str) -> crate::allow::Allow {
        crate::allow::Allow::parse(list).unwrap()
    }

    #[test]
    fn the_client_behind_a_proxy_is_the_last_address_a_trusted_proxy_did_not_add() {
        let t = trusted("127.0.0.1 10.0.0.0/8");
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // The peer is the proxy; it saw the client.
        assert_eq!(client_ip(ip("127.0.0.1"), Some("203.0.113.9"), &t), ip("203.0.113.9"));
        // A client that wrote a claim of its own before it: the claim is ignored.
        assert_eq!(client_ip(ip("127.0.0.1"), Some("6.6.6.6, 203.0.113.9"), &t), ip("203.0.113.9"));
        // Two proxies in a chain.
        assert_eq!(client_ip(ip("127.0.0.1"), Some("6.6.6.6, 203.0.113.9, 10.0.0.1"), &t), ip("203.0.113.9"));
        // Not from a trusted proxy: the header is not believed.
        assert_eq!(client_ip(ip("198.51.100.7"), Some("203.0.113.9"), &t), ip("198.51.100.7"));
        // No header, or one that is not an address: the proxy itself.
        assert_eq!(client_ip(ip("127.0.0.1"), None, &t), ip("127.0.0.1"));
        assert_eq!(client_ip(ip("127.0.0.1"), Some("not an address"), &t), ip("127.0.0.1"));
        assert_eq!(client_ip(ip("127.0.0.1"), Some("203.0.113.9, garbage"), &t), ip("127.0.0.1"));
        // Other ways to write an address.
        assert_eq!(client_ip(ip("127.0.0.1"), Some("203.0.113.9:51234"), &t), ip("203.0.113.9"));
        assert_eq!(client_ip(ip("127.0.0.1"), Some("2001:db8::7"), &t), ip("2001:db8::7"));
        assert_eq!(client_ip(ip("127.0.0.1"), Some("[2001:db8::7]:443"), &t), ip("2001:db8::7"));
    }
}
