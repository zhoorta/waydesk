//! End-to-end tests: the real gateway on a local port, a stand-in for the RDP daemon (plain X.224 exchange, then TLS, then upper-casing what it
//! receives), and a client that does what the browser does (HTTPS, the token, the WebSocket, the RDCleanPath request).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt as _, StreamExt as _};
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu, EXPIRED_ERROR_CODE, TLS_HANDSHAKE_FAILED_ERROR_CODE};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::Message;

use crate::tlsconf::{self, CertFiles};
use crate::web::{App, Config};

const X224_REQUEST: [u8; 11] = [3, 0, 0, 11, 6, 0xE0, 0, 0, 0, 0, 0];
const X224_CONFIRM: [u8; 11] = [3, 0, 0, 11, 6, 0xD0, 0, 0, 0x12, 0x34, 0];

/// Stands in for the root helper: the password of an account is `pw-` and its name, and nobody named `locked` gets in.
struct FakeAuth;

impl crate::portal::Authenticator for FakeAuth {
    fn check(&self, account: &str, password: &str, _source: &str) -> Result<bool, String> {
        Ok(account != "locked" && password == format!("pw-{account}"))
    }
}

/// What a signed-in browser holds.
#[derive(Clone)]
struct Browser {
    cookie: String,
    csrf: String,
}

struct Opts {
    rate: usize,
    per_ip: usize,
    /// The stand-in daemon uses another certificate than the file the gateway trusts.
    daemon_has_other_cert: bool,
    /// Behind a reverse proxy at 127.0.0.1 (which the test client is): plain HTTP, forwarded headers believed.
    proxy: bool,
    public_origin: Option<&'static str>,
    allow_from: Option<&'static str>,
    /// The proxies believed, when `proxy` is set (default: 127.0.0.1, the test client).
    trusted: Option<&'static str>,
    totp: crate::web::TotpMode,
    gateway_key: Option<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Self { rate: 100, per_ip: 10, daemon_has_other_cert: false, proxy: false, public_origin: None, allow_from: None, trusted: None, totp: crate::web::TotpMode::Off, gateway_key: None }
    }
}

struct Env {
    gateway: SocketAddr,
    dir: PathBuf,
    files: Arc<CertFiles>,
    daemon_connections: Arc<AtomicUsize>,
    /// The first line the stand-in daemon read, when it expects the gateway's preamble.
    preambles: Arc<std::sync::Mutex<Vec<String>>>,
}

fn write_cert(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (c, k) = (dir.join(format!("{name}-cert.pem")), dir.join(format!("{name}-key.pem")));
    std::fs::write(&c, ck.cert.pem()).unwrap();
    std::fs::write(&k, ck.signing_key.serialize_pem()).unwrap();
    (c, k)
}

async fn read_tpkt(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    let mut all = h.to_vec();
    all.resize(usize::from(u16::from_be_bytes([h[2], h[3]])), 0);
    s.read_exact(&mut all[4..]).await?;
    Ok(all)
}

async fn start(name: &str, opts: Opts) -> Env {
    let dir = std::env::temp_dir().join(format!("waydesk-web-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::write(dir.join("web/index.html"), "<h1>waydesk</h1>").unwrap();
    std::fs::write(dir.join("web/app.js"), "plain").unwrap();
    std::fs::write(dir.join("web/app.js.gz"), "zipped").unwrap();
    std::fs::write(dir.join("secret.txt"), "secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("secret.txt"), dir.join("web/link.txt")).unwrap();
    let (cert, key) = write_cert(&dir, "gw");
    let files = CertFiles::open(&cert, &key).unwrap();

    // The stand-in daemon.
    let daemon_files = if opts.daemon_has_other_cert {
        let (c, k) = write_cert(&dir, "other");
        CertFiles::open(&c, &k).unwrap()
    } else {
        files.clone()
    };
    let daemon = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let daemon_addr = daemon.local_addr().unwrap();
    let daemon_connections = Arc::new(AtomicUsize::new(0));
    let count = daemon_connections.clone();
    let preambles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (seen, expect_preamble) = (preambles.clone(), opts.gateway_key.is_some());
    let acceptor = tokio_rustls::TlsAcceptor::from(tlsconf::server_config(daemon_files).unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = daemon.accept().await else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                if expect_preamble {
                    let mut line = Vec::new();
                    let mut b = [0u8; 1];
                    while s.read_exact(&mut b).await.is_ok() && b[0] != b'\n' {
                        line.push(b[0]);
                    }
                    seen.lock().unwrap().push(String::from_utf8_lossy(&line).into_owned());
                }
                if read_tpkt(&mut s).await.is_err() || s.write_all(&X224_CONFIRM).await.is_err() {
                    return;
                }
                let Ok(mut tls) = acceptor.accept(s).await else { return };
                let mut buf = [0u8; 4096];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&buf[..n].to_ascii_uppercase()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
        target: daemon_addr.to_string(),
        root: dir.join("web"),
        allow_from: None,
        rate_per_minute: opts.rate,
        max_per_ip: opts.per_ip,
        max_total: 64,
        plain_http: opts.proxy,
        trusted_proxies: opts.proxy.then(|| opts.trusted.unwrap_or("127.0.0.1").to_string()),
        public_origin: opts.public_origin.map(str::to_string),
        totp: opts.totp,
        totp_dir: dir.join("totp"),
        gateway_key: opts.gateway_key.map(str::to_string),
        fail_delay: std::time::Duration::ZERO,
        idle: std::time::Duration::from_secs(1800),
        absolute: std::time::Duration::from_secs(8 * 3600),
        helper_socket: PathBuf::new(),
    };
    let app = App::new(cfg, tlsconf::daemon_client_config(files.clone()).unwrap(), Arc::new(FakeAuth));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    let allow = Arc::new(match opts.allow_from {
        Some(l) => crate::allow::Allow::parse(l).unwrap(),
        None => crate::allow::Allow::any(),
    });
    tokio::spawn(crate::serve(listener, app, tlsconf::server_config(files.clone()).unwrap(), allow));
    Env { gateway, dir, files, daemon_connections, preambles }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The body a test request carries: the sign-in of `ana` for the sign-in path, nothing for the others.
fn body_for(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("POST", "/api/login") => r#"{"username":"ana","password":"pw-ana","code":""}"#,
        _ => "",
    }
}

impl Env {
    async fn tls(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(self.gateway).await.unwrap();
        let cfg = tlsconf::daemon_client_config(self.files.clone()).unwrap();
        tokio_rustls::TlsConnector::from(cfg).connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap()
    }

    /// One plain HTTP/1.1 request, as a reverse proxy would send it; `Host` is this gateway's address unless `extra` sets it.
    async fn plain(&self, method: &str, path: &str, extra: &[(&str, &str)]) -> (u16, String) {
        let mut tcp = TcpStream::connect(self.gateway).await.unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
        if !extra.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            req += &format!("Host: {}\r\n", self.gateway);
        }
        for (k, v) in extra {
            req += &format!("{k}: {v}\r\n");
        }
        let body = body_for(method, path);
        req += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        tcp.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tcp.read_to_end(&mut out).await;
        let text = String::from_utf8_lossy(&out).into_owned();
        (text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), text)
    }

    fn host(&self) -> String {
        format!("localhost:{}", self.gateway.port())
    }

    /// One HTTP/1.1 request; returns the status and the rest of the response as text.
    async fn http(&self, method: &str, path: &str, extra: &[(&str, &str)]) -> (u16, String) {
        let mut tls = self.tls().await;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", self.host());
        for (k, v) in extra {
            req += &format!("{k}: {v}\r\n");
        }
        let body = body_for(method, path);
        req += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = tls.read(&mut buf).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        (status, text)
    }

    /// One request with a body over TLS; returns the status and the whole response text.
    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
        let mut tls = self.tls().await;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", self.host());
        for (k, v) in headers {
            req += &format!("{k}: {v}\r\n");
        }
        req += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = tls.read(&mut buf).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&out).into_owned();
        (text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), text)
    }

    fn origin(&self) -> String {
        format!("https://{}", self.host())
    }

    /// Signs in as the page does; returns the status and, on success, what the browser keeps.
    async fn sign_in(&self, account: &str, password: &str, code: &str) -> (u16, Option<Browser>) {
        let body = format!("{{\"username\":\"{account}\",\"password\":\"{password}\",\"code\":\"{code}\"}}");
        let (status, text) = self.send("POST", "/api/login", &[("Origin", &self.origin())], &body).await;
        let cookie = text.lines().find_map(|l| l.strip_prefix("set-cookie: ").or_else(|| l.strip_prefix("Set-Cookie: "))).map(|c| c.split(';').next().unwrap().to_string());
        let csrf = text.find("\"csrf\":\"").map(|at| text[at + 8..at + 40].to_string());
        (status, cookie.zip(csrf).map(|(cookie, csrf)| Browser { cookie, csrf }))
    }

    /// A browser signed in as `account` (the password is the stand-in's).
    async fn browser(&self, account: &str) -> Browser {
        self.sign_in(account, &format!("pw-{account}"), "").await.1.expect("signed in")
    }

    /// The token request of a signed-in browser.
    async fn session_for(&self, b: &Browser) -> (u16, Option<String>) {
        let (status, body) = self.send("POST", "/api/session", &[("Origin", &self.origin()), ("Cookie", &b.cookie), ("X-CSRF-Token", &b.csrf)], "").await;
        let token = body.find("\"token\":\"").map(|at| body[at + 9..at + 41].to_string());
        (status, token)
    }

    /// Signs in as `account` with `code` (and the right password), then asks for a token, as the page does.
    async fn token_for(&self, account: &str, code: &str) -> (u16, Option<String>) {
        match self.sign_in(account, &format!("pw-{account}"), code).await {
            (200, Some(b)) => self.session_for(&b).await,
            (status, _) => (status, None),
        }
    }

    async fn token(&self) -> Option<String> {
        let b = self.browser("ana").await;
        self.session_for(&b).await.1
    }

    async fn ws(&self, origin: Option<&str>) -> Result<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>, tokio_tungstenite::tungstenite::Error> {
        let mut req = format!("wss://{}/ws", self.host()).into_client_request().unwrap();
        if let Some(o) = origin {
            req.headers_mut().insert("Origin", o.parse().unwrap());
        }
        tokio_tungstenite::client_async(req, self.tls().await).await.map(|(s, _)| s)
    }

    async fn good_ws(&self) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>> {
        self.ws(Some(&format!("https://{}", self.host()))).await.unwrap()
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

async fn send_request(ws: &mut Ws, token: &str) {
    let pdu = RDCleanPathPdu::new_request(X224_REQUEST.to_vec(), "ignored:3389".into(), token.into(), None).unwrap();
    ws.send(Message::Binary(pdu.to_der().unwrap().into())).await.unwrap();
}

async fn next_pdu(ws: &mut Ws) -> RDCleanPathPdu {
    loop {
        match ws.next().await.expect("the gateway closed").expect("a frame") {
            Message::Binary(b) => return RDCleanPathPdu::from_der(&b).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_session_runs_through_the_bridge() {
    let env = start("happy", Opts::default()).await;
    let token = env.token().await.expect("a token");
    let mut ws = env.good_ws().await;
    send_request(&mut ws, &token).await;
    match next_pdu(&mut ws).await.into_enum().unwrap() {
        RDCleanPath::Response { x224_connection_response, server_cert_chain, .. } => {
            assert_eq!(x224_connection_response.as_bytes(), X224_CONFIRM);
            assert_eq!(server_cert_chain.len(), 1, "the daemon's certificate comes back");
        }
        other => panic!("not a response: {other:?}"),
    }
    ws.send(Message::Binary(b"hello rdp".to_vec().into())).await.unwrap();
    let mut got = Vec::new();
    while got.len() < 9 {
        if let Message::Binary(b) = ws.next().await.unwrap().unwrap() {
            got.extend_from_slice(&b);
        }
    }
    assert_eq!(got, b"HELLO RDP", "bytes pass both ways, through TLS to the daemon");
}

#[tokio::test]
async fn a_token_works_once_and_a_wrong_one_never_reaches_the_daemon() {
    let env = start("token", Opts::default()).await;
    let mut ws = env.good_ws().await;
    send_request(&mut ws, "00000000000000000000000000000000").await;
    let pdu = next_pdu(&mut ws).await;
    assert_eq!(pdu.error.as_ref().map(|e| e.error_code), Some(EXPIRED_ERROR_CODE));

    let token = env.token().await.unwrap();
    let mut first = env.good_ws().await;
    send_request(&mut first, &token).await;
    assert!(next_pdu(&mut first).await.error.is_none());
    let mut again = env.good_ws().await;
    send_request(&mut again, &token).await;
    assert_eq!(next_pdu(&mut again).await.error.as_ref().map(|e| e.error_code), Some(EXPIRED_ERROR_CODE), "used already");
    assert_eq!(env.daemon_connections.load(Ordering::SeqCst), 1, "only the good token got as far as the daemon");
}

#[tokio::test]
async fn a_request_from_another_page_is_refused() {
    let env = start("origin", Opts::default()).await;
    let b = env.browser("ana").await;
    for path in ["/api/login", "/api/session", "/api/logout"] {
        let (status, _) = env.http("POST", path, &[("Origin", "https://evil.example"), ("Cookie", &b.cookie), ("X-CSRF-Token", &b.csrf)]).await;
        assert_eq!(status, 403, "{path}");
        let (status, _) = env.http("POST", path, &[("Cookie", &b.cookie), ("X-CSRF-Token", &b.csrf)]).await;
        assert_eq!(status, 403, "{path}: no Origin at all");
    }
    assert!(env.ws(Some("https://evil.example")).await.is_err(), "the WebSocket handshake is refused");
    assert!(env.ws(None).await.is_err());
}

#[tokio::test]
async fn sign_ins_are_limited_per_address() {
    let env = start("rate", Opts { rate: 3, ..Opts::default() }).await;
    for _ in 0..3 {
        assert_eq!(env.sign_in("ana", "wrong", "").await.0, 401);
    }
    assert_eq!(env.sign_in("ana", "pw-ana", "").await.0, 429, "even the right password, until the minute is over");
}

#[tokio::test]
async fn sessions_are_limited_per_address() {
    let env = start("sessions", Opts { per_ip: 1, ..Opts::default() }).await;
    let _held = env.good_ws().await;
    assert!(env.ws(Some(&format!("https://{}", env.host()))).await.is_err(), "the second session from the address is refused");
}

#[tokio::test]
async fn the_daemon_must_present_the_certificate_in_the_file() {
    let env = start("pin", Opts { daemon_has_other_cert: true, ..Opts::default() }).await;
    let token = env.token().await.unwrap();
    let mut ws = env.good_ws().await;
    send_request(&mut ws, &token).await;
    let pdu = next_pdu(&mut ws).await;
    assert_eq!(pdu.error.as_ref().map(|e| e.error_code), Some(TLS_HANDSHAKE_FAILED_ERROR_CODE), "another certificate: no session");
}

#[tokio::test]
async fn the_web_client_is_served_from_its_directory_only() {
    let env = start("static", Opts::default()).await;
    let (status, body) = env.http("GET", "/", &[]).await;
    assert_eq!(status, 200);
    assert!(body.contains("<h1>waydesk</h1>"));
    let lower = body.to_ascii_lowercase();
    assert!(lower.contains("content-security-policy"), "security headers are set");
    assert!(lower.contains("x-content-type-options: nosniff"));

    let (_, plain) = env.http("GET", "/app.js", &[]).await;
    assert!(plain.contains("plain") && !plain.to_ascii_lowercase().contains("content-encoding"));
    let (_, zipped) = env.http("GET", "/app.js", &[("Accept-Encoding", "gzip")]).await;
    assert!(zipped.contains("zipped") && zipped.to_ascii_lowercase().contains("content-encoding: gzip"));

    assert_eq!(env.http("GET", "/../secret.txt", &[]).await.0, 404, "no way out of the directory");
    assert_eq!(env.http("GET", "/missing.js", &[]).await.0, 404);
    #[cfg(unix)]
    assert_eq!(env.http("GET", "/link.txt", &[]).await.0, 404, "a link that leads out of the directory");
    assert_eq!(env.http("GET", "/healthz", &[]).await.0, 200);
}

#[tokio::test]
async fn behind_a_proxy_clients_are_counted_by_their_forwarded_address_and_the_origin_follows_the_forwarded_host() {
    let env = start("proxy-rate", Opts { proxy: true, rate: 2, ..Opts::default() }).await;
    let a = [("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://waydesk.example")];
    assert_eq!(env.plain("POST", "/api/login", &a).await.0, 200);
    assert_eq!(env.plain("POST", "/api/login", &a).await.0, 200);
    assert_eq!(env.plain("POST", "/api/login", &a).await.0, 429, "the third from the same client");
    let b = [("X-Forwarded-For", "203.0.113.10"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://waydesk.example")];
    assert_eq!(env.plain("POST", "/api/login", &b).await.0, 200, "another client has its own count, though the proxy is the same");
    let wrong = [("X-Forwarded-For", "203.0.113.11"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://evil.example")];
    assert_eq!(env.plain("POST", "/api/login", &wrong).await.0, 403);
    // The forwarded host wins over the Host the proxy set.
    let host_origin = format!("https://{}", env.gateway);
    let own = [("X-Forwarded-For", "203.0.113.12"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", host_origin.as_str())];
    assert_eq!(env.plain("POST", "/api/login", &own).await.0, 403);
}

#[tokio::test]
async fn behind_a_proxy_the_allowed_list_is_about_the_forwarded_client() {
    let env = start("proxy-allow", Opts { proxy: true, allow_from: Some("203.0.113.0/24"), ..Opts::default() }).await;
    let ok = [("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://waydesk.example")];
    assert_eq!(env.plain("POST", "/api/login", &ok).await.0, 200);
    let elsewhere = [("X-Forwarded-For", "198.51.100.7"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://waydesk.example")];
    assert_eq!(env.plain("POST", "/api/login", &elsewhere).await.0, 403);
    assert_eq!(env.plain("GET", "/", &[("X-Forwarded-For", "198.51.100.7")]).await.0, 403, "not even the page");
    assert_eq!(env.plain("GET", "/", &[("X-Forwarded-For", "203.0.113.5")]).await.0, 200);
}

#[tokio::test]
async fn forwarded_headers_from_an_address_that_is_not_a_trusted_proxy_are_ignored() {
    let env = start("proxy-untrusted", Opts { proxy: true, trusted: Some("192.0.2.1"), rate: 2, ..Opts::default() }).await;
    // The test client is 127.0.0.1, which is not the proxy named: it cannot choose its address or its host.
    let host_origin = format!("https://{}", env.gateway);
    for (i, who) in ["203.0.113.1", "203.0.113.2"].iter().enumerate() {
        let h = [("X-Forwarded-For", *who), ("X-Forwarded-Host", "waydesk.example"), ("Origin", host_origin.as_str())];
        assert_eq!(env.plain("POST", "/api/login", &h).await.0, 200, "try {i}: its own Host and Origin match");
    }
    let third = [("X-Forwarded-For", "203.0.113.3"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", host_origin.as_str())];
    assert_eq!(env.plain("POST", "/api/login", &third).await.0, 429, "different claimed addresses, one real one");
    // The host it claims for itself is not believed either: this origin is not the gateway's own.
    let claimed = [("X-Forwarded-For", "203.0.113.4"), ("X-Forwarded-Host", "waydesk.example"), ("Origin", "https://waydesk.example")];
    assert_eq!(env.plain("POST", "/api/login", &claimed).await.0, 403);
}

#[tokio::test]
async fn a_public_origin_is_the_only_origin_behind_a_proxy() {
    let env = start("proxy-origin", Opts { proxy: true, public_origin: Some("https://waydesk.example.com"), ..Opts::default() }).await;
    let ok = [("Origin", "https://waydesk.example.com"), ("X-Forwarded-For", "203.0.113.5")];
    assert_eq!(env.plain("POST", "/api/login", &ok).await.0, 200, "whatever Host the proxy sends");
    let host_origin = format!("https://{}", env.gateway);
    let own_host = [("Origin", host_origin.as_str()), ("X-Forwarded-For", "203.0.113.5")];
    assert_eq!(env.plain("POST", "/api/login", &own_host).await.0, 403);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::test]
async fn a_required_code_is_checked_once_and_the_account_reaches_the_daemon() {
    let env = start("totp-required", Opts { totp: crate::web::TotpMode::Required, gateway_key: Some("a-long-enough-gateway-key"), ..Opts::default() }).await;
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    let (record, _) = store.enroll("ana").unwrap();

    assert_eq!(env.token_for("ana", "").await.0, 401, "no code");
    assert_eq!(env.token_for("bob", "123456").await.0, 401, "an account without an authenticator, when one is required");
    assert_eq!(env.token_for("../x", "123456").await.0, 401, "a name that is not an account");
    let code = crate::totp::code_at(&record.secret, unix_now());
    let (status, token) = env.token_for("ana", &code).await;
    assert_eq!(status, 200);
    assert_eq!(env.token_for("ana", &code).await.0, 401, "the same code again");

    // The token carries the account to the daemon, with the key and the client's address.
    let mut ws = env.good_ws().await;
    send_request(&mut ws, &token.unwrap()).await;
    assert!(next_pdu(&mut ws).await.error.is_none());
    assert_eq!(env.preambles.lock().unwrap().as_slice(), ["WAYDESK-GATEWAY 1 a-long-enough-gateway-key ana 127.0.0.1"]);
}

#[tokio::test]
async fn an_optional_code_is_asked_only_of_accounts_that_have_an_authenticator() {
    let env = start("totp-optional", Opts { totp: crate::web::TotpMode::Optional, ..Opts::default() }).await;
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    let (record, recovery) = store.enroll("ana").unwrap();
    assert_eq!(env.token_for("bob", "").await.0, 200, "no authenticator, no code asked");
    assert_eq!(env.token_for("ana", "").await.0, 401, "an authenticator, and no code");
    assert_eq!(env.token_for("ana", &crate::totp::code_at(&record.secret, unix_now())).await.0, 200);
    assert_eq!(env.token_for("ana", &recovery[0]).await.0, 200, "a recovery code");
    assert_eq!(env.token_for("ana", &recovery[0]).await.0, 401, "once");
}

#[tokio::test]
async fn guessing_codes_is_stopped() {
    let env = start("totp-guess", Opts { totp: crate::web::TotpMode::Required, ..Opts::default() }).await;
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    let (record, _) = store.enroll("ana").unwrap();
    let wrong = if crate::totp::code_at(&record.secret, unix_now()) == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        assert_eq!(env.token_for("ana", wrong).await.0, 401);
    }
    // After five wrong codes from this address the right one is refused too, for a while.
    let right = crate::totp::code_at(&record.secret, unix_now());
    assert_eq!(env.token_for("ana", &right).await.0, 401);
}

#[tokio::test]
async fn without_codes_the_gateway_asks_none() {
    let env = start("totp-off", Opts::default()).await;
    assert_eq!(env.token_for("anyone", "").await.0, 200);
    assert_eq!(env.token_for("not a name", "").await.0, 401);
}

#[tokio::test]
async fn a_token_needs_a_signed_in_browser_that_repeats_its_csrf_token() {
    let env = start("csrf", Opts::default()).await;
    let b = env.browser("ana").await;
    let origin = env.origin();
    assert_eq!(env.http("POST", "/api/session", &[("Origin", &origin)]).await.0, 401, "no cookie");
    assert_eq!(env.http("POST", "/api/session", &[("Origin", &origin), ("Cookie", &b.cookie)]).await.0, 403, "no csrf token");
    assert_eq!(env.http("POST", "/api/session", &[("Origin", &origin), ("Cookie", &b.cookie), ("X-CSRF-Token", &"0".repeat(32))]).await.0, 403, "another csrf token");
    let forged = format!("{}={}", crate::portal::COOKIE, "0".repeat(64));
    assert_eq!(env.http("POST", "/api/session", &[("Origin", &origin), ("Cookie", &forged), ("X-CSRF-Token", &b.csrf)]).await.0, 401, "a cookie nobody was given");
    // Another browser's csrf token does not go with this cookie.
    let other = env.browser("bob").await;
    assert_eq!(env.http("POST", "/api/session", &[("Origin", &origin), ("Cookie", &b.cookie), ("X-CSRF-Token", &other.csrf)]).await.0, 403);
    assert_eq!(env.session_for(&b).await.0, 200);
}

#[tokio::test]
async fn the_sign_in_sets_a_protected_cookie_and_signing_out_ends_it() {
    let env = start("cookie", Opts::default()).await;
    let body = r#"{"username":"ana","password":"pw-ana","code":""}"#;
    let (status, text) = env.send("POST", "/api/login", &[("Origin", &env.origin())], body).await;
    assert_eq!(status, 200);
    let lower = text.to_ascii_lowercase();
    let set = lower.lines().find(|l| l.starts_with("set-cookie:")).expect("a cookie");
    for part in ["__host-waydesk=", "path=/", "secure", "httponly", "samesite=strict"] {
        assert!(set.contains(part), "{set}");
    }
    assert!(!set.contains("domain"), "{set}");
    assert!(lower.contains("cache-control: no-store"));

    let b = env.browser("ana").await;
    let (status, me) = env.http("GET", "/api/me", &[("Cookie", &b.cookie)]).await;
    assert_eq!(status, 200);
    assert!(me.contains("\"account\":\"ana\"") && me.contains(&b.csrf), "{me}");
    assert_eq!(env.http("GET", "/api/me", &[]).await.0, 401);

    let origin = env.origin();
    assert_eq!(env.http("POST", "/api/logout", &[("Origin", &origin), ("Cookie", &b.cookie)]).await.0, 403, "signing out needs the csrf token too");
    let (status, out) = env.http("POST", "/api/logout", &[("Origin", &origin), ("Cookie", &b.cookie), ("X-CSRF-Token", &b.csrf)]).await;
    assert_eq!(status, 200);
    assert!(out.to_ascii_lowercase().contains("max-age=0"), "the cookie is removed in the browser too");
    assert_eq!(env.http("GET", "/api/me", &[("Cookie", &b.cookie)]).await.0, 401, "and on the server");
    assert_eq!(env.session_for(&b).await.0, 401);
}

#[tokio::test]
async fn a_wrong_password_never_reaches_the_code_and_every_refusal_reads_the_same() {
    let env = start("order", Opts { totp: crate::web::TotpMode::Required, gateway_key: Some("a-long-enough-gateway-key"), ..Opts::default() }).await;
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    let (record, _) = store.enroll("ana").unwrap();
    let code = crate::totp::code_at(&record.secret, unix_now());

    // A wrong password with the right code: refused, and the code is not used up.
    let (status, wrong_password) = env.send("POST", "/api/login", &[("Origin", &env.origin())], &format!("{{\"username\":\"ana\",\"password\":\"nope\",\"code\":\"{code}\"}}")).await;
    assert_eq!(status, 401);
    let (status, wrong_code) = env.send("POST", "/api/login", &[("Origin", &env.origin())], r#"{"username":"ana","password":"pw-ana","code":"000000"}"#).await;
    assert_eq!(status, 401);
    let (status, no_account) = env.send("POST", "/api/login", &[("Origin", &env.origin())], r#"{"username":"nobody","password":"pw-nobody","code":"123456"}"#).await;
    assert_eq!(status, 401);
    let (status, locked) = env.send("POST", "/api/login", &[("Origin", &env.origin())], &format!("{{\"username\":\"locked\",\"password\":\"pw-locked\",\"code\":\"{code}\"}}")).await;
    assert_eq!(status, 401);
    let body = |t: &str| t.split("\r\n\r\n").nth(1).unwrap().to_string();
    assert_eq!(body(&wrong_password), body(&wrong_code));
    assert_eq!(body(&wrong_password), body(&no_account));
    assert_eq!(body(&wrong_password), body(&locked));
    assert!(!wrong_password.to_ascii_lowercase().contains("set-cookie"));

    assert_eq!(env.sign_in("ana", "pw-ana", &code).await.0, 200, "the code was still good: a wrong password does not spend it");
}

#[tokio::test]
async fn without_a_helper_nobody_signs_in() {
    struct Down;
    impl crate::portal::Authenticator for Down {
        fn check(&self, _: &str, _: &str, _: &str) -> Result<bool, String> {
            Err("no helper".into())
        }
    }
    // Same gateway, a checker that cannot answer: the answer is "unavailable", not a sign-in.
    let env = start("down", Opts::default()).await;
    let dir = env.dir.clone();
    let (cert, key) = (dir.join("gw-cert.pem"), dir.join("gw-key.pem"));
    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
        target: "127.0.0.1:1".into(),
        root: dir.join("web"),
        allow_from: None,
        rate_per_minute: 100,
        max_per_ip: 10,
        max_total: 64,
        plain_http: false,
        trusted_proxies: None,
        public_origin: None,
        totp: crate::web::TotpMode::Off,
        totp_dir: dir.join("totp2"),
        gateway_key: None,
        fail_delay: std::time::Duration::ZERO,
        idle: std::time::Duration::from_secs(1800),
        absolute: std::time::Duration::from_secs(8 * 3600),
        helper_socket: PathBuf::new(),
    };
    let app = App::new(cfg, tlsconf::daemon_client_config(env.files.clone()).unwrap(), Arc::new(Down));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(crate::serve(listener, app, tlsconf::server_config(env.files.clone()).unwrap(), Arc::new(crate::allow::Allow::any())));
    let down = Env { gateway: addr, dir: dir.clone(), files: env.files.clone(), daemon_connections: env.daemon_connections.clone(), preambles: env.preambles.clone() };
    let (status, browser) = down.sign_in("ana", "pw-ana", "").await;
    assert_eq!(status, 503);
    assert!(browser.is_none());
    std::mem::forget(down); // the directory belongs to `env`
}
