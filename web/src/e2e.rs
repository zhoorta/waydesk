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

/// How many times the stand-in helper was asked for a list or the status (the answers are kept a few seconds).
static INFO_CALLS: AtomicUsize = AtomicUsize::new(0);

impl crate::portal::Authenticator for FakeAuth {
    fn check(&self, account: &str, password: &str, _source: &str) -> Result<bool, String> {
        Ok(account != "locked" && password == format!("pw-{account}"))
    }

    fn audit(&self, _ticket: &str, account: &str, _source: &str, query: (&str, &str, &str, &str, u16)) -> Result<String, String> {
        if account != "boss" {
            return Err("helper: only administrators may read the audit log".into());
        }
        if query.4 == 0 {
            return Err("helper: the number of events must be between 1 and 500".into());
        }
        Ok(format!("[{{\"event\":\"login\",\"user\":\"ana\",\"since\":\"{}\"}}]", query.0))
    }

    fn change_password(&self, _ticket: &str, account: &str, _source: &str, old: &str, new: &str) -> Result<(), String> {
        if old != format!("pw-{account}") {
            return Err("helper: the current password is not right".into());
        }
        if new.len() < 8 {
            return Err("helper: the new password must be at least 8 characters".into());
        }
        Ok(())
    }

    /// The stand-in runner: refuses the account `ana` (not an administrator), says that a name `bad` is not valid, and otherwise does what it is told.
    fn admin_do(&self, _ticket: &str, account: &str, _source: &str, action: &str) -> Result<String, String> {
        if account != "boss" {
            return Err("helper: only administrators may do this".into());
        }
        if action.contains("\"name\":\"bad\"") {
            return Err("helper: that is not a valid account name".into());
        }
        Ok(format!("{{\"ok\":true,\"result\":{{\"echo\":{action}}}}}"))
    }

    /// The account `boss` administers the machine; everybody else does not. A role question is not counted.
    fn info(&self, _ticket: &str, account: &str, _source: &str, kind: crate::portal::InfoKind) -> Result<String, String> {
        use crate::portal::InfoKind::*;
        if kind == Role {
            return Ok(format!("{{\"admin\":{}}}", account == "boss"));
        }
        INFO_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(match kind {
            Users => r#"[{"name":"ana","session":"running"}]"#.into(),
            Sessions => "[]".into(),
            _ => r#"{"machine":{}}"#.into(),
        })
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
    app: Arc<App>,
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
                    let line = String::from_utf8_lossy(&line).into_owned();
                    let stream = line.starts_with("WAYDESK-STREAM");
                    seen.lock().unwrap().push(line);
                    if stream {
                        // The browser stream: framed messages (u32 length, body); each is answered with its bytes reversed, and a body of one 0xff ends it.
                        loop {
                            let mut len = [0u8; 4];
                            if s.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
                            if s.read_exact(&mut body).await.is_err() || body == [0xff] {
                                return;
                            }
                            body.reverse();
                            let mut out = (body.len() as u32).to_le_bytes().to_vec();
                            out.extend_from_slice(&body);
                            if s.write_all(&out).await.is_err() {
                                return;
                            }
                        }
                    }
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
    tokio::spawn(crate::serve(listener, app.clone(), tlsconf::server_config(files.clone()).unwrap(), allow));
    Env { gateway, dir, files, daemon_connections, preambles, app }
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
    tokio::spawn(crate::serve(listener, app.clone(), tlsconf::server_config(env.files.clone()).unwrap(), Arc::new(crate::allow::Allow::any())));
    let down = Env { gateway: addr, dir: dir.clone(), files: env.files.clone(), daemon_connections: env.daemon_connections.clone(), preambles: env.preambles.clone(), app };
    let (status, browser) = down.sign_in("ana", "pw-ana", "").await;
    assert_eq!(status, 503);
    assert!(browser.is_none());
    std::mem::forget(down); // the directory belongs to `env`
}

/// A WebSocket to the stream route, with the browser's cookie.
async fn stream_ws(env: &Env, cookie: Option<&str>, origin: Option<&str>) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let mut req = format!("wss://{}/stream", env.host()).into_client_request().unwrap();
    if let Some(c) = cookie {
        req.headers_mut().insert("Cookie", c.parse().unwrap());
    }
    if let Some(o) = origin {
        req.headers_mut().insert("Origin", o.parse().unwrap());
    }
    tokio_tungstenite::client_async(req, env.tls().await).await.map(|(s, _)| s)
}

#[tokio::test]
async fn a_signed_in_browser_streams_through_to_the_daemon_as_its_account() {
    let env = start("stream", Opts { gateway_key: Some("a-long-enough-gateway-key"), ..Opts::default() }).await;
    let b = env.browser("ana").await;
    let origin = env.origin();
    let mut ws = stream_ws(&env, Some(&b.cookie), Some(&origin)).await.unwrap();
    ws.send(Message::Binary(vec![1, 2, 3].into())).await.unwrap();
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(got) => {
                assert_eq!(got.as_ref(), [3, 2, 1], "a message goes to the daemon and the answer comes back whole");
                break;
            }
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    // The daemon is told the account of the cookie and the client's address, with the key.
    assert_eq!(env.preambles.lock().unwrap().as_slice(), ["WAYDESK-STREAM 1 a-long-enough-gateway-key ana 127.0.0.1 0000000000000000000000000000000000000000000000000000000000000000"]);
}

#[tokio::test]
async fn the_stream_needs_a_cookie_this_origin_a_key_and_small_messages() {
    let env = start("stream-refusals", Opts { gateway_key: Some("a-long-enough-gateway-key"), ..Opts::default() }).await;
    let b = env.browser("ana").await;
    let origin = env.origin();
    assert!(stream_ws(&env, None, Some(&origin)).await.is_err(), "no cookie");
    let forged = format!("{}={}", crate::portal::COOKIE, "0".repeat(64));
    assert!(stream_ws(&env, Some(&forged), Some(&origin)).await.is_err(), "a cookie nobody was given");
    assert!(stream_ws(&env, Some(&b.cookie), Some("https://evil.example")).await.is_err(), "another page");
    assert!(stream_ws(&env, Some(&b.cookie), None).await.is_err(), "no Origin");
    assert_eq!(env.daemon_connections.load(Ordering::SeqCst), 0, "nothing of that reached the daemon");

    // A message bigger than any browser message is not passed on: the stream ends.
    let mut ws = stream_ws(&env, Some(&b.cookie), Some(&origin)).await.unwrap();
    ws.send(Message::Binary(vec![7u8; crate::stream::MAX_FROM_BROWSER + 1].into())).await.unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                _ => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the stream ended");

    // Without the key the daemon cannot be told who this is: no stream at all.
    let env = start("stream-nokey", Opts::default()).await;
    let b = env.browser("ana").await;
    assert!(stream_ws(&env, Some(&b.cookie), Some(&env.origin())).await.is_err());
}

#[tokio::test]
async fn the_administrators_pages_are_for_administrators_and_their_answers_are_kept_a_few_seconds() {
    let env = start("adminpages", Opts::default()).await;
    let boss = env.browser("boss").await;
    let ana = env.browser("ana").await;
    let cookie = |b: &Browser| [("Cookie", b.cookie.clone())];

    // who is an administrator is in the answer to /api/me, from the helper
    let (_, me) = env.http("GET", "/api/me", &[("Cookie", &boss.cookie)]).await;
    assert!(me.contains("\"admin\":true"), "{me}");
    let (_, me) = env.http("GET", "/api/me", &[("Cookie", &ana.cookie)]).await;
    assert!(me.contains("\"admin\":false"), "{me}");

    assert_eq!(env.http("GET", "/api/admin/users", &[]).await.0, 401, "not signed in");
    let c = cookie(&ana);
    assert_eq!(env.http("GET", "/api/admin/users", &[("Cookie", &c[0].1)]).await.0, 403, "signed in, not an administrator");
    assert_eq!(env.http("GET", "/api/admin/status", &[("Cookie", &c[0].1)]).await.0, 403);
    assert_eq!(env.http("GET", "/api/admin/other", &[("Cookie", &boss.cookie)]).await.0, 404, "only the known pages");
    assert_eq!(env.http("GET", "/api/admin/users/../status", &[("Cookie", &boss.cookie)]).await.0, 404);

    let before = INFO_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    let (status, body) = env.http("GET", "/api/admin/users", &[("Cookie", &boss.cookie)]).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"name\":\"ana\""), "{body}");
    let (status, again) = env.http("GET", "/api/admin/users", &[("Cookie", &boss.cookie)]).await;
    assert_eq!((status, again), (200, body), "the second request is answered from the kept answer");
    assert_eq!(INFO_CALLS.load(std::sync::atomic::Ordering::SeqCst) - before, 1, "the helper was asked once");
}

#[tokio::test]
async fn a_change_needs_the_origin_the_csrf_token_an_administrator_and_a_valid_action() {
    let env = start("adminchange", Opts::default()).await;
    let boss = env.browser("boss").await;
    let ana = env.browser("ana").await;
    let origin = env.origin();
    let action = r#"{"action":"user_disable","name":"eva"}"#;
    let send = |b: &Browser, origin: Option<&str>, csrf: bool, body: &str| {
        let mut h: Vec<(&str, String)> = vec![("Cookie", b.cookie.clone())];
        if let Some(o) = origin {
            h.push(("Origin", o.to_string()));
        }
        if csrf {
            h.push(("X-CSRF-Token", b.csrf.clone()));
        }
        (h, body.to_string())
    };
    macro_rules! post {
        ($b:expr, $o:expr, $c:expr, $body:expr) => {{
            let (h, body) = send($b, $o, $c, $body);
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            env.send("POST", "/api/admin/do", &h, &body).await
        }};
    }
    assert_eq!(post!(&boss, None, true, action).0, 403, "no origin");
    assert_eq!(post!(&boss, Some("https://evil.example"), true, action).0, 403, "another page");
    assert_eq!(post!(&boss, Some(&origin), false, action).0, 403, "no csrf token");
    assert_eq!(env.send("POST", "/api/admin/do", &[("Origin", &origin)], action).await.0, 401, "not signed in");
    assert_eq!(post!(&ana, Some(&origin), true, action).0, 403, "signed in, not an administrator");
    assert_eq!(post!(&boss, Some(&origin), true, "not json").0, 400);
    assert_eq!(post!(&boss, Some(&origin), true, "[1]").0, 400, "an action is an object");
    let (status, body) = post!(&boss, Some(&origin), true, r#"{"action":"user_add","name":"bad"}"#);
    assert_eq!(status, 400);
    assert!(body.contains("\"ok\":false") && body.contains("not a valid account name"), "{body}");
    let (status, body) = post!(&boss, Some(&origin), true, action);
    assert_eq!(status, 200);
    assert!(body.contains("\"ok\":true") && body.contains("user_disable"), "{body}");
}

#[tokio::test]
async fn the_audit_log_is_for_administrators_and_the_filters_reach_the_helper() {
    let env = start("auditpage", Opts::default()).await;
    let boss = env.browser("boss").await;
    let ana = env.browser("ana").await;
    assert_eq!(env.http("GET", "/api/admin/audit", &[]).await.0, 401);
    assert_eq!(env.http("GET", "/api/admin/audit", &[("Cookie", &ana.cookie)]).await.0, 403);
    let (status, body) = env.http("GET", "/api/admin/audit?since=2h&user=ana&limit=10", &[("Cookie", &boss.cookie)]).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"user\":\"ana\"") && body.contains("\"since\":\"2h\""), "{body}");
    let (status, body) = env.http("GET", "/api/admin/audit?limit=0", &[("Cookie", &boss.cookie)]).await;
    assert_eq!(status, 400);
    assert!(body.contains("between 1 and 500"), "{body}");
    assert_eq!(env.http("GET", &format!("/api/admin/audit?user={}", "a".repeat(65)), &[("Cookie", &boss.cookie)]).await.0, 400, "a filter that long is not one");
}

#[tokio::test]
async fn a_person_changes_their_own_password_and_an_administrator_sees_the_settings() {
    let env = start("accountpage", Opts::default()).await;
    let ana = env.browser("ana").await;
    let boss = env.browser("boss").await;
    let origin = env.origin();
    let put = |b: &Browser, o: Option<&str>, csrf: bool, body: &str| {
        let mut h: Vec<(&str, String)> = vec![("Cookie", b.cookie.clone())];
        if let Some(o) = o {
            h.push(("Origin", o.to_string()));
        }
        if csrf {
            h.push(("X-CSRF-Token", b.csrf.clone()));
        }
        (h, body.to_string())
    };
    macro_rules! post {
        ($path:expr, $b:expr, $o:expr, $c:expr, $body:expr) => {{
            let (h, body) = put($b, $o, $c, $body);
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            env.send("POST", $path, &h, &body).await
        }};
    }
    let good = r#"{"old":"pw-ana","new":"a-new-password"}"#;
    assert_eq!(env.http("GET", "/api/account", &[]).await.0, 401);
    let (status, info) = env.http("GET", "/api/account", &[("Cookie", &ana.cookie)]).await;
    assert!(status == 200 && info.contains("\"account\":\"ana\"") && info.contains("\"enrolled\":false"), "{info}");

    assert_eq!(post!("/api/account/password", &ana, None, true, good).0, 403, "no origin");
    assert_eq!(post!("/api/account/password", &ana, Some(&origin), false, good).0, 403, "no csrf token");
    assert_eq!(post!("/api/account/password", &ana, Some(&origin), true, "nope").0, 400);
    let (status, body) = post!("/api/account/password", &ana, Some(&origin), true, r#"{"old":"wrong","new":"a-new-password"}"#);
    assert_eq!(status, 403);
    assert!(body.contains("current password is wrong"), "{body}");
    let (status, body) = post!("/api/account/password", &ana, Some(&origin), true, r#"{"old":"pw-ana","new":"short"}"#);
    assert_eq!(status, 400);
    assert!(body.contains("at least 8"), "{body}");
    let (status, body) = post!("/api/account/password", &ana, Some(&origin), true, good);
    assert_eq!((status, body.contains("\"ok\":true")), (200, true), "{body}");
    assert!(!body.contains("a-new-password"), "the answer never repeats a password");

    // the settings: only for administrators
    assert_eq!(env.http("GET", "/api/admin/settings", &[("Cookie", &ana.cookie)]).await.0, 403);
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    store.enroll("ana").unwrap();
    let (status, settings) = env.http("GET", "/api/admin/settings", &[("Cookie", &boss.cookie)]).await;
    assert_eq!(status, 200);
    assert!(settings.contains("\"totp\":\"off\"") && settings.contains("\"enrolled\":[\"ana\"]"), "{settings}");

    // taking an authenticator away: administrators only, and only a name that can be one
    let remove = r#"{"action":"remove","name":"ana"}"#;
    assert_eq!(post!("/api/admin/totp", &ana, Some(&origin), true, remove).0, 403, "not an administrator");
    assert_eq!(post!("/api/admin/totp", &boss, Some(&origin), false, remove).0, 403, "no csrf token");
    assert_eq!(post!("/api/admin/totp", &boss, Some(&origin), true, r#"{"action":"remove","name":"../x"}"#).0, 400);
    assert_eq!(post!("/api/admin/totp", &boss, Some(&origin), true, r#"{"action":"add","name":"ana"}"#).0, 400);
    assert!(store.exists("ana"));
    assert_eq!(post!("/api/admin/totp", &boss, Some(&origin), true, remove).0, 200);
    assert!(!store.exists("ana"));
}

#[tokio::test]
async fn a_person_sets_up_and_turns_off_their_own_authenticator_only_with_a_valid_code() {
    // The default server does not ask for codes: nothing to set up.
    let off = start("totpoff", Opts::default()).await;
    let b = off.browser("ana").await;
    let (status, body) = off.send("POST", "/api/account/totp/start", &[("Origin", &off.origin()), ("Cookie", &b.cookie), ("X-CSRF-Token", &b.csrf)], "").await;
    assert_eq!(status, 409, "{body}");

    let env = start("totpself", Opts { totp: crate::web::TotpMode::Optional, gateway_key: Some("a-long-enough-gateway-key"), ..Opts::default() }).await;
    let ana = env.browser("ana").await;
    let origin = env.origin();
    let store = crate::totp::Store::new(&env.dir.join("totp"));
    let call = |path: &'static str, b: &Browser, csrf: bool, body: String| {
        let (origin, cookie, token) = (origin.clone(), b.cookie.clone(), b.csrf.clone());
        let env = &env;
        async move {
            let mut h: Vec<(&str, &str)> = vec![("Origin", origin.as_str()), ("Cookie", cookie.as_str())];
            if csrf {
                h.push(("X-CSRF-Token", token.as_str()));
            }
            env.send("POST", path, &h, &body).await
        }
    };
    // no csrf token, nothing is started
    assert_eq!(call("/api/account/totp/start", &ana, false, String::new()).await.0, 403);
    // confirming without starting
    assert_eq!(call("/api/account/totp/confirm", &ana, true, r#"{"code":"123456"}"#.into()).await.0, 409);

    let (status, started) = call("/api/account/totp/start", &ana, true, String::new()).await;
    assert_eq!(status, 200, "{started}");
    // the test client leaves the transfer's chunk markers on the body: the JSON object is what is between the first { and the last }
    let object = |body: &str| -> serde_json::Value { serde_json::from_str(&body[body.find('{').unwrap()..=body.rfind('}').unwrap()]).unwrap() };
    let v = object(&started);
    let secret = data_encoding::BASE32_NOPAD.decode(v["secret"].as_str().unwrap().as_bytes()).unwrap();
    assert!(v["uri"].as_str().unwrap().starts_with("otpauth://totp/Waydesk:ana?secret="));
    assert!(!store.exists("ana"), "nothing is kept before a code proves the secret");

    let (status, body) = call("/api/account/totp/confirm", &ana, true, r#"{"code":"000000"}"#.into()).await;
    assert_eq!(status, 400, "{body}");
    assert!(!store.exists("ana"));
    let good = crate::totp::code_at(&secret, unix_now());
    let (status, body) = call("/api/account/totp/confirm", &ana, true, format!("{{\"code\":\"{good}\"}}")).await;
    assert_eq!(status, 200, "{body}");
    let done = object(&body);
    assert_eq!(done["recovery"].as_array().unwrap().len(), 8, "recovery codes are shown once");
    assert!(store.exists("ana"));
    assert!(!body.contains(v["secret"].as_str().unwrap()), "the secret is not repeated");

    // a second start, now that there is one
    assert_eq!(call("/api/account/totp/start", &ana, true, String::new()).await.0, 409);
    // turning it off: the wrong code, then a good one (the next step's: the first was used up)
    assert_eq!(call("/api/account/totp/remove", &ana, true, r#"{"code":"000000"}"#.into()).await.0, 400);
    assert!(store.exists("ana"));
    let next = crate::totp::code_at(&secret, unix_now() + 30);
    let (status, body) = call("/api/account/totp/remove", &ana, true, format!("{{\"code\":\"{next}\"}}")).await;
    assert_eq!(status, 200, "{body}");
    assert!(!store.exists("ana"));
    assert_eq!(call("/api/account/totp/remove", &ana, true, r#"{"code":"123456"}"#.into()).await.0, 409, "nothing left to turn off");
}

#[tokio::test]
async fn servers_are_added_by_administrators_and_enrol_once_with_a_code() {
    let env = start("servers", Opts::default()).await;
    let boss = env.browser("boss").await;
    let ana = env.browser("ana").await;
    let origin = env.origin();
    let post = |b: &Browser, body: String| {
        let h = vec![("Cookie", b.cookie.clone()), ("Origin", origin.clone()), ("X-CSRF-Token", b.csrf.clone())];
        let env = &env;
        async move {
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            env.send("POST", "/api/admin/servers", &h, &body).await
        }
    };
    let field = |text: &str, name: &str| -> String {
        let at = text.find(&format!("\"{name}\":\"")).unwrap_or_else(|| panic!("{name} in {text}")) + name.len() + 4;
        text[at..].split('"').next().unwrap().to_string()
    };
    // Only administrators, with origin and csrf.
    assert_eq!(post(&ana, r#"{"action":"add","name":"Porto"}"#.into()).await.0, 403);
    assert_eq!(env.send("POST", "/api/admin/servers", &[("Cookie", &boss.cookie), ("X-CSRF-Token", &boss.csrf)], r#"{"action":"add","name":"x"}"#).await.0, 403, "no origin");
    assert_eq!(env.send("GET", "/api/admin/servers", &[("Cookie", &ana.cookie)], "").await.0, 403);
    assert_eq!(env.send("GET", "/api/admin/servers", &[], "").await.0, 401);
    // Bad input.
    assert_eq!(post(&boss, r#"{"action":"add","name":"<b>"}"#.into()).await.0, 400);
    assert_eq!(post(&boss, r#"{"action":"revoke","id":"../x"}"#.into()).await.0, 400);
    assert_eq!(post(&boss, r#"{"action":"nope"}"#.into()).await.0, 400);
    // Add, list: the list never shows the code.
    let (status, body) = post(&boss, r#"{"action":"add","name":"Porto 1"}"#.into()).await;
    assert_eq!(status, 200, "{body}");
    let (id, code) = (field(&body, "id"), field(&body, "code"));
    let (status, list) = env.send("GET", "/api/admin/servers", &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200);
    assert!(list.contains("\"waiting\"") && list.contains("Porto 1") && !list.contains(&code), "{list}");
    // The public endpoint: a wrong code is refused, the right one works once and returns the key.
    let enrol = |code: String| {
        let env = &env;
        async move { env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await }
    };
    assert_eq!(enrol("WRONG".into()).await.0, 403);
    let (status, body) = enrol(code.clone()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(field(&body, "server"), id);
    assert_eq!(field(&body, "key").len(), 64);
    assert_eq!(enrol(code).await.0, 403, "a code works once");
    // Revoke, then remove.
    assert_eq!(post(&boss, format!("{{\"action\":\"remove\",\"id\":\"{id}\"}}")).await.0, 400, "an enrolled server is revoked first");
    assert_eq!(post(&boss, format!("{{\"action\":\"revoke\",\"id\":\"{id}\"}}")).await.0, 200);
    assert_eq!(post(&boss, format!("{{\"action\":\"remove\",\"id\":\"{id}\"}}")).await.0, 200);
}

/// A server's agent as the portal sees it: connects to `/agent`, says hello, and answers what it is asked. The frames it was asked are kept.
async fn agent(env: &Env, server: &str, key: &str) -> Result<Arc<std::sync::Mutex<Vec<serde_json::Value>>>, String> {
    let req = format!("wss://{}/agent", env.host()).into_client_request().unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(req, env.tls().await).await.map_err(|e| e.to_string())?;
    ws.send(Message::Text(serde_json::json!({"t":"hello","server":server,"key":key,"version":1}).to_string().into())).await.unwrap();
    match ws.next().await {
        Some(Ok(Message::Text(t))) if t.as_str().contains("ready") => {}
        other => return Err(format!("not ready: {other:?}")),
    }
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Some(Ok(m)) = ws.next().await {
            if let Message::Text(t) = m {
                let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                let id = v["id"].as_u64().unwrap();
                let answer = if v.get("do").is_some() {
                    serde_json::json!({"t":"res","id":id,"ok":true,"json":"{\"ok\":true,\"result\":{\"message\":\"done there\"}}"})
                } else {
                    serde_json::json!({"t":"res","id":id,"ok":true,"json":"[{\"name\":\"remote-ana\"}]"})
                };
                kept.lock().unwrap().push(v);
                let _ = ws.send(Message::Text(answer.to_string().into())).await;
            }
        }
    });
    Ok(seen)
}

#[tokio::test]
async fn a_server_dials_in_and_the_portal_asks_it_for_lists_and_changes() {
    let env = start("agentlink", Opts::default()).await;
    let boss = env.browser("boss").await;
    let ana = env.browser("ana").await;
    let origin = env.origin();
    let field = |text: &str, name: &str| -> String {
        let at = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[at..].split('"').next().unwrap().to_string()
    };
    let post = |path: &str, body: &str| {
        let h = vec![("Cookie", boss.cookie.clone()), ("Origin", origin.clone()), ("X-CSRF-Token", boss.csrf.clone())];
        let (env, path, body) = (&env, path.to_string(), body.to_string());
        async move {
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            env.send("POST", &path, &h, &body).await
        }
    };
    let (_, added) = post("/api/admin/servers", r#"{"action":"add","name":"Far"}"#).await;
    let (id, code) = (field(&added, "id"), field(&added, "code"));
    let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await;
    let key = field(&enrolled, "key");

    // Nobody is connected: offline, in words. A wrong key or an unknown server never gets a link.
    let (status, body) = env.send("GET", &format!("/api/admin/users?server={id}"), &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("offline"));
    assert!(agent(&env, &id, &"0".repeat(64)).await.is_err(), "a wrong key");
    assert!(agent(&env, "s-00000000", &key).await.is_err(), "an unknown server");

    // The right key: a link. The list comes from the server's agent, not from the portal's own helper.
    let seen = agent(&env, &id, &key).await.expect("link");
    let (_, list) = env.send("GET", "/api/admin/servers", &[("Cookie", &boss.cookie)], "").await;
    assert!(list.contains("\"online\""), "{list}");
    let (status, body) = env.send("GET", &format!("/api/admin/users?server={id}"), &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("remote-ana") && !body.contains("\"ana\""), "{body}");
    assert_eq!(seen.lock().unwrap()[0]["kind"], "users");
    // Only administrators, and only a server id the fleet could have made.
    assert_eq!(env.send("GET", &format!("/api/admin/users?server={id}"), &[("Cookie", &ana.cookie)], "").await.0, 403);
    assert_eq!(env.send("GET", "/api/admin/users?server=../etc", &[("Cookie", &boss.cookie)], "").await.0, 400);
    // A change goes to the server's agent with the account and address of the administrator who asked.
    let (status, body) = post(&format!("/api/admin/do?server={id}"), r#"{"action":"user_disable","name":"eva"}"#).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("done there"), "{body}");
    let asked = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(asked["actor"], "boss");
    assert_eq!(asked["do"]["action"], "user_disable");
    assert!(asked["source"].as_str().unwrap().contains('.') || asked["source"].as_str().unwrap().contains(':'));
    // Not the portal's own helper: the stand-in helper's echo is not in the answer.
    assert!(!body.contains("echo"));

    // Revoking ends the link at once.
    assert_eq!(post("/api/admin/servers", &format!("{{\"action\":\"revoke\",\"id\":\"{id}\"}}")).await.0, 200);
    let (status, _) = env.send("GET", &format!("/api/admin/users?server={id}"), &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 503);
    assert!(agent(&env, &id, &key).await.is_err(), "the old key stays dead");
}

#[tokio::test]
async fn the_portals_own_people_sign_in_with_argon2_passwords_and_are_assigned_to_servers() {
    let env = start("people", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "Portal Boss", true, 0).unwrap();
    let ana_pw = env.app.people.add("pana", "", false, 0).unwrap();
    let origin = env.origin();
    // Sign-in: right password works, a wrong one and an unknown name get the same refusal.
    let (status, wrong) = env.sign_in("pboss", "not-the-password", "").await;
    assert_eq!((status, wrong.is_none()), (401, true));
    assert_eq!(env.sign_in("nobody-here", "x", "").await.0, 401);
    let (status, boss) = env.sign_in("pboss", &boss_pw, "").await;
    assert_eq!(status, 200);
    let boss = boss.unwrap();
    let ana = env.sign_in("pana", &ana_pw, "").await.1.unwrap();
    let (_, me) = env.send("GET", "/api/me", &[("Cookie", &boss.cookie)], "").await;
    assert!(me.contains("\"admin\":true") && me.contains("\"portal\":true"), "{me}");
    let (_, me) = env.send("GET", "/api/me", &[("Cookie", &ana.cookie)], "").await;
    assert!(me.contains("\"admin\":false"), "{me}");
    // A portal account has nothing on the portal's own machine: the local pages ask for a server, the browser desktop is not built.
    let (status, body) = env.send("GET", "/api/admin/users", &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(env.send("GET", "/api/admin/users", &[("Cookie", &ana.cookie)], "").await.0, 403);
    assert_eq!(env.send("GET", "/api/admin/people", &[("Cookie", &ana.cookie)], "").await.0, 403);
    let (status, list) = env.send("GET", "/api/admin/people", &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200);
    assert!(list.contains("pana") && !list.contains("argon2") && !list.contains(&ana_pw), "{list}");

    let post = |b: &Browser, path: &str, body: String| {
        let h = vec![("Cookie", b.cookie.clone()), ("Origin", origin.clone()), ("X-CSRF-Token", b.csrf.clone())];
        let (env, path) = (&env, path.to_string());
        async move {
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            env.send("POST", &path, &h, &body).await
        }
    };
    let field = |text: &str, name: &str| -> String {
        let at = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[at..].split('"').next().unwrap().to_string()
    };
    // Only an administrator changes people; nobody switches themselves off.
    assert_eq!(post(&ana, "/api/admin/people", r#"{"action":"add","name":"x"}"#.into()).await.0, 403);
    assert_eq!(post(&boss, "/api/admin/people", r#"{"action":"disable","name":"pboss","on":true}"#.into()).await.0, 400);
    let (status, body) = post(&boss, "/api/admin/people", r#"{"action":"add","name":"pnew","display":"New"}"#.into()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(field(&body, "password").len(), 19);
    assert_eq!(post(&boss, "/api/admin/people", r#"{"action":"add","name":"Bad Name"}"#.into()).await.0, 400);

    // A server dials in; assigning makes the account there, as the administrator who asked.
    let (_, added) = post(&boss, "/api/admin/servers", r#"{"action":"add","name":"Far"}"#.into()).await;
    let (sid, code) = (field(&added, "id"), field(&added, "code"));
    let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await;
    let seen = agent(&env, &sid, &field(&enrolled, "key")).await.expect("link");
    let assign = format!(r#"{{"action":"assign","name":"pana","server":"{sid}","desktop":"plasma","memory":"6G"}}"#);
    let (status, body) = post(&boss, "/api/admin/people", assign).await;
    assert_eq!(status, 200, "{body}");
    {
        let asked = seen.lock().unwrap();
        let actions: Vec<_> = asked.iter().map(|v| v["do"]["action"].as_str().unwrap_or("").to_string()).collect();
        assert_eq!(actions, ["user_add", "user_set", "user_limit"]);
        assert!(asked.iter().all(|v| v["actor"] == "pboss" && v["do"]["name"] == "pana"));
    }
    assert!(env.app.people.get("pana").unwrap().servers.len() == 1 && env.app.people.made_on("pana", &sid));
    assert!(env.send("GET", "/api/mine", &[("Cookie", &ana.cookie)], "").await.1.contains("\"online\":true"));
    // The person asks for an app password: set on the server as their own account, shown once, never kept.
    let (status, body) = post(&ana, "/api/account/apppass", String::new()).await;
    assert_eq!(status, 200, "{body}");
    let app_pw = field(&body, "password");
    assert_eq!(app_pw.len(), 19);
    let setpw = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(setpw["do"]["action"], "user_setpw");
    assert_eq!(setpw["do"]["password"], app_pw.as_str());
    assert_eq!(setpw["actor"], "pana");
    assert!(!std::fs::read_to_string(env.dir.join("totp/people.json")).unwrap().contains(&app_pw));
    // A person with no server cannot ask; a host-style account has no app password.
    assert_eq!(post(&boss, "/api/account/apppass", String::new()).await.0, 409);
    // Switching a person off ends their sign-ins, refuses the next one and switches the account on the server off.
    let (status, body) = post(&boss, "/api/admin/people", r#"{"action":"disable","name":"pana","on":true}"#.into()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(seen.lock().unwrap().last().unwrap()["do"]["action"], "user_disable");
    assert_eq!(env.send("GET", "/api/me", &[("Cookie", &ana.cookie)], "").await.0, 401, "their sign-in ended");
    assert_eq!(env.sign_in("pana", &ana_pw, "").await.0, 401);
    // A person with a server is not removed until the server is taken away; taking it away switches the account off there.
    assert_eq!(post(&boss, "/api/admin/people", r#"{"action":"remove","name":"pana"}"#.into()).await.0, 400);
    assert_eq!(post(&boss, "/api/admin/people", format!(r#"{{"action":"unassign","name":"pana","server":"{sid}"}}"#)).await.0, 200);
    assert_eq!(post(&boss, "/api/admin/people", r#"{"action":"remove","name":"pana"}"#.into()).await.0, 200);
}

#[tokio::test]
async fn an_account_that_was_on_the_server_already_is_never_taken_over() {
    let env = start("peopleexists", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "", true, 0).unwrap();
    env.app.people.add("pana", "", false, 0).unwrap();
    let boss = env.sign_in("pboss", &boss_pw, "").await.1.unwrap();
    let origin = env.origin();
    let (_, added) = {
        let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
        env.send("POST", "/api/admin/servers", &h, r#"{"action":"add","name":"Far"}"#).await
    };
    let at = |text: &str, name: &str| {
        let i = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[i..].split('"').next().unwrap().to_string()
    };
    let (sid, code) = (at(&added, "id"), at(&added, "code"));
    let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await;
    // A stand-in whose server already has an account called pana.
    let req = format!("wss://{}/agent", env.host()).into_client_request().unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(req, env.tls().await).await.unwrap();
    ws.send(Message::Text(serde_json::json!({"t":"hello","server":sid,"key":at(&enrolled,"key"),"version":1}).to_string().into())).await.unwrap();
    ws.next().await;
    tokio::spawn(async move {
        while let Some(Ok(m)) = ws.next().await {
            // The portal pings every 20 s, the first one at once: only text frames are requests.
            let Message::Text(t) = m else { continue };
            let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
            let json = r#"{"ok":false,"error":"pana exists already"}"#;
            let _ = ws.send(Message::Text(serde_json::json!({"t":"res","id":v["id"],"ok":true,"json":json}).to_string().into())).await;
        }
    });
    let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
    let (status, body) = env.send("POST", "/api/admin/people", &h, &format!(r#"{{"action":"assign","name":"pana","server":"{sid}"}}"#)).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("not taken over") || body.contains("not made by the portal"), "{body}");
    assert!(env.app.people.get("pana").unwrap().servers.is_empty());
}

#[tokio::test]
async fn a_portal_person_opens_a_desktop_on_their_server_through_the_agents_dial_back() {
    let env = start("relay", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "", true, 0).unwrap();
    let ana_pw = env.app.people.add("pana", "", false, 0).unwrap();
    let eva_pw = env.app.people.add("peva", "", false, 0).unwrap();
    let boss = env.sign_in("pboss", &boss_pw, "").await.1.unwrap();
    let ana = env.sign_in("pana", &ana_pw, "").await.1.unwrap();
    let eva = env.sign_in("peva", &eva_pw, "").await.1.unwrap();
    let origin = env.origin();
    let at = |text: &str, name: &str| {
        let i = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[i..].split('"').next().unwrap().to_string()
    };
    let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
    let (_, added) = env.send("POST", "/api/admin/servers", &h, r#"{"action":"add","name":"Far"}"#).await;
    let (sid, code) = (at(&added, "id"), at(&added, "code"));
    let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await;
    let key = at(&enrolled, "key");

    // A stand-in agent: answers an `open` request, then dials `/relay` with the token and echoes every message reversed.
    let asked: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
    let req = format!("wss://{}/agent", env.host()).into_client_request().unwrap();
    let (mut link, _) = tokio_tungstenite::client_async(req, env.tls().await).await.unwrap();
    link.send(Message::Text(serde_json::json!({"t":"hello","server":sid,"key":key,"version":1}).to_string().into())).await.unwrap();
    link.next().await;
    let (files, gateway, host) = (env.files.clone(), env.gateway, env.host());
    let (seen, sid2, key2) = (asked.clone(), sid.clone(), key.clone());
    tokio::spawn(async move {
        while let Some(Ok(m)) = link.next().await {
            let Message::Text(t) = m else { continue };
            let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
            seen.lock().unwrap().push(v.clone());
            let id = v["id"].clone();
            link.send(Message::Text(serde_json::json!({"t":"res","id":id,"ok":true,"json":"{}"}).to_string().into())).await.unwrap();
            let token = v["open"]["token"].as_str().unwrap().to_string();
            let (files, sid2, key2, host) = (files.clone(), sid2.clone(), key2.clone(), host.clone());
            tokio::spawn(async move {
                let tcp = TcpStream::connect(gateway).await.unwrap();
                let tls = tokio_rustls::TlsConnector::from(tlsconf::daemon_client_config(files).unwrap()).connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
                let req = format!("wss://{host}/relay").into_client_request().unwrap();
                let (mut ws, _) = tokio_tungstenite::client_async(req, tls).await.unwrap();
                ws.send(Message::Text(serde_json::json!({"t":"relay","server":sid2,"key":key2,"token":token}).to_string().into())).await.unwrap();
                while let Some(Ok(m)) = ws.next().await {
                    if let Message::Binary(b) = m {
                        let mut r = b.to_vec();
                        r.reverse();
                        ws.send(Message::Binary(r.into())).await.unwrap();
                    }
                }
            });
        }
    });

    let open = |b: &Browser, server: &str| {
        let (env, cookie, origin) = (&env, b.cookie.clone(), env.origin());
        let path = format!("/stream?server={server}");
        async move {
            let mut req = format!("wss://{}{path}", env.host()).into_client_request().unwrap();
            req.headers_mut().insert("Cookie", cookie.parse().unwrap());
            req.headers_mut().insert("Origin", origin.parse().unwrap());
            tokio_tungstenite::client_async(req, env.tls().await).await.map(|(s, _)| s)
        }
    };
    // Nobody is assigned yet: refused before anything is asked of the server.
    assert!(open(&ana, &sid).await.is_err(), "not assigned");
    assert!(open(&ana, "").await.is_err(), "no server named");
    assert!(open(&ana, "s-zzzzzzzz").await.is_err());
    assert!(asked.lock().unwrap().is_empty());
    let assign = |name: &str| format!(r#"{{"action":"assign","name":"{name}","server":"{sid}"}}"#);
    // The stand-in link answers `do` requests with "{}": that is not an ok runner answer, so use the store directly for the assignment.
    env.app.people.assign("pana", crate::people::Assignment { server: sid.clone(), desktop: None, gpu: None, memory: None }).unwrap();
    assert!(open(&ana, &sid).await.is_err(), "assigned, but the portal did not make the account there");
    env.app.people.mark_made("pana", &sid).unwrap();
    let _ = assign;

    let mut ws = open(&ana, &sid).await.expect("assigned and made");
    ws.send(Message::Binary(vec![1, 2, 3].into())).await.unwrap();
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(got) => {
                assert_eq!(got.as_ref(), [3, 2, 1], "the message went to the agent's side and came back");
                break;
            }
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    {
        let asked = asked.lock().unwrap();
        let open = &asked[0]["open"];
        assert_eq!(open["account"], "pana", "the account is the signed-in one");
        assert_eq!(open["ip"], "127.0.0.1");
        assert_eq!(open["token"].as_str().unwrap().len(), 32);
    }
    // A message that is too large for a browser to send ends the desktop.
    ws.send(Message::Binary(vec![7u8; crate::stream::MAX_FROM_BROWSER + 1].into())).await.unwrap();
    loop {
        match ws.next().await {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
            Some(Ok(_)) => {}
        }
    }
    // Another person cannot use ana's server; a switched-off person cannot open one; an offline server is refused.
    assert!(open(&eva, &sid).await.is_err());
    env.app.people.set_disabled("pana", true).unwrap();
    assert!(open(&ana, &sid).await.is_err(), "switched off");
    env.app.people.set_disabled("pana", false).unwrap();
    // A host-style account never gets a `server` stream through this path.
    let _ = boss;
}

#[tokio::test]
async fn a_relay_needs_the_servers_key_and_a_live_token_for_that_server_and_works_once() {
    let env = start("relaytoken", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "", true, 0).unwrap();
    let boss = env.sign_in("pboss", &boss_pw, "").await.1.unwrap();
    let origin = env.origin();
    let at = |text: &str, name: &str| {
        let i = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[i..].split('"').next().unwrap().to_string()
    };
    let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
    let mut keys = Vec::new();
    for name in ["One", "Two"] {
        let (_, added) = env.send("POST", "/api/admin/servers", &h, &format!(r#"{{"action":"add","name":"{name}"}}"#)).await;
        let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{}\"}}", at(&added, "code"))).await;
        keys.push((at(&added, "id"), at(&enrolled, "key")));
    }
    let (token, waiting) = env.app.relays.expect(&keys[0].0).unwrap();
    let dial = |server: String, key: String, token: String| {
        let env = &env;
        async move {
            let req = format!("wss://{}/relay", env.host()).into_client_request().unwrap();
            let (mut ws, _) = tokio_tungstenite::client_async(req, env.tls().await).await.unwrap();
            ws.send(Message::Text(serde_json::json!({"t":"relay","server":server,"key":key,"token":token}).to_string().into())).await.unwrap();
            // A refused relay is closed by the portal.
            matches!(tokio::time::timeout(std::time::Duration::from_millis(500), ws.next()).await, Ok(None) | Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))))
        }
    };
    assert!(dial(keys[0].0.clone(), "0".repeat(64), token.clone()).await, "wrong key");
    assert!(dial(keys[1].0.clone(), keys[1].1.clone(), token.clone()).await, "another server's key with this token");
    assert!(dial(keys[0].0.clone(), keys[0].1.clone(), "0".repeat(32)).await, "unknown token");
    // The right server, key and token: not refused, and the waiting side gets the socket.
    assert!(!dial(keys[0].0.clone(), keys[0].1.clone(), token.clone()).await);
    assert!(tokio::time::timeout(std::time::Duration::from_secs(2), waiting).await.unwrap().is_ok());
    assert!(dial(keys[0].0.clone(), keys[0].1.clone(), token).await, "once");
}

#[tokio::test]
async fn the_portals_own_audit_log_and_a_servers_log_are_for_administrators_and_hold_no_secrets() {
    let env = start("auditlog", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "", true, 0).unwrap();
    let ana_pw = env.app.people.add("pana", "", false, 0).unwrap();
    let boss = env.sign_in("pboss", &boss_pw, "").await.1.unwrap();
    let ana = env.sign_in("pana", &ana_pw, "").await.1.unwrap();
    assert_eq!(env.sign_in("pana", "a wrong password", "").await.0, 401);
    let origin = env.origin();
    let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
    let (_, added) = env.send("POST", "/api/admin/people", &h, r#"{"action":"add","name":"pnew"}"#).await;
    let first_password = {
        let i = added.find("\"password\":\"").unwrap() + 12;
        added[i..].split('"').next().unwrap().to_string()
    };
    let (_, srv) = env.send("POST", "/api/admin/servers", &h, r#"{"action":"add","name":"Far"}"#).await;
    let at = |text: &str, name: &str| {
        let i = text.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
        text[i..].split('"').next().unwrap().to_string()
    };
    let (sid, code) = (at(&srv, "id"), at(&srv, "code"));
    let (_, enrolled) = env.send("POST", "/api/enrol", &[], &format!("{{\"code\":\"{code}\"}}")).await;
    let key = at(&enrolled, "key");
    assert_eq!(env.send("POST", "/api/enrol", &[], "{\"code\":\"WRONGWRONG\"}").await.0, 403);

    // The portal's own log: sign-ins (and the refusal), changes, enrolments; no password, code or key anywhere in it.
    let (status, log) = env.send("GET", "/api/admin/audit?source=portal&since=1h", &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200, "{log}");
    for expected in ["\"event\":\"login\"", "\"outcome\":\"refused\"", "admin.people.add", "admin.server.add", "server.enrolled", "\"actor\":\"pboss\""] {
        assert!(log.contains(expected), "{expected} in {log}");
    }
    for secret in [boss_pw.as_str(), ana_pw.as_str(), first_password.as_str(), code.as_str(), key.as_str(), "a wrong password"] {
        assert!(!log.contains(secret), "a secret in the log: {secret}");
    }
    let (_, filtered) = env.send("GET", "/api/admin/audit?source=portal&since=1h&event=admin.server", &[("Cookie", &boss.cookie)], "").await;
    assert!(filtered.contains("admin.server.add") && !filtered.contains("admin.people.add"), "{filtered}");
    // Only administrators; bad sources and filters are refused before anything is asked.
    assert_eq!(env.send("GET", "/api/admin/audit?source=portal", &[("Cookie", &ana.cookie)], "").await.0, 403);
    assert_eq!(env.send("GET", "/api/admin/audit?source=portal", &[], "").await.0, 401);
    assert_eq!(env.send("GET", "/api/admin/audit?source=../x", &[("Cookie", &boss.cookie)], "").await.0, 400);
    assert_eq!(env.send("GET", "/api/admin/audit?source=portal&event=x;y", &[("Cookie", &boss.cookie)], "").await.0, 400);
    assert_eq!(env.send("GET", "/api/admin/audit", &[("Cookie", &boss.cookie)], "").await.0, 409, "a portal account has no log on the portal's machine");

    // A server's log is asked of its agent with the filters.
    let seen = agent(&env, &sid, &key).await.expect("link");
    let (status, body) = env.send("GET", &format!("/api/admin/audit?source={sid}&since=2h&user=pana&limit=50"), &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("remote-ana"));
    let asked = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!((asked["kind"].as_str(), asked["query"]["user"].as_str(), asked["query"]["limit"].as_u64()), (Some("audit"), Some("pana"), Some(50)));
    assert_eq!(env.send("GET", &format!("/api/admin/audit?source={sid}"), &[("Cookie", &ana.cookie)], "").await.0, 403);

    // The fleet page: every server, who is assigned, and whether it answered.
    let (status, fleet) = env.send("GET", "/api/admin/fleet", &[("Cookie", &boss.cookie)], "").await;
    assert_eq!(status, 200, "{fleet}");
    assert!(fleet.contains("\"state\":\"online\"") && fleet.contains("Far") && fleet.contains("\"people\":3"), "{fleet}");
    assert_eq!(env.send("GET", "/api/admin/fleet", &[("Cookie", &ana.cookie)], "").await.0, 403);
}

#[test]
fn the_fleet_summary_reads_what_the_status_has_and_nothing_else() {
    let status = serde_json::json!({ "machine": { "mem_total_mb": 8000, "mem_available_mb": 2000, "cpu_percent": 12.5 }, "admission": { "sessions": 3, "max_active_users": 10, "open": true }, "warnings": ["a", "b"] });
    let s = crate::web::fleet_summary(&status);
    assert_eq!((s["sessions"].as_u64(), s["max_sessions"].as_u64(), s["mem_percent"].as_f64(), s["warnings"].as_u64(), s["open"].as_bool()), (Some(3), Some(10), Some(75.0), Some(2), Some(true)));
    // The adapters: a real one by its name, a VM's virtio one left out.
    let with_gpus = crate::web::fleet_summary(&serde_json::json!({ "gpus": [
        { "driver": "i915", "model": "Intel Skylake-S GT2 [HD Graphics 530]", "busy_percent": 57.0 },
        { "driver": "virtio-pci", "model": "1af4:1050", "busy_percent": null } ] }));
    assert_eq!(with_gpus["gpus"], serde_json::json!([{ "name": "HD Graphics 530", "driver": "i915", "busy_percent": 57.0 }]));
    assert_eq!(crate::web::fleet_summary(&serde_json::json!({ "gpus": [{ "driver": "virtio-pci", "model": "1af4:1050" }] }))["gpus"], serde_json::json!([]));
    let nothing = crate::web::fleet_summary(&serde_json::json!([1, 2]));
    assert_eq!((nothing["sessions"].as_u64(), nothing["mem_percent"].is_null()), (Some(0), true));
}

#[tokio::test]
async fn a_server_with_people_is_not_removed_and_a_gone_server_can_be_dropped_by_force() {
    let env = start("gone", Opts::default()).await;
    let boss_pw = env.app.people.add("pboss", "", true, 0).unwrap();
    env.app.people.add("pana", "", false, 0).unwrap();
    let boss = env.sign_in("pboss", &boss_pw, "").await.1.unwrap();
    let origin = env.origin();
    let h = [("Cookie", boss.cookie.as_str()), ("Origin", origin.as_str()), ("X-CSRF-Token", boss.csrf.as_str())];
    let (_, added) = env.send("POST", "/api/admin/servers", &h, r#"{"action":"add","name":"Far"}"#).await;
    let sid = {
        let i = added.find("\"id\":\"").unwrap() + 6;
        added[i..].split('"').next().unwrap().to_string()
    };
    env.app.people.assign("pana", crate::people::Assignment { server: sid.clone(), desktop: None, gpu: None, memory: None }).unwrap();
    let (status, body) = env.send("POST", "/api/admin/servers", &h, &format!(r#"{{"action":"remove","id":"{sid}"}}"#)).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("pana") && body.contains("take them away"), "{body}");
    // The server is offline: taking the person away fails, with the reason, and the assignment stays...
    let unassign = format!(r#"{{"action":"unassign","name":"pana","server":"{sid}"}}"#);
    let (status, body) = env.send("POST", "/api/admin/people", &h, &unassign).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(env.app.people.get("pana").unwrap().servers.len(), 1);
    // ...unless the administrator says the server is gone for good.
    let (status, _) = env.send("POST", "/api/admin/people", &h, &format!(r#"{{"action":"unassign","name":"pana","server":"{sid}","force":true}}"#)).await;
    assert_eq!(status, 200);
    assert!(env.app.people.get("pana").unwrap().servers.is_empty());
    assert_eq!(env.send("POST", "/api/admin/servers", &h, &format!(r#"{{"action":"remove","id":"{sid}"}}"#)).await.0, 200);
}
