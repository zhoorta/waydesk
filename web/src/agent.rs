//! waydesk-agent: the part of a server that dials the portal (stage 3, slice 2 of docs/PORTAL-DESIGN.md).
//!
//! `waydesk-agent enrol https://portal.example.com CODE [--pin SHA256]` shows the join code to the portal, receives this server's key and writes
//! `/etc/waydesk/agent.json` (root only, mode 0600). `waydesk-agent run` keeps one outbound TLS link to the portal's `/agent` WebSocket open and
//! answers its requests: the read-only lists and status (`waydesk-admin ... --json`, fixed arguments) and the closed list of changes
//! (`adminaction.rs`, carried out by the runner behind `/run/waydesk-admin.sock`, which checks them again). Nothing else is reachable through it.
//!
//! The portal is trusted to name an administrator (the agent cannot know the portal's accounts), so what it can ask is what the closed list allows,
//! and what the portal's certificate is: pinned by fingerprint when `--pin` is given, otherwise the usual authorities (a portal behind a proxy with
//! a public certificate).

#[path = "../../src/adminaction.rs"]
#[allow(dead_code)]
mod adminaction;
mod link;
// The helper's own messages (a ticket for an account, without a password: root only) and the line the daemon's gateway port reads first.
#[path = "../../src/proto.rs"]
#[allow(dead_code)]
mod proto;
#[path = "../../src/gateway.rs"]
#[allow(dead_code)]
mod daemon_gateway;

use std::io::{BufRead as _, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use futures_util::{SinkExt as _, StreamExt as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Value};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

const CONFIG: &str = "/etc/waydesk/agent.json";
const ADMIN_EXE: &str = "/usr/bin/waydesk-admin";
const RUNNER_SOCKET: &str = "/run/waydesk-admin.sock";
const USAGE: &str = "usage: waydesk-agent enrol https://PORTAL[:PORT] CODE [--pin SHA256-HEX]
       waydesk-agent run
       waydesk-agent status";

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Config {
    portal: String,
    server: String,
    key: String,
    pin: Option<String>,
    /// The root helper's socket (it gives the agent a ticket for a person the portal signed in), the daemon's gateway port and the file with its key:
    /// where `waydesk` has them by default. A desktop can be opened here only when the daemon was started with `--gateway-bind` and `--gateway-key`.
    #[serde(default = "default_helper")]
    helper_socket: String,
    #[serde(default = "default_gateway")]
    gateway: String,
    #[serde(default = "default_gateway_key")]
    gateway_key_file: String,
}

fn default_helper() -> String {
    "/run/waydesk/helper.sock".into()
}
fn default_gateway() -> String {
    "127.0.0.1:3390".into()
}
fn default_gateway_key() -> String {
    "/etc/waydesk/gateway.key".into()
}

/// `https://host[:port]` -> (host, port). Nothing else is accepted: no path, no credentials, no plain HTTP.
fn parse_portal(url: &str) -> Result<(String, u16)> {
    let rest = url.strip_prefix("https://").context("the portal address must start with https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '@', '?', '#', ' ']) {
        bail!("the portal address must be https://HOST or https://HOST:PORT");
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h.trim_matches(['[', ']']), p.parse::<u16>().context("bad port")?),
        _ => (rest.trim_matches(['[', ']']), 443),
    };
    if host.is_empty() {
        bail!("no host in the portal address");
    }
    Ok((host.to_string(), port))
}

/// Accepts the portal's certificate if its SHA-256 is the pin, and checks its signature (which proves the portal holds the key).
#[derive(Debug)]
struct Pinned {
    pin: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha2::Sha256::digest(end_entity.as_ref());
        if subtle::ConstantTimeEq::ct_eq(got.as_slice(), self.pin.as_slice()).into() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the portal presents another certificate than the pinned one".into()))
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn tls_config(pin: Option<&str>) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    let cfg = match pin {
        Some(p) => {
            let pin = data_encoding::HEXLOWER_PERMISSIVE.decode(p.replace(':', "").as_bytes()).context("the pin is SHA-256 in hexadecimal")?;
            if pin.len() != 32 {
                bail!("the pin is SHA-256 in hexadecimal (64 digits)");
            }
            builder.dangerous().with_custom_certificate_verifier(Arc::new(Pinned { pin, algs: provider.signature_verification_algorithms })).with_no_client_auth()
        }
        None => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    Ok(Arc::new(cfg))
}

async fn connect(portal: &str, pin: Option<&str>) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let (host, port) = parse_portal(portal)?;
    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host.as_str(), port))).await.context("the portal did not answer")?.with_context(|| format!("cannot reach {host}:{port}"))?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from(host.clone()).context("not a usable host name")?;
    let tls = tokio_rustls::TlsConnector::from(tls_config(pin)?);
    tokio::time::timeout(Duration::from_secs(15), tls.connect(name, tcp)).await.context("the TLS handshake took too long")?.context("the TLS handshake failed (a wrong pin, or a certificate this server does not trust)")
}

/// One small POST, answered with a small body; `Connection: close`, so the end of the stream ends the answer.
async fn post_json(portal: &str, pin: Option<&str>, path: &str, body: &str) -> Result<(u16, String)> {
    let (host, _) = parse_portal(portal)?;
    let mut tls = connect(portal, pin).await?;
    let request = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    tls.write_all(request.as_bytes()).await?;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), (&mut tls).take(64 * 1024).read_to_end(&mut out)).await.context("the portal did not answer")??;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((status, text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()))
}

fn load_config() -> Result<Config> {
    use std::os::unix::fs::PermissionsExt as _;
    // The key is a secret: a file that others can read is refused, not used.
    if let Ok(m) = std::fs::metadata(CONFIG) {
        if m.permissions().mode() & 0o077 != 0 {
            bail!("{CONFIG} can be read by others: run `chmod 600 {CONFIG}`");
        }
    }
    let text = std::fs::read_to_string(CONFIG).with_context(|| format!("cannot read {CONFIG} (run `waydesk-agent enrol` first, as root)"))?;
    serde_json::from_str(&text).with_context(|| format!("{CONFIG} is not valid"))
}

fn save_config(cfg: &Config, path: &Path) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(serde_json::to_string_pretty(cfg)?.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn enrol(portal: &str, code: &str, pin: Option<String>) -> Result<()> {
    parse_portal(portal)?;
    let (status, body) = post_json(portal, pin.as_deref(), "/api/enrol", &json!({ "code": code }).to_string()).await?;
    match status {
        200 => {}
        403 => bail!("the portal refused the code (wrong, used or expired): make a new one on the Servers page"),
        429 => bail!("the portal says too many attempts: wait a minute"),
        s => bail!("the portal answered {s}"),
    }
    let v: Value = serde_json::from_str(body.trim()).context("the portal's answer is not JSON")?;
    let (server, key) = (v["server"].as_str().unwrap_or(""), v["key"].as_str().unwrap_or(""));
    if server.is_empty() || key.len() != 64 {
        bail!("the portal's answer is not what an enrolment looks like");
    }
    let cfg = Config { portal: portal.trim_end_matches('/').to_string(), server: server.to_string(), key: key.to_string(), pin, helper_socket: default_helper(), gateway: default_gateway(), gateway_key_file: default_gateway_key() };
    std::fs::create_dir_all("/etc/waydesk")?;
    save_config(&cfg, Path::new(CONFIG))?;
    match setup_gateway(Path::new(&cfg.gateway_key_file), Path::new(DEFAULTS)) {
        Ok(true) => println!("desktops from the portal: key made and {DEFAULTS} updated; restart the daemon when nobody is connected: systemctl restart waydesk"),
        Ok(false) => {}
        Err(e) => eprintln!("warning: the gateway for desktops from the portal is not set up ({e:#}); the link works, opening a desktop will not"),
    }
    println!("enrolled as {server}; start the link with: systemctl enable --now waydesk-agent");
    Ok(())
}

// ---- the daemon's gateway port (what opens a desktop in the browser) ----

const DEFAULTS: &str = "/etc/default/waydesk";
const GATEWAY_FLAGS: &str = "--gateway-bind 127.0.0.1:3390 --gateway-key /etc/waydesk/gateway.key";

/// The text of `/etc/default/waydesk` with the gateway flags in `WAYDESK_ARGS`; `None` when they are already there.
fn with_gateway_flags(text: &str) -> Option<String> {
    if text.lines().any(|l| !l.trim_start().starts_with('#') && l.contains("WAYDESK_ARGS=") && l.contains("--gateway-bind")) {
        return None;
    }
    let mut done = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            if done || !l.starts_with("WAYDESK_ARGS=") {
                return l.to_string();
            }
            done = true;
            let value = &l["WAYDESK_ARGS=".len()..];
            let (quote, inner) = match value.chars().next() {
                Some(q @ ('"' | '\'')) if value.len() >= 2 && value.ends_with(q) => (q.to_string(), &value[1..value.len() - 1]),
                _ => (String::new(), value),
            };
            let joined = if inner.trim().is_empty() { GATEWAY_FLAGS.to_string() } else { format!("{} {GATEWAY_FLAGS}", inner.trim()) };
            let q = if quote.is_empty() { "\"".to_string() } else { quote };
            format!("WAYDESK_ARGS={q}{joined}{q}")
        })
        .collect();
    if !done {
        out.push(format!("WAYDESK_ARGS=\"{GATEWAY_FLAGS}\""));
    }
    Some(out.join("\n") + "\n")
}

/// Makes the gateway key (kept if there is one) and adds the flags to the daemon's settings, so a desktop can be opened from the portal. Returns
/// true when the daemon has to be restarted to pick them up.
fn setup_gateway(key_path: &Path, defaults: &Path) -> Result<bool> {
    if !key_path.exists() {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no random numbers: {e}"))?;
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = key_path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        writeln!(f, "{hex}")?;
        f.sync_all()?;
        // The daemon (user waydesk) reads it; nobody else but root.
        if let Ok(c) = std::ffi::CString::new("waydesk") {
            let pw = unsafe { libc::getpwnam(c.as_ptr()) };
            if !pw.is_null() {
                let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
                std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))?;
            }
        }
        std::fs::rename(&tmp, key_path)?;
    }
    let text = std::fs::read_to_string(defaults).unwrap_or_default();
    match with_gateway_flags(&text) {
        Some(new) => {
            std::fs::write(defaults, new)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

// ---- accounts the portal manages ----

/// The accounts this agent made at the portal's request, one name per line. The portal can set the password of, and open a desktop as, only these: an
/// account that was on the server before (a person who has their own login) is never taken over, even by a portal that asks.
const MANAGED: &str = "/var/lib/waydesk-agent/managed";

fn managed_contains(path: &str, name: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| t.lines().any(|l| l == name))
}

fn managed_add(path: &str, name: &str) -> Result<()> {
    if managed_contains(path, name) {
        return Ok(());
    }
    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(path)?;
    writeln!(f, "{name}")?;
    Ok(())
}

// ---- answering the portal ----

/// The most a command may print, and the longest it may take.
const MAX_OUTPUT: usize = link::MAX_ANSWER - 4096;
const CLI_TIMEOUT: Duration = Duration::from_secs(20);

/// The fixed command line for a kind of read, and whether its output is JSON (the other two print sentences).
fn read_args(kind: &str) -> Option<(&'static [&'static str], bool)> {
    Some(match kind {
        "users" => (&["users", "list", "--json"], true),
        "sessions" => (&["sessions", "list", "--json"], true),
        "status" => (&["status", "--json"], true),
        "access" => (&["access", "show"], false),
        "cert" => (&["cert", "status"], false),
        _ => return None,
    })
}

fn run_cli(args: &[&str]) -> Result<String> {
    let mut child = Command::new(ADMIN_EXE).args(args).env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().context("cannot run waydesk-admin")?;
    let mut stdout = child.stdout.take().context("no output pipe")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + CLI_TIMEOUT;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("it took too long");
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let out = reader.join().map_err(|_| anyhow::anyhow!("reading failed"))?;
    if !status.success() {
        bail!("the command failed");
    }
    if out.len() > MAX_OUTPUT {
        bail!("the answer is too large");
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The runner's one-line answer for one action, asked on behalf of `actor` (an account of the portal's machine) from `source`.
fn run_action(actor: &str, source: &str, action: &Value) -> Result<String> {
    run_action_with(actor, source, action, MANAGED)
}

fn run_action_with(actor: &str, source: &str, action: &Value, managed: &str) -> Result<String> {
    let parsed = adminaction::AdminAction::from_json(action).map_err(|e| anyhow::anyhow!(e))?;
    // A chosen password only for an account this agent made for the portal.
    if let adminaction::AdminAction::UserSetPassword { name, .. } = &parsed {
        if !managed_contains(managed, name) {
            bail!("that account was not made by the portal, so the portal may not set its password");
        }
    }
    let mut sock = std::os::unix::net::UnixStream::connect(RUNNER_SOCKET).with_context(|| format!("cannot reach {RUNNER_SOCKET}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(100)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    let line = json!({ "remote_actor": actor, "source": source, "do": action }).to_string();
    sock.write_all(line.as_bytes())?;
    sock.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    std::io::BufReader::new(sock).take(link::MAX_ANSWER as u64).read_line(&mut answer)?;
    let v = serde_json::from_str::<Value>(answer.trim()).context("the runner's answer is not JSON")?;
    // An account made now is one the portal manages from here on.
    if let (adminaction::AdminAction::UserAdd { name }, true) = (&parsed, v["ok"] == true) {
        if let Err(e) = managed_add(managed, name) {
            eprintln!("waydesk-agent: could not record that {name} was made for the portal: {e}");
        }
    }
    Ok(answer.trim().to_string())
}

/// The audit log of this server for the portal's Audit page: the filters are checked here (the same rules as `waydesk-admin audit`), the command is
/// run with them as separate arguments, and its lines come back as one JSON list, newest first.
fn audit_list(q: &Value) -> Result<String, String> {
    let text = |k: &str| q.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (since, user, event, outcome) = (text("since"), text("user"), text("event"), text("outcome"));
    let limit = q.get("limit").and_then(Value::as_u64).unwrap_or(0);
    let since_ok = since.is_empty()
        || (since.len() <= 4 && since.len() >= 2 && since.ends_with(['m', 'h', 'd', 'w']) && since[..since.len() - 1].chars().all(|c| c.is_ascii_digit()))
        || (since.len() == 10 && since.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }));
    if !since_ok || (!user.is_empty() && !adminaction::valid_name(&user)) || (!event.is_empty() && (event.len() > 32 || !event.chars().all(|c| c.is_ascii_lowercase() || c == '.'))) || !matches!(outcome.as_str(), "" | "ok" | "fail" | "refused") || limit == 0 || limit > 500 {
        return Err("that is not a query this agent runs".into());
    }
    let limit = limit.to_string();
    let mut args = vec!["audit", "--json", "--since", if since.is_empty() { "7d" } else { &since }, "--limit", &limit];
    for (flag, value) in [("--user", &user), ("--event", &event), ("--outcome", &outcome)] {
        if !value.is_empty() {
            args.extend([flag, value.as_str()]);
        }
    }
    let out = run_cli(&args).map_err(|e| format!("{e:#}"))?;
    let mut rows: Vec<Value> = out.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(Value::is_object).collect();
    rows.reverse();
    Ok(Value::Array(rows).to_string())
}

/// Where a session's worker leaves the small picture of its screen (the daemon's `sessionshot`).
const STATUS_DIR: &str = "/run/waydesk/status";

/// The small picture of the desktop of `account` for the portal, as hex in `{"hex": ...}`, or `{"none": true}` when there is no session or no picture
/// yet. Only for an account this agent made (the same rule as setting a password or opening a desktop); the file is the account's own and is read as
/// root without following links, as a plain file of that uid, and only if it is a PNG of a sensible size.
fn desktop_shot(account: &str) -> Result<String, String> {
    if !adminaction::valid_name(account) || !managed_contains(MANAGED, account) {
        return Err("that account was not made by the portal".into());
    }
    let none = || Ok(json!({ "none": true }).to_string());
    let Ok(c) = std::ffi::CString::new(account) else { return none() };
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return none();
    }
    let uid = unsafe { (*pw).pw_uid };
    match read_shot(std::path::Path::new(STATUS_DIR), uid) {
        Some(png) => Ok(json!({ "hex": png.iter().map(|b| format!("{b:02x}")).collect::<String>() }).to_string()),
        None => none(),
    }
}

fn read_shot(dir: &std::path::Path, uid: u32) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    const MAX: u64 = 512 * 1024;
    let path = dir.join(uid.to_string()).join("shot.png");
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != uid || meta.len() > MAX {
        return None;
    }
    let mut png = Vec::with_capacity(meta.len() as usize);
    (&mut file).take(MAX).read_to_end(&mut png).ok()?;
    png.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]).then_some(png)
}

/// What one request from the portal gets: the JSON text, or why not.
fn handle(req: &Value) -> Result<String, String> {
    if req.get("kind").and_then(Value::as_str) == Some("audit") {
        return audit_list(req.get("query").unwrap_or(&Value::Null));
    }
    if let Some(kind) = req.get("kind").and_then(Value::as_str) {
        let (args, is_json) = read_args(kind).ok_or("not a request this agent answers")?;
        let out = run_cli(args).map_err(|e| format!("{e:#}"))?;
        return Ok(if is_json { out } else { json!({ "text": out.trim_end() }).to_string() });
    }
    if let Some(shot) = req.get("shot") {
        return desktop_shot(shot.get("account").and_then(Value::as_str).unwrap_or(""));
    }
    if let Some(action) = req.get("do") {
        let actor = req.get("actor").and_then(Value::as_str).filter(|a| adminaction::valid_name(a)).ok_or("bad actor name")?;
        let source = req.get("source").and_then(Value::as_str).unwrap_or("");
        if source.len() > 45 || !source.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':') {
            return Err("bad source address".into());
        }
        return run_action(actor, source, action).map_err(|e| format!("{e:#}"));
    }
    Err("not a request this agent answers".into())
}

/// One link: hello, then requests until the portal closes it or goes quiet. Ends with an error to be retried, or `Ok` when the portal closed it.
async fn serve(cfg: &Config) -> Result<()> {
    let tls = connect(&cfg.portal, cfg.pin.as_deref()).await?;
    let (host, port) = parse_portal(&cfg.portal)?;
    let url = if port == 443 { format!("wss://{host}/agent") } else { format!("wss://{host}:{port}/agent") };
    let ws_cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(link::MAX_FRAME)).max_frame_size(Some(link::MAX_FRAME));
    let (ws, _) = tokio_tungstenite::client_async_with_config(url, tls, Some(ws_cfg)).await.context("the portal did not accept the link")?;
    let (mut tx, mut rx) = ws.split();
    tx.send(Message::Text(json!({ "t": "hello", "server": cfg.server, "key": cfg.key, "version": link::VERSION }).to_string().into())).await?;
    match tokio::time::timeout(Duration::from_secs(15), rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) if t.as_str().contains("\"ready\"") => {}
        _ => bail!("the portal refused this server (revoked, or the key is not the portal's)"),
    }
    eprintln!("waydesk-agent: link up to {}", cfg.portal);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(8);
    let slots = Arc::new(tokio::sync::Semaphore::new(2));
    let cfg_shared = Arc::new(Config { portal: cfg.portal.clone(), server: cfg.server.clone(), key: cfg.key.clone(), pin: cfg.pin.clone(), helper_socket: cfg.helper_socket.clone(), gateway: cfg.gateway.clone(), gateway_key_file: cfg.gateway_key_file.clone() });
    // At most this many desktops through this agent at once.
    let desktops = Arc::new(tokio::sync::Semaphore::new(MAX_DESKTOPS));
    let mut last = Instant::now();
    let mut watch = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            frame = rx.next() => match frame {
                Some(Ok(Message::Text(t))) => {
                    last = Instant::now();
                    let Ok(req) = serde_json::from_str::<Value>(t.as_str()) else { continue };
                    if req["t"] != "req" {
                        continue;
                    }
                    let id = req["id"].as_u64().unwrap_or(0);
                    let out_tx = out_tx.clone();
                    if let Some(open) = req.get("open") {
                        // A desktop for a person the portal signed in: a ticket from the helper, then a second connection back to the portal.
                        tokio::spawn(open_desktop(cfg_shared.clone(), open.clone(), id, out_tx, desktops.clone()));
                        continue;
                    }
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        let _ = out_tx.send(json!({ "t": "res", "id": id, "ok": false, "error": "this server is busy, try again" }).to_string()).await;
                        continue;
                    };
                    tokio::spawn(async move {
                        let answer = tokio::task::spawn_blocking(move || handle(&req)).await.unwrap_or_else(|_| Err("it failed".into()));
                        drop(permit);
                        let frame = match answer {
                            Ok(j) => json!({ "t": "res", "id": id, "ok": true, "json": j }),
                            Err(e) => json!({ "t": "res", "id": id, "ok": false, "error": e }),
                        };
                        let _ = out_tx.send(frame.to_string()).await;
                    });
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => last = Instant::now(),
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(e)) => bail!("the link broke: {e}"),
            },
            Some(frame) = out_rx.recv() => tx.send(Message::Text(frame.into())).await?,
            _ = watch.tick() => if last.elapsed() > Duration::from_secs(70) { bail!("the portal went quiet") },
        }
    }
}

// ---- desktops ----

/// Desktops that may be open through one agent at once.
const MAX_DESKTOPS: usize = 32;
/// What the browser may send in a message (a clipboard text may be longer), and what the daemon may send (a whole H.264 picture): as in `stream.rs`.
const MAX_FROM_PORTAL: usize = 1 + 1024 * 1024;
const MAX_FROM_DAEMON: usize = 16 * 1024 * 1024;

/// A ticket for `account` from the root helper, for a person the portal signed in from `ip`. The helper refuses it for an account that may not log in.
fn ticket_for(helper_socket: &str, account: &str, ip: std::net::IpAddr) -> Result<String> {
    use proto::{HelperReq, HelperResp};
    let mut sock = std::os::unix::net::UnixStream::connect(helper_socket).with_context(|| format!("cannot reach the helper at {helper_socket}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))?;
    sock.set_write_timeout(Some(Duration::from_secs(15)))?;
    proto::write_frame(&mut sock, &HelperReq::IssueFor { user: account.to_string(), source: ip.to_string() }.encode()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = proto::read_frame(&mut sock).map_err(|e| anyhow::anyhow!("{e}"))?.context("the helper closed the connection")?;
    let answer = match HelperResp::decode(&body).map_err(|e| anyhow::anyhow!("{e}"))? {
        HelperResp::Ticket { ticket } => Ok(ticket),
        HelperResp::Error { message } => Err(anyhow::anyhow!("{message}")),
        other => Err(anyhow::anyhow!("unexpected answer from the helper: {other:?}")),
    };
    let _ = proto::write_frame(&mut sock, &HelperReq::Bye.encode());
    answer
}

/// The portal asked for a desktop: get the ticket, say so (the portal waits for the dial-back after that), and carry the desktop until it ends.
async fn open_desktop(cfg: Arc<Config>, open: Value, id: u64, out: tokio::sync::mpsc::Sender<String>, slots: Arc<tokio::sync::Semaphore>) {
    let answer = |ok: bool, text: &str| json!({ "t": "res", "id": id, "ok": ok, if ok { "json" } else { "error" }: text }).to_string();
    let token = open.get("token").and_then(Value::as_str).unwrap_or("");
    let account = open.get("account").and_then(Value::as_str).unwrap_or("");
    let ip = open.get("ip").and_then(Value::as_str).and_then(|i| i.parse::<std::net::IpAddr>().ok());
    let (Some(ip), true, true) = (ip, token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()), adminaction::valid_name(account)) else {
        let _ = out.send(answer(false, "not a request this agent answers")).await;
        return;
    };
    if !managed_contains(MANAGED, account) {
        let _ = out.send(answer(false, "that account was not made by the portal, so the portal may not open a desktop as it")).await;
        return;
    }
    let Ok(permit) = slots.try_acquire_owned() else {
        let _ = out.send(answer(false, "this server has too many desktops open through the portal")).await;
        return;
    };
    let (helper, who) = (cfg.helper_socket.clone(), account.to_string());
    let ticket = match tokio::task::spawn_blocking(move || ticket_for(&helper, &who, ip)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let _ = out.send(answer(false, &format!("{e:#}"))).await;
            return;
        }
        Err(_) => {
            let _ = out.send(answer(false, "it failed")).await;
            return;
        }
    };
    let _ = out.send(answer(true, "{}")).await;
    if let Err(e) = relay(&cfg, token, account, ip, &ticket).await {
        eprintln!("waydesk-agent: a desktop of {account} ended: {e:#}");
    }
    drop(permit);
}

/// One desktop: the daemon's gateway port on one side, a WebSocket to the portal's `/relay` on the other. Each WebSocket message is one message of the
/// daemon's browser protocol; towards the daemon it gets a length in front (`u32`, little endian), and the other way the length is taken off.
async fn relay(cfg: &Config, token: &str, account: &str, ip: std::net::IpAddr, ticket: &str) -> Result<()> {
    let key = std::fs::read_to_string(&cfg.gateway_key_file).with_context(|| format!("cannot read the gateway key {}", cfg.gateway_key_file))?;
    let daemon = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&cfg.gateway)).await.context("the daemon's gateway port did not answer")?.with_context(|| format!("cannot reach the gateway port {} (the daemon needs --gateway-bind and --gateway-key)", cfg.gateway))?;
    daemon.set_nodelay(true).ok();
    let (mut rd, mut wr) = daemon.into_split();
    wr.write_all(daemon_gateway::stream_line(key.trim(), account, ip, ticket).as_bytes()).await?;

    let tls = connect(&cfg.portal, cfg.pin.as_deref()).await?;
    let (host, port) = parse_portal(&cfg.portal)?;
    let url = if port == 443 { format!("wss://{host}/relay") } else { format!("wss://{host}:{port}/relay") };
    let ws_cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(MAX_FROM_PORTAL + 16)).max_frame_size(Some(MAX_FROM_PORTAL + 16));
    let (ws, _) = tokio_tungstenite::client_async_with_config(url, tls, Some(ws_cfg)).await.context("the portal did not accept the relay")?;
    let (mut tx, mut rx) = ws.split();
    tx.send(Message::Text(json!({ "t": "relay", "server": cfg.server, "key": cfg.key, "token": token }).to_string().into())).await?;

    // The daemon's messages are read in a task of their own: a read of a whole message is not something to cut short in a select.
    let (from_daemon_tx, mut from_daemon) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let reader = tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if rd.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(len) as usize;
            if len == 0 || len > MAX_FROM_DAEMON {
                return;
            }
            let mut body = vec![0u8; len];
            if rd.read_exact(&mut body).await.is_err() || from_daemon_tx.send(body).await.is_err() {
                return;
            }
        }
    });
    let mut last = Instant::now();
    let mut watch = tokio::time::interval(Duration::from_secs(15));
    let result: Result<()> = loop {
        tokio::select! {
            m = rx.next() => match m {
                Some(Ok(Message::Binary(b))) => {
                    last = Instant::now();
                    if b.is_empty() || b.len() > MAX_FROM_PORTAL { break Err(anyhow::anyhow!("a message of {} bytes from the portal", b.len())); }
                    let mut framed = Vec::with_capacity(4 + b.len());
                    framed.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    framed.extend_from_slice(&b);
                    if let Err(e) = wr.write_all(&framed).await { break Err(anyhow::anyhow!("write to the daemon: {e}")); }
                }
                Some(Ok(Message::Close(_))) | None => break Ok(()),
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => last = Instant::now(),
                Some(Ok(_)) => break Err(anyhow::anyhow!("a message of a kind the portal does not send")),
                Some(Err(e)) => break Err(anyhow::anyhow!("the portal's connection failed: {e}")),
            },
            m = from_daemon.recv() => match m {
                Some(body) => if let Err(e) = tx.send(Message::Binary(body.into())).await { break Err(anyhow::anyhow!("write to the portal: {e}")); },
                None => break Ok(()),
            },
            _ = watch.tick() => if last.elapsed() > Duration::from_secs(120) { break Err(anyhow::anyhow!("the portal went quiet")); },
        }
    };
    reader.abort();
    let _ = tx.send(Message::Close(None)).await;
    result
}

async fn run() -> Result<()> {
    let cfg = load_config()?;
    let mut wait = Duration::from_secs(2);
    loop {
        let started = Instant::now();
        match serve(&cfg).await {
            Ok(()) => eprintln!("waydesk-agent: the portal closed the link"),
            Err(e) => eprintln!("waydesk-agent: {e:#}"),
        }
        // A link that lasted a while starts the waiting over; one that fails at once waits longer each time, up to a minute.
        wait = if started.elapsed() > Duration::from_secs(60) { Duration::from_secs(2) } else { (wait * 2).min(Duration::from_secs(60)) };
        tokio::time::sleep(wait).await;
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["enrol", portal, code] => enrol_as_root(portal, code, None).await,
        ["enrol", portal, code, "--pin", pin] => enrol_as_root(portal, code, Some(pin.to_string())).await,
        ["run"] => run().await,
        ["status"] => {
            let cfg = load_config()?;
            println!("portal {}\nserver {}\npin    {}", cfg.portal, cfg.server, cfg.pin.as_deref().unwrap_or("none (certificate authorities)"));
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn enrol_as_root(portal: &str, code: &str, pin: Option<String>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("run this as root: it writes {CONFIG}");
    }
    enrol(portal, code, pin).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_gateway_flags_go_into_the_daemons_settings_once() {
        let f = super::GATEWAY_FLAGS;
        assert_eq!(super::with_gateway_flags("A=1\nWAYDESK_ARGS=\n").unwrap(), format!("A=1\nWAYDESK_ARGS=\"{f}\"\n"));
        assert_eq!(super::with_gateway_flags("WAYDESK_ARGS=\"--quality 28\"\n").unwrap(), format!("WAYDESK_ARGS=\"--quality 28 {f}\"\n"));
        assert_eq!(super::with_gateway_flags("#WAYDESK_ARGS=\"--x\"\n").unwrap(), format!("#WAYDESK_ARGS=\"--x\"\nWAYDESK_ARGS=\"{f}\"\n"));
        assert!(super::with_gateway_flags(&format!("WAYDESK_ARGS=\"{f}\"\n")).is_none());
        assert_eq!(super::with_gateway_flags("").unwrap(), format!("WAYDESK_ARGS=\"{f}\"\n"));
    }

    #[test]
    fn the_gateway_key_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("wd-agent-gw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (key, defaults) = (dir.join("gateway.key"), dir.join("waydesk"));
        std::fs::write(&defaults, "WAYDESK_ARGS=\n").unwrap();
        assert!(super::setup_gateway(&key, &defaults).unwrap());
        let first = std::fs::read_to_string(&key).unwrap();
        assert_eq!(first.trim().len(), 64);
        assert!(!super::setup_gateway(&key, &defaults).unwrap(), "second run changes nothing");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    use std::os::unix::fs::symlink;

    #[test]
    fn a_picture_is_taken_only_as_a_plain_png_of_the_account() {
        let dir = std::env::temp_dir().join(format!("wd-agent-shot-{}", std::process::id()));
        let mine = unsafe { libc::geteuid() };
        let folder = dir.join(mine.to_string());
        std::fs::create_dir_all(&folder).unwrap();
        let png = [&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a][..], b"rest"].concat();
        std::fs::write(folder.join("shot.png"), &png).unwrap();
        assert_eq!(read_shot(&dir, mine), Some(png.clone()));
        assert!(read_shot(&dir, mine + 1).is_none(), "no folder of that account");
        std::fs::write(folder.join("shot.png"), b"<html>").unwrap();
        assert!(read_shot(&dir, mine).is_none(), "not a PNG");
        std::fs::remove_file(folder.join("shot.png")).unwrap();
        std::fs::write(dir.join("elsewhere.png"), &png).unwrap();
        symlink(dir.join("elsewhere.png"), folder.join("shot.png")).unwrap();
        assert!(read_shot(&dir, mine).is_none(), "a link is not followed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_picture_is_refused_for_an_account_the_agent_did_not_make() {
        assert!(desktop_shot("../etc").is_err());
        assert!(desktop_shot("root").is_err(), "root is not in the managed file");
    }
    use super::*;

    #[test]
    fn the_portal_address_is_https_host_and_port_only() {
        assert_eq!(parse_portal("https://portal.example.com").unwrap(), ("portal.example.com".into(), 443));
        assert_eq!(parse_portal("https://portal.example.com:8443/").unwrap(), ("portal.example.com".into(), 8443));
        assert_eq!(parse_portal("https://[::1]:8443").unwrap(), ("::1".into(), 8443));
        for bad in ["http://x", "x", "https://", "https://u@x", "https://x/path", "https://x:99999", "https://x y"] {
            assert!(parse_portal(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_known_reads_have_a_command_line() {
        assert!(read_args("users").is_some() && read_args("status").is_some());
        for bad in ["", "do", "../x", "users --json", "audit"] {
            assert!(read_args(bad).is_none(), "{bad}");
        }
        assert!(handle(&json!({"kind":"rm"})).is_err());
        // The audit filters are the same rules as the command's: nothing else reaches its command line.
        for bad in [json!({"since":"yesterday","limit":10}), json!({"user":"A b","limit":10}), json!({"event":"x;y","limit":10}), json!({"outcome":"maybe","limit":10}), json!({"limit":0}), json!({"limit":501}), json!({"user":"--limit","limit":5})] {
            assert!(audit_list(&bad).is_err(), "{bad}");
        }
        assert!(handle(&json!({"nothing":1})).is_err());
    }

    #[test]
    fn a_change_needs_a_valid_actor_source_and_action_before_anything_is_run() {
        let ok_action = json!({"action":"session_end","name":"ana"});
        for bad in [json!({"do":ok_action,"actor":"Bad Name","source":"1.2.3.4"}), json!({"do":ok_action,"actor":"boss","source":"1.2.3.4; id"}), json!({"do":ok_action,"source":"1.2.3.4"})] {
            assert!(handle(&bad).is_err(), "{bad}");
        }
        // An action outside the closed list is refused here, before the runner is even asked.
        assert!(run_action("boss", "1.2.3.4", &json!({"action":"user_remove","name":"ana"})).is_err());
        assert!(run_action("boss", "1.2.3.4", &json!({"action":"user_enable","name":"Not Valid"})).is_err());
    }

    #[test]
    fn a_chosen_password_is_only_for_an_account_the_agent_made_and_the_list_is_kept() {
        let dir = std::env::temp_dir().join(format!("wd-agent-managed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("managed").to_string_lossy().into_owned();
        let setpw = json!({"action":"user_setpw","name":"alice","password":"a long enough password"});
        // alice was on the server before the portal: refused before the runner is even asked.
        let why = run_action_with("boss", "1.2.3.4", &setpw, &path).unwrap_err().to_string();
        assert!(why.contains("not made by the portal"), "{why}");
        managed_add(&path, "alice").unwrap();
        managed_add(&path, "alice").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "alice\n");
        assert!(managed_contains(&path, "alice") && !managed_contains(&path, "ali") && !managed_contains(&path, "bob"));
        // Now it gets as far as the runner (which is not here): the refusal is about the socket, not about the account.
        let why = run_action_with("boss", "1.2.3.4", &setpw, &path).unwrap_err().to_string();
        assert!(why.contains("cannot reach"), "{why}");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("wd-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.json");
        let cfg = Config { portal: "https://p".into(), server: "s-00000000".into(), key: "k".repeat(64), pin: None, helper_socket: default_helper(), gateway: default_gateway(), gateway_key_file: default_gateway_key() };
        save_config(&cfg, &path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(serde_json::from_str::<Config>(&std::fs::read_to_string(&path).unwrap()).unwrap(), cfg);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pin_is_sha256_in_hex() {
        assert!(tls_config(Some(&"ab".repeat(32))).is_ok());
        assert!(tls_config(Some(&"ab:".repeat(32).trim_end_matches(':').to_string())).is_ok());
        for bad in ["", "zz", &"ab".repeat(31), &"ab".repeat(33)] {
            assert!(tls_config(Some(bad)).is_err(), "{bad}");
        }
        assert!(tls_config(None).is_ok());
    }
}
