//! The HTTP side: the web client's files, a token for starting a session, and the WebSocket that the bridge runs on.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Extension, Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tracing::{info, warn};

use crate::limits::{RateLimiter, Refusal, Sessions, Tokens};
use crate::portal::{self, Authenticator, Portal, Signed};
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
    /// How long a failed sign-in takes whatever the reason (the helper's answer for a wrong password takes about this long, so a refusal that comes
    /// later from the code is no quicker, and the timing does not tell a right password from a wrong one).
    pub fail_delay: Duration,
    /// How long a signed-in browser may be silent, and how long a sign-in lasts at most.
    pub idle: Duration,
    pub absolute: Duration,
    /// The daemon's root helper, which checks the passwords.
    pub helper_socket: PathBuf,
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
    pub portal: Portal,
    pub auth: Arc<dyn Authenticator>,
    /// The last answers to the administrators' pages, kept a few seconds: a status costs the machine a second of measuring, and several admins (or
    /// one page that refreshes) must not multiply that.
    pub admin_cache: std::sync::Mutex<std::collections::HashMap<String, (Instant, String)>>,
    /// Changes asked for by administrators, per address.
    pub admin_rate: RateLimiter,
    /// Password changes, per address (a wrong old password is also slowed and counted by the helper).
    pub pw_rate: RateLimiter,
    /// Authenticators being set up: the secret a browser session was shown, kept (in memory only) until the person types a valid code from it or
    /// the time is up. Keyed by the browser session, so one browser cannot confirm another's.
    pub pending_totp: std::sync::Mutex<std::collections::HashMap<String, PendingTotp>>,
    /// The servers this portal controls (stage 3): `fleet.json` next to the authenticators.
    pub fleet: crate::fleet::Fleet,
    /// Servers enrolling with a join code, per address (the endpoint is public).
    pub enrol_rate: RateLimiter,
    /// The links the servers dialled, and how often an address may try to open one.
    pub links: crate::link::Links,
    pub agent_rate: RateLimiter,
    /// Desktops waiting for their server's agent to dial back (`relay.rs`).
    pub relays: crate::relay::Relays,
    /// The portal's own audit log (`audit.rs`).
    pub audit: crate::audit::Audit,
    /// The portal's own accounts (`people.rs`), their two-step records (apart from the host accounts'), and the limits that protect their passwords.
    pub people: crate::people::People,
    pub pstore: Store,
    pub pw_guesses: Guesses,
    /// At most this many password hashes at once: argon2 uses real memory, and sign-ins must not be able to exhaust it.
    pub hash_slots: tokio::sync::Semaphore,
}

pub struct PendingTotp {
    account: String,
    secret: Vec<u8>,
    at: Instant,
}

/// How long a secret that was shown waits for its first code, and how many wait at once.
const PENDING_TOTP_SECS: u64 = 600;
const PENDING_TOTP_MAX: usize = 1024;

/// How long an administrators' answer is reused.
const ADMIN_CACHE_SECS: u64 = 3;

impl App {
    pub fn new(cfg: Config, daemon_tls: Arc<rustls::ClientConfig>, auth: Arc<dyn Authenticator>) -> Arc<Self> {
        Arc::new(Self {
            portal: Portal::new(cfg.idle, cfg.absolute, 4096, 5),
            auth,
            admin_cache: Default::default(),
            admin_rate: RateLimiter::new(30, Duration::from_secs(60)),
            pw_rate: RateLimiter::new(5, Duration::from_secs(60)),
            pending_totp: Default::default(),
            // A file that cannot be read stops the portal at start: starting with an empty list would hide the servers and the next save would overwrite them.
            fleet: crate::fleet::Fleet::open(cfg.totp_dir.join("fleet.json")).expect("the fleet file could not be read"),
            enrol_rate: RateLimiter::new(10, Duration::from_secs(60)),
            links: crate::link::Links::new(),
            agent_rate: RateLimiter::new(30, Duration::from_secs(60)),
            relays: crate::relay::Relays::new(),
            audit: crate::audit::Audit::open(cfg.totp_dir.join("audit.jsonl")),
            people: crate::people::People::open(cfg.totp_dir.join("people.json")).expect("the people file could not be read"),
            pstore: Store::new(&cfg.totp_dir.join("people")),
            pw_guesses: Guesses::new(20, 5, Duration::from_secs(600)),
            hash_slots: tokio::sync::Semaphore::new(4),
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
        .route("/api/login", post(login).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/api/me", get(me))
        .route("/api/mine", get(mine))
        .route("/api/mine/shot", get(mine_shot))
        .route("/api/admin/do", post(admin_do).layer(axum::extract::DefaultBodyLimit::max(2048)))
        .route("/api/account", get(account_info))
        .route("/api/account/totp/start", post(totp_start).layer(axum::extract::DefaultBodyLimit::max(256)))
        .route("/api/account/totp/confirm", post(totp_confirm).layer(axum::extract::DefaultBodyLimit::max(512)))
        .route("/api/account/totp/remove", post(totp_remove).layer(axum::extract::DefaultBodyLimit::max(512)))
        .route("/api/account/password", post(change_password).layer(axum::extract::DefaultBodyLimit::max(2048)))
        .route("/api/admin/totp", post(admin_totp).layer(axum::extract::DefaultBodyLimit::max(1024)))
        .route("/api/admin/audit", get(admin_audit))
        .route("/api/admin/fleet", get(fleet_overview))
        .route("/api/admin/servers", get(servers_list).post(servers_do).layer(axum::extract::DefaultBodyLimit::max(1024)))
        .route("/agent", get(agent_ws))
        .route("/relay", get(relay_ws))
        .route("/api/admin/people", get(people_list).post(people_do).layer(axum::extract::DefaultBodyLimit::max(2048)))
        .route("/api/account/apppass", post(app_password).layer(axum::extract::DefaultBodyLimit::max(64)))
        .route("/api/enrol", post(enrol).layer(axum::extract::DefaultBodyLimit::max(512)))
        .route("/api/admin/{kind}", get(admin_page))
        .route("/api/logout", post(logout))
        .route("/api/session", post(session_token).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/ws", get(ws_handler))
        .route("/stream", get(stream_handler))
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
struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    code: String,
}

fn json(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], body).into_response()
}

/// The same answer whatever was wrong (the account, the password, the code, a limit), so that it does not say which accounts exist or have an authenticator.
fn refused() -> Response {
    json(StatusCode::UNAUTHORIZED, "{\"error\":\"Sign-in refused. Check the account, the password and the code.\"}\n".into())
}

fn signed_json(signed: &Signed) -> String {
    format!("{{\"account\":{},\"csrf\":\"{}\",\"portal\":{}}}\n", serde_json::Value::from(signed.account.as_str()), signed.csrf, signed.portal_user)
}

/// Who the request's cookie stands for.
fn signed_in(app: &App, headers: &HeaderMap) -> Option<(String, Signed)> {
    let id = portal::cookie_value(headers.get(header::COOKIE)?.to_str().ok()?)?;
    let signed = app.portal.get(id, Instant::now())?;
    Some((id.to_owned(), signed))
}

/// A request that changes something: from a page of this site (`Origin`), by a signed-in browser, repeating that browser's CSRF token.
fn changing(app: &App, headers: &HeaderMap, host: &str) -> Result<(String, Signed), Response> {
    if !origin_ok(headers, host, app.cfg.public_origin.as_deref()) {
        return Err(text(StatusCode::FORBIDDEN, "wrong origin\n"));
    }
    let Some((id, signed)) = signed_in(app, headers) else { return Err(text(StatusCode::UNAUTHORIZED, "not signed in\n")) };
    let sent = headers.get(portal::CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !portal::same_token(sent, &signed.csrf) {
        return Err(text(StatusCode::FORBIDDEN, "wrong csrf token\n"));
    }
    Ok((id, signed))
}

async fn login(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if !origin_ok(&headers, &host, app.cfg.public_origin.as_deref()) {
        return text(StatusCode::FORBIDDEN, "wrong origin\n");
    }
    let ip = peer.ip();
    let now = Instant::now();
    if !app.token_rate.hit(ip, now) {
        warn!(%ip, "too many sign-in attempts from this address");
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<LoginRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    let account = req.username.trim().to_owned();
    if !crate::totp::valid_account(&account) || req.password.is_empty() || req.password.len() > 512 {
        warn!(%ip, "sign-in with an account name or password that cannot be one");
        tokio::time::sleep(app.cfg.fail_delay).await;
        return refused();
    }
    // One of the portal's own accounts: its password is checked here (argon2id, with its own lockout); everything else goes to the helper, as before.
    if app.people.exists(&account) {
        return portal_login(&app, ip, account, req.password, &req.code, now).await;
    }
    // The password first: the helper counts a wrong one against the account and the address (the lockout RDP has), and a wrong password never gets
    // to spend a code of the person's authenticator.
    let source = ip.to_string();
    let auth = app.auth.clone();
    let (acct, pw, src) = (account.clone(), req.password, source);
    let checked = tokio::task::spawn_blocking(move || auth.login(&acct, &pw, &src)).await;
    let ticket = match checked {
        Ok(Ok(Some(t))) => t,
        Ok(Ok(None)) => {
            warn!(%ip, account, "sign-in refused: wrong password");
            return refused();
        }
        Ok(Err(why)) => {
            warn!(%ip, "sign-in: the password could not be checked: {why}");
            return text(StatusCode::SERVICE_UNAVAILABLE, "cannot check passwords now\n");
        }
        Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "cannot check passwords now\n"),
    };
    if let Some(why) = second_factor(&app, ip, &account, &req.code, now, false) {
        warn!(%ip, account, "sign-in refused: {why}");
        revoke(&app, ticket);
        tokio::time::sleep(app.cfg.fail_delay).await;
        return refused();
    }
    let Some((id, signed)) = app.portal.sign_in(&account, ip, ticket.clone(), Instant::now()) else {
        revoke(&app, ticket);
        return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    info!(%ip, account, "signed in");
    let mut res = json(StatusCode::OK, signed_json(&signed));
    if let Ok(v) = HeaderValue::from_str(&portal::set_cookie(Some(&id))) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

/// A place among the password hashes running now: waits a few seconds, and then says the portal is busy (a queue of waiting sign-ins is itself a way to
/// hold memory, so it does not grow without end).
async fn hash_slot(app: &App) -> Result<tokio::sync::SemaphorePermit<'_>, ()> {
    match tokio::time::timeout(Duration::from_secs(5), app.hash_slots.acquire()).await {
        Ok(Ok(p)) => Ok(p),
        _ => Err(()),
    }
}

/// Sign-in of a portal account. The same answer for every failure, the same delay, a lockout per account and per address, and a wrong password never
/// spends a code. The hashing runs off the async threads and at most `hash_slots` at once.
async fn portal_login(app: &Arc<App>, ip: IpAddr, account: String, password: String, code: &str, now: Instant) -> Response {
    // A refusal takes `fail_delay` in all, hashing included, so that the time does not say whether the name is a portal person's.
    let started = Instant::now();
    let pause = |app: &Arc<App>| tokio::time::sleep(app.cfg.fail_delay.saturating_sub(started.elapsed()));
    if app.pw_guesses.blocked(ip, &account, now) {
        warn!(%ip, account, "portal sign-in refused: too many wrong passwords");
        app.audit.record("login", "refused", "", &ip.to_string(), &account, "locked out after too many wrong passwords");
        pause(app).await;
        return refused();
    }
    let Ok(_slot) = hash_slot(&app).await else { return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n") };
    let (a2, name) = (app.clone(), account.clone());
    let verdict = tokio::task::spawn_blocking(move || a2.people.verify(&name, &password)).await;
    drop(_slot);
    match verdict {
        Ok(crate::people::Verdict::Good(_)) => app.pw_guesses.succeeded(ip, &account),
        Ok(crate::people::Verdict::Refused(why)) => {
            // A switched-off account is not a wrong guess (no count), but is refused the same way.
            if why != "account switched off" {
                app.pw_guesses.failed(ip, &account, now);
            }
            warn!(%ip, account, "portal sign-in refused: {why}");
            app.audit.record("login", "refused", "", &ip.to_string(), &account, why);
            pause(app).await;
            return refused();
        }
        Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "cannot check passwords now\n"),
    }
    if let Some(why) = second_factor(app, ip, &account, code, now, true) {
        warn!(%ip, account, "portal sign-in refused: {why}");
        app.audit.record("login", "refused", "", &ip.to_string(), &account, why);
        pause(app).await;
        return refused();
    }
    let Some((id, signed)) = app.portal.sign_in_as(&account, ip, String::new(), true, Instant::now()) else { return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n") };
    info!(%ip, account, "portal account signed in");
    app.audit.record("login", "ok", &account, &ip.to_string(), "", "");
    let mut res = json(StatusCode::OK, signed_json(&signed));
    if let Ok(v) = HeaderValue::from_str(&portal::set_cookie(Some(&id))) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

/// The two-step records of the signed-in account: portal accounts keep theirs apart from the host accounts', so a portal name that equals a host
/// account's cannot touch that account's authenticator.
fn store_for<'a>(app: &'a App, signed: &Signed) -> &'a Store {
    if signed.portal_user { &app.pstore } else { &app.store }
}

/// Checks the code of the account's authenticator when one is asked for; `Some(reason)` is a refusal.
fn second_factor(app: &App, ip: IpAddr, account: &str, code: &str, now: Instant, portal_user: bool) -> Option<&'static str> {
    let store = if portal_user { &app.pstore } else { &app.store };
    if app.cfg.totp == TotpMode::Off {
        return None;
    }
    if !store.exists(account) {
        return (app.cfg.totp == TotpMode::Required).then_some("no authenticator and one is required");
    }
    if app.guesses.blocked(ip, account, now) {
        return Some("too many wrong codes");
    }
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    match store.check_and_use(account, code, unix) {
        CodeCheck::Good => {
            app.guesses.succeeded(ip, account);
            None
        }
        CodeCheck::GoodRecovery(left) => {
            app.guesses.succeeded(ip, account);
            warn!(%ip, account, left, "a recovery code was used");
            None
        }
        CodeCheck::Wrong | CodeCheck::NoAuthenticator => {
            app.guesses.failed(ip, account, now);
            Some("wrong code")
        }
    }
}

async fn me(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    // Whether the account administers the machine is the helper's answer now (the page only uses it to show the admin menu; every admin request asks again).
    let admin = if signed.portal_user {
        app.people.is_admin(&signed.account)
    } else {
        match app.portal.ticket(&id) {
        Some(ticket) => {
            let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
            tokio::task::spawn_blocking(move || auth.is_admin(&ticket, &account, &source)).await.ok().and_then(Result::ok).unwrap_or(false)
        }
        None => false,
        }
    };
    json(StatusCode::OK, signed_json_with_role(&signed, admin))
}

fn signed_json_with_role(signed: &Signed, admin: bool) -> String {
    format!("{{\"account\":{},\"csrf\":\"{}\",\"admin\":{admin},\"portal\":{}}}\n", serde_json::Value::from(signed.account.as_str()), signed.csrf, signed.portal_user)
}

/// The path names of the administrators' pages and what the helper is asked for.
fn admin_kind(name: &str) -> Option<(&'static str, portal::InfoKind)> {
    match name {
        "users" => Some(("users", portal::InfoKind::Users)),
        "sessions" => Some(("sessions", portal::InfoKind::Sessions)),
        "status" => Some(("status", portal::InfoKind::Status)),
        "access" => Some(("access", portal::InfoKind::Access)),
        "cert" => Some(("cert", portal::InfoKind::Cert)),
        _ => None,
    }
}

/// A change an administrator asks for. The browser sends one JSON action (`{"action":"user_disable","name":"eva"}`, the closed list in
/// `src/adminaction.rs`); the portal checks the origin, the CSRF token and a rate, and passes it to the helper, which decides whether the account
/// is an administrator and whether the action is one it knows. Nothing the browser sends is put on a command line here or anywhere before the
/// helper has checked it.
async fn admin_do(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, Query(which): Query<WhichServer>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ip = peer.ip();
    if !app.admin_rate.hit(ip, Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many changes, wait a minute\n");
    }
    // Compact JSON of an object, nothing else: what the helper receives is what was checked here for shape.
    let Some(action) = serde_json::from_slice::<serde_json::Value>(&body).ok().filter(serde_json::Value::is_object).map(|v| v.to_string()) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    let remote = match which.server.as_deref() {
        None | Some("") => None,
        Some(sid) if valid_server_id(sid) => Some(sid.to_string()),
        Some(_) => return text(StatusCode::BAD_REQUEST, "bad request\n"),
    };
    if let Some(server) = remote {
        // The signed-in account has to administer THIS machine (the portal's own helper says so); the server's agent then checks the action against the
        // closed list again, and its runner writes the audit line there, naming this account and address.
        if let Err(r) = require_admin(&app, &id, &signed).await {
            return r;
        }
        let request = serde_json::json!({ "do": serde_json::from_str::<serde_json::Value>(&action).unwrap_or_default(), "actor": signed.account, "source": signed.ip.to_string() });
        let answer = app.links.request(&server, request, crate::link::CHANGE_TIMEOUT).await;
        app.admin_cache.lock().unwrap().clear();
        return match answer {
            // The runner's own JSON: {"ok":true,"result":...} or {"ok":false,"error":...}.
            Ok(body) => json(StatusCode::OK, format!("{body}\n")),
            Err(crate::link::LinkError::Refused(why)) => json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": why }))),
            Err(e) => link_error(e),
        };
    }
    let Some(ticket) = app.portal.ticket(&id).filter(|t| !t.is_empty()) else { return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"Choose a server: a portal account has nothing on the portal\\u2019s own machine.\"}\n".into()) };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    let answer = tokio::task::spawn_blocking(move || auth.admin_do(&ticket, &account, &source, &action)).await;
    // Whatever changed, the next look at the lists is a fresh one.
    app.admin_cache.lock().unwrap().clear();
    match answer {
        Ok(Ok(body)) => json(StatusCode::OK, format!("{body}\n")),
        Ok(Err(why)) if why.contains("only administrators") => text(StatusCode::FORBIDDEN, "administrators only\n"),
        // A refusal in words (a name that is not valid, "the server could not do this now"): shown to the administrator as it is.
        Ok(Err(why)) if why.starts_with("helper: ") => json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": &why["helper: ".len()..] }))),
        _ => text(StatusCode::BAD_GATEWAY, "the server could not be asked\n"),
    }
}

fn totp_mode_word(mode: TotpMode) -> &'static str {
    match mode {
        TotpMode::Off => "off",
        TotpMode::Optional => "optional",
        TotpMode::Required => "required",
    }
}

/// The portal's own settings, as the administrators' Settings page shows them (changing them is editing /etc/default/waydesk and restarting the portal).
fn settings_json(app: &App) -> String {
    serde_json::json!({
        "portal": {
            "bind": app.cfg.bind.to_string(),
            "plain_http": app.cfg.plain_http,
            "public_origin": app.cfg.public_origin,
            "allow_from": app.cfg.allow_from,
            "totp": totp_mode_word(app.cfg.totp),
            "idle_minutes": app.cfg.idle.as_secs() / 60,
            "absolute_hours": app.cfg.absolute.as_secs() / 3600,
        },
        "enrolled": app.store.list(),
    })
    .to_string()
}

/// What the signed-in person's own page shows: the account and whether it has a second factor.
async fn account_info(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((_, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    json(StatusCode::OK, format!("{}\n", serde_json::json!({ "account": signed.account, "totp": totp_mode_word(app.cfg.totp), "enrolled": store_for(&app, &signed).exists(&signed.account), "portal": signed.portal_user })))
}

#[derive(serde::Deserialize)]
struct PasswordChange {
    old: String,
    new: String,
}

/// The signed-in person changes their own password. The old one is checked by the helper like a login (same delay and lockout); the new one is set by
/// the runner. Neither is logged here, and the refusals are in words.
async fn change_password(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !app.pw_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<PasswordChange>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    if req.old.len() > 512 || req.new.len() > 512 {
        return text(StatusCode::BAD_REQUEST, "bad request\n");
    }
    if signed.portal_user {
        return change_portal_password(&app, peer.ip(), &signed.account, req.old, req.new).await;
    }
    let Some(ticket) = app.portal.ticket(&id) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    let answer = tokio::task::spawn_blocking(move || auth.change_password(&ticket, &account, &source, &req.old, &req.new)).await;
    let refuse = |status: StatusCode, why: &str| (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], format!("{}\n", serde_json::json!({ "ok": false, "error": why }))).into_response();
    match answer {
        Ok(Ok(())) => {
            info!(account = signed.account, "changed their own password");
            json(StatusCode::OK, "{\"ok\":true}\n".into())
        }
        Ok(Err(why)) if why.contains("current password") => refuse(StatusCode::FORBIDDEN, "The current password is wrong."),
        Ok(Err(why)) if why.starts_with("helper: ") => refuse(StatusCode::BAD_REQUEST, &why["helper: ".len()..]),
        _ => refuse(StatusCode::BAD_GATEWAY, "The server could not change the password now."),
    }
}

/// A portal account changes its own password: the old one is checked like a sign-in (same lockout), then the new one is hashed and kept.
async fn change_portal_password(app: &Arc<App>, ip: IpAddr, account: &str, old: String, new: String) -> Response {
    let refuse = |status: StatusCode, why: &str| (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], format!("{}\n", serde_json::json!({ "ok": false, "error": why }))).into_response();
    let now = Instant::now();
    if app.pw_guesses.blocked(ip, account, now) {
        tokio::time::sleep(app.cfg.fail_delay).await;
        return refuse(StatusCode::FORBIDDEN, "The current password is wrong.");
    }
    let Ok(_slot) = hash_slot(&app).await else { return refuse(StatusCode::SERVICE_UNAVAILABLE, "Busy, try again.") };
    let (a2, name) = (app.clone(), account.to_string());
    let done = tokio::task::spawn_blocking(move || a2.people.change_password(&name, &old, &new)).await;
    match done {
        Ok(Ok(())) => {
            app.pw_guesses.succeeded(ip, account);
            info!(account, "a portal account changed its own password");
            app.audit.record("account.password", "ok", account, &ip.to_string(), "", "");
            json(StatusCode::OK, "{\"ok\":true}\n".into())
        }
        Ok(Err(e)) => {
            let why = format!("{e:#}");
            if why.contains("current password") {
                app.pw_guesses.failed(ip, account, now);
                app.audit.record("account.password", "refused", account, &ip.to_string(), "", "the current password was wrong");
                tokio::time::sleep(app.cfg.fail_delay).await;
                refuse(StatusCode::FORBIDDEN, "The current password is wrong.")
            } else {
                refuse(StatusCode::BAD_REQUEST, &why)
            }
        }
        Err(_) => refuse(StatusCode::BAD_GATEWAY, "The portal could not change the password now."),
    }
}

#[derive(serde::Deserialize)]
struct CodeRequest {
    code: String,
}

/// Writes the audit line for an authenticator set up or taken away, in the background (the helper is local, but a slow one must not hold a request).
fn note(app: &Arc<App>, ticket: String, account: String, source: String, event: u8, target: String) {
    if ticket.is_empty() {
        // A portal account has no login at the helper to write a line under; the portal's own audit comes with the servers' (slice 5). The journal has it.
        let name = match event {
            crate::portal::NOTE_TOTP_ENROLLED => "account.totp.enrolled",
            crate::portal::NOTE_TOTP_REMOVED => "account.totp.removed",
            _ => "account.note",
        };
        app.audit.record(name, "ok", &account, &source, &target, "");
        return;
    }
    let auth = app.auth.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(why) = auth.note(&ticket, &account, &source, event, &target) {
            warn!("the audit line could not be written: {why}");
        }
    });
}

/// The person sets up their own authenticator, step one: a new secret, shown once (as a key to type and a link for the phone). Nothing is saved yet.
async fn totp_start(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if app.cfg.totp == TotpMode::Off {
        return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"This server does not ask for a code, so there is nothing to set up.\"}\n".into());
    }
    if store_for(&app, &signed).exists(&signed.account) {
        return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"You have an authenticator already. Turn it off first to set up a new one.\"}\n".into());
    }
    if !app.pw_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Ok(secret) = crate::totp::new_secret() else { return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n") };
    let uri = crate::totp::otpauth_uri("Waydesk", &signed.account, &secret);
    let shown = crate::totp::base32(&secret);
    {
        let mut pending = app.pending_totp.lock().unwrap();
        let now = Instant::now();
        pending.retain(|_, p| now.duration_since(p.at) < Duration::from_secs(PENDING_TOTP_SECS));
        if pending.len() >= PENDING_TOTP_MAX && !pending.contains_key(&id) {
            return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
        }
        pending.insert(id, PendingTotp { account: signed.account.clone(), secret: secret.to_vec(), at: now });
    }
    json(StatusCode::OK, format!("{}\n", serde_json::json!({ "ok": true, "secret": shown, "uri": uri })))
}

/// Step two: a code from the app proves the person holds the secret; only then is it kept, and the recovery codes are shown, once.
async fn totp_confirm(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(req) = serde_json::from_slice::<CodeRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    let ip = peer.ip();
    let now = Instant::now();
    if app.guesses.blocked(ip, &signed.account, now) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many wrong codes, wait a few minutes\n");
    }
    let secret = {
        let pending = app.pending_totp.lock().unwrap();
        match pending.get(&id) {
            Some(p) if p.account == signed.account && now.duration_since(p.at) < Duration::from_secs(PENDING_TOTP_SECS) => p.secret.clone(),
            _ => return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"Start again: the key you were shown has expired.\"}\n".into()),
        }
    };
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let code: String = req.code.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(step) = crate::totp::verify(&secret, &code, unix, None) else {
        app.guesses.failed(ip, &signed.account, now);
        return json(StatusCode::BAD_REQUEST, "{\"ok\":false,\"error\":\"That code is not right. Check the time on your phone and try the next code.\"}\n".into());
    };
    app.guesses.succeeded(ip, &signed.account);
    match store_for(&app, &signed).enroll_with(&signed.account, &secret, step) {
        Ok(codes) => {
            app.pending_totp.lock().unwrap().remove(&id);
            info!(account = signed.account, "set up an authenticator");
            if let Some(ticket) = app.portal.ticket(&id) {
                note(&app, ticket, signed.account.clone(), signed.ip.to_string(), crate::portal::NOTE_TOTP_ENROLLED, String::new());
            }
            json(StatusCode::OK, format!("{}\n", serde_json::json!({ "ok": true, "recovery": codes })))
        }
        Err(e) => {
            warn!("could not keep an authenticator: {e:#}");
            json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"It could not be set up (you may have one already).\"}\n".into())
        }
    }
}

/// The person turns their own authenticator off. A current code (or a recovery code) is needed, so a stolen session cannot take the second step away,
/// and a server that requires the code does not allow it at all.
async fn totp_remove(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(req) = serde_json::from_slice::<CodeRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    if app.cfg.totp == TotpMode::Required {
        return json(StatusCode::FORBIDDEN, "{\"ok\":false,\"error\":\"This server requires a code from everybody. Ask an administrator.\"}\n".into());
    }
    let ip = peer.ip();
    let now = Instant::now();
    if app.guesses.blocked(ip, &signed.account, now) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many wrong codes, wait a few minutes\n");
    }
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let code: String = req.code.chars().filter(|c| !c.is_whitespace()).collect();
    match store_for(&app, &signed).check_and_use(&signed.account, &code, unix) {
        CodeCheck::Good | CodeCheck::GoodRecovery(_) => {
            app.guesses.succeeded(ip, &signed.account);
            let _ = store_for(&app, &signed).remove(&signed.account);
            info!(account = signed.account, "turned their authenticator off");
            if let Some(ticket) = app.portal.ticket(&id) {
                note(&app, ticket, signed.account.clone(), signed.ip.to_string(), crate::portal::NOTE_TOTP_REMOVED, String::new());
            }
            json(StatusCode::OK, "{\"ok\":true}\n".into())
        }
        CodeCheck::NoAuthenticator => json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"You have no authenticator.\"}\n".into()),
        CodeCheck::Wrong => {
            app.guesses.failed(ip, &signed.account, now);
            json(StatusCode::BAD_REQUEST, "{\"ok\":false,\"error\":\"That code is not right.\"}\n".into())
        }
    }
}

#[derive(serde::Deserialize)]
struct TotpRequest {
    action: String,
    name: String,
}

/// An administrator takes an account's authenticator away (a lost phone): the account then signs in with the password alone, where the policy allows,
/// and sets a new one up. The administrator is checked by the helper on this request.
async fn admin_totp(State(app): State<Arc<App>>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(req) = serde_json::from_slice::<TotpRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    if req.action != "remove" || !crate::totp::valid_account(&req.name) {
        return text(StatusCode::BAD_REQUEST, "bad request\n");
    }
    let Some(ticket) = app.portal.ticket(&id) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    match tokio::task::spawn_blocking(move || auth.is_admin(&ticket, &account, &source)).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return text(StatusCode::FORBIDDEN, "administrators only\n"),
        _ => return text(StatusCode::BAD_GATEWAY, "the server could not be asked\n"),
    }
    match app.store.remove(&req.name) {
        Ok(removed) => {
            warn!(admin = signed.account, account = req.name, removed, "an administrator removed the authenticator of an account");
            if removed {
                if let Some(ticket) = app.portal.ticket(&id) {
                    note(&app, ticket, signed.account.clone(), signed.ip.to_string(), crate::portal::NOTE_TOTP_REMOVED_BY_ADMIN, req.name.clone());
                }
            }
            json(StatusCode::OK, format!("{}\n", serde_json::json!({ "ok": true, "removed": removed })))
        }
        Err(e) => {
            warn!("could not remove an authenticator: {e:#}");
            text(StatusCode::INTERNAL_SERVER_ERROR, "could not remove it\n")
        }
    }
}

#[derive(serde::Deserialize, Default)]
struct AuditParams {
    #[serde(default)]
    since: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    outcome: String,
    limit: Option<u16>,
    /// Whose log: empty for the portal's own machine (the helper's), `portal` for the portal's own audit log, or the id of a server.
    #[serde(default)]
    source: String,
}

/// The audit log, filtered (an administrator's page). The helper checks the administrator and every filter; the portal only passes them on, cut to
/// a sensible length first.
async fn admin_audit(State(app): State<Arc<App>>, Query(q): Query<AuditParams>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if [&q.since, &q.user, &q.event, &q.outcome].iter().any(|s| s.len() > 64) {
        return text(StatusCode::BAD_REQUEST, "bad request\n");
    }
    if !q.source.is_empty() {
        // The portal's own log, or a server's (asked of its agent, which checks the filters again and runs the same command as the command line).
        if q.source != "portal" && !valid_server_id(&q.source) {
            return text(StatusCode::BAD_REQUEST, "bad request\n");
        }
        if let Err(r) = require_admin(&app, &id, &signed).await {
            return r;
        }
        let query = crate::audit::Query { since: q.since.clone(), user: q.user.clone(), event: q.event.clone(), outcome: q.outcome.clone(), limit: q.limit.unwrap_or(200) };
        if let Err(why) = query.validate() {
            return json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": why })));
        }
        if q.source == "portal" {
            return json(StatusCode::OK, format!("{}\n", serde_json::Value::Array(app.audit.query(&query, unix_now()))));
        }
        let ask = serde_json::json!({ "kind": "audit", "query": { "since": query.since, "user": query.user, "event": query.event, "outcome": query.outcome, "limit": query.limit } });
        return match app.links.request(&q.source, ask, crate::link::READ_TIMEOUT).await {
            Ok(body) => json(StatusCode::OK, format!("{body}\n")),
            Err(e) => link_error(e),
        };
    }
    let Some(ticket) = app.portal.ticket(&id).filter(|t| !t.is_empty()) else { return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"Choose the portal or a server: a portal account has nothing on the portal\\u2019s own machine.\"}\n".into()) };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    let answer = tokio::task::spawn_blocking(move || auth.audit(&ticket, &account, &source, (&q.since, &q.user, &q.event, &q.outcome, q.limit.unwrap_or(200)))).await;
    match answer {
        Ok(Ok(body)) => json(StatusCode::OK, format!("{body}\n")),
        Ok(Err(why)) if why.contains("only administrators") => text(StatusCode::FORBIDDEN, "administrators only\n"),
        Ok(Err(why)) if why.starts_with("helper: ") => json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": &why["helper: ".len()..] }))),
        _ => text(StatusCode::BAD_GATEWAY, "the server could not be asked\n"),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The signed-in browser's account must administer the machine (asked of the helper on every request).
async fn require_admin(app: &Arc<App>, id: &str, signed: &Signed) -> Result<String, Response> {
    if signed.portal_user {
        // An administrator of the portal itself: nothing to ask the helper, and no ticket (so nothing on the portal's own machine, only servers).
        return if app.people.is_admin(&signed.account) { Ok(String::new()) } else { Err(text(StatusCode::FORBIDDEN, "administrators only\n")) };
    }
    let Some(ticket) = app.portal.ticket(id) else { return Err(text(StatusCode::UNAUTHORIZED, "not signed in\n")) };
    let (auth, account, source, t2) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string(), ticket.clone());
    match tokio::task::spawn_blocking(move || auth.is_admin(&t2, &account, &source)).await {
        Ok(Ok(true)) => Ok(ticket),
        Ok(Ok(false)) => Err(text(StatusCode::FORBIDDEN, "administrators only\n")),
        _ => Err(text(StatusCode::BAD_GATEWAY, "the server could not be asked\n")),
    }
}

async fn servers_list(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if let Err(r) = require_admin(&app, &id, &signed).await {
        return r;
    }
    // A link that is up is online whatever `last_seen` says; one that is down is offline at once.
    let mut servers = app.fleet.list(unix_now());
    for v in servers.iter_mut().filter(|v| v.state == "online" || v.state == "offline") {
        v.state = if app.links.online(&v.id) { "online" } else { "offline" };
    }
    json(StatusCode::OK, format!("{}\n", serde_json::json!({ "servers": servers, "portal": app.cfg.public_origin, "pin": cert_pin(&app.cfg) })))
}

#[derive(serde::Deserialize)]
struct ServerRequest {
    action: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    id: String,
}

/// An id the fleet could have made: `s-` and eight hex digits.
fn valid_server_id(id: &str) -> bool {
    id.len() == 10 && id.starts_with("s-") && id[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Add a server (the answer carries its join code, once), make a new code, revoke a server's key, remove a server from the list.
async fn servers_do(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !app.admin_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many changes, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<ServerRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    let ticket = match require_admin(&app, &id, &signed).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = unix_now();
    let fail = |why: String| json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": why })));
    let (event, target, extra) = match req.action.as_str() {
        "add" => match app.fleet.add_server(req.name.trim(), now) {
            Ok((sid, code)) => (crate::portal::NOTE_SERVER_ADDED, sid.clone(), serde_json::json!({ "id": sid, "code": code, "expires_in": crate::fleet::JOIN_TTL })),
            Err(e) => return fail(format!("{e:#}")),
        },
        "code" | "revoke" | "remove" if !valid_server_id(&req.id) => return text(StatusCode::BAD_REQUEST, "bad request\n"),
        "code" => match app.fleet.new_join(&req.id, now) {
            Ok(code) => (crate::portal::NOTE_SERVER_CODE, req.id.clone(), serde_json::json!({ "id": req.id, "code": code, "expires_in": crate::fleet::JOIN_TTL })),
            Err(e) => return fail(format!("{e:#}")),
        },
        "revoke" => match app.fleet.revoke(&req.id) {
            Ok(()) => {
                app.links.drop_link(&req.id);
                (crate::portal::NOTE_SERVER_REVOKED, req.id.clone(), serde_json::json!({}))
            }
            Err(e) => return fail(format!("{e:#}")),
        },
        "remove" if !app.people.assigned_to(&req.id).is_empty() => return fail(format!("{} are still assigned to it: take them away first", app.people.assigned_to(&req.id).join(", "))),
        "remove" => match app.fleet.remove(&req.id) {
            Ok(()) => (crate::portal::NOTE_SERVER_REMOVED, req.id.clone(), serde_json::json!({})),
            Err(e) => return fail(format!("{e:#}")),
        },
        _ => return text(StatusCode::BAD_REQUEST, "bad request\n"),
    };
    warn!(admin = signed.account, action = req.action, server = target, "an administrator changed the servers");
    app.audit.record(&format!("admin.server.{}", req.action), "ok", &signed.account, &signed.ip.to_string(), &target, if req.action == "add" { req.name.trim() } else { "" });
    note(&app, ticket, signed.account.clone(), signed.ip.to_string(), event, target);
    let mut out = extra;
    out["ok"] = serde_json::json!(true);
    json(StatusCode::OK, format!("{out}\n"))
}

#[derive(serde::Deserialize)]
struct EnrolRequest {
    code: String,
}

/// A server enrols: it shows a join code and gets its id and key (once). Public, so it is limited per address, and a wrong code gets the same
/// answer whatever was wrong with it.
async fn enrol(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, body: axum::body::Bytes) -> Response {
    let ip = peer.ip();
    if !app.enrol_rate.hit(ip, Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<EnrolRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    if req.code.len() > 64 {
        return text(StatusCode::BAD_REQUEST, "bad request\n");
    }
    match app.fleet.enrol(&req.code, unix_now()) {
        Ok((server, key)) => {
            warn!(%ip, server, "a server enrolled");
            app.audit.record("server.enrolled", "ok", "", &ip.to_string(), &server, "");
            json(StatusCode::OK, format!("{}\n", serde_json::json!({ "server": server, "key": key })))
        }
        Err(crate::fleet::EnrolError::Busy) => text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n"),
        Err(crate::fleet::EnrolError::BadCode) => {
            warn!(%ip, "enrolment refused: wrong, used or expired code");
            app.audit.record("server.enrolled", "refused", "", &ip.to_string(), "", "wrong, used or expired code");
            tokio::time::sleep(app.cfg.fail_delay).await;
            text(StatusCode::FORBIDDEN, "code refused\n")
        }
    }
}

#[derive(serde::Deserialize, Default)]
struct WhichServer {
    server: Option<String>,
}

fn link_error(e: crate::link::LinkError) -> Response {
    use crate::link::LinkError::*;
    match e {
        Offline => json(StatusCode::SERVICE_UNAVAILABLE, "{\"ok\":false,\"error\":\"That server is offline.\"}\n".into()),
        Timeout => json(StatusCode::GATEWAY_TIMEOUT, "{\"ok\":false,\"error\":\"That server did not answer in time.\"}\n".into()),
        BadAnswer => json(StatusCode::BAD_GATEWAY, "{\"ok\":false,\"error\":\"That server sent an answer the portal does not accept.\"}\n".into()),
        Refused(why) => json(StatusCode::BAD_GATEWAY, format!("{}\n", serde_json::json!({ "ok": false, "error": why }))),
    }
}

/// SHA-256 (hex) of the portal's own certificate, which a server pins when it enrols. Nothing when a reverse proxy holds the certificate (the server
/// then trusts the usual authorities).
fn cert_pin(cfg: &Config) -> Option<String> {
    use rustls::pki_types::pem::PemObject as _;
    use sha2::Digest as _;
    if cfg.plain_http {
        return None;
    }
    let leaf = rustls::pki_types::CertificateDer::pem_file_iter(&cfg.cert).ok()?.next()?.ok()?;
    Some(data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(leaf.as_ref())))
}

/// A server's agent dials this: `/agent`, upgraded to a WebSocket. The first frame proves which server it is (id and key, checked against the
/// fleet); after that the portal sends requests and the agent answers (see `link.rs`). Public, so limited per address and with a short wait for the hello.
async fn agent_ws(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, ws: WebSocketUpgrade) -> Response {
    if !app.agent_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    ws.max_message_size(crate::link::MAX_FRAME).max_frame_size(crate::link::MAX_FRAME).on_upgrade(move |socket| agent_link(socket, peer.ip(), app))
}

async fn agent_link(mut socket: axum::extract::ws::WebSocket, ip: IpAddr, app: Arc<App>) {
    use axum::extract::ws::Message;
    let hello = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Text(t)))) if t.len() <= 1024 => t,
        _ => return,
    };
    let v: serde_json::Value = serde_json::from_str(hello.as_str()).unwrap_or_default();
    let (server, key) = (v["server"].as_str().unwrap_or(""), v["key"].as_str().unwrap_or(""));
    if v["t"] != "hello" || v["version"].as_u64() != Some(crate::link::VERSION) || !valid_server_id(server) || key.len() != 64 || !app.fleet.authenticate(server, key) {
        warn!(%ip, "a server link was refused: wrong hello, version or key");
        app.audit.record("server.link", "refused", "", &ip.to_string(), if valid_server_id(server) { server } else { "" }, "wrong hello, version or key");
        tokio::time::sleep(app.cfg.fail_delay).await;
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let server = server.to_string();
    let mut link = app.links.attach(&server);
    info!(%ip, server, "a server link is up");
    app.audit.record("server.link", "ok", "", &ip.to_string(), &server, "up");
    app.fleet.touch(&server, unix_now());
    if socket.send(Message::Text("{\"t\":\"ready\"}".into())).await.is_err() {
        app.links.detach(&server, link.gen);
        return;
    }
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    let mut last = Instant::now();
    loop {
        tokio::select! {
            frame = socket.recv() => match frame {
                Some(Ok(Message::Text(t))) => {
                    last = Instant::now();
                    app.fleet.touch(&server, unix_now());
                    app.links.answer(&link, t.as_str());
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Ping(_))) => {
                    last = Instant::now();
                    app.fleet.touch(&server, unix_now());
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(Message::Binary(_))) => break,
            },
            out = link.outgoing.recv() => match out {
                Some(frame) => if socket.send(Message::Text(frame.into())).await.is_err() { break },
                None => break, // replaced by a newer link, or revoked
            },
            _ = ping.tick() => {
                if last.elapsed() > Duration::from_secs(60) || socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
    app.links.detach(&server, link.gen);
    let _ = socket.send(Message::Close(None)).await;
    info!(%ip, server, "a server link ended");
    app.audit.record("server.link", "ok", "", &ip.to_string(), &server, "ended");
}

/// One change on a server, asked of its agent as the person who asked for it: the runner's `result`, or why not, in words.
async fn remote_do(app: &Arc<App>, server: &str, actor: &str, source: &str, action: serde_json::Value) -> Result<serde_json::Value, String> {
    use crate::link::LinkError::*;
    let request = serde_json::json!({ "do": action, "actor": actor, "source": source });
    match app.links.request(server, request, crate::link::CHANGE_TIMEOUT).await {
        Ok(body) => {
            let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| "the server's answer is not usable".to_string())?;
            if v["ok"] == true { Ok(v["result"].clone()) } else { Err(v["error"].as_str().unwrap_or("it failed").chars().take(300).collect()) }
        }
        Err(Offline) => Err("that server is offline".into()),
        Err(Timeout) => Err("that server did not answer in time".into()),
        Err(BadAnswer) => Err("that server sent an answer the portal does not accept".into()),
        Err(Refused(why)) => Err(why),
    }
}

async fn people_list(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if let Err(r) = require_admin(&app, &id, &signed).await {
        return r;
    }
    let servers: Vec<_> = app.fleet.list(unix_now()).into_iter().filter(|v| v.state == "online" || v.state == "offline").map(|v| serde_json::json!({ "id": v.id, "name": v.name, "online": app.links.online(&v.id) })).collect();
    json(StatusCode::OK, format!("{}\n", serde_json::json!({ "people": app.people.list(), "servers": servers, "me": signed.account })))
}

#[derive(serde::Deserialize)]
struct PeopleRequest {
    action: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    on: bool,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    server: String,
    desktop: Option<String>,
    gpu: Option<String>,
    memory: Option<String>,
    /// `unassign` only: drop the assignment even though the server could not be told (it is gone for good); the account there stays as it is.
    #[serde(default)]
    force: bool,
}

/// Changes to the portal's people: add, reset a password, make or stop being an administrator, switch off or on, remove, assign a server or take it away.
/// Assigning makes the system account on the server (through its agent); nothing is half done: the assignment is recorded after the server did its part.
async fn people_do(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let who = signed_in(&app, &headers).map(|(_, s)| s.account);
    let asked = serde_json::from_slice::<PeopleRequest>(&body).ok();
    let response = people_do_inner(State(app.clone()), Extension(ClientAddr(peer)), Extension(PublicHost(host)), headers, body).await;
    // A change that was allowed to be tried is in the log, with how it went (never the password it may have made).
    if let (Some(who), Some(req)) = (who, asked) {
        let status = response.status();
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN && status != StatusCode::TOO_MANY_REQUESTS {
            let detail = if req.action == "assign" { req.server.as_str() } else if req.action == "unassign" { req.server.as_str() } else { "" };
            app.audit.record(&format!("admin.people.{}", req.action), if status == StatusCode::OK { "ok" } else { "fail" }, &who, &peer.ip().to_string(), &req.name, detail);
        }
    }
    response
}

async fn people_do_inner(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !app.admin_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many changes, wait a minute\n");
    }
    let Ok(req) = serde_json::from_slice::<PeopleRequest>(&body) else { return text(StatusCode::BAD_REQUEST, "bad request\n") };
    if let Err(r) = require_admin(&app, &id, &signed).await {
        return r;
    }
    if !crate::people::valid_name(&req.name) {
        return text(StatusCode::BAD_REQUEST, "bad request\n");
    }
    let (actor, source) = (signed.account.clone(), signed.ip.to_string());
    let myself = req.name == actor;
    let fail = |why: String| json(StatusCode::BAD_REQUEST, format!("{}\n", serde_json::json!({ "ok": false, "error": why })));
    let ok = |extra: serde_json::Value| {
        let mut out = extra;
        out["ok"] = serde_json::json!(true);
        json(StatusCode::OK, format!("{out}\n"))
    };
    let now = unix_now();
    warn!(admin = actor, action = req.action, person = req.name, server = req.server, "an administrator changed the portal's people");
    match req.action.as_str() {
        "add" => {
            let Ok(_slot) = hash_slot(&app).await else { return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n") };
            let (a2, name, display, admin) = (app.clone(), req.name.clone(), req.display.clone(), req.admin);
            match tokio::task::spawn_blocking(move || a2.people.add(&name, &display, admin, now)).await {
                Ok(Ok(password)) => ok(serde_json::json!({ "name": req.name, "password": password })),
                Ok(Err(e)) => fail(format!("{e:#}")),
                Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "it failed\n"),
            }
        }
        "passwd" => {
            let Ok(_slot) = hash_slot(&app).await else { return text(StatusCode::SERVICE_UNAVAILABLE, "busy\n") };
            let (a2, name) = (app.clone(), req.name.clone());
            match tokio::task::spawn_blocking(move || a2.people.set_password(&name, None)).await {
                Ok(Ok(password)) => {
                    app.portal.end_account(&req.name);
                    ok(serde_json::json!({ "name": req.name, "password": password }))
                }
                Ok(Err(e)) => fail(format!("{e:#}")),
                Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "it failed\n"),
            }
        }
        "admin" => {
            if myself && !req.on {
                return fail("you cannot take administrator rights from yourself".into());
            }
            match app.people.set_admin(&req.name, req.on) {
                Ok(()) => ok(serde_json::json!({})),
                Err(e) => fail(format!("{e:#}")),
            }
        }
        "disable" => {
            if myself && req.on {
                return fail("you cannot switch yourself off".into());
            }
            let Some(p) = app.people.get(&req.name) else { return fail("no such person".into()) };
            if let Err(e) = app.people.set_disabled(&req.name, req.on) {
                return fail(format!("{e:#}"));
            }
            if req.on {
                app.portal.end_account(&req.name);
            }
            // Their accounts on the servers follow (best effort: a server that is offline now is told in the answer, and the account stays as it was there).
            let mut warnings = Vec::new();
            for a in &p.servers {
                let action = if req.on { serde_json::json!({ "action": "user_disable", "name": req.name, "keep_session": false }) } else { serde_json::json!({ "action": "user_enable", "name": req.name }) };
                if let Err(why) = remote_do(&app, &a.server, &actor, &source, action).await {
                    warnings.push(serde_json::json!({ "server": a.server, "error": why }));
                }
            }
            ok(serde_json::json!({ "warnings": warnings }))
        }
        "remove" => {
            if myself {
                return fail("you cannot remove yourself".into());
            }
            match app.people.remove(&req.name) {
                Ok(()) => {
                    app.portal.end_account(&req.name);
                    ok(serde_json::json!({}))
                }
                Err(e) => fail(format!("{e:#}")),
            }
        }
        "assign" => {
            if !valid_server_id(&req.server) {
                return text(StatusCode::BAD_REQUEST, "bad request\n");
            }
            let Some(p) = app.people.get(&req.name) else { return fail("no such person".into()) };
            if p.disabled {
                return fail("that person is switched off".into());
            }
            if !app.links.online(&req.server) {
                return fail("that server is offline: it has to be reachable to make the account".into());
            }
            // The account on the server. One that was there before the portal came is somebody else's: it is never taken over.
            match remote_do(&app, &req.server, &actor, &source, serde_json::json!({ "action": "user_add", "name": req.name })).await {
                Ok(_) => {
                    if let Err(e) = app.people.mark_made(&req.name, &req.server) {
                        return fail(format!("the account was made but not recorded: {e:#}"));
                    }
                }
                Err(why) if why.contains("exists already") && app.people.made_on(&req.name, &req.server) => {
                    if let Err(why) = remote_do(&app, &req.server, &actor, &source, serde_json::json!({ "action": "user_enable", "name": req.name })).await {
                        return fail(why);
                    }
                }
                Err(why) if why.contains("exists already") => return fail(format!("an account named {} is already on that server and was not made by the portal; it is not taken over", req.name)),
                Err(why) => return fail(why),
            }
            if req.desktop.is_some() || req.gpu.is_some() {
                if let Err(why) = remote_do(&app, &req.server, &actor, &source, serde_json::json!({ "action": "user_set", "name": req.name, "desktop": req.desktop, "gpu": req.gpu })).await {
                    return fail(format!("the account was made, but its settings were refused: {why}"));
                }
            }
            if let Some(memory) = &req.memory {
                if let Err(why) = remote_do(&app, &req.server, &actor, &source, serde_json::json!({ "action": "user_limit", "name": req.name, "memory": memory })).await {
                    return fail(format!("the account was made, but its memory limit was refused: {why}"));
                }
            }
            match app.people.assign(&req.name, crate::people::Assignment { server: req.server.clone(), desktop: req.desktop.clone(), gpu: req.gpu.clone(), memory: req.memory.clone() }) {
                Ok(()) => ok(serde_json::json!({})),
                Err(e) => fail(format!("{e:#}")),
            }
        }
        "unassign" => {
            if !valid_server_id(&req.server) {
                return text(StatusCode::BAD_REQUEST, "bad request\n");
            }
            // The account on the server is switched off (never deleted: its files stay), and then the assignment goes.
            if let Err(why) = remote_do(&app, &req.server, &actor, &source, serde_json::json!({ "action": "user_disable", "name": req.name, "keep_session": false })).await {
                if !req.force {
                    return fail(format!("{why}: the account there was not switched off, so the assignment stays"));
                }
                warn!(admin = actor, person = req.name, server = req.server, "an assignment was dropped without the server: {why}");
            }
            match app.people.unassign(&req.name, &req.server) {
                Ok(()) => ok(serde_json::json!({})),
                Err(e) => fail(format!("{e:#}")),
            }
        }
        _ => text(StatusCode::BAD_REQUEST, "bad request\n"),
    }
}

/// A person asks for an app password: the one to type in a native RDP client (Windows App, mstsc, Remmina) in place of their portal password. It is
/// made here, set as the password of their account on every server they are assigned to, and shown once; the portal does not keep it.
async fn app_password(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap) -> Response {
    let (_, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !signed.portal_user {
        return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"This account is a system account of the server: its own password is the one for RDP.\"}\n".into());
    }
    if !app.pw_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let Some(me) = app.people.get(&signed.account) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let servers: Vec<_> = me.servers.iter().filter(|a| app.people.made_on(&me.name, &a.server)).map(|a| a.server.clone()).collect();
    if servers.is_empty() {
        return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"You are not assigned to any server yet.\"}\n".into());
    }
    let Ok(password) = crate::people::generate_password() else { return text(StatusCode::INTERNAL_SERVER_ERROR, "it failed\n") };
    let source = signed.ip.to_string();
    let known = app.fleet.list(unix_now());
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    for server in servers {
        let name = known.iter().find(|k| k.id == server).map_or(server.clone(), |k| k.name.clone());
        match remote_do(&app, &server, &me.name, &source, serde_json::json!({ "action": "user_setpw", "name": me.name, "password": password })).await {
            Ok(_) => done.push(name),
            Err(why) => failed.push(serde_json::json!({ "server": name, "error": why })),
        }
    }
    if done.is_empty() {
        return json(StatusCode::BAD_GATEWAY, format!("{}\n", serde_json::json!({ "ok": false, "error": "No server could set it now.", "failed": failed })));
    }
    let _ = app.people.mark_app_password(&me.name, unix_now());
    info!(account = me.name, servers = done.len(), "an app password was made");
    app.audit.record("account.apppass", if failed.is_empty() { "ok" } else { "fail" }, &me.name, &source, "", &format!("set on {} server(s), not on {}", done.len(), failed.len()));
    json(StatusCode::OK, format!("{}\n", serde_json::json!({ "ok": true, "password": password, "servers": done, "failed": failed })))
}

/// The numbers of one server's status that the fleet page shows: sessions, memory and CPU use, warnings, whether it takes new sessions.
pub fn fleet_summary(status: &serde_json::Value) -> serde_json::Value {
    let m = &status["machine"];
    let a = &status["admission"];
    let total = m["mem_total_mb"].as_f64().unwrap_or(0.0);
    let avail = m["mem_available_mb"].as_f64().unwrap_or(0.0);
    let sessions = a["sessions"].as_u64().unwrap_or_else(|| status["users"].as_array().map_or(0, |u| u.iter().filter(|x| x["session"].is_string() && x["session"] != "none").count() as u64));
    serde_json::json!({
        "sessions": sessions,
        "max_sessions": a["max_active_users"],
        "mem_percent": if total > 0.0 { serde_json::json!(((total - avail) / total * 100.0).round()) } else { serde_json::Value::Null },
        "cpu_percent": m["cpu_percent"],
        "warnings": status["warnings"].as_array().map_or(0, Vec::len),
        "open": a["open"],
    })
}

/// All servers at a glance: each online server is asked for its status at the same time, and one that does not answer in time is shown as such.
async fn fleet_overview(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if let Err(r) = require_admin(&app, &id, &signed).await {
        return r;
    }
    let now = Instant::now();
    if let Some((at, body)) = app.admin_cache.lock().unwrap().get("fleet@") {
        if now.duration_since(*at) < Duration::from_secs(5) {
            return json(StatusCode::OK, body.clone());
        }
    }
    let list = app.fleet.list(unix_now());
    let asked = list.iter().filter(|v| (v.state == "online" || v.state == "offline") && app.links.online(&v.id)).map(|v| {
        let (app, id) = (app.clone(), v.id.clone());
        async move {
            let answer = app.links.request(&id, serde_json::json!({ "kind": "status" }), Duration::from_secs(8)).await;
            (id, answer)
        }
    });
    let answers: std::collections::HashMap<String, Result<String, crate::link::LinkError>> = futures_util::future::join_all(asked).await.into_iter().collect();
    let servers: Vec<_> = list
        .iter()
        .map(|v| {
            let live = app.links.online(&v.id);
            let state = if matches!(v.state, "online" | "offline") { if live { "online" } else { "offline" } } else { v.state };
            let mut row = serde_json::json!({ "id": v.id, "name": v.name, "state": state, "people": app.people.assigned_to(&v.id).len() });
            match answers.get(&v.id) {
                Some(Ok(body)) => {
                    if let Ok(status) = serde_json::from_str::<serde_json::Value>(body) {
                        if let (Some(r), Some(f)) = (row.as_object_mut(), fleet_summary(&status).as_object()) {
                            r.extend(f.clone());
                        }
                    }
                }
                Some(Err(_)) => row["error"] = serde_json::json!("did not answer"),
                None => {}
            }
            row
        })
        .collect();
    let body = format!("{}\n", serde_json::json!({ "servers": servers, "people": app.people.list().len() }));
    app.admin_cache.lock().unwrap().insert("fleet@".to_string(), (now, body.clone()));
    json(StatusCode::OK, body)
}

/// Read-only data for the administrators' pages: the helper's lists and status. Whether the account is an administrator is asked of the helper on
/// every request (a person taken out of the group loses the pages at once); the answer itself is kept a few seconds.
async fn admin_page(State(app): State<Arc<App>>, UrlPath(kind): UrlPath<String>, Query(which): Query<WhichServer>, headers: HeaderMap) -> Response {
    // "settings" is the portal's own configuration, which needs no question to the helper; the rest are the helper's.
    let settings = kind == "settings";
    let Some((name, info_kind)) = (if settings { Some(("settings", portal::InfoKind::Role)) } else { admin_kind(&kind) }) else { return text(StatusCode::NOT_FOUND, "not found\n") };
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let ticket = match require_admin(&app, &id, &signed).await {
        Ok(t) => t,
        Err(r) => {
            warn!(account = signed.account, kind = name, "an account that is not an administrator asked for an administrators' page");
            return r;
        }
    };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    if settings {
        return json(StatusCode::OK, format!("{}\n", settings_json(&app)));
    }
    let remote = match which.server.as_deref() {
        None | Some("") => None,
        Some(id) if valid_server_id(id) => Some(id.to_string()),
        Some(_) => return text(StatusCode::BAD_REQUEST, "bad request\n"),
    };
    let key = format!("{name}@{}", remote.as_deref().unwrap_or(""));
    let now = Instant::now();
    if let Some((at, body)) = app.admin_cache.lock().unwrap().get(&key) {
        if now.duration_since(*at) < Duration::from_secs(ADMIN_CACHE_SECS) {
            return json(StatusCode::OK, body.clone());
        }
    }
    if let Some(server) = remote {
        // Another server: its agent answers with the same JSON the command line prints there.
        return match app.links.request(&server, serde_json::json!({ "kind": name }), crate::link::READ_TIMEOUT).await {
            Ok(body) => {
                app.admin_cache.lock().unwrap().insert(key, (now, body.clone()));
                json(StatusCode::OK, body)
            }
            Err(e) => link_error(e),
        };
    }
    if ticket.is_empty() {
        return json(StatusCode::CONFLICT, "{\"ok\":false,\"error\":\"Choose a server: a portal account has nothing on the portal\\u2019s own machine.\"}\n".into());
    }
    match tokio::task::spawn_blocking(move || auth.info(&ticket, &account, &source, info_kind)).await {
        Ok(Ok(body)) => {
            app.admin_cache.lock().unwrap().insert(key, (now, body.clone()));
            json(StatusCode::OK, body)
        }
        Ok(Err(why)) => {
            warn!(kind = name, "the helper could not answer: {why}");
            text(StatusCode::BAD_GATEWAY, "the server could not be asked\n")
        }
        Err(_) => text(StatusCode::BAD_GATEWAY, "the server could not be asked\n"),
    }
}

/// A small picture of the signed-in portal person's own running desktop on one of their servers (the card on My desktop). Only for a person assigned
/// to that server, with an account the portal made there, not switched off; the account asked of the agent is the signed-in one, the browser names
/// only the server. Nothing is stored or logged, and the answer is never cached. 204 when there is no session (or no picture yet).
async fn mine_shot(State(app): State<Arc<App>>, Query(which): Query<WhichServer>, headers: HeaderMap) -> Response {
    let Some((_, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let server = which.server.unwrap_or_default();
    if !signed.portal_user || !valid_server_id(&server) {
        return text(StatusCode::BAD_REQUEST, "choose a server\n");
    }
    let Some(me) = app.people.get(&signed.account).filter(|p| !p.disabled && p.servers.iter().any(|a| a.server == server) && app.people.made_on(&p.name, &server)) else {
        return text(StatusCode::FORBIDDEN, "that server is not assigned to you\n");
    };
    let answer = match app.links.request(&server, serde_json::json!({ "shot": { "account": me.name } }), crate::link::READ_TIMEOUT).await {
        Ok(a) => a,
        Err(e) => return link_error(e),
    };
    let Some(png) = serde_json::from_str::<serde_json::Value>(&answer).ok().and_then(|v| v.get("hex")?.as_str().map(decode_hex)).flatten() else {
        return text(StatusCode::NO_CONTENT, "");
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "no-store"), (header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
        png,
    )
        .into_response()
}

/// Hex text to bytes (`None` when it is not hex, or is too big for a picture of the card).
fn decode_hex(h: &str) -> Option<Vec<u8>> {
    if h.len() % 2 != 0 || h.len() > 2 * 512 * 1024 || !h.starts_with("89504e47") {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok()).collect()
}

/// The signed-in account's own desktop, from the helper: whether its session is running and since when, its desktop and graphics. The helper decides
/// what an account may see (its own row); when it cannot be asked, the page still works and says nothing about the state.
async fn mine(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if signed.portal_user {
        return json(StatusCode::OK, mine_portal(&app, &signed.account));
    }
    let Some(ticket) = app.portal.ticket(&id) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    let (auth, account, source) = (app.auth.clone(), signed.account.clone(), signed.ip.to_string());
    let answer = tokio::task::spawn_blocking(move || auth.info(&ticket, &account, &source, crate::portal::InfoKind::Users)).await;
    json(StatusCode::OK, mine_json(answer.ok().and_then(Result::ok).as_deref(), &signed.account))
}

/// What a portal account's own page shows: the servers they are assigned to, and whether each is reachable now.
fn mine_portal(app: &App, account: &str) -> String {
    let Some(me) = app.people.get(account) else { return "{\"available\":false}\n".into() };
    let known = app.fleet.list(unix_now());
    let servers: Vec<_> = me
        .servers
        .iter()
        .map(|a| {
            let name = known.iter().find(|k| k.id == a.server).map_or("(removed)", |k| k.name.as_str());
            serde_json::json!({ "id": a.server, "name": name, "online": app.links.online(&a.server), "desktop": a.desktop, "gpu": a.gpu })
        })
        .collect();
    format!("{}\n", serde_json::json!({ "available": true, "portal": true, "display": me.display, "servers": servers, "app_password_set": me.app_password_set }))
}

/// The row of `account` in the helper's user list, cut down to what the page shows; `{"available":false}` when there is none.
fn mine_json(list: Option<&str>, account: &str) -> String {
    let row = list.and_then(|l| serde_json::from_str::<Vec<serde_json::Value>>(l).ok()).and_then(|rows| rows.into_iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(account)));
    let Some(row) = row else { return "{\"available\":false}\n".into() };
    let text = |k: &str| row.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    let out = serde_json::json!({
        "available": true,
        "session": text("session").unwrap_or_else(|| "none".into()),
        "since": text("session_since"),
        "desktop": text("desktop"),
        "desktop_running": text("desktop_running"),
        "gpu": text("gpu"),
    });
    format!("{out}\n")
}

/// Tells the helper that a ticket is no longer wanted (in the background: the helper is a local socket, but a slow one must not hold a request).
fn revoke(app: &Arc<App>, ticket: String) {
    let auth = app.auth.clone();
    tokio::task::spawn_blocking(move || auth.revoke(&ticket));
}

async fn logout(State(app): State<Arc<App>>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap) -> Response {
    let (id, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(ticket) = app.portal.sign_out(&id) {
        revoke(&app, ticket);
    }
    info!(account = signed.account, "signed out");
    let mut res = json(StatusCode::OK, "{}\n".into());
    if let Ok(v) = HeaderValue::from_str(&portal::set_cookie(None)) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

/// A one-time token for opening the signed-in account's desktop (see `bridge.rs`).
async fn session_token(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, headers: HeaderMap) -> Response {
    let (_, signed) = match changing(&app, &headers, &host) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ip = peer.ip();
    let now = Instant::now();
    if !app.token_rate.hit(ip, now) {
        warn!(%ip, "too many session requests from this address");
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    match app.tokens.issue(ip, &signed.account, now) {
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

/// The browser stream: a signed-in browser's WebSocket, bridged to the daemon (see `stream.rs`). The account is the cookie's. A WebSocket carries
/// no CSRF header, so what keeps another page from opening one in a visitor's name is the `Origin` check and the cookie's `SameSite=Strict`.
async fn stream_handler(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, Extension(PublicHost(host)): Extension<PublicHost>, Query(which): Query<WhichServer>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if !origin_ok(&headers, &host, app.cfg.public_origin.as_deref()) {
        return text(StatusCode::FORBIDDEN, "wrong origin\n");
    }
    let Some((id, signed)) = signed_in(&app, &headers) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if signed.portal_user {
        return remote_stream(&app, peer.ip(), signed, which.server.as_deref().unwrap_or(""), ws);
    }
    let Some(ticket) = app.portal.ticket(&id) else { return text(StatusCode::UNAUTHORIZED, "not signed in\n") };
    if app.cfg.gateway_key.is_none() {
        return text(StatusCode::SERVICE_UNAVAILABLE, "the browser stream needs --gateway-key\n");
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
    info!(%ip, account = signed.account, active = app.sessions.active(), "stream requested");
    ws.max_message_size(crate::stream::MAX_CLIPBOARD_FROM_BROWSER).max_frame_size(crate::stream::MAX_CLIPBOARD_FROM_BROWSER).on_upgrade(move |socket| crate::stream::run(socket, ip, signed.account, ticket, app, guard))
}

/// A portal account opens a desktop on one of its servers: it has to be assigned to it (and made there by the portal), not switched off, and the
/// server has to be online. The portal then makes a token, the server's agent is told over its link to dial back with it, and the two WebSockets are
/// passed on to each other (`stream::run_remote`). The account the server is told is the signed-in one; the browser names only the server.
fn remote_stream(app: &Arc<App>, ip: IpAddr, signed: Signed, server: &str, ws: WebSocketUpgrade) -> Response {
    if !valid_server_id(server) {
        return text(StatusCode::BAD_REQUEST, "choose a server\n");
    }
    let Some(me) = app.people.get(&signed.account).filter(|p| !p.disabled && p.servers.iter().any(|a| a.server == server) && app.people.made_on(&p.name, server)) else {
        return text(StatusCode::FORBIDDEN, "that server is not assigned to you\n");
    };
    if !app.links.online(server) {
        return text(StatusCode::SERVICE_UNAVAILABLE, "that server is offline\n");
    }
    if !app.ws_rate.hit(ip, Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    let guard = match app.sessions.start(ip) {
        Ok(g) => g,
        Err(Refusal::PerAddress) => return text(StatusCode::TOO_MANY_REQUESTS, "too many sessions from this address\n"),
        Err(Refusal::Total) => return text(StatusCode::SERVICE_UNAVAILABLE, "the portal is full\n"),
    };
    let Some((token, agent)) = app.relays.expect(server) else { return text(StatusCode::SERVICE_UNAVAILABLE, "too many desktops are opening, try again\n") };
    info!(%ip, account = me.name, server, "remote stream requested");
    app.audit.record("stream.open", "ok", &me.name, &ip.to_string(), server, "");
    let (app, server) = (app.clone(), server.to_string());
    ws.max_message_size(crate::stream::MAX_CLIPBOARD_FROM_BROWSER).max_frame_size(crate::stream::MAX_CLIPBOARD_FROM_BROWSER).on_upgrade(move |socket| crate::stream::run_remote(socket, ip, me.name, server, token, agent, app, guard))
}

/// The agent of a server dials this to carry one desktop: `/relay`, upgraded to a WebSocket. The first frame names the server, its key and the token
/// the portal gave it over the link; the WebSocket is then handed to the browser's task that waits for it.
async fn relay_ws(State(app): State<Arc<App>>, Extension(ClientAddr(peer)): Extension<ClientAddr>, ws: WebSocketUpgrade) -> Response {
    if !app.agent_rate.hit(peer.ip(), Instant::now()) {
        return text(StatusCode::TOO_MANY_REQUESTS, "too many attempts, wait a minute\n");
    }
    ws.max_message_size(crate::stream::MAX_FROM_DAEMON).max_frame_size(crate::stream::MAX_FROM_DAEMON).on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message;
        let hello = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
            Ok(Some(Ok(Message::Text(t)))) if t.len() <= 1024 => t,
            _ => return,
        };
        let v: serde_json::Value = serde_json::from_str(hello.as_str()).unwrap_or_default();
        let (server, key, token) = (v["server"].as_str().unwrap_or(""), v["key"].as_str().unwrap_or(""), v["token"].as_str().unwrap_or(""));
        if v["t"] != "relay" || !valid_server_id(server) || key.len() != 64 || token.len() != 32 || !app.fleet.authenticate(server, key) {
            warn!(ip = %peer.ip(), "a relay was refused: wrong hello or key");
            return;
        }
        match app.relays.take(token, server) {
            Some(waiting) => {
                // The browser's task takes it from here; when it has gone, the socket is dropped and the agent sees the end.
                let _ = waiting.send(socket);
            }
            None => warn!(ip = %peer.ip(), server, "a relay was refused: the token is not live for this server"),
        }
    })
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
    #[test]
    fn the_picture_of_a_card_is_a_png_in_hex_and_nothing_else() {
        assert_eq!(decode_hex("89504e47ff"), Some(vec![0x89, 0x50, 0x4e, 0x47, 0xff]));
        assert!(decode_hex("89504e4").is_none(), "odd length");
        assert!(decode_hex("89504e47zz").is_none(), "not hex");
        assert!(decode_hex("3c68746d6c3e").is_none(), "not a PNG");
        assert!(decode_hex(&format!("89504e47{}", "00".repeat(512 * 1024))).is_none(), "too big");
    }

    use super::*;

    #[test]
    fn the_page_gets_only_the_accounts_own_fields() {
        let list = r#"[{"name":"bob","session":"running","uid":1002},{"name":"alice","session":"running","session_since":"Tue 2026-11-17 08:41:00 UTC","desktop":"plasma","desktop_running":"plasma","gpu":"off","uid":1001,"sudo":true}]"#;
        let v: serde_json::Value = serde_json::from_str(&mine_json(Some(list), "alice")).unwrap();
        assert_eq!(v["available"], true);
        assert_eq!(v["session"], "running");
        assert_eq!(v["desktop"], "plasma");
        assert!(v.get("uid").is_none() && v.get("sudo").is_none(), "nothing the page does not need");
        for none in [None, Some("not json"), Some("[]"), Some(r#"[{"name":"bob"}]"#)] {
            assert_eq!(mine_json(none, "alice").trim(), r#"{"available":false}"#);
        }
    }

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
