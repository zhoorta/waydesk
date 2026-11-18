//! The root helper (`waydesk-server --helper`): the only part that runs with root rights, and the only part that
//! does what needs them: check a password for any account (PAM) and start a session process as that account.
//! It speaks the small protocol of `proto::HelperReq` on a Unix socket that only the daemon's account can open, and
//! never touches the network or the RDP protocol.
//!
//! Rules it enforces, whatever the daemon says:
//! - a session is started only for the account that authenticated on the same connection;
//! - one login per connection;
//! - what is started and with which arguments is the helper's own configuration.
//!
//! Sessions outlive connections: a session process registers at the helper's second socket (`sessions.sock`, which any
//! local account may open) right after it starts; the kernel tells the helper which account is on the other end, so a
//! session can only ever register as its own account. A reconnecting client gets a new socket pair: one end goes to
//! the session process over its registration, the other to the daemon. The helper never connects to a path inside an
//! account's directories (a symlink there could point root at something else).

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context as _, Result};
use tracing::{info, warn};

use crate::audit::{self, Outcome};
use crate::auth::{lookup_user, PamPolicy, UserInfo};
use crate::fdpass;
use crate::memory::{self, Admission};
use crate::proto::{self, HelperReq, HelperResp};
use crate::spawn::spawn_worker;

pub struct Config {
    pub socket: PathBuf,
    /// The only account that may connect.
    pub daemon_user: String,
    pub allow_users: Option<Vec<String>>,
    /// A group every account that logs in has to be in.
    pub require_group: Option<String>,
    pub exe: PathBuf,
    pub worker_args: Vec<String>,
    pub workspace: String,
    /// Start sessions as `waydesk-session@<uid>.service` (the packaged way: they get the account's own slice and none
    /// of the helper's sandbox) instead of as children of the helper.
    pub systemd_sessions: bool,
    /// What a new session needs (see `memory::admission`).
    pub min_available_mb: Option<u64>,
    pub max_active_users: usize,
    /// `waydesk-admin`, which answers the read-only `Info` requests (`admininfo.rs`).
    pub admin_exe: PathBuf,
    /// The runner's socket (`waydesk-admin.socket`), where administrators' changes are sent.
    pub admin_socket: PathBuf,
}

/// Connections served at once.
const MAX_CONNECTIONS: usize = 64;
/// Registration connections open at once, in all and per account (any local account may open this socket).
const MAX_REGISTRATIONS: usize = 256;
const MAX_REGISTRATIONS_PER_ACCOUNT: usize = 4;
/// How long a new session process may take to register.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(20);

/// A running session process, as it registered.
struct Registered {
    /// Our end of its registration socket: client sockets are sent through it.
    sock: UnixStream,
    generation: u64,
}

/// The sessions that exist, by account, and the processes started for them.
struct Sessions {
    by_uid: Mutex<HashMap<u32, Registered>>,
    registered: Condvar,
    next_generation: AtomicU64,
    /// One at a time per account while a session is looked up or started.
    gates: Mutex<HashMap<u32, Arc<Mutex<()>>>>,
    /// Session processes, to be reaped when they end.
    children: Mutex<Vec<Child>>,
    /// Open registration connections, per account and in all.
    registrations: Mutex<HashMap<u32, usize>>,
}

impl Sessions {
    fn gate(&self, uid: u32) -> Arc<Mutex<()>> {
        self.gates.lock().unwrap().entry(uid).or_default().clone()
    }

    /// A socket to the running session of `uid`, if there is one that still answers.
    fn attach(&self, uid: u32) -> Option<UnixStream> {
        let mut map = self.by_uid.lock().unwrap();
        let reg = map.get(&uid)?;
        let (ours, theirs) = UnixStream::pair().ok()?;
        if fdpass::send_fd(&reg.sock, theirs.as_raw_fd()).is_ok() {
            return Some(ours);
        }
        // The process behind the registration is gone.
        map.remove(&uid);
        None
    }

    fn reap(&self) {
        self.children.lock().unwrap().retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }
}

pub fn run(cfg: Config) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "the helper has to run as root");
    let daemon = lookup_user(&cfg.daemon_user).with_context(|| format!("no account named {}", cfg.daemon_user))?;
    ensure!(daemon.uid != 0, "the daemon must not be root");
    let policy = PamPolicy::new("waydesk-server", cfg.allow_users.clone(), cfg.require_group.clone())?;

    let dir = cfg.socket.parent().context("--helper-socket needs a directory")?.to_path_buf();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let register_path = dir.join("sessions.sock");
    // Where the session processes say what they run (src/sessionstatus.rs): written by root only, with a folder of its own for every account that has a
    // session (made in `session_for` and at registration), so no account can take another's file names.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let status_dir = dir.join("status");
        std::fs::create_dir_all(&status_dir).with_context(|| format!("creating {}", status_dir.display()))?;
        std::fs::set_permissions(&status_dir, std::fs::Permissions::from_mode(0o755)).with_context(|| format!("setting the mode of {}", status_dir.display()))?;
    }

    // The daemon's socket: owner only from the first moment, then handed to the daemon's account.
    let listener = bind(&cfg.socket, 0o177)?;
    let path = std::ffi::CString::new(cfg.socket.as_os_str().as_encoded_bytes())?;
    ensure!(unsafe { libc::chown(path.as_ptr(), daemon.uid, daemon.gid) } == 0, "chown of the socket failed");
    // The registration socket: any local account may open it (session processes run as their accounts).
    let registrations = bind(&register_path, 0o000)?;
    info!(socket = %cfg.socket.display(), registrations = %register_path.display(), daemon = %daemon.name, "helper listening");

    let sessions = Arc::new(Sessions {
        by_uid: Mutex::new(HashMap::new()),
        registered: Condvar::new(),
        next_generation: AtomicU64::new(1),
        gates: Mutex::new(HashMap::new()),
        children: Mutex::new(Vec::new()),
        registrations: Mutex::new(HashMap::new()),
    });

    {
        let sessions = sessions.clone();
        std::thread::spawn(move || {
            for conn in registrations.incoming().flatten() {
                let sessions = sessions.clone();
                std::thread::spawn(move || registration(conn, &sessions));
            }
        });
    }
    {
        let sessions = sessions.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            sessions.reap();
        });
    }

    let cfg = Arc::new(cfg);
    // A ticket lives as long as the portal's longest sign-in (8 hours).
    let tickets = Arc::new(crate::tickets::Tickets::new(Duration::from_secs(8 * 3600)));
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let sock = match conn {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        // The daemon's account, and root: a server's agent (root) may ask for tickets (`IssueFor`) and for nothing else.
        let root_peer = match peer_uid(&sock) {
            Some(uid) if uid == daemon.uid => false,
            Some(0) => true,
            other => {
                warn!(?other, "refused a connection from another account");
                continue;
            }
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            warn!("too many connections, refused");
            continue;
        }
        let (cfg, policy, sessions, active, register_path, tickets) = (cfg.clone(), policy.clone(), sessions.clone(), active.clone(), register_path.clone(), tickets.clone());
        std::thread::spawn(move || {
            serve(sock, &cfg, &policy, &sessions, &tickets, &register_path, root_peer);
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

/// Binds a Unix socket created with the given umask (so it is never briefly more open than intended); a mask of 0
/// leaves it world-connectable.
fn bind(path: &std::path::Path, umask: libc::mode_t) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let old = unsafe { libc::umask(umask) };
    let listener = UnixListener::bind(path).with_context(|| format!("cannot listen on {}", path.display()));
    unsafe { libc::umask(old) };
    listener
}

/// The uid of the process on the other end (SO_PEERCRED).
fn peer_uid(sock: &UnixStream) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    (rc == 0).then_some(cred.uid)
}

/// A session process says it is up. It never sends anything: it stays connected until it ends, and the end of
/// the connection is how we learn that it is gone.
fn registration(mut conn: UnixStream, sessions: &Sessions) {
    use std::io::Read;
    let Some(uid) = peer_uid(&conn) else { return };
    // Only ordinary accounts have sessions; root and system accounts have no business here.
    if uid < 1000 || uid == 65534 {
        warn!(uid, "registration refused");
        return;
    }
    {
        let mut counts = sessions.registrations.lock().unwrap();
        let total: usize = counts.values().sum();
        let mine = counts.entry(uid).or_insert(0);
        if total >= MAX_REGISTRATIONS || *mine >= MAX_REGISTRATIONS_PER_ACCOUNT {
            warn!(uid, total, "too many registrations, refused");
            return;
        }
        *mine += 1;
    }
    let _count = CountGuard { sessions, uid };
    // A session that was running when the helper restarted lost its status folder with the runtime directory: it gets it back here.
    prepare_status(uid);
    let Ok(sock) = conn.try_clone() else { return };
    let generation = sessions.next_generation.fetch_add(1, Ordering::Relaxed);
    let registered_at = Instant::now();
    sessions.by_uid.lock().unwrap().insert(uid, Registered { sock, generation });
    sessions.registered.notify_all();
    info!(uid, "session registered");
    let mut buf = [0u8; 64];
    while matches!(conn.read(&mut buf), Ok(n) if n > 0) {}
    let mut map = sessions.by_uid.lock().unwrap();
    if map.get(&uid).is_some_and(|r| r.generation == generation) {
        map.remove(&uid);
    }
    info!(uid, "session ended");
    let mut e = audit::event("session.end", Outcome::Ok);
    if let Some(name) = audit::name_of(uid) {
        e = e.str("user", &name);
    }
    e.num("uid", uid.into()).num("seconds", registered_at.elapsed().as_secs()).emit();
}

/// Gives a registration slot back when the connection ends, however it ends.
struct CountGuard<'a> {
    sessions: &'a Sessions,
    uid: u32,
}

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        let mut counts = self.sessions.registrations.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.uid);
            }
        }
    }
}

/// The account's own status folder (src/sessionstatus.rs). A failure only costs `waydesk-admin status` its line about this session.
fn prepare_status(uid: u32) {
    if let Err(e) = crate::sessionstatus::prepare(std::path::Path::new(crate::sessionstatus::DIR), uid) {
        warn!(uid, "cannot make the status folder of the account: {e}");
    }
}

fn reply(sock: &mut UnixStream, resp: &HelperResp) -> bool {
    proto::write_frame(sock, &resp.encode()).is_ok()
}

/// Makes sure the account has a runtime directory (`/run/user/<uid>`): starts its systemd user manager if need be. That
/// is what `loginctl enable-linger` does too, but without changing the account's settings for good.
fn ensure_runtime_dir(user: &UserInfo) -> Result<()> {
    let dir = PathBuf::from(format!("/run/user/{}", user.uid));
    if dir.is_dir() {
        return Ok(());
    }
    info!(user = %user.name, "starting the user manager for its runtime directory");
    let status = std::process::Command::new("systemctl")
        .arg("start")
        .arg(format!("user@{}.service", user.uid))
        .stdin(std::process::Stdio::null())
        .status()
        .context("cannot run systemctl")?;
    ensure!(status.success(), "systemctl start user@{}.service failed ({status})", user.uid);
    for _ in 0..100 {
        if dir.is_dir() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("{} did not appear", dir.display())
}

/// A new session was refused on purpose (memory, number of users); the daemon turns it into the reason the client is shown.
#[derive(Debug)]
struct Refused {
    reason: u8,
    message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// The running session of the account, or a new one (started and waited for until it registers).
fn session_for(user: &UserInfo, source: &str, cfg: &Config, sessions: &Sessions, register_path: &std::path::Path) -> Result<UnixStream> {
    let gate = sessions.gate(user.uid);
    let _one_at_a_time = gate.lock().unwrap();
    if let Some(s) = sessions.attach(user.uid) {
        info!(user = %user.name, "reconnecting to the running session");
        audit::event("session.reconnect", Outcome::Ok).str("user", &user.name).num("uid", user.uid.into()).source(source).emit();
        return Ok(s);
    }
    // A new session costs memory the others may need: when the machine cannot take one more, the login is refused here (the
    // account's running session, if it has one, was handed out above, so nobody is thrown out for a newcomer).
    if let Some(info) = memory::read_meminfo() {
        let running = sessions.by_uid.lock().unwrap().len();
        match memory::admission(&info, running, cfg.min_available_mb, cfg.max_active_users) {
            Admission::Open => {}
            Admission::Full { available_mb, needed_mb } => {
                warn!(user = %user.name, available_mb, needed_mb, running, "session refused: the machine is short of memory");
                audit::event("session.refused", Outcome::Refused).str("user", &user.name).num("uid", user.uid.into()).str("reason", "memory").source(source).emit();
                return Err(Refused {
                    reason: proto::REFUSED_MEMORY,
                    message: format!("the server is short of memory ({available_mb} MB available, {needed_mb} MB needed for a new session)"),
                }
                .into());
            }
            Admission::TooManyUsers { users, max } => {
                warn!(user = %user.name, users, max, "session refused: the limit of active users is reached");
                audit::event("session.refused", Outcome::Refused).str("user", &user.name).num("uid", user.uid.into()).str("reason", "users_limit").source(source).emit();
                return Err(Refused { reason: proto::REFUSED_USERS, message: format!("the limit of {max} active users is reached") }.into());
            }
        }
    }
    ensure_runtime_dir(user)?;
    prepare_status(user.uid);
    if cfg.systemd_sessions {
        let unit = format!("waydesk-session@{}.service", user.uid);
        let status = std::process::Command::new("systemctl").arg("start").arg(&unit).stdin(std::process::Stdio::null()).status().context("cannot run systemctl")?;
        ensure!(status.success(), "systemctl start {unit} failed ({status})");
        info!(user = %user.name, %unit, "session unit started");
    } else {
        let (child, _) = spawn_worker(&cfg.exe, &cfg.worker_args, &cfg.workspace, Some(user), true, Some(register_path))?;
        info!(user = %user.name, pid = child.id(), "session process started");
        sessions.children.lock().unwrap().push(child);
    }

    let deadline = Instant::now() + REGISTER_TIMEOUT;
    let mut map = sessions.by_uid.lock().unwrap();
    while !map.contains_key(&user.uid) {
        let left = deadline.saturating_duration_since(Instant::now());
        ensure!(!left.is_zero(), "the session process did not register in {} s", REGISTER_TIMEOUT.as_secs());
        map = sessions.registered.wait_timeout(map, left).unwrap().0;
    }
    drop(map);
    let attached = sessions.attach(user.uid).context("the new session process is already gone")?;
    audit::event("session.start", Outcome::Ok).str("user", &user.name).num("uid", user.uid.into()).source(source).flag("systemd", cfg.systemd_sessions).emit();
    Ok(attached)
}

/// One daemon connection: one client of the daemon.
fn serve(mut sock: UnixStream, cfg: &Config, policy: &PamPolicy, sessions: &Sessions, tickets: &crate::tickets::Tickets, register_path: &std::path::Path, root_peer: bool) {
    let mut who: Option<UserInfo> = None;
    // Where the client that logged in on this connection comes from, and since when: the daemon holds one connection per client, so the
    // end of this one is the end of that client's connection (written here, where the daemon cannot forge it).
    let mut login: Option<(String, Instant)> = None;
    let mut started = false;
    loop {
        let body = match proto::read_frame(&mut sock) {
            Ok(Some(b)) => b,
            _ => break,
        };
        let req = match HelperReq::decode(&body) {
            Ok(r) => r,
            Err(e) => {
                warn!("bad request from the daemon: {e}");
                break;
            }
        };
        // Root (an agent) may ask for a ticket and say goodbye, and nothing else; the daemon's account may do everything but ask for a ticket without a password.
        let allowed_for_peer = match &req {
            HelperReq::Bye => true,
            HelperReq::IssueFor { .. } => root_peer,
            _ => !root_peer,
        };
        if !allowed_for_peer {
            warn!(root_peer, "a request that this peer may not make");
            reply(&mut sock, &HelperResp::Error { message: "not allowed for this peer".into() });
            break;
        }
        let ok = match req {
            HelperReq::IssueFor { user, source } => {
                let allowed = source.parse::<std::net::IpAddr>().ok().and_then(|_| policy.still_allowed(&user));
                match allowed.and_then(|info| tickets.issue(&info, &source, Instant::now()).map(|t| (info, t))) {
                    Some((info, ticket)) => {
                        audit::event("login.ticket.issued", Outcome::Ok).typed_name(&info.name).num("uid", info.uid.into()).source(&source).str("via", "agent").emit();
                        reply(&mut sock, &HelperResp::Ticket { ticket })
                    }
                    None => {
                        audit::event("login.ticket.issued", Outcome::Refused).str("reason", "not_allowed").source(&source).str("via", "agent").emit();
                        reply(&mut sock, &HelperResp::Error { message: "that account may not log in".into() })
                    }
                }
            }
            HelperReq::Authenticate { user, password, source } => {
                if who.is_some() {
                    reply(&mut sock, &HelperResp::Error { message: "already logged in on this connection".into() })
                } else {
                    match policy.authenticate(&user, &password, &source) {
                        Some(info) => {
                            who = Some(info);
                            login = Some((source, Instant::now()));
                            reply(&mut sock, &HelperResp::AuthOk)
                        }
                        None => reply(&mut sock, &HelperResp::AuthFail),
                    }
                }
            }
            HelperReq::StartSession => match &who {
                None => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
                Some(_) if started => reply(&mut sock, &HelperResp::Error { message: "a session was already handed out on this connection".into() }),
                Some(user) => match session_for(user, login.as_ref().map_or("", |l| l.0.as_str()), cfg, sessions, register_path) {
                    Ok(ours) => {
                        started = true;
                        // The session process holds its end; ours goes to the daemon, and then we let go of it.
                        reply(&mut sock, &HelperResp::Started) && fdpass::send_fd(&sock, ours.as_raw_fd()).is_ok()
                    }
                    Err(e) => {
                        warn!(user = %user.name, "cannot start the session: {e:#}");
                        match e.downcast_ref::<Refused>() {
                            Some(r) => reply(&mut sock, &HelperResp::Refused { reason: r.reason, message: r.message.clone() }),
                            None => reply(&mut sock, &HelperResp::Error { message: format!("{e:#}") }),
                        }
                    }
                },
            },
            HelperReq::IssueTicket => match (&who, &login) {
                (Some(user), Some((source, _))) => match tickets.issue(user, source, Instant::now()) {
                    Some(ticket) => reply(&mut sock, &HelperResp::Ticket { ticket }),
                    None => reply(&mut sock, &HelperResp::Error { message: "no ticket can be made now".into() }),
                },
                _ => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
            },
            HelperReq::Redeem { ticket, user, source } => {
                if who.is_some() {
                    reply(&mut sock, &HelperResp::Error { message: "already logged in on this connection".into() })
                } else {
                    // The account must still be one that may log in (its group, its shell), as at the password check.
                    match tickets.redeem(&ticket, &source, Instant::now()).filter(|u| u.name == user).and_then(|u| policy.still_allowed(&u.name)) {
                        Some(info) => {
                            audit::event("login.ticket", Outcome::Ok).typed_name(&info.name).num("uid", info.uid.into()).source(&source).emit();
                            who = Some(info);
                            login = Some((source, Instant::now()));
                            reply(&mut sock, &HelperResp::AuthOk)
                        }
                        None => {
                            audit::event("login.ticket", Outcome::Fail).str("reason", "bad_ticket").source(&source).emit();
                            reply(&mut sock, &HelperResp::AuthFail)
                        }
                    }
                }
            }
            HelperReq::RevokeTicket { ticket } => {
                tickets.revoke(&ticket);
                reply(&mut sock, &HelperResp::AuthOk)
            }
            HelperReq::Info { kind } => match &who {
                None => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
                Some(user) => {
                    // The administrator check is made again on every request: a person taken out of the group stops being one at once.
                    let admin = crate::admininfo::is_admin(&user.groups);
                    match crate::admininfo::answer(kind, &user.name, admin, &cfg.admin_exe) {
                        Ok(json) => reply(&mut sock, &HelperResp::Info { json }),
                        Err(e) => {
                            warn!(user = %user.name, ?kind, "info refused or failed: {e:#}");
                            reply(&mut sock, &HelperResp::Error { message: format!("{e:#}") })
                        }
                    }
                }
            },
            HelperReq::Admin { json } => match (&who, &login) {
                (Some(user), Some((source, _))) => {
                    // The administrator is checked on this request (the group list was read when this connection logged in, and the portal logs in anew
                    // for every request); the action is checked against the closed list; the runner checks both again.
                    let refuse = |sock: &mut UnixStream, why: &str| reply(sock, &HelperResp::Error { message: why.into() });
                    if !crate::admininfo::is_admin(&user.groups) {
                        warn!(user = %user.name, "a change was asked for by an account that is not an administrator");
                        audit::event("admin.refused", Outcome::Refused).str("user", &user.name).num("uid", user.uid.into()).source(source).str("reason", "not_admin").emit();
                        refuse(&mut sock, "only administrators may do this")
                    } else {
                        match serde_json::from_str::<serde_json::Value>(&json).map_err(|_| "the request is not JSON".to_string()).and_then(|v| crate::adminaction::AdminAction::from_json(&v)) {
                            Err(why) => refuse(&mut sock, &why),
                            Ok(action) if action.carries_secret() => refuse(&mut sock, "this change is only made through a server's agent"),
                            Ok(action) => match crate::admininfo::run_action(&cfg.admin_socket, user.uid, source, &action) {
                                Ok(answer) => reply(&mut sock, &HelperResp::Info { json: answer }),
                                Err(e) => {
                                    warn!(user = %user.name, "the runner could not be asked: {e:#}");
                                    refuse(&mut sock, "the server could not do this now")
                                }
                            },
                        }
                    }
                }
                _ => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
            },
            HelperReq::Audit { since, user, event, outcome, limit } => match &who {
                None => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
                Some(me) if !crate::admininfo::is_admin(&me.groups) => reply(&mut sock, &HelperResp::Error { message: "only administrators may read the audit log".into() }),
                Some(me) => match crate::admininfo::audit(&crate::admininfo::AuditQuery { since, user, event, outcome, limit }, &cfg.admin_exe) {
                    Ok(json) => reply(&mut sock, &HelperResp::Info { json }),
                    Err(e) => {
                        warn!(user = %me.name, "audit log not read: {e:#}");
                        reply(&mut sock, &HelperResp::Error { message: format!("{e:#}") })
                    }
                },
            },
            HelperReq::AuditNote { event, target } => match (&who, &login) {
                (Some(user), Some((source, _))) => {
                    let name = match event {
                        proto::NOTE_TOTP_ENROLLED => "account.totp.enrolled",
                        proto::NOTE_TOTP_REMOVED => "account.totp.removed",
                        proto::NOTE_TOTP_REMOVED_BY_ADMIN => "admin.totp.removed",
                        proto::NOTE_SERVER_ADDED => "admin.server.add",
                        proto::NOTE_SERVER_CODE => "admin.server.code",
                        proto::NOTE_SERVER_REVOKED => "admin.server.revoke",
                        proto::NOTE_SERVER_REMOVED => "admin.server.remove",
                        _ => "",
                    };
                    // Only the known notes, about a name that can be one; the administrators' notes only from an administrator.
                    let by_admin = matches!(event, proto::NOTE_TOTP_REMOVED_BY_ADMIN | proto::NOTE_SERVER_ADDED | proto::NOTE_SERVER_CODE | proto::NOTE_SERVER_REVOKED | proto::NOTE_SERVER_REMOVED);
                    if name.is_empty() || (!target.is_empty() && !crate::adminaction::valid_name(&target)) || (by_admin && !crate::admininfo::is_admin(&user.groups)) {
                        reply(&mut sock, &HelperResp::Error { message: "not a note the helper writes".into() })
                    } else {
                        let mut e = audit::event(name, Outcome::Ok).str("user", &user.name).num("uid", user.uid.into()).source(source).str("via", "portal");
                        if !target.is_empty() {
                            e = e.str("target", &target);
                        }
                        e.emit();
                        reply(&mut sock, &HelperResp::AuthOk)
                    }
                }
                _ => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
            },
            HelperReq::ChangePassword { old, new } => match (&who, &login) {
                (Some(user), Some((source, _))) => {
                    let fail = |sock: &mut UnixStream, why: &str| reply(sock, &HelperResp::Error { message: why.into() });
                    if let Err(why) = crate::admininfo::check_new_password(&old, &new) {
                        fail(&mut sock, why)
                    } else if policy.authenticate(&user.name, &old, source).is_none() {
                        // The old password is checked like a login: same delay, same lockout. Whatever happens, neither password is written anywhere.
                        audit::event("admin.user.passwd", Outcome::Refused).str("user", &user.name).num("uid", user.uid.into()).source(source).str("reason", "old_password").emit();
                        fail(&mut sock, "the current password is not right")
                    } else {
                        match crate::admininfo::run_self_password(&cfg.admin_socket, user.uid, source, &new) {
                            Ok(answer) => reply(&mut sock, &HelperResp::Info { json: answer }),
                            Err(e) => {
                                warn!(user = %user.name, "the runner could not change the password: {e:#}");
                                fail(&mut sock, "the server could not change the password now")
                            }
                        }
                    }
                }
                _ => reply(&mut sock, &HelperResp::Error { message: "not logged in".into() }),
            },
            HelperReq::Bye => false,
        };
        if !ok {
            break;
        }
    }
    // The session belongs to the account and goes on without this connection.
    if let (Some(user), Some((source, since))) = (&who, &login) {
        audit::event("connection.end", Outcome::Ok).str("user", &user.name).num("uid", user.uid.into()).source(source).num("seconds", since.elapsed().as_secs()).emit();
    }
}
