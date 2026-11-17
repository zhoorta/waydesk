//! The portal's sign-in: who is signed in (cookie sessions kept in memory) and how a password is checked (through the root helper).
//!
//! A person signs in once, with the account's password and the code of their authenticator; the password is checked by the root helper, which is
//! also what the RDP daemon asks, so the lockout and the delay after a failed login are shared with RDP and cannot be bypassed from the web. The
//! portal keeps no password: it passes it on and forgets it. What it keeps is a random cookie value that stands for "this account signed in from
//! this address", with a CSRF token that every request that changes anything has to repeat in a header.

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[path = "../../src/proto.rs"]
#[allow(dead_code)] // the daemon uses all of it, this crate the helper's login only
mod proto;
use proto::{HelperReq, HelperResp};
pub use proto::InfoKind;

/// The name of the cookie. `__Host-` makes the browser accept it only with `Secure`, `Path=/` and no `Domain`, so a subdomain or a plain-HTTP page
/// cannot plant or overwrite it.
pub const COOKIE: &str = "__Host-waydesk";
/// The header that repeats the CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Checks an account's password.
pub trait Authenticator: Send + Sync {
    /// `Ok(true)`: the password is right. `Ok(false)`: it is not (or the account may not log in). `Err`: the check could not be made.
    fn check(&self, account: &str, password: &str, source: &str) -> Result<bool, String>;

    /// Like `check`; when the password is right, the helper's ticket for this sign-in, which the portal keeps instead of the password and the daemon
    /// redeems when the browser opens a stream. (The default is for stand-ins that have no helper: a ticket of zeros.)
    fn login(&self, account: &str, password: &str, source: &str) -> Result<Option<String>, String> {
        Ok(self.check(account, password, source)?.then(|| "0".repeat(64)))
    }

    /// The ticket is no longer wanted (the person signed out).
    fn revoke(&self, _ticket: &str) {}

    /// Read-only information about the signed-in account's machine, as JSON (`proto::InfoKind`): the account's own rows, or everybody's for an
    /// administrator. The helper decides what the account may see; the portal only passes it on. (Stand-ins without a helper have nothing to say.)
    fn info(&self, _ticket: &str, _account: &str, _source: &str, _kind: InfoKind) -> Result<String, String> {
        Err("no helper".into())
    }
}

/// The root helper of the daemon (`waydesk-server --helper`). Its socket opens only for the daemon's account, so the portal runs as that account.
pub struct HelperAuth {
    pub socket: PathBuf,
}

impl HelperAuth {
    fn connect(&self) -> Result<UnixStream, String> {
        let sock = UnixStream::connect(&self.socket).map_err(|e| format!("cannot reach the helper at {}: {e}", self.socket.display()))?;
        // A failed login takes the helper a few seconds on purpose; anything longer than that is a helper that does not answer.
        let limit = Some(Duration::from_secs(30));
        let _ = sock.set_read_timeout(limit);
        let _ = sock.set_write_timeout(limit);
        Ok(sock)
    }

    fn ask(sock: &mut UnixStream, req: &HelperReq) -> Result<HelperResp, String> {
        proto::write_frame(sock, &req.encode()).map_err(|e| e.to_string())?;
        let body = proto::read_frame(sock).map_err(|e| e.to_string())?.ok_or("the helper closed the connection")?;
        HelperResp::decode(&body).map_err(|e| e.to_string())
    }

    /// The password check, and with `want_ticket` the ticket on the same connection (the ticket is the helper's proof of this very login).
    fn run(&self, account: &str, password: &str, source: &str, want_ticket: bool) -> Result<Option<String>, String> {
        let mut sock = self.connect()?;
        let req = HelperReq::Authenticate { user: account.to_owned(), password: password.to_owned(), source: source.to_owned() };
        let answer = Self::ask(&mut sock, &req)?;
        let result = match answer {
            HelperResp::AuthOk if want_ticket => match Self::ask(&mut sock, &HelperReq::IssueTicket)? {
                HelperResp::Ticket { ticket } => Ok(Some(ticket)),
                HelperResp::Error { message } => Err(format!("helper: {message}")),
                other => Err(format!("unexpected answer to a ticket request: {other:?}")),
            },
            HelperResp::AuthOk => Ok(Some(String::new())),
            HelperResp::AuthFail => Ok(None),
            HelperResp::Error { message } => Err(format!("helper: {message}")),
            other => Err(format!("unexpected answer to a login: {other:?}")),
        };
        // One login per connection: say goodbye so that the helper does not wait for more.
        let _ = proto::write_frame(&mut sock, &HelperReq::Bye.encode());
        result
    }
}

impl Authenticator for HelperAuth {
    fn check(&self, account: &str, password: &str, source: &str) -> Result<bool, String> {
        Ok(self.run(account, password, source, false)?.is_some())
    }

    fn login(&self, account: &str, password: &str, source: &str) -> Result<Option<String>, String> {
        self.run(account, password, source, true)
    }

    fn info(&self, ticket: &str, account: &str, source: &str, kind: InfoKind) -> Result<String, String> {
        let mut sock = self.connect()?;
        let redeem = HelperReq::Redeem { ticket: ticket.to_owned(), user: account.to_owned(), source: source.to_owned() };
        let result = match Self::ask(&mut sock, &redeem)? {
            HelperResp::AuthOk => match Self::ask(&mut sock, &HelperReq::Info { kind })? {
                HelperResp::Info { json } => Ok(json),
                HelperResp::Error { message } => Err(format!("helper: {message}")),
                other => Err(format!("unexpected answer to an info request: {other:?}")),
            },
            HelperResp::AuthFail => Err("the sign-in is no longer good".into()),
            HelperResp::Error { message } => Err(format!("helper: {message}")),
            other => Err(format!("unexpected answer to a ticket: {other:?}")),
        };
        let _ = proto::write_frame(&mut sock, &HelperReq::Bye.encode());
        result
    }

    fn revoke(&self, ticket: &str) {
        if let Ok(mut sock) = self.connect() {
            let _ = Self::ask(&mut sock, &HelperReq::RevokeTicket { ticket: ticket.to_owned() });
            let _ = proto::write_frame(&mut sock, &HelperReq::Bye.encode());
        }
    }
}

/// What a signed-in browser holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub account: String,
    pub ip: IpAddr,
    pub csrf: String,
}

struct Entry {
    signed: Signed,
    /// The helper's ticket for this sign-in; it stays here, never in the cookie or the page.
    ticket: String,
    created: Instant,
    last: Instant,
}

/// The signed-in browsers: at most `max` in all and `per_account` for one account, each ended after `idle` without a request or `absolute` after
/// signing in. The oldest idle one makes room when the table is full, so a flood of sign-ins cannot lock everybody else out, but one account cannot
/// push others out either (its own limit is lower).
pub struct Portal {
    idle: Duration,
    absolute: Duration,
    max: usize,
    per_account: usize,
    entries: Mutex<HashMap<String, Entry>>,
}

fn random_hex(bytes: usize) -> Option<String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw).ok()?;
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}

impl Portal {
    pub fn new(idle: Duration, absolute: Duration, max: usize, per_account: usize) -> Self {
        Self { idle, absolute, max, per_account, entries: Mutex::new(HashMap::new()) }
    }

    /// The value of the cookie.
    pub fn sign_in(&self, account: &str, ip: IpAddr, ticket: String, now: Instant) -> Option<(String, Signed)> {
        let id = random_hex(32)?;
        let signed = Signed { account: account.to_owned(), ip, csrf: random_hex(16)? };
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut map, now);
        // The account's oldest sign-in goes when it has too many.
        let mine: Vec<(&String, Instant)> = map.iter().filter(|(_, e)| e.signed.account == account).map(|(k, e)| (k, e.last)).collect();
        if mine.len() >= self.per_account {
            let oldest = mine.iter().min_by_key(|(_, t)| *t).map(|(k, _)| (*k).clone());
            if let Some(k) = oldest {
                map.remove(&k);
            }
        }
        if map.len() >= self.max {
            return None;
        }
        map.insert(id.clone(), Entry { signed: signed.clone(), ticket, created: now, last: now });
        Some((id, signed))
    }

    /// Who the cookie stands for, if it is still good. A request counts as activity.
    pub fn get(&self, id: &str, now: Instant) -> Option<Signed> {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let e = map.get_mut(id)?;
        if now.duration_since(e.last) >= self.idle || now.duration_since(e.created) >= self.absolute {
            map.remove(id);
            return None;
        }
        e.last = now;
        Some(e.signed.clone())
    }

    /// Ends the sign-in; its ticket, to be revoked at the helper.
    pub fn sign_out(&self, id: &str) -> Option<String> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).remove(id).map(|e| e.ticket)
    }

    /// The helper's ticket of a live sign-in.
    pub fn ticket(&self, id: &str) -> Option<String> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).get(id).map(|e| e.ticket.clone())
    }

    pub fn count(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn expire(&self, map: &mut HashMap<String, Entry>, now: Instant) {
        let (idle, absolute) = (self.idle, self.absolute);
        map.retain(|_, e| now.duration_since(e.last) < idle && now.duration_since(e.created) < absolute);
    }
}

/// The cookie's value in a `Cookie` header, if there is exactly one cookie of our name.
pub fn cookie_value(header: &str) -> Option<&str> {
    let mut found = None;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(COOKIE).and_then(|r| r.strip_prefix('=')) {
            if found.is_some() {
                return None; // two cookies of this name: not believed
            }
            found = Some(v);
        }
    }
    found.filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The `Set-Cookie` value that stores a sign-in (or, with an empty value, removes it).
pub fn set_cookie(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("{COOKIE}={v}; Path=/; Secure; HttpOnly; SameSite=Strict"),
        None => format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
    }
}

/// Whether two tokens are equal, in time that does not depend on where they differ.
pub fn same_token(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));

    fn portal() -> Portal {
        Portal::new(Duration::from_secs(1800), Duration::from_secs(8 * 3600), 4, 2)
    }

    #[test]
    fn a_cookie_stands_for_the_account_that_signed_in() {
        let p = portal();
        let now = Instant::now();
        let (id, signed) = p.sign_in("ana", IP, String::new(), now).unwrap();
        assert_eq!(id.len(), 64);
        assert_eq!(p.get(&id, now).unwrap(), signed);
        assert!(p.get(&"0".repeat(64), now).is_none(), "a value nobody was given");
        assert_eq!(p.sign_out(&id), Some(String::new()));
        assert!(p.get(&id, now).is_none());
    }

    #[test]
    fn idle_and_absolute_limits_end_a_sign_in() {
        let p = portal();
        let t0 = Instant::now();
        let (id, _) = p.sign_in("ana", IP, String::new(), t0).unwrap();
        // Activity keeps it alive past the idle limit counted from the sign-in...
        assert!(p.get(&id, t0 + Duration::from_secs(1500)).is_some());
        assert!(p.get(&id, t0 + Duration::from_secs(3000)).is_some());
        // ...but 30 minutes of silence ends it,
        assert!(p.get(&id, t0 + Duration::from_secs(3000 + 1800)).is_none());
        // and eight hours end it whatever the activity.
        let (id, _) = p.sign_in("ana", IP, String::new(), t0).unwrap();
        let mut t = t0;
        while t < t0 + Duration::from_secs(8 * 3600 - 600) {
            t += Duration::from_secs(600);
            assert!(p.get(&id, t).is_some());
        }
        assert!(p.get(&id, t0 + Duration::from_secs(8 * 3600)).is_none());
    }

    #[test]
    fn an_account_keeps_its_newest_sign_ins_and_cannot_fill_the_table() {
        let p = portal();
        let t = Instant::now();
        let (a, _) = p.sign_in("ana", IP, String::new(), t).unwrap();
        let (b, _) = p.sign_in("ana", IP, String::new(), t + Duration::from_secs(1)).unwrap();
        let (c, _) = p.sign_in("ana", IP, String::new(), t + Duration::from_secs(2)).unwrap();
        assert!(p.get(&a, t + Duration::from_secs(3)).is_none(), "the oldest of three goes");
        assert!(p.get(&b, t + Duration::from_secs(3)).is_some());
        assert!(p.get(&c, t + Duration::from_secs(3)).is_some());
        // The table holds 4: two more accounts fill it, and a fifth sign-in is refused instead of throwing others out.
        assert!(p.sign_in("bob", IP, String::new(), t).is_some());
        assert!(p.sign_in("eve", IP, String::new(), t).is_some());
        assert!(p.sign_in("zed", IP, String::new(), t).is_none());
        assert_eq!(p.count(), 4);
    }

    #[test]
    fn the_cookie_header_is_read_strictly() {
        let id = "ab".repeat(32);
        assert_eq!(cookie_value(&format!("{COOKIE}={id}")), Some(id.as_str()));
        assert_eq!(cookie_value(&format!("theme=dark; {COOKIE}={id}; other=1")), Some(id.as_str()));
        assert_eq!(cookie_value(&format!("{COOKIE}={id}; {COOKIE}={id}")), None, "two of our cookie");
        assert_eq!(cookie_value(&format!("{COOKIE}=short")), None);
        assert_eq!(cookie_value(&format!("{COOKIE}={}", "zz".repeat(32))), None, "not hex");
        assert_eq!(cookie_value(&format!("x{COOKIE}={id}")), None, "another name that ends with ours");
        assert_eq!(cookie_value(""), None);
    }

    #[test]
    fn the_cookie_is_set_with_every_protection() {
        let c = set_cookie(Some("v"));
        for part in ["__Host-waydesk=v", "Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(c.contains(part), "{c}");
        }
        assert!(!c.contains("Domain"), "a __Host- cookie must not name a domain");
        assert!(set_cookie(None).contains("Max-Age=0"));
    }

    #[test]
    fn tokens_are_compared_whole() {
        assert!(same_token("abc", "abc"));
        assert!(!same_token("abc", "abd"));
        assert!(!same_token("abc", "abcd"));
        assert!(!same_token("", "a"));
    }

    #[test]
    fn a_login_gets_a_ticket_on_the_connection_of_its_password_check_and_only_then() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("waydesk-portal-ticket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..3 {
                let (mut s, _) = listener.accept().unwrap();
                loop {
                    let Some(body) = proto::read_frame(&mut s).unwrap() else { break };
                    let req = HelperReq::decode(&body).unwrap();
                    let answer = match &req {
                        HelperReq::Authenticate { password, .. } if password == "right" => HelperResp::AuthOk,
                        HelperReq::Authenticate { .. } => HelperResp::AuthFail,
                        HelperReq::IssueTicket => HelperResp::Ticket { ticket: "ab".repeat(32) },
                        HelperReq::RevokeTicket { .. } => HelperResp::AuthOk,
                        _ => break,
                    };
                    seen.push(req);
                    proto::write_frame(&mut s, &answer.encode()).unwrap();
                }
            }
            seen
        });
        let auth = HelperAuth { socket: path.clone() };
        assert_eq!(auth.login("ana", "right", "203.0.113.9"), Ok(Some("ab".repeat(32))));
        assert_eq!(auth.login("ana", "wrong", "203.0.113.9"), Ok(None), "no ticket for a wrong password");
        auth.revoke(&"ab".repeat(32));
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), 4);
        assert_eq!(seen[1], HelperReq::IssueTicket, "asked on the connection that checked the password");
        assert_eq!(seen[3], HelperReq::RevokeTicket { ticket: "ab".repeat(32) });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ticket_stays_in_the_portal() {
        let p = portal();
        let (id, signed) = p.sign_in("ana", IP, "t".repeat(64), Instant::now()).unwrap();
        assert_eq!(p.ticket(&id), Some("t".repeat(64)));
        assert!(!format!("{signed:?}").contains("tttt"), "what the browser is given has no ticket");
        assert!(p.ticket(&"0".repeat(64)).is_none());
        assert_eq!(p.sign_out(&id), Some("t".repeat(64)), "sign-out hands it back to be revoked");
        assert!(p.ticket(&id).is_none());
    }

    #[test]
    fn the_helper_is_asked_with_its_own_protocol() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("waydesk-portal-helper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let req = HelperReq::decode(&proto::read_frame(&mut s).unwrap().unwrap()).unwrap();
                let answer = match &req {
                    HelperReq::Authenticate { password, .. } if password == "right" => HelperResp::AuthOk,
                    _ => HelperResp::AuthFail,
                };
                proto::write_frame(&mut s, &answer.encode()).unwrap();
                seen.push(req);
            }
            seen
        });
        let auth = HelperAuth { socket: path.clone() };
        assert_eq!(auth.check("ana", "right", "203.0.113.9"), Ok(true));
        assert_eq!(auth.check("ana", "wrong", "203.0.113.9"), Ok(false));
        let seen = server.join().unwrap();
        assert_eq!(seen[0], HelperReq::Authenticate { user: "ana".into(), password: "right".into(), source: "203.0.113.9".into() });
        assert!(HelperAuth { socket: dir.join("none.sock") }.check("ana", "x", "y").is_err(), "no helper there");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
