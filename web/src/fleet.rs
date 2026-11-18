//! The registry of servers a portal controls (stage 3, slice 1 of docs/PORTAL-DESIGN.md): which servers exist, the single-use join codes that
//! enrol them, and the long-lived key each server then proves itself with.
//!
//! Secrets are never kept: a join code and a server key are random, shown once, and stored only as a SHA-256 hash (they carry 160 and 256 bits,
//! so a fast hash is enough, as for the portal's tickets). Everything takes `now` (unix seconds) so that expiry is testable.
//! The file is written through a temporary file with mode 0600, like the authenticator records.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::VecDeque;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// How long a join code works.
pub const JOIN_TTL: u64 = 3600;
/// Most servers one portal keeps (pending and revoked ones count).
pub const MAX_SERVERS: usize = 200;
/// Longest server name.
pub const MAX_NAME: usize = 40;
/// Enrolment attempts with a wrong code that the portal tolerates in `FAIL_WINDOW` seconds, from everybody together: the endpoint is public, and a
/// code has 160 bits, so this only stops noise and log floods, not a real guess.
const MAX_FAILS: usize = 20;
const FAIL_WINDOW: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// `s-` and 8 hex digits: stable, never reused, safe in a URL and in the audit log.
    pub id: String,
    pub name: String,
    pub created: u64,
    /// SHA-256 (hex) of the server key; `None` until the server enrols, and again after a revocation.
    pub key_hash: Option<String>,
    pub enrolled: Option<u64>,
    pub revoked: bool,
    /// Last time the link was seen alive (set by the link, slice 2).
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Join {
    hash: String,
    server_id: String,
    expires: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Data {
    servers: Vec<Server>,
    joins: Vec<Join>,
}

/// What the Servers page shows about one server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct View {
    pub id: String,
    pub name: String,
    /// `waiting` (a join code is out), `expired` (the code ran out, make a new one), `online`, `offline`, `revoked`.
    pub state: &'static str,
    pub created: u64,
    pub enrolled: Option<u64>,
    pub last_seen: Option<u64>,
}

/// A server counts as online when the link answered within this many seconds.
pub const ONLINE_WITHIN: u64 = 60;

pub struct Fleet {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

struct Inner {
    data: Data,
    fails: VecDeque<u64>,
}

/// Why an enrolment was refused. The caller gives the same answer for all of them.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrolError {
    /// Wrong, used or expired code.
    BadCode,
    /// Too many wrong codes lately.
    Busy,
}

/// A name for a server: 1 to 40 characters, letters, digits, space, dot, dash, underscore, and not only spaces. No control characters, no markup.
pub fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_NAME).contains(&n)
        && name == name.trim()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
}

/// What a person typed or pasted, without the dashes and spaces a code may be grouped with, in the case the code is made in.
fn normalise(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase()
}

fn sha_hex(text: &str) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(text.as_bytes()))
}

fn random(bytes: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(b)
}

/// 160 random bits as 32 base32 characters.
fn new_code() -> Result<String> {
    Ok(data_encoding::BASE32_NOPAD.encode(&random(20)?))
}

/// 256 random bits as 64 hex digits.
fn new_key() -> Result<String> {
    Ok(data_encoding::HEXLOWER.encode(&random(32)?))
}

fn same(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

impl Fleet {
    /// A registry kept in `path` (read now; a missing file is an empty registry, a broken one is an error and is not overwritten).
    pub fn open(path: PathBuf) -> Result<Self> {
        let data = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("{} is not a valid fleet file", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Fleet { path: Some(path), inner: Mutex::new(Inner { data, fails: VecDeque::new() }) })
    }

    /// A registry that lives in memory only (tests, and the portal before it has a directory).
    pub fn in_memory() -> Self {
        Fleet { path: None, inner: Mutex::new(Inner { data: Data::default(), fails: VecDeque::new() }) }
    }

    fn save(&self, data: &Data) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("tmp");
        let text = serde_json::to_vec_pretty(data)?;
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&text)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Runs `change` on a copy and keeps it only when it succeeds and the file is written: a failed save changes nothing in memory either.
    fn edit<T>(&self, change: impl FnOnce(&mut Data) -> Result<T>) -> Result<T> {
        let mut g = self.inner.lock().map_err(|_| anyhow::anyhow!("fleet lock poisoned"))?;
        let mut copy = Data { servers: g.data.servers.clone(), joins: g.data.joins.clone() };
        let out = change(&mut copy)?;
        self.save(&copy)?;
        g.data = copy;
        Ok(out)
    }

    /// Adds a pending server and returns its id and the join code, shown once.
    pub fn add_server(&self, name: &str, now: u64) -> Result<(String, String)> {
        if !valid_name(name) {
            bail!("the name must be 1 to {MAX_NAME} letters, digits, spaces, dots, dashes or underscores");
        }
        self.edit(|d| {
            if d.servers.len() >= MAX_SERVERS {
                bail!("too many servers");
            }
            if d.servers.iter().any(|s| s.name.eq_ignore_ascii_case(name)) {
                bail!("a server with that name exists");
            }
            let id = loop {
                let id = format!("s-{}", data_encoding::HEXLOWER.encode(&random(4)?));
                if !d.servers.iter().any(|s| s.id == id) {
                    break id;
                }
            };
            let code = new_code()?;
            d.servers.push(Server { id: id.clone(), name: name.to_string(), created: now, key_hash: None, enrolled: None, revoked: false, last_seen: None });
            d.joins.push(Join { hash: sha_hex(&code), server_id: id.clone(), expires: now + JOIN_TTL });
            Ok((id, code))
        })
    }

    /// A new join code for a server that is waiting or whose code ran out. The old codes of that server stop working. Not for an enrolled server
    /// (revoke it first: a live server must not be replaced by whoever holds a code).
    pub fn new_join(&self, id: &str, now: u64) -> Result<String> {
        self.edit(|d| {
            let s = d.servers.iter().find(|s| s.id == id).context("no such server")?;
            if s.key_hash.is_some() {
                bail!("the server is enrolled; revoke it before making a new code");
            }
            let code = new_code()?;
            d.joins.retain(|j| j.server_id != id);
            d.joins.push(Join { hash: sha_hex(&code), server_id: id.to_string(), expires: now + JOIN_TTL });
            if let Some(s) = d.servers.iter_mut().find(|s| s.id == id) {
                s.revoked = false;
            }
            Ok(code)
        })
    }

    /// Redeems a join code: the code is used up, and the server gets its key (returned once, with the server id).
    pub fn enrol(&self, code: &str, now: u64) -> Result<(String, String), EnrolError> {
        {
            let mut g = self.inner.lock().map_err(|_| EnrolError::Busy)?;
            while g.fails.front().is_some_and(|t| now.saturating_sub(*t) >= FAIL_WINDOW) {
                g.fails.pop_front();
            }
            if g.fails.len() >= MAX_FAILS {
                return Err(EnrolError::Busy);
            }
        }
        let want = sha_hex(&normalise(code));
        let result = self.edit(|d| {
            d.joins.retain(|j| j.expires > now);
            // Compare against every code, so the time does not say which one was close.
            let mut found = None;
            for (i, j) in d.joins.iter().enumerate() {
                if same(&j.hash, &want) {
                    found = Some(i);
                }
            }
            let i = found.context("bad code")?;
            let join = d.joins.remove(i);
            let key = new_key()?;
            let server = d.servers.iter_mut().find(|s| s.id == join.server_id).context("bad code")?;
            server.key_hash = Some(sha_hex(&key));
            server.enrolled = Some(now);
            server.revoked = false;
            Ok((server.id.clone(), key))
        });
        match result {
            Ok(v) => Ok(v),
            Err(_) => {
                if let Ok(mut g) = self.inner.lock() {
                    g.fails.push_back(now);
                }
                Err(EnrolError::BadCode)
            }
        }
    }

    /// Whether `key` is the live key of server `id` (constant time; a revoked or unenrolled server never matches).
    pub fn authenticate(&self, id: &str, key: &str) -> bool {
        let Ok(g) = self.inner.lock() else { return false };
        let got = sha_hex(key);
        let mut ok = false;
        for s in &g.data.servers {
            if let Some(h) = &s.key_hash {
                if s.id == id && !s.revoked && same(h, &got) {
                    ok = true;
                }
            }
        }
        ok
    }

    /// Records that the link of a server was alive.
    pub fn touch(&self, id: &str, now: u64) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(s) = g.data.servers.iter_mut().find(|s| s.id == id) {
                s.last_seen = Some(now);
            }
        }
    }

    /// Takes the key away: the server can no longer connect and its codes stop working. It stays in the list (history, audit lines) until removed.
    pub fn revoke(&self, id: &str) -> Result<()> {
        self.edit(|d| {
            let s = d.servers.iter_mut().find(|s| s.id == id).context("no such server")?;
            s.key_hash = None;
            s.revoked = true;
            d.joins.retain(|j| j.server_id != id);
            Ok(())
        })
    }

    /// Deletes a server from the list. Only a revoked or never-enrolled server: an enrolled one is revoked first, so a click cannot drop a live one.
    pub fn remove(&self, id: &str) -> Result<()> {
        self.edit(|d| {
            let i = d.servers.iter().position(|s| s.id == id).context("no such server")?;
            if d.servers[i].key_hash.is_some() {
                bail!("revoke the server first");
            }
            d.servers.remove(i);
            d.joins.retain(|j| j.server_id != id);
            Ok(())
        })
    }

    pub fn list(&self, now: u64) -> Vec<View> {
        let Ok(g) = self.inner.lock() else { return Vec::new() };
        g.data
            .servers
            .iter()
            .map(|s| {
                let state = if s.revoked {
                    "revoked"
                } else if s.key_hash.is_some() {
                    if s.last_seen.is_some_and(|t| now.saturating_sub(t) <= ONLINE_WITHIN) { "online" } else { "offline" }
                } else if g.data.joins.iter().any(|j| j.server_id == s.id && j.expires > now) {
                    "waiting"
                } else {
                    "expired"
                };
                View { id: s.id.clone(), name: s.name.clone(), state, created: s.created, enrolled: s.enrolled, last_seen: s.last_seen }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_000_000;

    #[test]
    fn a_code_enrols_a_server_once_and_gives_it_a_key() {
        let f = Fleet::in_memory();
        let (id, code) = f.add_server("Porto 1", T).unwrap();
        assert_eq!(f.list(T)[0].state, "waiting");
        let (got, key) = f.enrol(&code, T + 5).unwrap();
        assert_eq!(got, id);
        assert!(f.authenticate(&id, &key));
        assert_eq!(f.list(T + 5)[0].state, "offline");
        assert_eq!(f.enrol(&code, T + 6), Err(EnrolError::BadCode), "a code works once");
    }

    #[test]
    fn a_code_is_read_without_dashes_spaces_or_case() {
        let f = Fleet::in_memory();
        let (_, code) = f.add_server("a", T).unwrap();
        let typed = format!("{}-{} {}", &code[..8].to_ascii_lowercase(), &code[8..16], &code[16..]);
        assert!(f.enrol(&typed, T).is_ok());
    }

    #[test]
    fn a_code_runs_out_after_an_hour() {
        let f = Fleet::in_memory();
        let (_, code) = f.add_server("a", T).unwrap();
        assert_eq!(f.list(T + JOIN_TTL + 1)[0].state, "expired");
        assert_eq!(f.enrol(&code, T + JOIN_TTL), Err(EnrolError::BadCode));
        assert_eq!(f.enrol(&code, T + JOIN_TTL + 1), Err(EnrolError::BadCode));
    }

    #[test]
    fn a_new_code_replaces_the_old_one_and_not_for_a_live_server() {
        let f = Fleet::in_memory();
        let (id, old) = f.add_server("a", T).unwrap();
        let new = f.new_join(&id, T + 10).unwrap();
        assert_ne!(old, new);
        assert_eq!(f.enrol(&old, T + 11), Err(EnrolError::BadCode));
        assert!(f.enrol(&new, T + 12).is_ok());
        assert!(f.new_join(&id, T + 13).is_err(), "an enrolled server is not re-enrolled by a code");
    }

    #[test]
    fn a_revoked_server_cannot_connect_and_can_be_enrolled_again() {
        let f = Fleet::in_memory();
        let (id, code) = f.add_server("a", T).unwrap();
        let (_, key) = f.enrol(&code, T).unwrap();
        f.revoke(&id).unwrap();
        assert!(!f.authenticate(&id, &key));
        assert_eq!(f.list(T)[0].state, "revoked");
        let again = f.new_join(&id, T + 1).unwrap();
        let (_, key2) = f.enrol(&again, T + 2).unwrap();
        assert!(!f.authenticate(&id, &key), "the old key stays dead");
        assert!(f.authenticate(&id, &key2));
    }

    #[test]
    fn a_key_belongs_to_one_server() {
        let f = Fleet::in_memory();
        let (a, ca) = f.add_server("a", T).unwrap();
        let (b, cb) = f.add_server("b", T).unwrap();
        let (_, ka) = f.enrol(&ca, T).unwrap();
        let (_, kb) = f.enrol(&cb, T).unwrap();
        assert!(f.authenticate(&a, &ka) && f.authenticate(&b, &kb));
        assert!(!f.authenticate(&a, &kb) && !f.authenticate(&b, &ka));
        assert!(!f.authenticate("s-00000000", &ka));
        assert!(!f.authenticate(&a, ""));
    }

    #[test]
    fn a_pending_server_has_no_key_to_guess() {
        let f = Fleet::in_memory();
        let (id, _) = f.add_server("a", T).unwrap();
        assert!(!f.authenticate(&id, ""));
        assert!(!f.authenticate(&id, "x"));
    }

    #[test]
    fn many_wrong_codes_stop_further_tries_for_a_minute() {
        let f = Fleet::in_memory();
        let (_, code) = f.add_server("a", T).unwrap();
        for _ in 0..MAX_FAILS {
            assert_eq!(f.enrol("WRONG", T), Err(EnrolError::BadCode));
        }
        assert_eq!(f.enrol(&code, T + 1), Err(EnrolError::Busy), "even the right code waits");
        assert!(f.enrol(&code, T + FAIL_WINDOW + 1).is_ok());
    }

    #[test]
    fn names_are_short_plain_and_unique() {
        assert!(valid_name("Porto 1") && valid_name("gpu-1.example_x"));
        for bad in ["", " a", "a ", "<b>", "a/b", "a\nb", &"x".repeat(41), "é"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        let f = Fleet::in_memory();
        f.add_server("Porto", T).unwrap();
        assert!(f.add_server("porto", T).is_err());
        assert!(f.add_server("<script>", T).is_err());
    }

    #[test]
    fn only_a_server_without_a_key_can_be_removed() {
        let f = Fleet::in_memory();
        let (id, code) = f.add_server("a", T).unwrap();
        f.enrol(&code, T).unwrap();
        assert!(f.remove(&id).is_err());
        f.revoke(&id).unwrap();
        f.remove(&id).unwrap();
        assert!(f.list(T).is_empty());
    }

    #[test]
    fn online_means_seen_within_a_minute() {
        let f = Fleet::in_memory();
        let (id, code) = f.add_server("a", T).unwrap();
        f.enrol(&code, T).unwrap();
        f.touch(&id, T + 10);
        assert_eq!(f.list(T + 10 + ONLINE_WITHIN)[0].state, "online");
        assert_eq!(f.list(T + 11 + ONLINE_WITHIN)[0].state, "offline");
    }

    #[test]
    fn the_registry_is_kept_between_runs_with_only_hashes_and_mode_0600() {
        let dir = std::env::temp_dir().join(format!("wd-fleet-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fleet.json");
        let _ = fs::remove_file(&path);
        let (id, code, key);
        {
            let f = Fleet::open(path.clone()).unwrap();
            let (i, c) = f.add_server("a", T).unwrap();
            let (_, k) = f.enrol(&c, T).unwrap();
            (id, code, key) = (i, c, k);
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&code) && !text.contains(&key), "no secret is stored");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let f = Fleet::open(path.clone()).unwrap();
        assert!(f.authenticate(&id, &key));
        fs::write(&path, "not json").unwrap();
        assert!(Fleet::open(path).is_err(), "a broken file is an error, not an empty fleet");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let f = Fleet { path: Some(PathBuf::from("/nonexistent-dir/fleet.json")), inner: Mutex::new(Inner { data: Data::default(), fails: VecDeque::new() }) };
        assert!(f.add_server("a", T).is_err());
        assert!(f.list(T).is_empty());
    }
}
