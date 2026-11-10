//! Tickets of the root helper: a proof that an account signed in, which the portal holds instead of the account's password.
//!
//! The portal checks the password once (the helper's `Authenticate`) and asks for a ticket on that same connection. The browser stream's daemon
//! connection then redeems the ticket (`Redeem`) and is logged in as that account, from the address the ticket was made for, without the password
//! passing through the portal and the daemon a second time. A ticket is a random 256 bit value that only the portal and the helper know (it never
//! reaches the browser); it works for several connections (a page reload opens a new stream) until it is revoked (sign-out) or too old.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth::UserInfo;

/// The most tickets one account holds (the oldest goes first) and in all.
const PER_ACCOUNT: usize = 8;
const MAX_TICKETS: usize = 1024;

struct Ticket {
    user: UserInfo,
    source: String,
    created: Instant,
}

pub struct Tickets {
    max_age: Duration,
    map: Mutex<HashMap<String, Ticket>>,
}

fn random_hex() -> Option<String> {
    use std::io::Read as _;
    let mut raw = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut raw)).ok()?;
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}

impl Tickets {
    pub fn new(max_age: Duration) -> Self {
        Self { max_age, map: Mutex::new(HashMap::new()) }
    }

    /// A ticket for `user` signed in from `source`; `None` when the table is full of live tickets or no random value can be had.
    pub fn issue(&self, user: &UserInfo, source: &str, now: Instant) -> Option<String> {
        let token = random_hex()?;
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let max_age = self.max_age;
        map.retain(|_, t| now.duration_since(t.created) < max_age);
        let mine: Vec<(String, Instant)> = map.iter().filter(|(_, t)| t.user.uid == user.uid).map(|(k, t)| (k.clone(), t.created)).collect();
        if mine.len() >= PER_ACCOUNT {
            if let Some((oldest, _)) = mine.into_iter().min_by_key(|(_, c)| *c) {
                map.remove(&oldest);
            }
        }
        if map.len() >= MAX_TICKETS {
            return None;
        }
        map.insert(token.clone(), Ticket { user: user.clone(), source: source.to_owned(), created: now });
        Some(token)
    }

    /// The account of a live ticket that was made for this address.
    pub fn redeem(&self, token: &str, source: &str, now: Instant) -> Option<UserInfo> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let t = map.get(token)?;
        if now.duration_since(t.created) >= self.max_age {
            map.remove(token);
            return None;
        }
        (t.source == source).then(|| t.user.clone())
    }

    pub fn revoke(&self, token: &str) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32) -> UserInfo {
        UserInfo { name: format!("u{uid}"), uid, gid: uid, home: "/home/x".into(), groups: vec![uid], shell: "/bin/sh".into() }
    }

    #[test]
    fn a_ticket_logs_in_its_account_from_its_address_only() {
        let t = Tickets::new(Duration::from_secs(3600));
        let now = Instant::now();
        let a = t.issue(&user(1001), "203.0.113.9", now).unwrap();
        assert_eq!(a.len(), 64);
        assert_eq!(t.redeem(&a, "203.0.113.9", now).unwrap().uid, 1001);
        assert_eq!(t.redeem(&a, "203.0.113.9", now).unwrap().uid, 1001, "a reload redeems it again");
        assert!(t.redeem(&a, "198.51.100.1", now).is_none(), "another address");
        assert!(t.redeem(&"0".repeat(64), "203.0.113.9", now).is_none(), "a value nobody was given");
        assert!(t.redeem("", "203.0.113.9", now).is_none());
    }

    #[test]
    fn tickets_end_by_age_and_by_revoking() {
        let t = Tickets::new(Duration::from_secs(60));
        let now = Instant::now();
        let a = t.issue(&user(1001), "x", now).unwrap();
        let b = t.issue(&user(1001), "x", now).unwrap();
        assert!(t.redeem(&a, "x", now + Duration::from_secs(59)).is_some());
        assert!(t.redeem(&a, "x", now + Duration::from_secs(60)).is_none(), "too old");
        t.revoke(&b);
        assert!(t.redeem(&b, "x", now).is_none(), "revoked");
    }

    #[test]
    fn one_account_cannot_fill_the_table() {
        let t = Tickets::new(Duration::from_secs(3600));
        let now = Instant::now();
        let first = t.issue(&user(1001), "x", now).unwrap();
        for i in 0..PER_ACCOUNT {
            t.issue(&user(1001), "x", now + Duration::from_millis(1 + i as u64)).unwrap();
        }
        assert!(t.redeem(&first, "x", now).is_none(), "the oldest made room");
        assert!(t.issue(&user(1002), "x", now).is_some());
    }
}
