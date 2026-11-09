//! Limits on who may start sessions, and how fast: a sliding-window rate per address, a number of sessions at once per address and in total,
//! and one-time tokens that a session needs to start.
//!
//! The gateway cannot see a failed login (it happens inside the encrypted RDP connection), so it bounds what a guesser can try instead: new sessions
//! per address per minute, and sessions at once. The daemon's own delay and lockout per account stay in force behind it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The key an address is counted under: an IPv4 address as it is, an IPv6 address by its /64 (a host usually holds a whole /64, and counting each
/// address would let it rotate), an IPv4-mapped IPv6 address as the IPv4 one.
pub fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
        v4 => v4,
    }
}

/// At most `max` hits per address within `window`.
pub struct RateLimiter {
    max: usize,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

/// The most addresses remembered at once. A scan from many addresses cannot grow the table without bound: when it is full, new addresses are refused
/// until old entries have expired.
const MAX_TRACKED: usize = 100_000;

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self { max, window, hits: Mutex::new(HashMap::new()) }
    }

    /// Counts one hit from `ip` and says whether it is within the limit. A refused hit is not counted, so a caller that keeps trying does not keep
    /// itself locked out.
    pub fn hit(&self, ip: IpAddr, now: Instant) -> bool {
        let k = key(ip);
        let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_TRACKED {
            let window = self.window;
            map.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < window));
            if map.len() >= MAX_TRACKED && !map.contains_key(&k) {
                return false;
            }
        }
        let list = map.entry(k).or_default();
        list.retain(|t| now.duration_since(*t) < self.window);
        if list.len() >= self.max {
            return false;
        }
        list.push(now);
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// This address already runs as many sessions as it may.
    PerAddress,
    /// The gateway runs as many sessions as it may.
    Total,
}

/// Sessions running now: per address and in total. A [`SessionGuard`] counts one, until it is dropped.
pub struct Sessions {
    per_ip: usize,
    total: usize,
    state: Mutex<(HashMap<IpAddr, usize>, usize)>,
}

impl Sessions {
    pub fn new(per_ip: usize, total: usize) -> Arc<Self> {
        Arc::new(Self { per_ip, total, state: Mutex::new((HashMap::new(), 0)) })
    }

    pub fn start(self: &Arc<Self>, ip: IpAddr) -> Result<SessionGuard, Refusal> {
        let k = key(ip);
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.1 >= self.total {
            return Err(Refusal::Total);
        }
        let n = s.0.entry(k).or_insert(0);
        if *n >= self.per_ip {
            return Err(Refusal::PerAddress);
        }
        *n += 1;
        s.1 += 1;
        Ok(SessionGuard { sessions: Arc::clone(self), key: k })
    }

    pub fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}

pub struct SessionGuard {
    sessions: Arc<Sessions>,
    key: IpAddr,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut s = self.sessions.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = s.0.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                s.0.remove(&self.key);
            }
        }
        s.1 -= 1;
    }
}

/// One-time tokens for starting a session. A token is made for an address and an account, lives `ttl`, and can be used once, from that address.
///
/// This is the step where a second factor or a single sign-on belongs: whatever decides that a browser may start a session decides it before
/// it asks for a token here, and the rest of the gateway does not change.
pub struct Tokens {
    ttl: Duration,
    inner: Mutex<HashMap<String, (IpAddr, Instant, String)>>,
}

const MAX_TOKENS: usize = 10_000;

impl Tokens {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, inner: Mutex::new(HashMap::new()) }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// A new token for `ip` and `account`, or `None` when too many are waiting to be used.
    pub fn issue(&self, ip: IpAddr, account: &str, now: Instant) -> Option<String> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).ok()?;
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_TOKENS {
            let ttl = self.ttl;
            map.retain(|_, (_, at, _)| now.duration_since(*at) < ttl);
            if map.len() >= MAX_TOKENS {
                return None;
            }
        }
        map.insert(token.clone(), (key(ip), now, account.to_owned()));
        Some(token)
    }

    /// Uses a token: gives the account it was made for, once, to the address it was made for, within its lifetime. A token that is wrong, expired
    /// or used is gone either way.
    pub fn consume(&self, token: &str, ip: IpAddr, now: Instant) -> Option<String> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match map.remove(token) {
            Some((owner, at, account)) if owner == key(ip) && now.duration_since(at) < self.ttl => Some(account),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rate_limit_counts_per_address_and_forgets_after_the_window() {
        let r = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(r.hit(ip("203.0.113.1"), t0));
        assert!(r.hit(ip("203.0.113.1"), t0));
        assert!(r.hit(ip("203.0.113.1"), t0));
        assert!(!r.hit(ip("203.0.113.1"), t0), "the fourth in a minute is refused");
        assert!(r.hit(ip("203.0.113.2"), t0), "another address has its own count");
        assert!(r.hit(ip("203.0.113.1"), t0 + Duration::from_secs(61)), "and the window moves on");
    }

    #[test]
    fn a_refused_hit_is_not_counted() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(r.hit(ip("203.0.113.1"), t0));
        for s in 1..50 {
            assert!(!r.hit(ip("203.0.113.1"), t0 + Duration::from_secs(s)));
        }
        assert!(r.hit(ip("203.0.113.1"), t0 + Duration::from_secs(61)), "50 refused tries did not extend the lockout");
    }

    #[test]
    fn an_ipv6_host_is_counted_by_its_64() {
        assert_eq!(key(ip("2001:db8:1:2:aaaa::1")), key(ip("2001:db8:1:2:bbbb::9")));
        assert_ne!(key(ip("2001:db8:1:2::1")), key(ip("2001:db8:1:3::1")));
        assert_eq!(key(ip("::ffff:192.0.2.5")), ip("192.0.2.5"));
    }

    #[test]
    fn sessions_are_limited_per_address_and_in_total_and_freed_on_drop() {
        let s = Sessions::new(2, 3);
        let a1 = s.start(ip("203.0.113.1")).unwrap();
        let _a2 = s.start(ip("203.0.113.1")).unwrap();
        assert_eq!(s.start(ip("203.0.113.1")).err(), Some(Refusal::PerAddress));
        let _b = s.start(ip("203.0.113.2")).unwrap();
        assert_eq!(s.start(ip("203.0.113.3")).err(), Some(Refusal::Total));
        assert_eq!(s.active(), 3);
        drop(a1);
        assert_eq!(s.active(), 2);
        assert!(s.start(ip("203.0.113.3")).is_ok());
    }

    #[test]
    fn a_token_works_once_from_its_address_within_its_lifetime() {
        let t = Tokens::new(Duration::from_secs(30));
        let t0 = Instant::now();
        let a = t.issue(ip("203.0.113.1"), "ana", t0).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(t.consume(&a, ip("203.0.113.1"), t0 + Duration::from_secs(1)).as_deref(), Some("ana"), "it gives the account it was made for");
        assert_eq!(t.consume(&a, ip("203.0.113.1"), t0 + Duration::from_secs(2)), None, "used");

        let b = t.issue(ip("203.0.113.1"), "ana", t0).unwrap();
        assert_eq!(t.consume(&b, ip("203.0.113.9"), t0), None, "another address");
        assert_eq!(t.consume(&b, ip("203.0.113.1"), t0), None, "and it is gone after a wrong try");

        let c = t.issue(ip("203.0.113.1"), "ana", t0).unwrap();
        assert_eq!(t.consume(&c, ip("203.0.113.1"), t0 + Duration::from_secs(31)), None, "expired");
        assert_eq!(t.consume("not a token", ip("203.0.113.1"), t0), None);
    }

    #[test]
    fn tokens_are_different_each_time() {
        let t = Tokens::new(Duration::from_secs(30));
        let t0 = Instant::now();
        let a = t.issue(ip("203.0.113.1"), "ana", t0).unwrap();
        let b = t.issue(ip("203.0.113.1"), "ana", t0).unwrap();
        assert_ne!(a, b);
    }
}
