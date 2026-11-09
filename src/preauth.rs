//! Limits connections that have not logged in yet, per source address (the idea of sshd's PerSourceMaxStartups).
//!
//! All connections share one pool of permits, so without this one address could open that many idle connections, hold each for the
//! whole login window and keep everyone else out. A connection counts against its address from accept until its login is accepted
//! (or it ends); an address over the limit is refused before TLS. Loopback is exempt: the web gateway reaches the server from there on
//! behalf of many users.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Connections from one address that may be waiting to log in at the same time.
pub const MAX_PRE_LOGIN_PER_SOURCE: usize = 10;

#[derive(Default)]
pub struct PreAuthLimiter {
    counts: Mutex<HashMap<IpAddr, usize>>,
}

/// Holds one pre-login slot of an address; gives it back on `release` or on drop, whichever comes first.
pub struct PreAuthSlot {
    limiter: Arc<PreAuthLimiter>,
    ip: Option<IpAddr>,
}

impl PreAuthLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// None when the address already has `max` connections waiting to log in.
    pub fn enter(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<PreAuthSlot> {
        if ip.is_loopback() {
            return Some(PreAuthSlot { limiter: self.clone(), ip: None });
        }
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(PreAuthSlot { limiter: self.clone(), ip: Some(ip) })
    }

    fn leave(&self, ip: IpAddr) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&ip);
            }
        }
    }
}

impl PreAuthSlot {
    /// The login is done (or the connection is): the address may use the slot again.
    pub fn release(&mut self) {
        if let Some(ip) = self.ip.take() {
            self.limiter.leave(ip);
        }
    }
}

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_address_cannot_use_every_slot_and_others_are_unaffected() {
        let l = PreAuthLimiter::new();
        let a: IpAddr = "192.168.1.5".parse().unwrap();
        let b: IpAddr = "192.168.1.6".parse().unwrap();
        let held: Vec<_> = (0..3).map(|_| l.enter(a, 3).expect("within the limit")).collect();
        assert!(l.enter(a, 3).is_none(), "the fourth from the same address is refused");
        assert!(l.enter(b, 3).is_some(), "another address still gets in");
        drop(held);
        assert!(l.enter(a, 3).is_some(), "slots come back when the connections end");
        assert!(l.counts.lock().unwrap().len() <= 2);
    }

    #[test]
    fn a_released_slot_is_given_back_once_and_loopback_is_exempt() {
        let l = PreAuthLimiter::new();
        let a: IpAddr = "10.0.0.2".parse().unwrap();
        let mut s = l.enter(a, 1).unwrap();
        assert!(l.enter(a, 1).is_none());
        s.release();
        s.release();
        drop(s);
        assert!(l.counts.lock().unwrap().is_empty());
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let _many: Vec<_> = (0..50).map(|_| l.enter(lo, 1).expect("loopback is not limited")).collect();
    }
}
