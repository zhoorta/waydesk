//! The meeting point of a browser and a server's agent for a desktop (stage 3, slice 4 of docs/PORTAL-DESIGN.md).
//!
//! A browser asks to open a desktop on a server. The portal makes a one-time token, tells the server's agent over its link to dial back with it, and
//! waits here. The agent opens a second WebSocket (`/relay`), proves which server it is, and names the token; the portal hands that WebSocket to the
//! waiting browser's task, which then passes messages between the two. A token works once, for one server, for a few seconds; the table is small.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocket;
use tokio::sync::oneshot;

/// How long an agent has to dial back.
pub const WAIT: Duration = Duration::from_secs(15);
/// The most desktops waiting for their agent at once.
const MAX_WAITING: usize = 64;

struct Waiting {
    server: String,
    tx: oneshot::Sender<WebSocket>,
    created: Instant,
}

#[derive(Default)]
pub struct Relays {
    map: Mutex<HashMap<String, Waiting>>,
}

fn token() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).ok()?;
    Some(data_encoding::HEXLOWER.encode(&raw))
}

impl Relays {
    pub fn new() -> Self {
        Self::default()
    }

    /// A token for a desktop on `server`, and where its agent's WebSocket will arrive. `None` when too many are waiting.
    pub fn expect(&self, server: &str) -> Option<(String, oneshot::Receiver<WebSocket>)> {
        let token = token()?;
        let (tx, rx) = oneshot::channel();
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, w| w.created.elapsed() < WAIT * 2 && !w.tx.is_closed());
        if m.len() >= MAX_WAITING {
            return None;
        }
        m.insert(token.clone(), Waiting { server: server.to_string(), tx, created: Instant::now() });
        Some((token, rx))
    }

    /// The agent of `server` arrives with `token`: the waiting side, if the token is live and was made for that server. The token is used up either way
    /// it is looked up with the right server; one made for another server stays (a wrong server learns nothing and spends nothing).
    pub fn take(&self, token: &str, server: &str) -> Option<oneshot::Sender<WebSocket>> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if m.get(token).is_some_and(|w| w.server == server) {
            let w = m.remove(token)?;
            return (w.created.elapsed() < WAIT && !w.tx.is_closed()).then_some(w.tx);
        }
        None
    }

    pub fn forget(&self, token: &str) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_for_one_server_and_works_once() {
        let r = Relays::new();
        let (t, _rx) = r.expect("s-1").unwrap();
        assert_eq!(t.len(), 32);
        assert!(r.take(&t, "s-2").is_none(), "another server");
        assert!(r.take("0".repeat(32).as_str(), "s-1").is_none(), "an unknown token");
        assert!(r.take(&t, "s-1").is_some());
        assert!(r.take(&t, "s-1").is_none(), "once");
    }

    #[test]
    fn a_token_whose_waiter_gave_up_is_dead_and_the_table_is_small() {
        let r = Relays::new();
        let (t, rx) = r.expect("s-1").unwrap();
        drop(rx);
        assert!(r.take(&t, "s-1").is_none());
        let mut keep = Vec::new();
        for _ in 0..MAX_WAITING {
            keep.push(r.expect("s-1").unwrap());
        }
        assert!(r.expect("s-1").is_none());
        r.forget(&keep[0].0);
        assert!(r.expect("s-1").is_some());
    }
}
