//! The links the servers dialled (stage 3, slice 2 of docs/PORTAL-DESIGN.md): which servers are connected right now, and request and answer over a link.
//!
//! One link per server. A server that connects again replaces the old link (the old one ends). A request gets a number; the answer that carries the
//! same number reaches the one waiting for it, and nobody else. When a link ends, everybody waiting on it is told the server is offline at once.
//! The messages are JSON text frames (`proto` below); this file knows nothing about sockets, so it is tested with plain channels.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

/// Link protocol version, sent by the agent in its hello.
pub const VERSION: u64 = 1;
/// The largest frame either side accepts (a status of a large machine is a few hundred KiB).
pub const MAX_FRAME: usize = 5 * 1024 * 1024;
/// The longest an answer may be (the same limit the helper has for what it carries).
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// How long a request may take: reads are quick, a change that waits for a session to end can take a minute and a half.
#[allow(dead_code)]
pub const READ_TIMEOUT: Duration = Duration::from_secs(25);
#[allow(dead_code)]
pub const CHANGE_TIMEOUT: Duration = Duration::from_secs(110);

#[derive(Debug, PartialEq, Eq)]
pub enum LinkError {
    /// No link, or it ended while waiting.
    Offline,
    Timeout,
    /// The server answered with a refusal, in words.
    Refused(String),
    /// The server's answer is not something the portal passes on.
    BadAnswer,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<String, String>>>>>;

struct Entry {
    gen: u64,
    tx: mpsc::Sender<String>,
    pending: Pending,
}

/// What a link's own task holds: the frames to send, and where to deliver the answers it reads.
pub struct Attached {
    pub gen: u64,
    pub outgoing: mpsc::Receiver<String>,
    pending: Pending,
}

#[derive(Default)]
pub struct Links {
    map: Mutex<HashMap<String, Entry>>,
    next_gen: AtomicU64,
    next_id: AtomicU64,
}

impl Links {
    pub fn new() -> Self {
        Self::default()
    }

    /// A server's link is up. Any link it had before is ended (its queue closes, and those waiting on it are told it is offline).
    pub fn attach(&self, server: &str) -> Attached {
        let (tx, outgoing) = mpsc::channel(16);
        let gen = self.next_gen.fetch_add(1, Ordering::Relaxed) + 1;
        let pending: Pending = Default::default();
        let old = self.map.lock().unwrap().insert(server.to_string(), Entry { gen, tx, pending: pending.clone() });
        Self::end(old);
        Attached { gen, outgoing, pending }
    }

    /// The link of generation `gen` ended. A newer link of the same server is left alone.
    pub fn detach(&self, server: &str, gen: u64) {
        let mut m = self.map.lock().unwrap();
        if m.get(server).is_some_and(|e| e.gen == gen) {
            Self::end(m.remove(server));
        }
    }

    /// Ends a server's link (its key was revoked).
    pub fn drop_link(&self, server: &str) {
        let old = self.map.lock().unwrap().remove(server);
        Self::end(old);
    }

    /// Those waiting on a link that ended are told at once (their waiting channels close), not when their time runs out.
    fn end(entry: Option<Entry>) {
        if let Some(e) = entry {
            e.pending.lock().unwrap().clear();
        }
    }

    pub fn online(&self, server: &str) -> bool {
        self.map.lock().unwrap().get(server).is_some_and(|e| !e.tx.is_closed())
    }

    /// A text frame read from the server. Only an answer to a request somebody is waiting for does anything; anything else is ignored.
    pub fn answer(&self, link: &Attached, frame: &str) {
        let Ok(v) = serde_json::from_str::<Value>(frame) else { return };
        if v.get("t").and_then(Value::as_str) != Some("res") {
            return;
        }
        let Some(id) = v.get("id").and_then(Value::as_u64) else { return };
        let result = if v.get("ok").and_then(Value::as_bool) == Some(true) {
            match v.get("json").and_then(Value::as_str) {
                Some(j) if j.len() <= MAX_ANSWER && serde_json::from_str::<Value>(j).is_ok() => Ok(j.to_string()),
                _ => Err(String::new()),
            }
        } else {
            Err(v.get("error").and_then(Value::as_str).unwrap_or("it failed").chars().take(300).collect())
        };
        if let Some(waiter) = link.pending.lock().unwrap().remove(&id) {
            let _ = waiter.send(result);
        }
    }

    /// Sends `request` (an object; the number is added) to the server and waits for its answer: the answer's JSON text.
    pub async fn request(&self, server: &str, mut request: Value, timeout: Duration) -> Result<String, LinkError> {
        let (tx, pending) = {
            let m = self.map.lock().unwrap();
            let e = m.get(server).ok_or(LinkError::Offline)?;
            (e.tx.clone(), e.pending.clone())
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        request["t"] = json!("req");
        request["id"] = json!(id);
        let (done, wait) = oneshot::channel();
        pending.lock().unwrap().insert(id, done);
        if tx.send(request.to_string()).await.is_err() {
            pending.lock().unwrap().remove(&id);
            return Err(LinkError::Offline);
        }
        let outcome = tokio::time::timeout(timeout, wait).await;
        pending.lock().unwrap().remove(&id);
        match outcome {
            Err(_) => Err(LinkError::Timeout),
            Ok(Err(_)) => Err(LinkError::Offline),
            Ok(Ok(Ok(json))) => Ok(json),
            Ok(Ok(Err(why))) if why.is_empty() => Err(LinkError::BadAnswer),
            Ok(Ok(Err(why))) => Err(LinkError::Refused(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in agent: answers every request with its own text.
    fn spawn_agent(links: Arc<Links>, mut link: Attached, reply: &'static str) {
        tokio::spawn(async move {
            while let Some(frame) = link.outgoing.recv().await {
                let v: Value = serde_json::from_str(&frame).unwrap();
                let id = v["id"].as_u64().unwrap();
                let answer = if reply == "refuse" { json!({"t":"res","id":id,"ok":false,"error":"no"}) } else { json!({"t":"res","id":id,"ok":true,"json":reply}) };
                links.answer(&link, &answer.to_string());
            }
        });
    }

    #[tokio::test]
    async fn a_request_gets_its_own_answer() {
        let links = Arc::new(Links::new());
        let link = links.attach("s-1");
        assert!(links.online("s-1"));
        spawn_agent(links.clone(), link, r#"{"x":1}"#);
        let got = links.request("s-1", json!({"kind":"users"}), Duration::from_secs(2)).await;
        assert_eq!(got, Ok(r#"{"x":1}"#.to_string()));
    }

    #[tokio::test]
    async fn no_link_means_offline_and_a_refusal_is_passed_on_in_words() {
        let links = Arc::new(Links::new());
        assert_eq!(links.request("s-9", json!({}), Duration::from_millis(50)).await, Err(LinkError::Offline));
        let link = links.attach("s-1");
        spawn_agent(links.clone(), link, "refuse");
        assert_eq!(links.request("s-1", json!({}), Duration::from_secs(2)).await, Err(LinkError::Refused("no".into())));
    }

    #[tokio::test]
    async fn an_answer_that_is_not_json_is_not_passed_on() {
        let links = Arc::new(Links::new());
        let link = links.attach("s-1");
        spawn_agent(links.clone(), link, "<script>");
        assert_eq!(links.request("s-1", json!({}), Duration::from_secs(2)).await, Err(LinkError::BadAnswer));
    }

    #[tokio::test]
    async fn a_silent_server_times_out_and_a_new_link_ends_the_old_one() {
        let links = Arc::new(Links::new());
        let _quiet = links.attach("s-1");
        assert_eq!(links.request("s-1", json!({}), Duration::from_millis(50)).await, Err(LinkError::Timeout));
        let l2 = links.clone();
        let waiting = tokio::spawn(async move { l2.request("s-1", json!({}), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _new = links.attach("s-1"); // the first link ends: the one waiting is told at once
        assert_eq!(waiting.await.unwrap(), Err(LinkError::Offline));
    }

    #[tokio::test]
    async fn an_old_link_ending_does_not_end_the_new_one_and_revoking_does() {
        let links = Arc::new(Links::new());
        let old = links.attach("s-1");
        let new = links.attach("s-1");
        links.detach("s-1", old.gen);
        assert!(links.online("s-1"));
        links.detach("s-1", new.gen);
        assert!(!links.online("s-1"));
        let _again = links.attach("s-1");
        links.drop_link("s-1");
        assert!(!links.online("s-1"));
    }

    #[tokio::test]
    async fn an_answer_with_another_number_or_not_an_answer_reaches_nobody() {
        let links = Arc::new(Links::new());
        let link = links.attach("s-1");
        let l2 = links.clone();
        let waiting = tokio::spawn(async move { l2.request("s-1", json!({}), Duration::from_millis(200)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        links.answer(&link, r#"{"t":"res","id":9999,"ok":true,"json":"{}"}"#);
        links.answer(&link, r#"{"t":"req","id":1,"ok":true,"json":"{}"}"#);
        links.answer(&link, "garbage");
        assert_eq!(waiting.await.unwrap(), Err(LinkError::Timeout));
    }
}
