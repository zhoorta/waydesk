//! The portal's own audit log (stage 3, slice 5 of docs/PORTAL-DESIGN.md): what happened at the portal itself, one JSON object per line.
//!
//! The servers keep theirs (`waydesk-admin audit`); the portal keeps what only it can see: who signed in to the portal and who was refused, every
//! change to people and servers, servers enrolling and their links coming and going, app passwords, desktops opened through it. The file is
//! append-only from the portal's side, mode 0600, and rotates once at 10 MiB (the old file is kept as `.1`, the one before it is dropped).
//! Passwords, keys, tokens and codes are never written: the callers pass names and addresses, and nothing else.
#![cfg_attr(not(test), allow(dead_code))]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{json, Value};

const ROTATE_AT: u64 = 10 * 1024 * 1024;
pub const MAX_LIMIT: u16 = 500;

pub struct Audit {
    path: Option<PathBuf>,
    lock: Mutex<()>,
}

/// The filters of the Audit page; the same rules as `waydesk-admin audit` and the helper's query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub since: String,
    pub user: String,
    pub event: String,
    pub outcome: String,
    pub limit: u16,
}

impl Query {
    pub fn validate(&self) -> Result<(), &'static str> {
        let since_ok = self.since.is_empty()
            || (self.since.len() <= 4 && self.since.len() >= 2 && self.since.ends_with(['m', 'h', 'd', 'w']) && self.since[..self.since.len() - 1].chars().all(|c| c.is_ascii_digit()))
            || (self.since.len() == 10 && self.since.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }));
        if !since_ok {
            return Err("the time must be like 30m, 2h, 7d, 1w or a date such as 2026-10-29");
        }
        if !self.user.is_empty() && !crate::people::valid_name(&self.user) {
            return Err("that is not a valid account name");
        }
        if !self.event.is_empty() && (self.event.len() > 32 || !self.event.chars().all(|c| c.is_ascii_lowercase() || c == '.')) {
            return Err("the kind of event must be lower case letters and dots");
        }
        if !matches!(self.outcome.as_str(), "" | "ok" | "fail" | "refused") {
            return Err("the outcome must be ok, fail or refused");
        }
        if self.limit == 0 || self.limit > MAX_LIMIT {
            return Err("the number of events must be between 1 and 500");
        }
        Ok(())
    }

    /// The earliest time (unix seconds) that counts, for a `since` that passed `validate`.
    fn from(&self, now: u64) -> u64 {
        let s = if self.since.is_empty() { "7d" } else { &self.since };
        if s.len() == 10 {
            let n: Vec<u64> = s.split('-').filter_map(|p| p.parse().ok()).collect();
            return n.as_slice().first().zip(n.get(1)).zip(n.get(2)).map_or(0, |((y, m), d)| days_from_civil(*y as i64, *m as i64, *d as i64).max(0) as u64 * 86_400);
        }
        let (n, unit) = s.split_at(s.len() - 1);
        let n: u64 = n.parse().unwrap_or(0);
        now.saturating_sub(n * match unit { "m" => 60, "h" => 3600, "d" => 86_400, _ => 604_800 })
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm), and back.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2026-11-18T14:38:25.123Z`
pub fn iso(secs: u64, millis: u32) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// Seconds since the epoch of a timestamp written by `iso`.
fn parse_iso(ts: &str) -> Option<u64> {
    let b = ts.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |a: usize, z: usize| ts.get(a..z)?.parse::<i64>().ok();
    let days = days_from_civil(num(0, 4)?, num(5, 7)?, num(8, 10)?);
    u64::try_from(days * 86_400 + num(11, 13)? * 3600 + num(14, 16)? * 60 + num(17, 19)?).ok()
}

impl Audit {
    pub fn open(path: PathBuf) -> Self {
        Audit { path: Some(path), lock: Mutex::new(()) }
    }

    pub fn in_memory() -> Self {
        Audit { path: None, lock: Mutex::new(()) }
    }

    /// Writes one line. Best effort by design: a log that cannot be written must not stop a sign-in or a change, so it is told to the journal.
    /// `actor` is who did it (an account name, or empty), `target` what it was done to, `detail` a short plain-words note (never a secret).
    pub fn record(&self, event: &str, outcome: &str, actor: &str, source: &str, target: &str, detail: &str) {
        let Some(path) = &self.path else { return };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let mut line = json!({ "ts": iso(now.as_secs(), now.subsec_millis()), "origin": "portal", "event": event, "outcome": outcome });
        for (k, v) in [("actor", actor), ("source", source), ("target", target), ("detail", detail)] {
            if !v.is_empty() {
                line[k] = json!(v.chars().filter(|c| !c.is_control()).take(200).collect::<String>());
            }
        }
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let result = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            if fs::metadata(path).is_ok_and(|m| m.len() > ROTATE_AT) {
                fs::rename(path, path.with_extension("jsonl.1"))?;
            }
            let mut f = fs::OpenOptions::new().append(true).create(true).mode(0o600).open(path)?;
            writeln!(f, "{line}")
        })();
        if let Err(e) = result {
            tracing::warn!("the portal's audit log could not be written: {e}");
        }
    }

    /// The lines that match, newest first (the current file and the one before it).
    pub fn query(&self, q: &Query, now: u64) -> Vec<Value> {
        let Some(path) = &self.path else { return Vec::new() };
        let from = q.from(now);
        let mut rows: Vec<Value> = Vec::new();
        for file in [path.with_extension("jsonl.1"), path.clone()] {
            let Ok(text) = fs::read_to_string(&file) else { continue };
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
                let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
                if parse_iso(s("ts")).is_none_or(|t| t < from) {
                    continue;
                }
                if (!q.user.is_empty() && s("actor") != q.user && s("target") != q.user) || (!q.event.is_empty() && !s("event").starts_with(&q.event)) || (!q.outcome.is_empty() && s("outcome") != q.outcome) {
                    continue;
                }
                rows.push(v);
            }
        }
        rows.reverse();
        rows.truncate(usize::from(q.limit));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wd-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("audit.jsonl")
    }

    fn q(f: impl FnOnce(&mut Query)) -> Query {
        let mut q = Query { limit: 100, ..Default::default() };
        f(&mut q);
        q
    }

    #[test]
    fn timestamps_round_trip_and_a_date_is_midnight_utc() {
        assert_eq!(iso(0, 0), "1970-01-01T00:00:00.000Z");
        let t = 1_795_012_705;
        assert_eq!(parse_iso(&iso(t, 123)), Some(t));
        assert_eq!(iso(1_795_012_705, 5), "2026-11-18T14:38:25.005Z");
        assert_eq!(q(|q| q.since = "2026-11-18".into()).from(0), 1_794_960_000);
    }

    #[test]
    fn lines_are_written_filtered_and_come_back_newest_first() {
        let path = temp("filter");
        let a = Audit::open(path.clone());
        a.record("login", "ok", "ana", "1.2.3.4", "", "");
        a.record("admin.people.add", "ok", "boss", "1.2.3.4", "bo", "");
        a.record("login", "refused", "", "5.6.7.8", "ana", "wrong password");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let all = a.query(&q(|_| {}), now);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["outcome"], "refused", "newest first");
        assert_eq!(a.query(&q(|q| q.event = "admin".into()), now).len(), 1);
        assert_eq!(a.query(&q(|q| q.outcome = "refused".into()), now).len(), 1);
        assert_eq!(a.query(&q(|q| q.user = "ana".into()), now).len(), 2, "as actor or as target");
        assert_eq!(a.query(&q(|q| q.limit = 2), now).len(), 2);
        assert_eq!(a.query(&q(|q| q.since = "1h".into()), now + 7200).len(), 0, "older than an hour");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode_bits(), 0o600);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_line_has_no_control_characters_and_a_bounded_length() {
        let path = temp("clean");
        let a = Audit::open(path.clone());
        a.record("login", "fail", "x\ny", "1.2.3.4", &"t".repeat(1000), "bad\r\n{\"event\":\"forged\"}");
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "one line, however hostile the text");
        let v: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["event"], "login");
        assert_eq!(v["target"].as_str().unwrap().len(), 200);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_filters_are_checked_like_the_commands() {
        assert!(q(|_| {}).validate().is_ok());
        for bad in [q(|q| q.since = "yesterday".into()), q(|q| q.user = "A b".into()), q(|q| q.event = "x;y".into()), q(|q| q.outcome = "maybe".into()), q(|q| q.limit = 0), q(|q| q.limit = 501)] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(q(|q| q.since = "2026-10-29".into()).validate().is_ok());
    }

    #[test]
    fn a_big_file_rotates_once() {
        let path = temp("rotate");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, vec![b'x'; (ROTATE_AT + 1) as usize]).unwrap();
        let a = Audit::open(path.clone());
        a.record("login", "ok", "ana", "", "", "");
        assert!(path.with_extension("jsonl.1").exists());
        assert!(fs::metadata(&path).unwrap().len() < 1000);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    trait Bits {
        fn mode_bits(&self) -> u32;
    }
    impl Bits for fs::Permissions {
        fn mode_bits(&self) -> u32 {
            use std::os::unix::fs::PermissionsExt as _;
            self.mode() & 0o777
        }
    }
}
