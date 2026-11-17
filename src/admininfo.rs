//! Read-only information for the portal, answered by the root helper (`HelperReq::Info`).
//!
//! The helper runs `waydesk-admin users list|sessions list|status --json` with fixed arguments (no shell, nothing the caller wrote), so the portal and the
//! command line show the same facts from the same code. An administrator (a member of the `sudo` group, or `wheel` on Arch and Fedora, as for the polkit
//! rules and the Users & Access panel) gets everything; any other account gets its own row of the user and session lists and no status.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context as _, Result};

use crate::proto::{InfoKind, MAX_INFO};

/// The longest the command may take (the status measures for a second) and the most it may print (a little under what the protocol carries).
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT: usize = (MAX_INFO as usize) - 4096;
/// At most this many run at once: a status costs a second of measuring, and a signed-in person must not be able to keep the helper busy with it.
const MAX_AT_ONCE: usize = 2;
static RUNNING: AtomicUsize = AtomicUsize::new(0);

/// The group whose members administer the machine: `sudo` on Debian and Ubuntu, `wheel` on Arch and Fedora (the first one that exists, `sudo` when both do).
pub fn admin_group() -> &'static str {
    static GROUP: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    GROUP.get_or_init(|| {
        let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
        if groups.lines().any(|l| l.starts_with("sudo:")) || !groups.lines().any(|l| l.starts_with("wheel:")) { "sudo" } else { "wheel" }
    })
}

/// Whether an account with these groups administers the machine. Looked up on every request, never kept.
pub fn is_admin(groups: &[u32]) -> bool {
    crate::auth::group_gid(admin_group()).is_some_and(|gid| groups.contains(&gid))
}

fn args(kind: InfoKind) -> &'static [&'static str] {
    match kind {
        InfoKind::Users => &["users", "list", "--json"],
        InfoKind::Sessions => &["sessions", "list", "--json"],
        InfoKind::Status => &["status", "--json"],
        InfoKind::Role => &[],
    }
}

/// The rows of a JSON list that belong to `name` (the lists have a `name` field in every row).
pub fn own_rows(json: &str, name: &str) -> Result<String> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(json).context("the list is not JSON")?;
    let mine: Vec<_> = rows.into_iter().filter(|r| r.get("name").and_then(|n| n.as_str()) == Some(name)).collect();
    Ok(serde_json::to_string(&mine)?)
}

/// What the account may be told, or why not. `exe` is `waydesk-admin`.
pub fn answer(kind: InfoKind, name: &str, admin: bool, exe: &Path) -> Result<String> {
    if kind == InfoKind::Role {
        return Ok(format!("{{\"admin\":{admin}}}"));
    }
    ensure!(admin || kind != InfoKind::Status, "only administrators may ask for the status");
    let out = run(exe, args(kind))?;
    if admin || kind == InfoKind::Status { Ok(out) } else { own_rows(&out, name) }
}

/// Has the runner do an action: connects to its socket (root only), sends one line of JSON and reads its one-line answer. The action has been
/// validated by the caller and is checked again by the runner. `actor` is the administrator who asked, `source` the address they came from.
pub fn run_action(socket: &Path, actor_uid: u32, source: &str, action: &crate::adminaction::AdminAction) -> Result<String> {
    use std::io::Write as _;
    // No slot here: changes do not wait behind status measurements; the runner's socket limits how many run at once.
    let mut sock = std::os::unix::net::UnixStream::connect(socket).with_context(|| format!("cannot reach the administration socket {}", socket.display()))?;
    let limit = Some(Duration::from_secs(95));
    let _ = sock.set_read_timeout(limit);
    let _ = sock.set_write_timeout(limit);
    let request = serde_json::json!({ "actor_uid": actor_uid, "source": source, "do": action.to_json() });
    sock.write_all(format!("{request}\n").as_bytes())?;
    sock.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    (&sock).take(64 * 1024).read_to_string(&mut answer).context("reading the answer")?;
    ensure!(!answer.trim().is_empty(), "the runner gave no answer");
    Ok(answer.trim().to_owned())
}

/// A look at the audit log: the filters of `waydesk-admin audit`, each checked against a short rule. Empty means no filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub since: String,
    pub user: String,
    pub event: String,
    pub outcome: String,
    pub limit: u16,
}

pub const AUDIT_MAX_LIMIT: u16 = 500;

impl AuditQuery {
    /// Why the query is not one we run, in plain words.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        let since_ok = self.since.is_empty()
            || (self.since.len() <= 4 && self.since.len() >= 2 && self.since.ends_with(['m', 'h', 'd', 'w']) && self.since[..self.since.len() - 1].chars().all(|c| c.is_ascii_digit()))
            || (self.since.len() == 10 && self.since.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }));
        if !since_ok {
            return Err("the time must be like 30m, 2h, 7d, 1w or a date such as 2026-10-29");
        }
        if !self.user.is_empty() && !crate::adminaction::valid_name(&self.user) {
            return Err("that is not a valid account name");
        }
        if !self.event.is_empty() && (self.event.len() > 32 || !self.event.chars().all(|c| c.is_ascii_lowercase() || c == '.')) {
            return Err("the kind of event must be lower case letters and dots");
        }
        if !matches!(self.outcome.as_str(), "" | "ok" | "fail" | "refused") {
            return Err("the outcome must be ok, fail or refused");
        }
        if self.limit == 0 || self.limit > AUDIT_MAX_LIMIT {
            return Err("the number of events must be between 1 and 500");
        }
        Ok(())
    }

    fn args(&self) -> Vec<String> {
        let mut v = vec!["audit".to_owned(), "--json".to_owned(), "--since".to_owned(), if self.since.is_empty() { "7d".into() } else { self.since.clone() }, "--limit".to_owned(), self.limit.to_string()];
        for (flag, value) in [("--user", &self.user), ("--event", &self.event), ("--outcome", &self.outcome)] {
            if !value.is_empty() {
                v.extend([flag.to_owned(), value.clone()]);
            }
        }
        v
    }
}

/// One JSON object per line (what `waydesk-admin audit --json` prints, oldest first) as one JSON list, newest first. A line that is not JSON is left out.
pub fn audit_lines_to_list(lines: &str) -> String {
    let mut rows: Vec<serde_json::Value> = lines.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(serde_json::Value::is_object).collect();
    rows.reverse();
    serde_json::Value::Array(rows).to_string()
}

/// The audit log for an administrator.
pub fn audit(query: &AuditQuery, exe: &Path) -> Result<String> {
    query.validate().map_err(|why| anyhow::anyhow!(why))?;
    let args = query.args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(audit_lines_to_list(&run(exe, &args)?))
}

struct Slot;
impl Slot {
    fn take() -> Option<Slot> {
        if RUNNING.fetch_add(1, Ordering::AcqRel) < MAX_AT_ONCE {
            Some(Slot)
        } else {
            RUNNING.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run(exe: &Path, args: &[&str]) -> Result<String> {
    let Some(_slot) = Slot::take() else { bail!("busy, try again in a moment") };
    let mut child = Command::new(exe).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().with_context(|| format!("cannot run {}", exe.display()))?;
    let mut stdout = child.stdout.take().context("no output pipe")?;
    // Read in a thread so a command that prints a lot cannot block on a full pipe while we wait for it; stop at the limit.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} took more than {} s", exe.display(), TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let buf = reader.join().map_err(|_| anyhow::anyhow!("reader failed"))?;
    ensure!(status.success(), "{} failed ({status})", exe.display());
    ensure!(buf.len() <= MAX_OUTPUT, "the answer is too long");
    String::from_utf8(buf).context("the answer is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// The tests that run the command share the counter of slots, so they take turns.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn script(body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("waydesk-admininfo-{}-{}", std::process::id(), body.len()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fake-admin");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn a_person_sees_only_their_own_row() {
        let list = r#"[{"name":"alice","uid":1001},{"name":"bob","uid":1002}]"#;
        assert_eq!(own_rows(list, "alice").unwrap(), r#"[{"name":"alice","uid":1001}]"#);
        assert_eq!(own_rows(list, "carol").unwrap(), "[]");
        assert!(own_rows("not json", "alice").is_err());
        // a row without a name belongs to nobody
        assert_eq!(own_rows(r#"[{"uid":1}]"#, "alice").unwrap(), "[]");
    }

    #[test]
    fn an_action_goes_to_the_runner_as_one_line_and_its_answer_comes_back() {
        use std::io::{Read as _, Write as _};
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("waydesk-runner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut got = String::new();
            conn.read_to_string(&mut got).unwrap();
            conn.write_all(b"{\"ok\":true,\"result\":{\"message\":\"done\"}}\n").unwrap();
            got
        });
        let action = crate::adminaction::AdminAction::SessionEnd { name: "eva".into() };
        let answer = run_action(&path, 1000, "10.0.0.7", &action).unwrap();
        assert_eq!(answer, r#"{"ok":true,"result":{"message":"done"}}"#);
        let sent: serde_json::Value = serde_json::from_str(server.join().unwrap().trim()).unwrap();
        assert_eq!(sent["actor_uid"], 1000);
        assert_eq!(sent["source"], "10.0.0.7");
        assert_eq!(sent["do"]["action"], "session_end");
        assert_eq!(sent["do"]["name"], "eva");
        // no runner: an error, and the slot is given back
        assert!(run_action(&dir.join("nobody.sock"), 1000, "10.0.0.7", &action).is_err());
    }

    #[test]
    fn an_audit_query_is_checked_and_becomes_one_fixed_command_line() {
        let q = |since: &str, user: &str, event: &str, outcome: &str, limit: u16| AuditQuery { since: since.into(), user: user.into(), event: event.into(), outcome: outcome.into(), limit };
        assert!(q("", "", "", "", 200).validate().is_ok());
        assert!(q("2h", "alice", "admin.user", "fail", 500).validate().is_ok());
        assert!(q("2026-11-17", "", "login", "", 1).validate().is_ok());
        for bad in [q("7 days", "", "", "", 10), q("-1d", "", "", "", 10), q("h", "", "", "", 10), q("1000d", "", "", "", 10), q("", "-rf", "", "", 10), q("", "", "Login", "", 10), q("", "", "a b", "", 10), q("", "", "", "maybe", 10), q("", "", "", "", 0), q("", "", "", "", 501), q("2026-11-1x", "", "", "", 10), q("", "", &"a".repeat(33), "", 10)] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert_eq!(q("", "", "", "", 50).args(), ["audit", "--json", "--since", "7d", "--limit", "50"]);
        assert_eq!(q("2h", "alice", "admin", "fail", 10).args(), ["audit", "--json", "--since", "2h", "--limit", "10", "--user", "alice", "--event", "admin", "--outcome", "fail"]);
    }

    #[test]
    fn the_audit_lines_become_a_list_newest_first_and_bad_lines_are_left_out() {
        let list = audit_lines_to_list("{\"n\":1}\nnot json\n[2]\n{\"n\":3}\n");
        assert_eq!(list, r#"[{"n":3},{"n":1}]"#);
        assert_eq!(audit_lines_to_list(""), "[]");
        let fake = script(r#"echo '{"event":"login","n":1}'; echo '{"event":"admin.user.add","n":2}'"#);
        let q = AuditQuery { since: "1d".into(), user: String::new(), event: String::new(), outcome: String::new(), limit: 10 };
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(audit(&q, &fake).unwrap(), r#"[{"event":"admin.user.add","n":2},{"event":"login","n":1}]"#);
        assert!(audit(&AuditQuery { limit: 0, ..q }, &fake).is_err());
    }

    #[test]
    fn the_role_is_answered_without_running_anything() {
        let nothing = Path::new("/nonexistent/waydesk-admin");
        assert_eq!(answer(InfoKind::Role, "alice", true, nothing).unwrap(), r#"{"admin":true}"#);
        assert_eq!(answer(InfoKind::Role, "alice", false, nothing).unwrap(), r#"{"admin":false}"#);
    }

    #[test]
    fn only_administrators_get_the_status_and_the_other_lists_are_filtered() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fake = script(r#"case "$1" in users) echo '[{"name":"alice"},{"name":"bob"}]';; status) echo '{"machine":{}}';; *) exit 3;; esac"#);
        assert!(answer(InfoKind::Status, "alice", false, &fake).is_err());
        assert_eq!(answer(InfoKind::Status, "root", true, &fake).unwrap().trim(), r#"{"machine":{}}"#);
        assert_eq!(answer(InfoKind::Users, "alice", false, &fake).unwrap(), r#"[{"name":"alice"}]"#);
        assert!(answer(InfoKind::Users, "alice", true, &fake).unwrap().contains("bob"));
        // a failing command is an error, not an empty answer
        assert!(answer(InfoKind::Sessions, "alice", true, &fake).is_err());
    }

    #[test]
    fn a_command_that_prints_too_much_or_is_missing_is_refused_and_the_slots_are_limited() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let big = script("head -c 5000000 /dev/zero | tr '\\0' 'x'");
        assert!(run(&big, &[]).is_err());
        assert_eq!(RUNNING.load(Ordering::Acquire), 0, "the slot is given back");
        assert!(run(Path::new("/nonexistent/waydesk-admin"), &[]).is_err());
        assert_eq!(RUNNING.load(Ordering::Acquire), 0);
        // only so many at once; a slot given back can be taken again
        let held: Vec<_> = (0..MAX_AT_ONCE).map(|_| Slot::take().expect("a free slot")).collect();
        assert!(Slot::take().is_none());
        assert!(run(Path::new("/bin/true"), &[]).is_err(), "busy");
        drop(held);
        assert!(Slot::take().is_some());
    }

    #[test]
    fn a_command_that_hangs_is_stopped() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let hang = script("sleep 60");
        let started = Instant::now();
        // the real limit is 20 s; the test only checks the kill path by running the same loop with the real constant
        let err = run(&hang, &[]).unwrap_err().to_string();
        assert!(err.contains("took more than"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(30));
        assert_eq!(RUNNING.load(Ordering::Acquire), 0);
    }
}
