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
