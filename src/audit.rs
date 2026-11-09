//! The audit log: who logged in, from where, what sessions started and ended, what the administrators changed. One JSON object per line,
//! in `/var/log/waydesk/audit.log` and, as a copy, in the system log (identifier `waydesk-audit`, facility authpriv), which is how it
//! leaves the machine. See docs/AUDIT-DESIGN.md.
//!
//! This is not `tracing`: the names and fields here are a contract that changes only with a major version, while log messages change
//! with every edit. Only root-owned processes write it (the helper, `waydesk-admin`); the network daemon never does.
//! Nothing secret goes in: no passwords, no names that cannot be an account name (people type their password in that field).

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tracing::warn;

pub const DEFAULT_PATH: &str = "/var/log/waydesk/audit.log";
/// The group that may read the log, besides root.
const READ_GROUP: &str = "adm";
/// Longest account name that is written as text.
const MAX_NAME: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Fail,
    Refused,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Fail => "fail",
            Outcome::Refused => "refused",
        }
    }
}

struct Sink {
    path: PathBuf,
    file: Option<File>,
    /// Counts the lines of this process; a gap shows a line that was lost. `None`: not numbered (short-lived processes).
    seq: Option<u64>,
    origin: &'static str,
    host: String,
    syslog: Option<UnixDatagram>,
}

static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();
/// Set by SIGHUP (logrotate): the file is opened again before the next line.
static REOPEN: AtomicBool = AtomicBool::new(false);
/// When set, a login that could not be written down is refused.
static REQUIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sighup(_: libc::c_int) {
    REOPEN.store(true, Ordering::Relaxed);
}

/// Starts the log for this process. `origin` says who writes (`helper`, `admin`); `numbered` gives the lines a sequence number (for a process that
/// lives long). Failing to open the file is not fatal: lines are then only sent to the system log, and `emit` says so.
pub fn init(path: &Path, origin: &'static str, numbered: bool, required: bool) {
    let mut sink = Sink { path: path.to_owned(), file: None, seq: numbered.then_some(0), origin, host: hostname(), syslog: UnixDatagram::unbound().ok() };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        if unsafe { libc::geteuid() } == 0 {
            // The directory is root's, readable for the group, so that `adm` can read what the helper writes.
            chown_group(dir, READ_GROUP);
            let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o750));
        }
    }
    if let Err(e) = sink.open() {
        warn!(path = %path.display(), "cannot open the audit log: {e}; audit lines go to the system log only");
    }
    REQUIRED.store(required, Ordering::Relaxed);
    if numbered {
        // SAFETY: the handler only stores into an atomic.
        unsafe { libc::signal(libc::SIGHUP, on_sighup as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
    let _ = SINK.set(Mutex::new(sink));
}

/// True when a login must be refused because it cannot be written down (`--audit-required`).
pub fn required() -> bool {
    REQUIRED.load(Ordering::Relaxed)
}

impl Sink {
    fn open(&mut self) -> std::io::Result<()> {
        let file = OpenOptions::new().append(true).create(true).mode(0o640).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&self.path)?;
        if unsafe { libc::geteuid() } == 0 {
            let _ = std::os::unix::fs::fchown(&file, None, group_id(READ_GROUP));
        }
        self.file = Some(file);
        Ok(())
    }

    /// The file is opened again when logrotate moved it away (the path now names another file, or none) or asked us to.
    fn check_rotated(&mut self) {
        let moved = REOPEN.swap(false, Ordering::Relaxed)
            || match (&self.file, std::fs::metadata(&self.path)) {
                (Some(f), Ok(on_disk)) => f.metadata().map(|m| (m.dev(), m.ino()) != (on_disk.dev(), on_disk.ino())).unwrap_or(true),
                (Some(_), Err(_)) | (None, _) => true,
            };
        if moved {
            self.file = None;
            let _ = self.open();
        }
    }
}

/// One line being built.
pub struct Event {
    name: &'static str,
    outcome: Outcome,
    fields: Vec<(&'static str, Value)>,
}

pub fn event(name: &'static str, outcome: Outcome) -> Event {
    Event { name, outcome, fields: Vec::new() }
}

impl Event {
    pub fn str(mut self, key: &'static str, value: &str) -> Self {
        self.fields.push((key, Value::from(clean(value, 200))));
        self
    }

    pub fn num(mut self, key: &'static str, value: u64) -> Self {
        self.fields.push((key, Value::from(value)));
        self
    }

    pub fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.fields.push((key, Value::from(value)));
        self
    }

    /// An account name as typed at a login: text if it can be an account name, otherwise only its length (it is often a password).
    pub fn typed_name(mut self, name: &str) -> Self {
        if plausible_name(name) {
            self.fields.push(("user", Value::from(name)));
        } else {
            self.fields.push(("user_invalid", Value::from(true)));
            self.fields.push(("user_len", Value::from(name.chars().count() as u64)));
        }
        self
    }

    /// A source address; anything that is not an address is left out.
    pub fn source(mut self, source: &str) -> Self {
        match source.parse::<std::net::IpAddr>() {
            Ok(ip) => self.fields.push(("source", Value::from(ip.to_string()))),
            Err(_) => self.fields.push(("source_invalid", Value::from(true))),
        }
        self
    }

    /// The line, without writing it.
    fn render(&self, ts: &str, seq: Option<u64>, host: &str, origin: &str) -> String {
        let mut line = String::with_capacity(256);
        line.push_str("{\"ts\":");
        line.push_str(&json(ts));
        if let Some(n) = seq {
            line.push_str(&format!(",\"seq\":{n}"));
        }
        line.push_str(&format!(",\"host\":{},\"version\":{},\"origin\":{},\"event\":{},\"outcome\":\"{}\"", json(host), json(env!("CARGO_PKG_VERSION")), json(origin), json(self.name), self.outcome.as_str()));
        for (k, v) in &self.fields {
            line.push_str(&format!(",\"{k}\":{v}"));
        }
        line.push('}');
        line
    }

    /// Writes the line. Returns false when it could not be written to the file (it is still sent to the system log).
    pub fn emit(self) -> bool {
        let Some(sink) = SINK.get() else { return false };
        let mut sink = sink.lock().unwrap_or_else(|p| p.into_inner());
        sink.check_rotated();
        let seq = sink.seq.map(|n| n + 1);
        if let Some(n) = seq {
            sink.seq = Some(n);
        }
        let mut line = self.render(&rfc3339(SystemTime::now()), seq, &sink.host, sink.origin);
        // One write() per line on an O_APPEND file: lines of two processes never mix.
        let wrote = match &mut sink.file {
            Some(f) => {
                line.push('\n');
                let ok = f.write_all(line.as_bytes()).is_ok();
                line.pop();
                ok
            }
            None => false,
        };
        if !wrote {
            warn!(event = self.name, "the audit line could not be written to the file");
        }
        // facility authpriv (10) * 8 + severity: notice for what went wrong, info for the rest.
        let priority = 80 + if self.outcome == Outcome::Ok { 6 } else { 5 };
        if let Some(s) = &sink.syslog {
            let _ = s.send_to(format!("<{priority}>waydesk-audit[{}]: {line}", std::process::id()).as_bytes(), "/dev/log");
        }
        wrote
    }
}

/// Whether `name` may be written as text: short, and made of what account names are made of. Anything else is more likely a password typed
/// in the wrong box than a name.
pub fn plausible_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '$' | '\\'))
}

/// Text for a field: cut to `max` characters, control characters made harmless (JSON escaping does the rest).
fn clean(s: &str, max: usize) -> String {
    s.chars().take(max).map(|c| if c.is_control() { '?' } else { c }).collect()
}

fn json(s: &str) -> String {
    Value::from(s).to_string()
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    clean(&String::from_utf8_lossy(&buf[..end]), 100)
}

fn group_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    (!gr.is_null()).then(|| unsafe { (*gr).gr_gid })
}

fn chown_group(path: &Path, group: &str) {
    if let Some(gid) = group_id(group) {
        let _ = std::os::unix::fs::chown(path, None, Some(gid));
    }
}

/// The account name of a uid, for lines written by a part that only knows the number.
pub fn name_of(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    (!pw.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }.to_string_lossy().into_owned())
}

/// RFC 3339, UTC, milliseconds: `2026-10-29T14:03:11.482Z`. Fixed width, so lines sort and compare as text.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (secs, ms) = (d.as_secs() as i64, d.subsec_millis());
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, day) = civil_from_days(days);
    format!("{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_rfc3339_utc_with_milliseconds() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(UNIX_EPOCH + std::time::Duration::from_millis(1_782_741_791_482)), "2026-06-29T14:03:11.482Z");
        // A leap day and the end of a year.
        assert_eq!(rfc3339(UNIX_EPOCH + std::time::Duration::from_secs(951_782_400)), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(UNIX_EPOCH + std::time::Duration::from_secs(1_798_761_599)), "2026-12-31T23:59:59.000Z");
    }

    #[test]
    fn a_line_has_the_documented_shape() {
        let e = event("login", Outcome::Fail).str("reason", "bad_password").typed_name("ana").source("10.0.0.23");
        assert_eq!(
            e.render("2026-10-29T14:03:11.482Z", Some(412), "srv1", "helper"),
            format!(
                "{{\"ts\":\"2026-10-29T14:03:11.482Z\",\"seq\":412,\"host\":\"srv1\",\"version\":\"{}\",\"origin\":\"helper\",\"event\":\"login\",\"outcome\":\"fail\",\"reason\":\"bad_password\",\"user\":\"ana\",\"source\":\"10.0.0.23\"}}",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn a_hostile_value_cannot_start_a_second_line_or_break_the_object() {
        let e = event("admin.user.add", Outcome::Ok).str("args", "a\n{\"event\":\"login\"}\r\0\u{1b}[31m\"\\");
        let line = e.render("t", None, "h", "admin");
        assert!(!line.contains('\n') && !line.contains('\r'));
        let parsed: Value = serde_json::from_str(&line).expect("still one valid object");
        assert_eq!(parsed["event"], "admin.user.add");
        assert_eq!(parsed.as_object().unwrap().len(), 7, "no extra key was smuggled in");
    }

    #[test]
    fn a_typed_name_that_cannot_be_an_account_is_only_counted() {
        let line = event("login", Outcome::Fail).typed_name("Tr0ub4dor&3 horse").render("t", None, "h", "helper");
        assert!(!line.contains("Tr0ub4dor"), "the text is not written");
        assert!(line.contains("\"user_invalid\":true") && line.contains("\"user_len\":17"));
        let long = "a".repeat(65);
        assert!(!plausible_name(&long) && !plausible_name("") && !plausible_name("a b") && !plausible_name("a\nb"));
        assert!(plausible_name("ana.silva") && plausible_name("DOM\\ana") && plausible_name("ana@example.pt"));
    }

    #[test]
    fn a_source_that_is_not_an_address_is_not_written() {
        let line = event("login", Outcome::Ok).source("10.0.0.1\"},{\"x\":1").render("t", None, "h", "helper");
        assert!(line.contains("\"source_invalid\":true") && !line.contains("\"x\""));
        assert!(event("login", Outcome::Ok).source("::1").render("t", None, "h", "helper").contains("\"source\":\"::1\""));
    }

    #[test]
    fn a_file_moved_away_is_opened_again() {
        let dir = std::env::temp_dir().join(format!("waydesk-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let mut sink = Sink { path: path.clone(), file: None, seq: None, origin: "helper", host: "h".into(), syslog: None };
        sink.open().unwrap();
        sink.file.as_mut().unwrap().write_all(b"one\n").unwrap();
        std::fs::rename(&path, dir.join("audit.log.1")).unwrap();
        sink.check_rotated();
        sink.file.as_mut().unwrap().write_all(b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(std::fs::read_to_string(dir.join("audit.log.1")).unwrap(), "one\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
