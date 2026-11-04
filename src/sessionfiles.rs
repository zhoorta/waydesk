//! Clipboard files, client to session (docs/decisions/016-clipboard-files.md). The session process runs as the account,
//! so it is the one that writes the files: into a private spool under the runtime directory (a tmpfs, 0700), from which
//! the file manager copies them when the user pastes. The daemon names files by index and sends bytes in order; it never
//! names a path. Everything here is checked again whatever the daemon already checked.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::proto::{MAX_FILES, MAX_FILES_TOTAL, MAX_FILE_BYTES};

/// The name a received file gets, or `None` when the whole list must be refused: a name with a path in it, a control
/// character, nothing at all, or too long. A leading dot is replaced by an underscore (a transfer does not create
/// hidden files).
pub fn clean_name(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
        return None;
    }
    if name.chars().any(|c| c == '/' || c == '\\' || c.is_control()) {
        return None;
    }
    Some(match name.strip_prefix('.') {
        Some(rest) => format!("_{rest}"),
        None => name.to_owned(),
    })
}

/// `name`, or `name (2)`, `name (3)`... (before the extension) when `used` already holds it.
fn unique(name: &str, used: &HashSet<String>) -> String {
    if !used.contains(name) {
        return name.to_owned();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (2..)
        .map(|n| format!("{stem} ({n}){ext}"))
        .find(|c| c.len() <= 255 && !used.contains(c))
        .expect("a free name")
}

/// What a call did.
#[derive(Debug, PartialEq)]
pub enum FilesOutcome {
    /// The transfer was accepted. `done`: it is already complete (only empty files); the list for the clipboard.
    Ready { done: Option<String> },
    /// More bytes expected.
    Continue,
    /// All files are in; the `text/uri-list` for the clipboard.
    Done(String),
    /// Refused or broken; nothing is left on disk.
    Failed,
}

struct Slot {
    path: PathBuf,
    file: File,
    size: u64,
    written: u64,
}

struct Transfer {
    id: u32,
    dir: PathBuf,
    files: Vec<Slot>,
    /// The first file that is not complete.
    next: usize,
}

#[derive(Default)]
pub struct Files {
    cur: Option<Transfer>,
}

fn spool_base() -> Option<PathBuf> {
    let base = Path::new(&std::env::var_os("XDG_RUNTIME_DIR")?).join("waydesk-files");
    match std::fs::symlink_metadata(&base) {
        Ok(m) => {
            use std::os::unix::fs::MetadataExt as _;
            // Ours and a real directory, or not used at all.
            if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } {
                return None;
            }
        }
        Err(_) => std::fs::DirBuilder::new().mode(0o700).create(&base).ok()?,
    }
    Some(base)
}

/// `file:///path` with everything but unreserved characters and `/` percent-encoded.
fn file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    let mut out = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Files {
    /// Starts transfer `id`: checks the list, makes the spool and an empty file for each entry.
    pub fn begin(&mut self, id: u32, list: &[(String, u64)]) -> FilesOutcome {
        self.clear();
        let total: u64 = list.iter().map(|(_, s)| *s).fold(0, u64::saturating_add);
        if list.is_empty() || list.len() > MAX_FILES || total > MAX_FILES_TOTAL || list.iter().any(|(_, s)| *s > MAX_FILE_BYTES) {
            warn!(files = list.len(), total, "clipboard files refused: over the limits");
            return FilesOutcome::Failed;
        }
        let mut used = HashSet::new();
        let mut names = Vec::new();
        for (name, _) in list {
            let Some(clean) = clean_name(name) else {
                warn!("clipboard files refused: a file name is not acceptable");
                return FilesOutcome::Failed;
            };
            let name = unique(&clean, &used);
            used.insert(name.clone());
            names.push(name);
        }
        let Some(base) = spool_base() else {
            warn!("clipboard files refused: no private spool directory");
            return FilesOutcome::Failed;
        };
        // Whatever an earlier transfer left (a session that was killed) goes first.
        if let Ok(old) = std::fs::read_dir(&base) {
            for e in old.flatten() {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
        let dir = base.join(id.to_string());
        if std::fs::DirBuilder::new().mode(0o700).create(&dir).is_err() {
            return FilesOutcome::Failed;
        }
        let mut files = Vec::new();
        for (name, (_, size)) in names.iter().zip(list) {
            let path = dir.join(name);
            match OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path) {
                Ok(file) => files.push(Slot { path, file, size: *size, written: 0 }),
                Err(e) => {
                    warn!("clipboard files: cannot create a file: {e}");
                    let _ = std::fs::remove_dir_all(&dir);
                    return FilesOutcome::Failed;
                }
            }
        }
        info!(id, files = files.len(), total, "clipboard files accepted");
        let mut t = Transfer { id, dir, files, next: 0 };
        t.skip_complete();
        let done = t.finished().then(|| t.uri_list());
        self.cur = Some(t);
        FilesOutcome::Ready { done }
    }

    /// The next bytes of file `index`. Only the next expected bytes of the first incomplete file are accepted.
    pub fn data(&mut self, id: u32, index: u32, offset: u64, data: &[u8]) -> FilesOutcome {
        let Some(t) = self.cur.as_mut().filter(|t| t.id == id) else { return FilesOutcome::Failed };
        let ok = t.next == index as usize
            && t.files.get(t.next).is_some_and(|f| f.written == offset && offset + data.len() as u64 <= f.size && !data.is_empty());
        if !ok {
            warn!(id, index, offset, len = data.len(), "clipboard files: bytes out of order or past the size; transfer dropped");
            self.clear();
            return FilesOutcome::Failed;
        }
        let slot = &mut t.files[t.next];
        if let Err(e) = slot.file.write_all(data) {
            warn!("clipboard files: write failed: {e}");
            self.clear();
            return FilesOutcome::Failed;
        }
        slot.written += data.len() as u64;
        t.skip_complete();
        if t.finished() {
            FilesOutcome::Done(t.uri_list())
        } else {
            FilesOutcome::Continue
        }
    }

    /// Drops transfer `id` (or nothing, when it is not the current one).
    pub fn cancel(&mut self, id: u32) {
        if self.cur.as_ref().is_some_and(|t| t.id == id) {
            self.clear();
        }
    }

    /// Removes the spool of the current transfer.
    pub fn clear(&mut self) {
        if let Some(t) = self.cur.take() {
            let _ = std::fs::remove_dir_all(&t.dir);
        }
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Transfer {
    fn skip_complete(&mut self) {
        while self.files.get(self.next).is_some_and(|f| f.written == f.size) {
            self.next += 1;
        }
    }

    fn finished(&self) -> bool {
        self.next >= self.files.len()
    }

    fn uri_list(&self) -> String {
        self.files.iter().map(|f| format!("{}\r\n", file_uri(&f.path))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_names_are_refused_and_dots_are_replaced() {
        for bad in ["", ".", "..", "a/b", "a\\b", "../x", "/etc/passwd", "C:\\x\\y", "a\0b", "a\nb", &"x".repeat(256)] {
            assert_eq!(clean_name(bad), None, "{bad:?}");
        }
        assert_eq!(clean_name("report.pdf").as_deref(), Some("report.pdf"));
        assert_eq!(clean_name(".bashrc").as_deref(), Some("_bashrc"));
        assert_eq!(clean_name("..x").as_deref(), Some("_.x"));
        assert_eq!(clean_name("é ü 日本.txt").as_deref(), Some("é ü 日本.txt"));
    }

    #[test]
    fn duplicate_names_get_a_number_before_the_extension() {
        let mut used = HashSet::new();
        used.insert("a.txt".to_string());
        assert_eq!(unique("a.txt", &used), "a (2).txt");
        used.insert("a (2).txt".to_string());
        assert_eq!(unique("a.txt", &used), "a (3).txt");
        assert_eq!(unique("b", &used), "b");
    }

    #[test]
    fn uris_are_percent_encoded() {
        assert_eq!(file_uri(Path::new("/run/user/1000/a b#é.txt")), "file:///run/user/1000/a%20b%23%C3%A9.txt");
    }

    fn with_runtime<T>(f: impl FnOnce() -> T) -> T {
        let dir = std::env::temp_dir().join(format!("wdfiles-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        let out = f();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    // One test touches the environment, so everything that needs the spool runs in it.
    #[test]
    fn a_transfer_writes_files_in_order_and_refuses_the_rest() {
        with_runtime(|| {
            let mut f = Files::default();
            let list = vec![("a.txt".to_string(), 5), ("empty".to_string(), 0), ("a.txt".to_string(), 3)];
            assert_eq!(f.begin(1, &list), FilesOutcome::Ready { done: None });
            // Out of order: the third file before the first.
            assert_eq!(f.data(1, 2, 0, b"abc"), FilesOutcome::Failed);
            assert!(f.cur.is_none(), "a bad chunk drops the transfer");

            assert_eq!(f.begin(2, &list), FilesOutcome::Ready { done: None });
            assert_eq!(f.data(2, 0, 0, b"he"), FilesOutcome::Continue);
            assert_eq!(f.data(2, 0, 0, b"he"), FilesOutcome::Failed, "the same offset again");

            assert_eq!(f.begin(3, &list), FilesOutcome::Ready { done: None });
            assert_eq!(f.data(3, 0, 0, b"hello"), FilesOutcome::Continue);
            // The empty file is skipped; the next bytes belong to the third entry.
            assert_eq!(f.data(3, 1, 0, b"x"), FilesOutcome::Failed, "an empty file takes no bytes");

            assert_eq!(f.begin(4, &list), FilesOutcome::Ready { done: None });
            assert_eq!(f.data(4, 0, 0, b"hello"), FilesOutcome::Continue);
            let FilesOutcome::Done(uris) = f.data(4, 2, 0, b"abc") else { panic!("not done") };
            let lines: Vec<&str> = uris.split("\r\n").filter(|l| !l.is_empty()).collect();
            assert_eq!(lines.len(), 3);
            assert!(lines[0].ends_with("/4/a.txt") && lines[1].ends_with("/4/empty") && lines[2].ends_with("/4/a%20%282%29.txt"), "{lines:?}");
            let p = |l: &str| PathBuf::from(l.trim_start_matches("file://").replace("%20", " ").replace("%28", "(").replace("%29", ")"));
            assert_eq!(std::fs::read(p(lines[0])).unwrap(), b"hello");
            assert_eq!(std::fs::read(p(lines[2])).unwrap(), b"abc");

            // Too long, too many, too big, a path in a name.
            assert_eq!(f.begin(5, &[("big".into(), MAX_FILE_BYTES + 1)]), FilesOutcome::Failed);
            assert_eq!(f.begin(6, &[("a/b".into(), 1)]), FilesOutcome::Failed);
            let many: Vec<_> = (0..=MAX_FILES).map(|i| (format!("f{i}"), 1)).collect();
            assert_eq!(f.begin(7, &many), FilesOutcome::Failed);
            let total: Vec<_> = (0..5).map(|i| (format!("f{i}"), MAX_FILE_BYTES)).collect();
            assert_eq!(f.begin(8, &total), FilesOutcome::Failed, "256 MiB in total");

            // Only empty files: complete at once. A new transfer replaces the old spool.
            let FilesOutcome::Ready { done: Some(_) } = f.begin(9, &[("e".into(), 0)]) else { panic!("not done") };
            assert!(!f.cur.as_ref().unwrap().dir.parent().unwrap().join("4").exists());
            f.cancel(9);
            assert!(f.cur.is_none());
        });
    }
}
