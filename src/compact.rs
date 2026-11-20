//! Compacting a session nobody is looking at: when its client has been gone for a while, the session worker asks the root helper (one byte, `C`, on its
//! registration socket) and the helper asks the kernel to push the memory of the account's slice out (`memory.reclaim` of `user-UID.slice`: the session
//! scope with the compositor and the programs, the user manager with the sound server, the session unit). Anonymous pages go to swap (with the packaged zram
//! they stay in RAM, compressed about 2 to 4 times) and cached file pages are dropped. Nothing is stopped: the programs go on running, and what they touch
//! again is read back (the first seconds after a reconnect are a little slower).
//!
//! The helper is the one that does it because only root can write `memory.reclaim` there: the worker runs as the account, and its processes sit in a PAM
//! session scope that systemd does not delegate. The helper names the slice from the uid it has checked on the socket (SO_PEERCRED), never from anything
//! the worker sends, so a worker can only ask for its own account's memory to be compacted, and not more often than `MIN_GAP`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a session is without a client before it asks to be compacted (`--compact-after`, seconds; zero: never).
pub const DEFAULT_AFTER: Duration = Duration::from_secs(600);
/// The helper compacts an account at most this often, whatever is asked.
pub const MIN_GAP: Duration = Duration::from_secs(60);
/// The byte a worker sends on its registration socket.
pub const REQUEST: u8 = b'C';

/// What compacting did, in bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub before: u64,
    pub after: u64,
    /// What the slice holds in swap after.
    pub swapped: u64,
}

/// The cgroup directory of an account's slice, below `root` (`/sys/fs/cgroup`).
pub fn slice_dir(root: &Path, uid: u32) -> PathBuf {
    root.join(format!("user.slice/user-{uid}.slice"))
}

fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Asks the kernel to reclaim what `dir` (a cgroup directory) holds. `Err` says why not, for the log.
pub fn reclaim_in(dir: &Path) -> Result<Outcome, String> {
    let before = read_u64(&dir.join("memory.current")).ok_or("memory.current is not readable (no memory controller for this cgroup)")?;
    let target = dir.join("memory.reclaim");
    // The kernel reclaims up to the amount asked for and answers EAGAIN when it could not get that much: for "everything" that is the normal case.
    // Ask in steps so that one call does not sit long on a big session, and stop when a step frees (nearly) nothing.
    for _ in 0..4 {
        let now = read_u64(&dir.join("memory.current")).unwrap_or(0);
        if now < 8 << 20 {
            break;
        }
        match std::fs::write(&target, format!("{now}")) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
            Err(e) => return Err(format!("memory.reclaim: {e}")),
        }
        let after = read_u64(&dir.join("memory.current")).unwrap_or(now);
        if now.saturating_sub(after) < 4 << 20 {
            break;
        }
    }
    let after = read_u64(&dir.join("memory.current")).unwrap_or(before);
    let swapped = read_u64(&dir.join("memory.swap.current")).unwrap_or(0);
    Ok(Outcome { before, after, swapped })
}

/// Compacts the account `uid` (root only).
pub fn reclaim_account(uid: u32) -> Result<Outcome, String> {
    reclaim_in(&slice_dir(Path::new("/sys/fs/cgroup"), uid))
}

pub fn mb(bytes: u64) -> u64 {
    bytes / (1 << 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slice_is_named_from_the_uid_alone() {
        assert_eq!(slice_dir(Path::new("/sys/fs/cgroup"), 1001), PathBuf::from("/sys/fs/cgroup/user.slice/user-1001.slice"));
    }

    #[test]
    fn a_folder_without_the_files_says_why() {
        let dir = std::env::temp_dir().join(format!("waydesk-compact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(reclaim_in(&dir).unwrap_err().contains("memory.current"));
        // With the files but nothing worth reclaiming (under 8 MB), it reports the numbers and writes nothing.
        std::fs::write(dir.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(dir.join("memory.swap.current"), "0\n").unwrap();
        std::fs::write(dir.join("memory.reclaim"), "").unwrap();
        assert_eq!(reclaim_in(&dir), Ok(Outcome { before: 1048576, after: 1048576, swapped: 0 }));
        assert_eq!(std::fs::read_to_string(dir.join("memory.reclaim")).unwrap(), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
