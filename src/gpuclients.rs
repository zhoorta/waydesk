//! How much of a GPU each account uses: the kernel keeps, for every open DRM file, the time its engines worked (`/proc/PID/fdinfo/N`: `drm-engine-render: 123 ns`,
//! the same for Intel, AMD and the other open drivers). Two readings a little apart give a share of the time between them, per account.
//! NVIDIA's proprietary driver writes nothing there: its accounts show no figure.
//!
//! Only the files that point into `/dev/dri` are read, so a sample costs a `readlink` per open file of each of the accounts' programs.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt as _;

/// What the engines of one account worked (nanoseconds, added over its DRM files).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Engines {
    /// Drawing and compute: `render`, `gfx`, `rcs`, `ccs`, `compute`.
    pub render_ns: u64,
    /// Video work, which is where H.264 encoding runs: `video`, `video-enhance`, `vcs`, `vecs`, `enc`, `dec`.
    pub video_ns: u64,
}

/// One DRM file as its fdinfo says it: the identity (the same file seen through several descriptors or programs is one), and the time of its engines.
#[derive(Debug, PartialEq, Eq)]
pub struct Client {
    pub key: String,
    pub engines: Engines,
}

fn class_of(engine: &str) -> Option<bool> {
    // true = video, false = render
    const VIDEO: [&str; 6] = ["video", "vcs", "vecs", "enc", "dec", "jpeg"];
    const RENDER: [&str; 5] = ["render", "gfx", "rcs", "ccs", "compute"];
    if VIDEO.iter().any(|p| engine.starts_with(p)) {
        Some(true)
    } else if RENDER.iter().any(|p| engine.starts_with(p)) {
        Some(false)
    } else {
        None
    }
}

/// The text of one `/proc/PID/fdinfo/N`; `None` when the file is not a DRM file that counts its engines.
pub fn parse_fdinfo(text: &str) -> Option<Client> {
    let (mut driver, mut pdev, mut id) = (None, "", None);
    let mut engines = Engines::default();
    let mut counted = false;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k {
            "drm-driver" => driver = Some(v),
            "drm-pdev" => pdev = v,
            "drm-client-id" => id = Some(v),
            _ => {
                let Some(engine) = k.strip_prefix("drm-engine-") else { continue };
                if engine.starts_with("capacity-") {
                    continue;
                }
                let ns: u64 = v.split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
                counted = true;
                match class_of(engine) {
                    Some(true) => engines.video_ns = engines.video_ns.saturating_add(ns),
                    Some(false) => engines.render_ns = engines.render_ns.saturating_add(ns),
                    None => {}
                }
            }
        }
    }
    let (driver, id) = (driver?, id?);
    counted.then(|| Client { key: format!("{driver}/{pdev}/{id}"), engines })
}

/// The engine time of each of the accounts now, over the DRM files of their programs. An account without any such file is absent.
pub fn read(uids: &HashSet<u32>) -> HashMap<u32, Engines> {
    let mut seen: HashSet<(u32, String)> = HashSet::new();
    let mut out: HashMap<u32, Engines> = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return out };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().filter(|n| n.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let Ok(meta) = std::fs::metadata(entry.path()) else { continue };
        let uid = meta.uid();
        if !uids.contains(&uid) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            if !target.starts_with("/dev/dri/") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", fd.file_name().to_string_lossy())) else { continue };
            let Some(client) = parse_fdinfo(&text) else { continue };
            if seen.insert((uid, client.key)) {
                let e = out.entry(uid).or_default();
                e.render_ns = e.render_ns.saturating_add(client.engines.render_ns);
                e.video_ns = e.video_ns.saturating_add(client.engines.video_ns);
            }
        }
    }
    out
}

/// The share of the time between two readings, in percent of one engine (an engine that never stopped is 100). A program that ended in between took its
/// counter with it: that reads as no growth, never as a negative.
pub fn percent(before: Engines, after: Engines, elapsed_ns: f64) -> (f64, f64) {
    let share = |b: u64, a: u64| (a.saturating_sub(b) as f64 / elapsed_ns.max(1.0) * 100.0).min(100.0);
    (share(before.render_ns, after.render_ns), share(before.video_ns, after.video_ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    const I915: &str = "pos:\t0\nflags:\t02100002\ndrm-driver:\ti915\ndrm-pdev:\t0000:00:02.0\ndrm-client-id:\t134\ndrm-engine-render:\t107560613 ns\ndrm-engine-copy:\t5 ns\ndrm-engine-video:\t257788289 ns\ndrm-engine-capacity-video:\t2\ndrm-engine-video-enhance:\t10 ns\n";

    #[test]
    fn an_intel_file_gives_render_and_video_and_ignores_copy_and_capacity() {
        let c = parse_fdinfo(I915).unwrap();
        assert_eq!(c.key, "i915/0000:00:02.0/134");
        assert_eq!(c.engines, Engines { render_ns: 107_560_613, video_ns: 257_788_299 });
    }

    #[test]
    fn an_amd_file_counts_gfx_compute_and_the_video_engines() {
        let t = "drm-driver:\tamdgpu\ndrm-pdev:\t0000:03:00.0\ndrm-client-id:\t7\ndrm-engine-gfx:\t1000 ns\ndrm-engine-compute:\t200 ns\ndrm-engine-dma:\t9 ns\ndrm-engine-enc:\t300 ns\ndrm-engine-dec:\t40 ns\n";
        assert_eq!(parse_fdinfo(t).unwrap().engines, Engines { render_ns: 1200, video_ns: 340 });
    }

    #[test]
    fn files_that_are_not_drm_or_count_nothing_are_skipped() {
        assert_eq!(parse_fdinfo("pos:\t0\nflags:\t0100000\n"), None);
        assert_eq!(parse_fdinfo("drm-driver:\tnvidia\ndrm-client-id:\t1\n"), None);
        assert_eq!(parse_fdinfo("drm-engine-render:\t5 ns\n"), None);
    }

    #[test]
    fn the_share_is_of_the_time_between_readings_and_never_negative() {
        let a = Engines { render_ns: 100, video_ns: 100 };
        let b = Engines { render_ns: 100 + 250_000_000, video_ns: 100 + 1_000_000_000 };
        let (r, v) = percent(a, b, 1_000_000_000.0);
        assert!((r - 25.0).abs() < 1e-6 && (v - 100.0).abs() < 1e-6);
        assert_eq!(percent(b, a, 1_000_000_000.0), (0.0, 0.0));
    }
}
