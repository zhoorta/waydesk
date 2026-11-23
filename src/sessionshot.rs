//! A small picture of a running session, for the card of the person's own desktop in the portal ("My desktop", one per server).
//!
//! The session worker takes it from a frame it has already captured (so it works on every desktop backend, and runs no screenshot tool inside the
//! session): at most one every `INTERVAL`, cut down to `WIDTH` pixels, as a PNG (the `png` crate is there for clipboard images already). It is written to
//! `/run/waydesk/status/UID/shot.png`, the account's own 0700 folder (see `sessionstatus`), readable by the account and root only. The agent (root)
//! reads it for the portal, which shows it to that account and nobody else. A session that ends takes its picture with it. The file shows the
//! screen, so it is never logged, never put where another account can read it, and read with the same care as `status.json` (no links, owner checked).
#![allow(dead_code)]

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::sessionstatus::{dir_for, DIR};

/// A picture is made at most this often.
pub const INTERVAL: Duration = Duration::from_secs(10);
/// The picture is this wide (a narrower screen is not enlarged).
pub const WIDTH: usize = 320;
/// What `read` takes at most: a picture this size is far beyond a 320-pixel one.
pub const MAX_BYTES: u64 = 512 * 1024;

pub fn path_for(dir: &Path, uid: u32) -> PathBuf {
    dir_for(dir, uid).join("shot.png")
}

/// The picture of a tight BGRA frame of `w` x `h`, cut down to at most `WIDTH` pixels wide (each new pixel is the average of the block it covers),
/// as PNG bytes. `None` for a frame that is empty or does not have the bytes its size says.
pub fn thumbnail(bgra: &[u8], w: usize, h: usize) -> Option<Vec<u8>> {
    if w == 0 || h == 0 || bgra.len() < w.checked_mul(h)?.checked_mul(4)? {
        return None;
    }
    let tw = w.min(WIDTH);
    let th = (h * tw / w).max(1);
    let mut rgb = Vec::with_capacity(tw * th * 3);
    for ty in 0..th {
        let (y0, y1) = (ty * h / th, ((ty + 1) * h / th).max(ty * h / th + 1).min(h));
        for tx in 0..tw {
            let (x0, x1) = (tx * w / tw, ((tx + 1) * w / tw).max(tx * w / tw + 1).min(w));
            let (mut b, mut g, mut r, mut n) = (0u32, 0u32, 0u32, 0u32);
            for y in y0..y1 {
                let row = &bgra[(y * w + x0) * 4..(y * w + x1) * 4];
                for px in row.chunks_exact(4) {
                    b += u32::from(px[0]);
                    g += u32::from(px[1]);
                    r += u32::from(px[2]);
                    n += 1;
                }
            }
            rgb.extend_from_slice(&[(r / n) as u8, (g / n) as u8, (b / n) as u8]);
        }
    }
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, tw as u32, th as u32);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::Fast);
    enc.write_header().ok()?.write_image_data(&rgb).ok()?;
    Some(out)
}

static LAST: Mutex<Option<Instant>> = Mutex::new(None);
/// A frame came while no picture was due, so the picture on disk may be older than the screen.
static SKIPPED: AtomicBool = AtomicBool::new(false);
/// The picture has been still for a moment (the worker is sending its settle keyframe): the screen has reached its final state.
static SETTLED: AtomicBool = AtomicBool::new(false);
/// A settled screen is photographed early, but not more often than this.
const SETTLED_MIN: Duration = Duration::from_secs(1);

/// The worker calls this when the picture has stopped changing. Frames are only made when something changes, so without it a screen that went still
/// less than `INTERVAL` after the last picture would keep showing the state from before its last changes, for as long as it stays still.
pub fn settled() {
    SETTLED.store(true, Ordering::Relaxed);
}

/// True when a picture is due now (and notes that one is being made).
fn due() -> bool {
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = *last {
        if t.elapsed() < INTERVAL {
            let late = SETTLED.load(Ordering::Relaxed) && SKIPPED.load(Ordering::Relaxed) && t.elapsed() >= SETTLED_MIN;
            if !late {
                // The settle frame of a picture that was photographed at its last change shows nothing new.
                if SETTLED.load(Ordering::Relaxed) && !SKIPPED.load(Ordering::Relaxed) {
                    SETTLED.store(false, Ordering::Relaxed);
                } else {
                    SKIPPED.store(true, Ordering::Relaxed);
                }
                return false;
            }
        }
    }
    SETTLED.store(false, Ordering::Relaxed);
    SKIPPED.store(false, Ordering::Relaxed);
    *last = Some(Instant::now());
    true
}

/// Called with every frame the encoder is given. Nearly always it only looks at the clock; when a picture is due, `bgra` gives the frame's bytes
/// (a frame in GPU memory is read out then, and not for the other frames) and the picture is written to the account's folder.
pub fn offer<'a>(w: usize, h: usize, bgra: impl FnOnce() -> Option<Cow<'a, [u8]>>) {
    if !due() {
        return;
    }
    let uid = unsafe { libc::geteuid() };
    // Not under the helper (a session started by hand, a test): no folder, nothing to write to.
    if !dir_for(Path::new(DIR), uid).is_dir() {
        return;
    }
    let Some(bytes) = bgra() else { return };
    let Some(png) = thumbnail(&bytes, w, h) else { return };
    let _ = write(Path::new(DIR), uid, &png);
}

fn write(dir: &Path, uid: u32, png: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = dir_for(dir, uid).join("shot.png.tmp");
    std::fs::write(&tmp, png)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path_for(dir, uid))
}

/// The session ends: its picture goes too (and the next session of the account does not start with the last one's screen).
pub fn clear() {
    let uid = unsafe { libc::geteuid() };
    let _ = std::fs::remove_file(path_for(Path::new(DIR), uid));
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = None;
    SKIPPED.store(false, Ordering::Relaxed);
    SETTLED.store(false, Ordering::Relaxed);
}

/// A picture as the reader gets it: the PNG and when it was made (Unix seconds).
pub struct Shot {
    pub png: Vec<u8>,
    pub at: u64,
}

/// The picture of the session of `uid`, for root (the agent). Only a plain file of that account is taken: a link is not followed and a file of
/// another owner is not believed (the folder is the account's own, so the account could put anything there, but only for itself to be shown).
pub fn read(dir: &Path, uid: u32) -> Option<Shot> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path_for(dir, uid)).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != uid || meta.len() > MAX_BYTES {
        return None;
    }
    let mut png = Vec::with_capacity(meta.len() as usize);
    file.by_ref().take(MAX_BYTES).read_to_end(&mut png).ok()?;
    // Only a PNG is passed on (the account wrote the file, and the browser will be told it is an image).
    if !png.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return None;
    }
    let at = meta.mtime().max(0) as u64;
    Some(Shot { png, at })
}

pub fn age_secs(s: &Shot) -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).saturating_sub(s.at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: usize, h: usize, bgra: [u8; 4]) -> Vec<u8> {
        bgra.iter().copied().cycle().take(w * h * 4).collect()
    }

    fn decode(png_bytes: &[u8]) -> (u32, u32, Vec<u8>) {
        let dec = png::Decoder::new(std::io::Cursor::new(png_bytes));
        let mut reader = dec.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        (info.width, info.height, buf[..info.buffer_size()].to_vec())
    }

    #[test]
    fn a_big_screen_is_cut_down_and_keeps_its_shape_and_colour() {
        let big = frame(1920, 1080, [10, 20, 200, 255]); // B, G, R, A
        let (w, h, rgb) = decode(&thumbnail(&big, 1920, 1080).unwrap());
        assert_eq!((w, h), (320, 180));
        assert_eq!(&rgb[..3], &[200, 20, 10], "red, green, blue");
    }

    #[test]
    fn blocks_are_averaged() {
        // Left half black, right half white: the middle columns of the picture are grey, the sides are not.
        let (w, h) = (640, 10);
        let mut f = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in w / 2..w {
                f[(y * w + x) * 4..(y * w + x) * 4 + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
        let (tw, _, rgb) = decode(&thumbnail(&f, w, h).unwrap());
        assert_eq!(tw, 320);
        assert_eq!(rgb[0], 0);
        assert_eq!(rgb[(tw as usize - 1) * 3], 255);
    }

    #[test]
    fn a_small_screen_is_not_enlarged_and_bad_input_is_nothing() {
        let (w, h, _) = decode(&thumbnail(&frame(200, 100, [0; 4]), 200, 100).unwrap());
        assert_eq!((w, h), (200, 100));
        assert!(thumbnail(&[], 0, 0).is_none());
        assert!(thumbnail(&[0; 16], 100, 100).is_none(), "fewer bytes than the size says");
        assert!(thumbnail(&[0; 16], usize::MAX, 2).is_none(), "a size that overflows");
    }

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("waydesk-shot-{name}-{}", std::process::id()))
    }

    #[test]
    fn a_picture_is_read_back_and_only_if_it_is_the_accounts_own_plain_png() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("read");
        let mine = unsafe { libc::geteuid() };
        crate::sessionstatus::prepare(&dir, mine).unwrap();
        let png = thumbnail(&frame(64, 64, [1, 2, 3, 255]), 64, 64).unwrap();
        write(&dir, mine, &png).unwrap();
        assert_eq!(std::fs::metadata(path_for(&dir, mine)).unwrap().permissions().mode() & 0o777, 0o600);
        let shot = read(&dir, mine).expect("read");
        assert_eq!(shot.png, png);
        assert!(age_secs(&shot) < 5);
        // Another uid's folder holding a file of ours is not that account's.
        std::fs::create_dir_all(dir_for(&dir, mine + 1)).unwrap();
        std::fs::copy(path_for(&dir, mine), path_for(&dir, mine + 1)).unwrap();
        assert!(read(&dir, mine + 1).is_none());
        // Something that is not a PNG is not passed on.
        std::fs::write(path_for(&dir, mine), b"<html>not a picture</html>").unwrap();
        assert!(read(&dir, mine).is_none());
        // A link is not followed.
        std::fs::remove_file(path_for(&dir, mine)).unwrap();
        let elsewhere = dir.join("elsewhere.png");
        std::fs::write(&elsewhere, &png).unwrap();
        std::os::unix::fs::symlink(&elsewhere, path_for(&dir, mine)).unwrap();
        assert!(read(&dir, mine).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_picture_is_made_once_in_a_while() {
        *LAST.lock().unwrap() = None;
        assert!(due());
        assert!(!due(), "not again at once");
        *LAST.lock().unwrap() = Some(Instant::now() - INTERVAL - Duration::from_secs(1));
        assert!(due());
        // A screen that goes still soon after a picture is photographed again once it has settled, and only if frames were skipped.
        *LAST.lock().unwrap() = None;
        assert!(due());
        settled();
        *LAST.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3));
        assert!(!due(), "settled, but nothing was skipped: the picture is current");
        assert!(!SKIPPED.load(Ordering::Relaxed) && !SETTLED.load(Ordering::Relaxed));
        assert!(!due(), "a change frame, skipped");
        settled();
        *LAST.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3));
        assert!(due(), "a frame was skipped and the screen settled");
        assert!(!due(), "not again at once");
        // Settling right after a picture waits for the minimum.
        *LAST.lock().unwrap() = Some(Instant::now() - Duration::from_millis(200));
        assert!(!due());
        settled();
        assert!(!due(), "too soon after the last picture");
        *LAST.lock().unwrap() = Some(Instant::now() - Duration::from_secs(2));
        assert!(due());
        clear();
    }
}
