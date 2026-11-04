//! The session side of the clipboard (text only): the session process runs as the account and so can reach its own
//! Wayland clipboard through the `wl-clipboard` tools. The network daemon, which has no access to it, only relays text.
//! Client copy: the daemon sends the text, `wl-copy` puts it on the clipboard.
//! Session copy: `wl-paste --watch` notices a change and the text goes to the daemon.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::proto::{Up, MAX_CLIPBOARD, MAX_CLIPBOARD_IMAGE};

/// Watches the session's clipboard while the client's channel is open. Stopped when dropped.
pub struct Clipboard {
    watcher: Arc<Mutex<Option<Child>>>,
    /// Set when this watch is stopped (a thread that still waits for COSMIC's display then gives up).
    stopped: Arc<std::sync::atomic::AtomicBool>,
    up: mpsc::UnboundedSender<Up>,
    /// Text the client put on the clipboard: its echo must not go back to the client.
    last_set: Arc<Mutex<Option<String>>>,
    /// The same for an image (PNG bytes).
    last_image: Arc<Mutex<Option<Vec<u8>>>>,
    /// The daemon allows files to go to the client (`Down::FilesOut`).
    files_out: Arc<std::sync::atomic::AtomicBool>,
    /// The files of the session clipboard that were offered to the client.
    out_files: Arc<Mutex<crate::sessionfiles::OutFiles>>,
}

impl Clipboard {
    pub fn new(up: mpsc::UnboundedSender<Up>) -> Self {
        Self { watcher: Arc::new(Mutex::new(None)), stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)), up, last_set: Arc::new(Mutex::new(None)), last_image: Arc::new(Mutex::new(None)), files_out: Arc::new(std::sync::atomic::AtomicBool::new(false)), out_files: Arc::new(Mutex::new(Default::default())) }
    }

    /// (Re)starts the watch. `wl-paste --watch` runs its command once at once and then on every change; that first
    /// run is skipped: what the session held before the client came is older than what the client holds, and
    /// offering it at connect would replace the client's clipboard with it.
    pub fn watch(&mut self) {
        self.stop();
        self.stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (up, last_set, last_image, watcher, stopped) = (self.up.clone(), self.last_set.clone(), self.last_image.clone(), self.watcher.clone(), self.stopped.clone());
        let (files_out, out_files) = (self.files_out.clone(), self.out_files.clone());
        // The clipboard of a nested desktop (COSMIC, Plasma) is its own, on its own display, which appears some seconds after the session starts: wait for it off this thread.
        std::thread::spawn(move || {
            let display = if crate::compositor::is_nested() {
                let mut found = None;
                for _ in 0..90 {
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    found = nested_display();
                    if found.is_some() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                if found.is_none() {
                    warn!("clipboard: the nested desktop's display did not show up in 90 s");
                }
                found
            } else {
                None
            };
            let mut cmd = Command::new("wl-paste");
            cmd.args(["--watch", "sh", "-c", "echo c"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            if let Some(d) = &display {
                cmd.env("WAYLAND_DISPLAY", d);
            }
            match cmd.spawn() {
                Ok(mut c) => {
                    let out = c.stdout.take().expect("piped stdout");
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = c.kill();
                        let _ = c.wait();
                        return;
                    }
                    *watcher.lock().unwrap() = Some(c);
                    let mut first = true;
                    for line in BufReader::new(out).lines() {
                        if line.is_err() {
                            break;
                        }
                        if std::mem::take(&mut first) {
                            continue;
                        }
                        // Files copied in the session (a file manager) go to the client as files, when that is allowed.
                        if files_out.load(std::sync::atomic::Ordering::Relaxed) {
                            if let Some(list) = wayland_uri_list() {
                                if last_set.lock().unwrap().as_deref() == Some(list.as_str()) {
                                    continue; // the files the client just sent
                                }
                                let offered = out_files.lock().unwrap().offer(&list);
                                if let Some((id, files)) = offered {
                                    if up.send(Up::FilesOffered { id, files }).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                            }
                        }
                        // Text wins when both are offered (a spreadsheet cell comes as text and as a picture).
                        let Some(text) = wayland_text() else {
                            if let Some(png) = wayland_image() {
                                if last_image.lock().unwrap().as_deref() == Some(png.as_slice()) {
                                    continue;
                                }
                                info!(len = png.len(), "session clipboard image changed");
                                if up.send(Up::ClipboardImage { png }).is_err() {
                                    break;
                                }
                            }
                            continue;
                        };
                        if last_set.lock().unwrap().as_deref() == Some(text.as_str()) {
                            continue;
                        }
                        if text.len() > MAX_CLIPBOARD {
                            info!(len = text.len(), "session clipboard text is too long to send");
                            continue;
                        }
                        info!(len = text.len(), "session clipboard changed");
                        if up.send(Up::Clipboard { data: text.into_bytes() }).is_err() {
                            break;
                        }
                    }
                }
                Err(e) => warn!("clipboard from session to client is off (cannot run wl-paste --watch): {e}"),
            }
        });
    }

    pub fn stop(&mut self) {
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(mut c) = self.watcher.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Puts the client's text on the session clipboard.
    pub fn set(&self, data: Vec<u8>) {
        if data.len() > MAX_CLIPBOARD {
            warn!(len = data.len(), "client clipboard text is too long; ignored");
            return;
        }
        let Ok(text) = String::from_utf8(data) else {
            warn!("client clipboard text is not UTF-8; ignored");
            return;
        };
        if text.is_empty() {
            return;
        }
        *self.last_set.lock().unwrap() = Some(text.clone());
        std::thread::spawn(move || {
            // wl-copy forks into the background to keep serving the selection; its parent returns at once.
            let mut cmd = Command::new("wl-copy");
            cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
            if crate::compositor::is_nested() {
                if let Some(d) = nested_display() {
                    cmd.env("WAYLAND_DISPLAY", d);
                }
            }
            match cmd.spawn() {
                Ok(mut c) => {
                    if let Some(mut stdin) = c.stdin.take() {
                        let _ = stdin.write_all(text.as_bytes());
                    }
                    let status = c.wait();
                    info!(?status, "wl-copy done");
                }
                Err(e) => warn!("cannot run wl-copy: {e}"),
            }
        });
    }
}

impl Clipboard {
    /// The daemon allows (or not) the session's files to be offered to the client.
    pub fn set_files_out(&self, on: bool) {
        self.files_out.store(on, std::sync::atomic::Ordering::Relaxed);
        if !on {
            *self.out_files.lock().unwrap() = Default::default();
        }
    }

    /// Reads a range of an offered file and sends it (or the failure) to the daemon.
    pub fn files_read(&self, id: u32, index: u32, offset: u64, len: u32) {
        let (out, up) = (self.out_files.clone(), self.up.clone());
        let allowed = self.files_out.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::spawn(move || {
            let data = if allowed { out.lock().unwrap().read(id, index, offset, len) } else { None };
            let _ = up.send(match data {
                Some(data) => Up::FilesData { id, index, offset, data },
                None => Up::FilesReadFailed { id, index, offset },
            });
        });
    }

    /// Puts a list of files (`text/uri-list`, CRLF lines) on the session clipboard: a paste in the file manager copies them.
    pub fn set_uri_list(&self, list: String) {
        // Remembered so that the watch does not send the list back to the client as text.
        *self.last_set.lock().unwrap() = Some(list.clone());
        std::thread::spawn(move || {
            let mut cmd = Command::new("wl-copy");
            cmd.args(["--type", "text/uri-list"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
            if crate::compositor::is_nested() {
                if let Some(d) = nested_display() {
                    cmd.env("WAYLAND_DISPLAY", d);
                }
            }
            match cmd.spawn() {
                Ok(mut c) => {
                    if let Some(mut stdin) = c.stdin.take() {
                        let _ = stdin.write_all(list.as_bytes());
                    }
                    let status = c.wait();
                    info!(?status, "wl-copy (file list) done");
                }
                Err(e) => warn!("cannot run wl-copy: {e}"),
            }
        });
    }

    /// Puts the client's image (PNG) on the session clipboard.
    pub fn set_image(&self, png: Vec<u8>) {
        if png.len() > MAX_CLIPBOARD_IMAGE || !png.starts_with(b"\x89PNG\r\n\x1a\n") {
            warn!(len = png.len(), "client clipboard image is not an acceptable PNG; ignored");
            return;
        }
        *self.last_image.lock().unwrap() = Some(png.clone());
        std::thread::spawn(move || {
            let mut cmd = Command::new("wl-copy");
            cmd.args(["--type", "image/png"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
            if crate::compositor::is_nested() {
                if let Some(d) = nested_display() {
                    cmd.env("WAYLAND_DISPLAY", d);
                }
            }
            match cmd.spawn() {
                Ok(mut c) => {
                    if let Some(mut stdin) = c.stdin.take() {
                        let _ = stdin.write_all(&png);
                    }
                    let status = c.wait();
                    info!(?status, "wl-copy (image) done");
                }
                Err(e) => warn!("cannot run wl-copy: {e}"),
            }
        });
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What the Wayland clipboard holds as text, if anything.
fn wayland_text() -> Option<String> {
    let mut cmd = Command::new("wl-paste");
    cmd.args(["--no-newline", "--type", "text"]).stderr(Stdio::null());
    if crate::compositor::is_nested() {
        cmd.env("WAYLAND_DISPLAY", nested_display()?);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    (!text.is_empty()).then_some(text)
}

/// The `text/uri-list` the Wayland clipboard offers (at most 256 kB), if it offers one.
fn wayland_uri_list() -> Option<String> {
    use std::io::Read as _;
    let display = if crate::compositor::is_nested() { Some(nested_display()?) } else { None };
    let mut types = Command::new("wl-paste");
    types.arg("--list-types").stderr(Stdio::null());
    if let Some(d) = &display {
        types.env("WAYLAND_DISPLAY", d);
    }
    let listed = String::from_utf8(types.output().ok()?.stdout).ok()?;
    if !listed.lines().any(|t| t == "text/uri-list") {
        return None;
    }
    let mut cmd = Command::new("wl-paste");
    cmd.args(["--type", "text/uri-list"]).stdout(Stdio::piped()).stderr(Stdio::null());
    if let Some(d) = &display {
        cmd.env("WAYLAND_DISPLAY", d);
    }
    let mut child = cmd.spawn().ok()?;
    let mut bytes = Vec::new();
    child.stdout.take()?.take(256 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    let _ = child.kill();
    let _ = child.wait();
    (bytes.len() <= 256 * 1024).then(|| String::from_utf8(bytes).ok()).flatten().filter(|s| !s.is_empty())
}

/// What the Wayland clipboard holds as a PNG, if it offers an image and no text.
fn wayland_image() -> Option<Vec<u8>> {
    use std::io::Read as _;
    let display = if crate::compositor::is_nested() { Some(nested_display()?) } else { None };
    let mut types = Command::new("wl-paste");
    types.arg("--list-types").stderr(Stdio::null());
    if let Some(d) = &display {
        types.env("WAYLAND_DISPLAY", d);
    }
    let listed = String::from_utf8(types.output().ok()?.stdout).ok()?;
    if !listed.lines().any(|t| t == "image/png") {
        return None;
    }
    let mut cmd = Command::new("wl-paste");
    cmd.args(["--type", "image/png"]).stdout(Stdio::piped()).stderr(Stdio::null());
    if let Some(d) = &display {
        cmd.env("WAYLAND_DISPLAY", d);
    }
    let mut child = cmd.spawn().ok()?;
    // Read at most one byte more than allowed: an application that offers an endless image cannot fill memory.
    let mut png = Vec::new();
    child.stdout.take()?.take(MAX_CLIPBOARD_IMAGE as u64 + 1).read_to_end(&mut png).ok()?;
    let _ = child.kill();
    let _ = child.wait();
    (!png.is_empty() && png.len() <= MAX_CLIPBOARD_IMAGE).then_some(png)
}

/// The display of the desktop (COSMIC, Plasma) that runs inside the session's sway: the other Wayland socket of the runtime directory (sway's own is `WAYLAND_DISPLAY`).
fn nested_display() -> Option<String> {
    use std::os::unix::fs::FileTypeExt as _;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    let own = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
    let mut names: Vec<String> = std::fs::read_dir(runtime)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("wayland-") && n[8..].chars().all(|c| c.is_ascii_digit()) && *n != own)
        .collect();
    names.sort();
    names.pop()
}
