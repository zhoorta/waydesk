//! The session side of the sound: the session process runs as the account and so reaches its own PipeWire. It makes the virtual
//! speaker (a null sink the apps play into), records its monitor with `parec` and sends 20 ms chunks to the network daemon, which
//! only relays them to the client (`audio.rs`). Recording runs while the client's sound channel is open.

use std::io::Read as _;
use std::process::{Child, Command, Stdio};

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::audio::{ensure_sink, pactl, CHUNK, MIC_CHUNK, MIC_RATE, MIC_SOURCE, RATE, SINK};
use crate::proto::Up;

pub struct Audio {
    child: Option<Child>,
    up: mpsc::UnboundedSender<Up>,
    /// The default sink before the session took over, put back when the recording ends.
    previous_sink: Option<String>,
}

impl Audio {
    pub fn new(up: mpsc::UnboundedSender<Up>) -> Self {
        Self { child: None, up, previous_sink: None }
    }

    pub fn start(&mut self) {
        self.stop();
        let previous = pactl(&["get-default-sink"]).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty() && s != SINK);
        if previous.is_some() {
            self.previous_sink = previous;
        }
        if let Err(e) = ensure_sink() {
            warn!("sound: no audio server in this session ({e}); is pipewire-pulse running?");
            return;
        }
        let spawned = Command::new("parec")
            .args([&format!("--device={SINK}.monitor"), "--format=s16le", &format!("--rate={RATE}"), "--channels=2", "--latency-msec=20"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                warn!("sound: cannot run parec ({e}); is pulseaudio-utils installed?");
                return;
            }
        };
        let mut out = child.stdout.take().expect("piped stdout");
        self.child = Some(child);
        let up = self.up.clone();
        info!("sound: recording the session speaker");
        std::thread::spawn(move || {
            let mut buf = vec![0u8; CHUNK];
            let mut sent = 0u64;
            while out.read_exact(&mut buf).is_ok() {
                if up.send(Up::Audio { pcm: buf.clone() }).is_err() {
                    break;
                }
                sent += 1;
            }
            info!(chunks = sent, "sound: recording ended");
        });
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Give the account's own speakers back.
        if let Some(sink) = self.previous_sink.take() {
            let _ = pactl(&["set-default-sink", &sink]);
        }
    }
}

impl Drop for Audio {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The account's microphone: a PipeWire/PulseAudio "pipe source" (a real input device, not a monitor, so apps list it) that reads a FIFO;
/// the client's microphone chunks are written into it. It exists while the client's microphone is on.
#[derive(Default)]
pub struct Mic {
    fifo: Option<std::fs::File>,
    module: Option<String>,
    path: Option<std::path::PathBuf>,
    previous_source: Option<String>,
    dropped: u64,
}

impl Mic {
    pub fn start(&mut self) {
        self.stop();
        let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from) else {
            warn!("microphone: no XDG_RUNTIME_DIR in this session");
            return;
        };
        let path = dir.join("waydesk-mic.fifo");
        let _ = std::fs::remove_file(&path);
        // Mode 0600 by the umask of the session; the FIFO lives in the account's own runtime directory.
        let made = Command::new("mkfifo").arg("-m").arg("600").arg(&path).stderr(Stdio::null()).status();
        if !matches!(made, Ok(s) if s.success()) {
            warn!("microphone: cannot make the pipe (is mkfifo installed?)");
            return;
        }
        let args = [
            "load-module".to_string(),
            "module-pipe-source".to_string(),
            format!("source_name={MIC_SOURCE}"),
            format!("file={}", path.display()),
            "format=s16le".to_string(),
            format!("rate={MIC_RATE}"),
            "channels=1".to_string(),
            "source_properties=device.description=Waydesk-Microphone".to_string(),
        ];
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let module = match pactl(&args) {
            Ok(id) if !id.trim().is_empty() => id.trim().to_owned(),
            _ => {
                warn!("microphone: no audio server in this session (is pipewire-pulse running?)");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };
        // Read and write at once: opening only for writing would wait for the reader, and a full pipe must not block the session.
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(&path);
        let Ok(file) = file else {
            warn!("microphone: cannot open the pipe");
            let _ = pactl(&["unload-module", &module]);
            let _ = std::fs::remove_file(&path);
            return;
        };
        self.previous_source = pactl(&["get-default-source"]).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty() && s != MIC_SOURCE);
        let _ = pactl(&["set-default-source", MIC_SOURCE]);
        info!("microphone: the session has a virtual microphone");
        self.fifo = Some(file);
        self.module = Some(module);
        self.path = Some(path);
        self.dropped = 0;
    }

    pub fn write(&mut self, pcm: &[u8]) {
        use std::io::Write as _;
        if pcm.len() != MIC_CHUNK {
            return;
        }
        if let Some(f) = self.fifo.as_mut() {
            // A full pipe (the audio server is behind) loses the chunk: late sound is worse than a gap.
            if f.write_all(pcm).is_err() {
                self.dropped += 1;
                if self.dropped == 1 {
                    warn!("microphone: the pipe is full, chunks are dropped");
                }
            }
        }
    }

    pub fn stop(&mut self) {
        self.fifo = None;
        if let Some(m) = self.module.take() {
            let _ = pactl(&["unload-module", &m]);
        }
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
        if let Some(s) = self.previous_source.take() {
            let _ = pactl(&["set-default-source", &s]);
        }
    }
}

impl Drop for Mic {
    fn drop(&mut self) {
        self.stop();
    }
}
